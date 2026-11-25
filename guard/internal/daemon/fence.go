package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
)

type State string

const (
	StateBlockedBoot    State = "BlockedBoot"
	StateBlockedLocked  State = "BlockedLocked"
	StateVerifying      State = "Verifying"
	StateAckWait        State = "AckWait"
	StateOpen           State = "Open"
	StateUpgradingFence State = "UpgradingFence"
)

const (
	AckWaitTimeoutNs  = int64(3_000_000_000) // 3s AckWait window
	SwitchoverGraceNs = int64(1_500_000_000) // 1.5s switchover grace while tun0 remains UP
)

type EvalInput struct {
	BootID            string
	NowMonoNs         int64
	PolicyLoaded      bool
	Policy            contracts.Policy
	KnownClientUID    int
	Paused            bool
	Fence             contracts.UpgradeFence
	IdentityOK        bool
	LGPPresent        bool
	Session           *netfilter.ActiveSession
	Ack               *contracts.SandboxAckV1
	CurrentExemption  *contracts.ExemptionV1
	LastGeneration    uint64
	AckWaitDeadlineNs int64
	AckWaitBlocked    bool // true after AckWait timeout until a new trigger clears it
	// TProxyReady is true when the proxy core is alive and listening on the sandbox TProxy port
	// (only consulted when Policy.Mode == "tproxy").
	TProxyReady bool
}

type EvalDecision struct {
	NextState        State
	WriteExemption   bool
	NewExemption     contracts.ExemptionV1
	ArmRawDrop       bool
	OpenGate         bool
	ClearFence       bool
	StartAckWait     bool
	ClearAckDeadline bool
	AckTimedOut      bool
	Reason           string
}

func FenceActive(f contracts.UpgradeFence, bootID string, nowMonoNs int64) bool {
	return f.Active && f.BootID != "" && f.BootID == bootID && nowMonoNs < f.UntilMonoNs
}

func AckMatchesExemption(ack *contracts.SandboxAckV1, ex *contracts.ExemptionV1, bootID string) bool {
	if ack == nil || ex == nil || bootID == "" {
		return false
	}
	return ack.ContractVersion == contracts.ContractVersion &&
		ack.BootID == bootID &&
		ex.BootID == bootID &&
		ack.AppliedGeneration == ex.Generation &&
		ack.WriterPID() > 0
}

func SameExemptionContent(a, b contracts.ExemptionV1) bool {
	return a.ContractVersion == b.ContractVersion &&
		a.BootID == b.BootID &&
		a.State == b.State &&
		a.UserID == b.UserID &&
		a.Serial == b.Serial &&
		a.UIDStart == b.UIDStart &&
		a.UIDEnd == b.UIDEnd &&
		a.ClientUID == b.ClientUID &&
		a.VPNNetID == b.VPNNetID &&
		a.TunIf == b.TunIf &&
		a.TunIfindex == b.TunIfindex &&
		a.PortalDNS4 == b.PortalDNS4 &&
		a.EndpointV4 == b.EndpointV4 &&
		a.EndpointPort == b.EndpointPort &&
		a.IPv6Enabled == b.IPv6Enabled &&
		a.Mode == b.Mode &&
		a.TProxyPort == b.TProxyPort &&
		a.TProxyMark == b.TProxyMark
}

func BuildBlockedExemption(policy contracts.Policy, bootID string, clientUID int, gen uint64) contracts.ExemptionV1 {
	uidStart, uidEnd := policy.UIDRange()
	ex := contracts.ExemptionV1{
		ContractVersion: contracts.ContractVersion,
		Generation:      gen,
		BootID:          bootID,
		State:           "blocked",
		UserID:          policy.UserID,
		Serial:          policy.Serial,
		UIDStart:        uidStart,
		UIDEnd:          uidEnd,
		ClientUID:       clientUID,
		VPNNetID:        0,
		TunIf:           "",
		TunIfindex:      0,
		PortalDNS4:      policy.PortalDNS4,
		EndpointV4:      policy.EndpointV4,
		EndpointPort:    policy.EndpointPort,
		IPv6Enabled:     policy.IPv6Enabled,
	}
	if policy.IsTProxy() {
		ex.Mode = contracts.ModeTProxy
		ex.TProxyPort = policy.TProxyPort
		ex.TProxyMark = policy.TProxyMark
	}
	return ex
}

func BuildOpenExemption(policy contracts.Policy, bootID string, sess *netfilter.ActiveSession, gen uint64) contracts.ExemptionV1 {
	uidStart, uidEnd := policy.UIDRange()
	return contracts.ExemptionV1{
		ContractVersion: contracts.ContractVersion,
		Generation:      gen,
		BootID:          bootID,
		State:           "open",
		UserID:          policy.UserID,
		Serial:          policy.Serial,
		UIDStart:        uidStart,
		UIDEnd:          uidEnd,
		ClientUID:       sess.ClientUID,
		VPNNetID:        sess.VPNNetID,
		TunIf:           sess.TunIf,
		TunIfindex:      sess.TunIfindex,
		PortalDNS4:      policy.PortalDNS4,
		EndpointV4:      policy.EndpointV4,
		EndpointPort:    policy.EndpointPort,
		IPv6Enabled:     policy.IPv6Enabled,
	}
}

// BuildTProxyOpenExemption builds the "open" exemption for Mode == "tproxy" (no tun/vpn_net_id).
func BuildTProxyOpenExemption(policy contracts.Policy, bootID string, clientUID int, gen uint64) contracts.ExemptionV1 {
	ex := BuildBlockedExemption(policy, bootID, clientUID, gen)
	ex.State = "open"
	ex.Mode = contracts.ModeTProxy
	ex.TProxyPort = policy.TProxyPort
	ex.TProxyMark = policy.TProxyMark
	return ex
}

func nextGen(in EvalInput) uint64 {
	g := in.LastGeneration
	if in.CurrentExemption != nil && in.CurrentExemption.Generation > g {
		g = in.CurrentExemption.Generation
	}
	return g + 1
}

// Evaluate implements the deterministic guard & upgrade-fence state machine.
func Evaluate(in EvalInput) EvalDecision {
	if !in.PolicyLoaded {
		return EvalDecision{
			NextState:        StateBlockedBoot,
			ArmRawDrop:       false,
			OpenGate:         false,
			ClearAckDeadline: true,
			Reason:           "policy not loaded",
		}
	}

	// 1. Upgrade Fence takes highest priority while active.
	if FenceActive(in.Fence, in.BootID, in.NowMonoNs) {
		// If a fresh matching ack arrived after upgrade-begin unlinked the old ack,
		// and our candidate exemption is open, exit the fence immediately -> Verifying.
		if in.CurrentExemption != nil && in.CurrentExemption.State == "open" &&
			AckMatchesExemption(in.Ack, in.CurrentExemption, in.BootID) {
			dec := evaluateNormal(in)
			dec.ClearFence = true
			return dec
		}
		return EvalDecision{
			NextState:        StateUpgradingFence,
			WriteExemption:   false, // Keep candidate exemption open during external proxy upgrade.
			ArmRawDrop:       true,
			OpenGate:         false,
			ClearAckDeadline: true,
			Reason:           "upgrade fence active",
		}
	}

	dec := evaluateNormal(in)
	if in.Fence.Active {
		dec.ClearFence = true
	}
	return dec
}

func evaluateNormal(in EvalInput) EvalDecision {
	tproxy := in.Policy.IsTProxy()
	// 2. Paused, unverified profile/DPC, or missing VPN session / TProxy core -> BlockedLocked.
	missingTransport := in.Session == nil
	if tproxy {
		missingTransport = !in.TProxyReady
	}
	if in.Paused || !in.IdentityOK || missingTransport {
		clientUID := in.KnownClientUID
		if clientUID == 0 && in.CurrentExemption != nil {
			clientUID = in.CurrentExemption.ClientUID
		}
		candidate := BuildBlockedExemption(in.Policy, in.BootID, clientUID, 0)
		var eff contracts.ExemptionV1
		writeEx := false
		if in.CurrentExemption == nil || !SameExemptionContent(*in.CurrentExemption, candidate) {
			candidate.Generation = nextGen(in)
			eff = candidate
			writeEx = true
		} else {
			eff = *in.CurrentExemption
		}
		armRaw := in.LGPPresent && !AckMatchesExemption(in.Ack, &eff, in.BootID)
		reason := "vpn session inactive"
		if tproxy {
			reason = "tproxy core not ready"
		}
		if in.Paused {
			reason = "paused by user"
		} else if !in.IdentityOK {
			reason = "profile/DPC/lockdown unverified"
		}
		return EvalDecision{
			NextState:        StateBlockedLocked,
			WriteExemption:   writeEx,
			NewExemption:     eff,
			ArmRawDrop:       armRaw,
			OpenGate:         false,
			ClearAckDeadline: true,
			Reason:           reason,
		}
	}

	// 3. Valid transport (work VPN session or TProxy core) -> prepare candidate "open" exemption.
	clientUID := in.KnownClientUID
	if in.Session != nil {
		clientUID = in.Session.ClientUID
	}
	if clientUID == 0 && in.CurrentExemption != nil {
		clientUID = in.CurrentExemption.ClientUID
	}
	var candidate contracts.ExemptionV1
	if tproxy {
		candidate = BuildTProxyOpenExemption(in.Policy, in.BootID, clientUID, 0)
	} else {
		candidate = BuildOpenExemption(in.Policy, in.BootID, in.Session, 0)
	}
	var eff contracts.ExemptionV1
	writeEx := false
	if in.CurrentExemption == nil || !SameExemptionContent(*in.CurrentExemption, candidate) {
		if in.AckWaitBlocked && in.LGPPresent {
			// Hold blocked until a new ack/upgrade/START_VPN clears AckWaitBlocked.
			blocked := BuildBlockedExemption(in.Policy, in.BootID, clientUID, 0)
			if in.CurrentExemption == nil || !SameExemptionContent(*in.CurrentExemption, blocked) {
				blocked.Generation = nextGen(in)
				eff = blocked
				writeEx = true
			} else {
				eff = *in.CurrentExemption
			}
			return EvalDecision{
				NextState:        StateBlockedLocked,
				WriteExemption:   writeEx,
				NewExemption:     eff,
				ArmRawDrop:       true,
				OpenGate:         false,
				ClearAckDeadline: true,
				Reason:           "waiting for proxy ack clearance",
			}
		}
		candidate.Generation = nextGen(in)
		eff = candidate
		writeEx = true
	} else {
		eff = *in.CurrentExemption
	}

	// 4. Standalone mode (no external capture) -> Open immediately.
	if !in.LGPPresent {
		return EvalDecision{
			NextState:        StateOpen,
			WriteExemption:   writeEx,
			NewExemption:     eff,
			ArmRawDrop:       false,
			OpenGate:         true,
			ClearAckDeadline: true,
			Reason:           "open (standalone)",
		}
	}

	// 5. External proxy hook present: require matching sandbox_ack.v1.json.
	if AckMatchesExemption(in.Ack, &eff, in.BootID) {
		return EvalDecision{
			NextState:        StateOpen,
			WriteExemption:   writeEx,
			NewExemption:     eff,
			ArmRawDrop:       false,
			OpenGate:         true,
			ClearAckDeadline: true,
			Reason:           "open (acked)",
		}
	}

	// 6. AckWait timeout check (3s).
	if in.AckWaitDeadlineNs > 0 && in.NowMonoNs >= in.AckWaitDeadlineNs {
		blocked := BuildBlockedExemption(in.Policy, in.BootID, clientUID, nextGen(in))
		return EvalDecision{
			NextState:        StateBlockedLocked,
			WriteExemption:   true,
			NewExemption:     blocked,
			ArmRawDrop:       true,
			OpenGate:         false,
			ClearAckDeadline: true,
			AckTimedOut:      true,
			Reason:           "sandbox_ack timeout",
		}
	}

	return EvalDecision{
		NextState:      StateAckWait,
		WriteExemption: writeEx,
		NewExemption:   eff,
		ArmRawDrop:     true,
		OpenGate:       false,
		StartAckWait:   in.AckWaitDeadlineNs == 0,
		Reason:         fmt.Sprintf("waiting for sandbox_ack generation %d", eff.Generation),
	}
}

func ParseSandboxAck(data []byte, expectedBootID string) (*contracts.SandboxAckV1, error) {
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(data)))
	dec.UseNumber()
	var fields map[string]json.RawMessage
	if err := dec.Decode(&fields); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data in sandbox_ack")
	}
	if fields == nil {
		return nil, errors.New("empty sandbox_ack object")
	}

	var ack contracts.SandboxAckV1
	for k, raw := range fields {
		switch k {
		case "contract_version":
			if err := json.Unmarshal(raw, &ack.ContractVersion); err != nil {
				return nil, err
			}
		case "applied_generation":
			if err := json.Unmarshal(raw, &ack.AppliedGeneration); err != nil {
				return nil, err
			}
		case "boot_id":
			if err := json.Unmarshal(raw, &ack.BootID); err != nil {
				return nil, err
			}
		case "core_pid":
			if err := json.Unmarshal(raw, &ack.CorePID); err != nil {
				return nil, err
			}
		case "pid":
			if err := json.Unmarshal(raw, &ack.PID); err != nil {
				return nil, err
			}
		default:
			// Allow a proxy core to report its PID under an explicit *_pid key while rejecting unrelated fields.
			if strings.HasSuffix(k, "_pid") {
				var customPID int
				if err := json.Unmarshal(raw, &customPID); err != nil {
					return nil, fmt.Errorf("invalid %s in sandbox_ack: %w", k, err)
				}
				if ack.CorePID == 0 && customPID > 0 {
					ack.CorePID = customPID
				}
				continue
			}
			return nil, fmt.Errorf("json: unknown field %q", k)
		}
	}
	if ack.ContractVersion != contracts.ContractVersion || ack.AppliedGeneration == 0 || ack.WriterPID() <= 0 {
		return nil, errors.New("invalid sandbox_ack fields")
	}
	if expectedBootID != "" && ack.BootID != expectedBootID {
		return nil, errors.New("sandbox_ack boot_id mismatch")
	}
	return &ack, nil
}
