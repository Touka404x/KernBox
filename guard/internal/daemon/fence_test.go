package daemon

import (
	"bufio"
	"strings"
	"testing"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
)

func testPolicy() contracts.Policy {
	p := contracts.Policy{
		UserID:           10,
		Serial:           1000,
		CallerPackage:    contracts.DefaultWorkPackage,
		CallerCertSHA256: strings.Repeat("a", 64),
	}
	_ = p.NormalizeAndValidate()
	return p
}

func testSession() *netfilter.ActiveSession {
	return &netfilter.ActiveSession{
		ClientUID:   1010376,
		VPNNetID:    106,
		TunIf:       "tun0",
		TunIfindex:  19,
		UplinkNetID: 100,
		UplinkIf:    "wlan0",
		UplinkIndex: 12,
	}
}

func TestUpgradeFenceStateMachine(t *testing.T) {
	const boot = "11111111-2222-3333-4444-555555555555"
	pol := testPolicy()
	sess := testSession()

	// 1. Policy not loaded -> BlockedBoot
	d1 := Evaluate(EvalInput{BootID: boot, PolicyLoaded: false})
	if d1.NextState != StateBlockedBoot || d1.OpenGate || d1.ArmRawDrop {
		t.Fatalf("unexpected BlockedBoot decision: %+v", d1)
	}

	// 2. Policy loaded, no VPN session, no LGP -> BlockedLocked, raw pass-through (fast tcp-reset)
	d2 := Evaluate(EvalInput{
		BootID: boot, NowMonoNs: 100, PolicyLoaded: true, Policy: pol,
		IdentityOK: true, LGPPresent: false, Session: nil,
	})
	if d2.NextState != StateBlockedLocked || !d2.WriteExemption || d2.NewExemption.State != "blocked" || d2.ArmRawDrop || d2.OpenGate {
		t.Fatalf("unexpected BlockedLocked decision: %+v", d2)
	}

	// 3. Ready + hook present -> enters AckWait, writes open exemption gen=2, arms SBW_RAW_OUTPUT
	exBlocked := d2.NewExemption
	d3 := Evaluate(EvalInput{
		BootID: boot, NowMonoNs: 1_000_000, PolicyLoaded: true, Policy: pol,
		IdentityOK: true, LGPPresent: true, TProxyReady: true, Session: sess,
		CurrentExemption: &exBlocked, LastGeneration: exBlocked.Generation,
	})
	if d3.NextState != StateAckWait || !d3.WriteExemption || d3.NewExemption.State != "open" || d3.NewExemption.Generation != 2 || !d3.ArmRawDrop || d3.OpenGate || !d3.StartAckWait {
		t.Fatalf("unexpected AckWait decision: %+v", d3)
	}

	// 4. Ack timeout after 3s -> BlockedLocked, reverts exemption to blocked, arms SBW_RAW_OUTPUT
	exOpen := d3.NewExemption
	d4Timeout := Evaluate(EvalInput{
		BootID: boot, NowMonoNs: 1_000_000 + AckWaitTimeoutNs + 1, PolicyLoaded: true, Policy: pol,
		IdentityOK: true, LGPPresent: true, TProxyReady: true, Session: sess,
		CurrentExemption: &exOpen, LastGeneration: exOpen.Generation,
		AckWaitDeadlineNs: 1_000_000 + AckWaitTimeoutNs,
	})
	if d4Timeout.NextState != StateBlockedLocked || !d4Timeout.AckTimedOut || !d4Timeout.ArmRawDrop || d4Timeout.OpenGate || d4Timeout.NewExemption.State != "blocked" {
		t.Fatalf("unexpected AckWait timeout decision: %+v", d4Timeout)
	}

	// 5. Matching sandbox_ack arrives -> Open, disarms SBW_RAW_OUTPUT, opens SBW_OUTPUT/SBW_EGRESS
	ack := &contracts.SandboxAckV1{ContractVersion: 1, AppliedGeneration: exOpen.Generation, BootID: boot, CorePID: 4321}
	d5 := Evaluate(EvalInput{
		BootID: boot, NowMonoNs: 2_000_000, PolicyLoaded: true, Policy: pol,
		IdentityOK: true, LGPPresent: true, TProxyReady: true, Session: sess,
		Ack: ack, CurrentExemption: &exOpen, LastGeneration: exOpen.Generation,
	})
	if d5.NextState != StateOpen || d5.WriteExemption || d5.ArmRawDrop || !d5.OpenGate {
		t.Fatalf("unexpected Open decision: %+v", d5)
	}

	// 6. Handoff wlan0 -> ccmni2 (same tun0, vpn_net_id, client_uid) -> zero rewrite of exemption.v1.json!
	sessCell := *sess
	sessCell.UplinkIf = "ccmni2"
	sessCell.UplinkNetID = 101
	dHandoff := Evaluate(EvalInput{
		BootID: boot, NowMonoNs: 3_000_000, PolicyLoaded: true, Policy: pol,
		IdentityOK: true, LGPPresent: true, TProxyReady: true, Session: &sessCell,
		Ack: ack, CurrentExemption: &exOpen, LastGeneration: exOpen.Generation,
	})
	if dHandoff.NextState != StateOpen || dHandoff.WriteExemption || !dHandoff.OpenGate {
		t.Fatalf("handoff must not rewrite exemption.v1.json: %+v", dHandoff)
	}

	// 7. Upgrade-begin fence (90s TTL, stale ack unlinked) -> UpgradingFence, keeps exemption open candidate, arms RAW DROP!
	fence := contracts.UpgradeFence{BootID: boot, Active: true, UntilMonoNs: 93_000_000_000, TTLSeconds: 90}
	dFence := Evaluate(EvalInput{
		BootID: boot, NowMonoNs: 5_000_000, PolicyLoaded: true, Policy: pol,
		Fence: fence, IdentityOK: true, LGPPresent: true, TProxyReady: true, Session: sess,
		Ack: nil, CurrentExemption: &exOpen, LastGeneration: exOpen.Generation,
	})
	if dFence.NextState != StateUpgradingFence || dFence.WriteExemption || !dFence.ArmRawDrop || dFence.OpenGate {
		t.Fatalf("unexpected UpgradingFence decision: %+v", dFence)
	}

	// 8. Fresh matching ack arrives during fence -> exits fence immediately and opens!
	dFenceAck := Evaluate(EvalInput{
		BootID: boot, NowMonoNs: 6_000_000, PolicyLoaded: true, Policy: pol,
		Fence: fence, IdentityOK: true, LGPPresent: true, TProxyReady: true, Session: sess,
		Ack: ack, CurrentExemption: &exOpen, LastGeneration: exOpen.Generation,
	})
	if dFenceAck.NextState != StateOpen || !dFenceAck.ClearFence || dFenceAck.ArmRawDrop || !dFenceAck.OpenGate {
		t.Fatalf("expected immediate exit from fence on matching ack: %+v", dFenceAck)
	}

	// 9. Fence TTL expires -> evaluates normal state
	dFenceExpire := Evaluate(EvalInput{
		BootID: boot, NowMonoNs: 94_000_000_000, PolicyLoaded: true, Policy: pol,
		Fence: fence, IdentityOK: true, LGPPresent: false, TProxyReady: true, Session: sess,
		CurrentExemption: &exOpen, LastGeneration: exOpen.Generation,
	})
	if dFenceExpire.NextState != StateOpen || !dFenceExpire.ClearFence || !dFenceExpire.OpenGate {
		t.Fatalf("expected TTL expiry to open standalone: %+v", dFenceExpire)
	}
}

func TestCountStuckSocketsFromReader(t *testing.T) {
	const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 010011AC:A123 040013C6:01BB 02 00000000:00000000 00:00000000 00000000 1010376      0 12345
   1: 010011AC:A124 040012C6:01BB 02 00000000:00000000 00:00000000 00000000 1010555      0 12346
   2: 010011AC:A125 040012C6:01BB 02 00000000:00000000 00:00000000 00000000 10398        0 12347
   3: 010011AC:A126 040013C6:01BB 01 00000000:00000000 00:00000000 00000000 1010376      0 12348
`
	w, c := CountStuckSocketsFromReader(bufio.NewScanner(strings.NewReader(procNetTCP)), 1000000, 1099999)
	if w != 1 || c != 1 {
		t.Fatalf("unexpected stuck counts: work13C6=%d cross12C6=%d", w, c)
	}
}
