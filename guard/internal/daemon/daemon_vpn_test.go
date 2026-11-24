//go:build transport_vpn

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
)

func newTestReconcileDaemon(t *testing.T, withExtCap bool) (*Daemon, *mockCmdRunner, *statefulMockIPTables, *mockVPNStatusResolver) {
	t.Helper()
	dir := t.TempDir()
	pol := testPolicy()
	pol.Mode = contracts.ModeVPN
	pol.EndpointV4 = "203.0.113.10"
	pol.EndpointPort = 443
	if withExtCap {
		pol.ProxySkipPrefix = "EXT_PROXY_"
	}
	pkg := contracts.DefaultWorkPackage
	runner := &mockCmdRunner{out: map[string]string{
		"cmd user list -v":                                                   "0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running) (current)\n1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running) (profile-owner)\n",
		"dumpsys user --user 10":                                             "  UserInfo{10:Work:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
		"cmd device_policy list-owners":                                      "User 10: admin=" + contracts.DefaultAdminComponent + ",ManagedProfileOwner(parentUserId=0)\n",
		"settings --user 10 get secure always_on_vpn_app":                    pkg + "\n",
		"settings --user 10 get secure always_on_vpn_lockdown":               "1\n",
		"settings --user 10 get secure always_on_vpn_lockdown_whitelist":     "null\n",
		"dumpsys vpn_management":                                             "  10: " + pkg + "\n",
		"cmd package list packages --user 10 -U " + pkg:                      "package:" + pkg + " uid:1010376\n",
		"dumpsys deviceidle whitelist +" + pkg:                               "",
		"cmd appops set --user 10 " + pkg + " RUN_ANY_IN_BACKGROUND allow":   "",
		"cmd appops set --user 10 " + pkg + " POST_NOTIFICATION allow":       "",
	}}
	nfMock := newStatefulMockIPTables(withExtCap)
	stRes := &mockVPNStatusResolver{uid: 1010376}
	d := &Daemon{
		nf:               &netfilter.Controller{Runner: nfMock, LockPath: filepath.Join(dir, "nf.lock")},
		runner:           runner,
		resolver:         stRes,
		bootID:           "boot-switch-1",
		policy:           pol,
		policyLoaded:     true,
		state:            StateBlockedBoot,
		workCfgDir:       dir,
		desiredStatePath: filepath.Join(dir, "desired_state.json"),
		exemptionPath:    filepath.Join(dir, "exemption.v1.json"),
		sandboxAckPath:   filepath.Join(dir, "sandbox_ack.v1.json"),
		upgradeFencePath: filepath.Join(dir, "upgrade_fence.json"),
		reconcileCh:      make(chan reconcileReq, 4),
	}
	return d, runner, nfMock, stRes
}

func TestReconcileSwitchoverOpenToOpenPreservesGenerationAndSkipsAckWait(t *testing.T) {
	d, _, nfMock, stRes := newTestReconcileDaemon(t, true)
	const boot = "boot-switch-1"
	nowNs := int64(10_000_000_000)
	d.nowMonoNsFn = func() int64 { return nowNs }
	d.probeTunAlive = func(tunIf string, idx int) bool { return tunIf == "tun0" && idx == 19 }
	d.probeServiceAlive = func(uid int) bool { return uid == 1010376 }

	tun := android.LiveIface{Name: "tun0", Index: 19, Up: true, HasIPv4: true, IPv4CIDRs: []string{"172.19.0.1/30"}}
	wlan := android.LiveIface{Name: "wlan0", Index: 12, Up: true, HasIPv4: true, IPv4CIDRs: []string{"192.168.1.5/24"}}
	cell := android.LiveIface{Name: "ccmni2", Index: 8, Up: true, HasIPv4: true, IPv4CIDRs: []string{"10.1.2.3/24"}}
	d.probeFastSession = func(b string, uid int, st *contracts.VPNStatus) (*netfilter.ActiveSession, bool) {
		return android.TryFastStatusSession(b, uid, st, []android.LiveIface{tun, wlan, cell})
	}

	// Step 1: Enter AckWait -> write sandbox_ack -> reach StateOpen on wlan0 (gen=1).
	stRes.payload = []byte(`{"boot_id":"boot-switch-1","running":true,"tun_if":"tun0","vpn_net_id":132,"underlay_if":"wlan0","underlay_net_id":138}`)
	if err := d.reconcileOnce(context.Background(), reconcileReq{}); err != nil {
		t.Fatal(err)
	}
	if d.state != StateAckWait || d.lastGen != 1 {
		t.Fatalf("expected StateAckWait gen=1, got state=%s gen=%d err=%q", d.state, d.lastGen, d.lastError)
	}
	ackBytes, _ := json.Marshal(contracts.SandboxAckV1{ContractVersion: 1, AppliedGeneration: 1, BootID: boot, CorePID: 5555})
	if err := os.WriteFile(d.sandboxAckPath, ackBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.reconcileOnce(context.Background(), reconcileReq{clearAckBlock: true}); err != nil {
		t.Fatal(err)
	}
	if d.state != StateOpen || d.lastGen != 1 || d.lastRawArmed || !d.lastOpen {
		t.Fatalf("expected StateOpen gen=1, got state=%s gen=%d raw=%v open=%v", d.state, d.lastGen, d.lastRawArmed, d.lastOpen)
	}
	exBefore, err := os.ReadFile(d.exemptionPath)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: Physical uplink switches wlan0 -> ccmni2 (same tun0/vpn_net_id=132/client_uid).
	// Must stay StateOpen, NOT increment generation, NOT enter AckWait, NOT arm SBW_RAW_OUTPUT!
	stRes.payload = []byte(`{"boot_id":"boot-switch-1","running":true,"tun_if":"tun0","vpn_net_id":132,"underlay_if":"ccmni2","underlay_net_id":100}`)
	if err := d.reconcileOnce(context.Background(), reconcileReq{hintHandoff: true}); err != nil {
		t.Fatal(err)
	}
	if d.state != StateOpen || d.lastGen != 1 || d.lastRawArmed || !d.lastOpen {
		t.Fatalf("switchover must stay StateOpen with gen=1 and raw=false, got state=%s gen=%d raw=%v open=%v", d.state, d.lastGen, d.lastRawArmed, d.lastOpen)
	}
	exAfter, _ := os.ReadFile(d.exemptionPath)
	if !bytes.Equal(exBefore, exAfter) {
		t.Fatalf("exemption.v1.json must not be rewritten on uplink switchover:\nbefore=%s\nafter=%s", exBefore, exAfter)
	}
	if len(nfMock.tables["4/raw"][contracts.ChainRawOutput]) != 0 {
		t.Fatalf("SBW_RAW_OUTPUT must remain empty pass-through during uplink switchover, got %v", nfMock.tables["4/raw"][contracts.ChainRawOutput])
	}
	sbwOut := strings.Join(nfMock.tables["4/filter"][contracts.ChainOutput], "\n")
	if !strings.Contains(sbwOut, "-o ccmni2 -p tcp -d 203.0.113.10/32 --dport 443") || strings.Contains(sbwOut, "-o wlan0 ") {
		t.Fatalf("expected SBW_OUTPUT swapped in-place to ccmni2, got:\n%s", sbwOut)
	}
}

func TestReconcileSwitchoverGracePeriodAndExpiry(t *testing.T) {
	d, runner, nfMock, stRes := newTestReconcileDaemon(t, true)
	const boot = "boot-switch-1"
	nowNs := int64(20_000_000_000)
	d.nowMonoNsFn = func() int64 { return nowNs }
	tunAlive := true
	svcAlive := true
	d.probeTunAlive = func(tunIf string, idx int) bool { return tunAlive && tunIf == "tun0" && idx == 19 }
	d.probeServiceAlive = func(uid int) bool { return svcAlive && uid == 1010376 }

	tun := android.LiveIface{Name: "tun0", Index: 19, Up: true, HasIPv4: true, IPv4CIDRs: []string{"172.19.0.1/30"}}
	wlan := android.LiveIface{Name: "wlan0", Index: 12, Up: true, HasIPv4: true, IPv4CIDRs: []string{"192.168.1.5/24"}}
	fastLive := true
	d.probeFastSession = func(b string, uid int, st *contracts.VPNStatus) (*netfilter.ActiveSession, bool) {
		if !fastLive {
			return nil, false
		}
		return android.TryFastStatusSession(b, uid, st, []android.LiveIface{tun, wlan})
	}

	// Bring daemon to StateOpen first.
	stRes.payload = []byte(`{"boot_id":"boot-switch-1","running":true,"tun_if":"tun0","vpn_net_id":132,"underlay_if":"wlan0","underlay_net_id":138}`)
	_ = d.reconcileOnce(context.Background(), reconcileReq{})
	ackBytes, _ := json.Marshal(contracts.SandboxAckV1{ContractVersion: 1, AppliedGeneration: 1, BootID: boot, CorePID: 5555})
	_ = os.WriteFile(d.sandboxAckPath, ackBytes, 0600)
	_ = d.reconcileOnce(context.Background(), reconcileReq{clearAckBlock: true})
	if d.state != StateOpen {
		t.Fatalf("precondition failed: want StateOpen, got %s err=%q", d.state, d.lastError)
	}

	// 1. Transient missing uplink (e.g. ConnectivityService gap) while tun0 is alive -> grace holds StateOpen!
	fastLive = false
	runner.out["dumpsys connectivity"] = "Current Networks:\n"
	if err := d.reconcileOnce(context.Background(), reconcileReq{}); err != nil {
		t.Fatal(err)
	}
	if d.state != StateOpen || d.lastGen != 1 || d.lastRawArmed || d.switchGraceUntilNs != nowNs+SwitchoverGraceNs {
		t.Fatalf("expected grace to preserve StateOpen gen=1 raw=false, got state=%s gen=%d raw=%v grace=%d",
			d.state, d.lastGen, d.lastRawArmed, d.switchGraceUntilNs)
	}
	if len(nfMock.tables["4/raw"][contracts.ChainRawOutput]) != 0 {
		t.Fatalf("SBW_RAW_OUTPUT must NOT arm during active switchover grace")
	}

	// 2. Subsequent wake 500ms later keeps original deadline without extending indefinitely.
	wantDeadline := d.switchGraceUntilNs
	nowNs += 500_000_000
	_ = d.reconcileOnce(context.Background(), reconcileReq{})
	if d.state != StateOpen || d.switchGraceUntilNs != wantDeadline || d.lastGen != 1 {
		t.Fatalf("expected same grace deadline %d at +500ms, got state=%s grace=%d gen=%d",
			wantDeadline, d.state, d.switchGraceUntilNs, d.lastGen)
	}

	// 3. Past 1500ms grace with no uplink -> fail-closed StateBlockedLocked + armed SBW_RAW_OUTPUT!
	nowNs = wantDeadline + 1
	_ = d.reconcileOnce(context.Background(), reconcileReq{})
	if d.state != StateBlockedLocked || !d.lastRawArmed || d.lastOpen || d.switchGraceUntilNs != 0 {
		t.Fatalf("expected fail-closed after 1500ms grace expiry, got state=%s raw=%v open=%v grace=%d",
			d.state, d.lastRawArmed, d.lastOpen, d.switchGraceUntilNs)
	}

	// 4. Re-open, then kill tun0 -> MUST block immediately with 0ms grace!
	fastLive = true
	nowNs += 100_000_000
	_ = d.reconcileOnce(context.Background(), reconcileReq{clearAckBlock: true})
	ackBytes2, _ := json.Marshal(contracts.SandboxAckV1{ContractVersion: 1, AppliedGeneration: d.lastGen, BootID: boot, CorePID: 5555})
	_ = os.WriteFile(d.sandboxAckPath, ackBytes2, 0600)
	_ = d.reconcileOnce(context.Background(), reconcileReq{clearAckBlock: true})
	if d.state != StateOpen {
		t.Fatalf("expected StateOpen restore, got %s", d.state)
	}
	fastLive = false
	tunAlive = false // tun0 vanished (e.g. kill -9 TunService)
	_ = d.reconcileOnce(context.Background(), reconcileReq{})
	if d.state != StateBlockedLocked || !d.lastRawArmed || d.switchGraceUntilNs != 0 {
		t.Fatalf("expected immediate BlockedLocked when tun0 dies, got state=%s raw=%v grace=%d",
			d.state, d.lastRawArmed, d.switchGraceUntilNs)
	}
}

func TestDualUplinkStatusBypassThrottleAndZeroDumpsys(t *testing.T) {
	d, runner, _, stRes := newTestReconcileDaemon(t, true)
	const boot = "boot-switch-1"
	nowNs := int64(30_000_000_000)
	d.nowMonoNsFn = func() int64 { return nowNs }
	d.probeTunAlive = func(tunIf string, idx int) bool { return tunIf == "tun0" && idx == 19 }
	d.probeServiceAlive = func(uid int) bool { return uid == 1010376 }

	tun := android.LiveIface{Name: "tun0", Index: 19, Up: true, HasIPv4: true, IPv4CIDRs: []string{"172.19.0.1/30"}}
	wlan := android.LiveIface{Name: "wlan0", Index: 12, Up: true, HasIPv4: true, IPv4CIDRs: []string{"192.168.1.5/24"}}
	cell := android.LiveIface{Name: "ccmni2", Index: 8, Up: true, HasIPv4: true, IPv4CIDRs: []string{"10.1.2.3/24"}}
	d.probeFastSession = func(b string, uid int, st *contracts.VPNStatus) (*netfilter.ActiveSession, bool) {
		return android.TryFastStatusSession(b, uid, st, []android.LiveIface{tun, wlan, cell})
	}

	// Open initially on wlan0 while BOTH wlan0 and ccmni2 are up.
	stRes.payload = []byte(`{"boot_id":"boot-switch-1","running":true,"tun_if":"tun0","vpn_net_id":132,"underlay_if":"wlan0","underlay_net_id":138}`)
	_ = d.reconcileOnce(context.Background(), reconcileReq{})
	ackBytes, _ := json.Marshal(contracts.SandboxAckV1{ContractVersion: 1, AppliedGeneration: 1, BootID: boot, CorePID: 5555})
	_ = os.WriteFile(d.sandboxAckPath, ackBytes, 0600)
	_ = d.reconcileOnce(context.Background(), reconcileReq{clearAckBlock: true})

	// Changed (underlay_if, underlay_net_id) while dual-uplink up MUST bypass 100ms throttle AND avoid dumpsys connectivity!
	stRes.payload = []byte(`{"boot_id":"boot-switch-1","running":true,"tun_if":"tun0","vpn_net_id":132,"underlay_if":"ccmni2","underlay_net_id":100}`)
	if !d.shouldBypassHintThrottle() {
		t.Fatal("expected shouldBypassHintThrottle() == true on changed underlay")
	}
	runner.calls = nil
	if err := d.reconcileOnce(context.Background(), reconcileReq{hintHandoff: true}); err != nil {
		t.Fatal(err)
	}
	for _, c := range runner.calls {
		if strings.Contains(c, "dumpsys connectivity") {
			t.Fatalf("dual-uplink fast status path must not invoke dumpsys connectivity, calls=%v", runner.calls)
		}
	}
	if d.lastSession == nil || d.lastSession.UplinkIf != "ccmni2" || d.lastSession.UplinkNetID != 100 {
		t.Fatalf("expected active session ccmni2/100, got %+v", d.lastSession)
	}
	// Repeat event with identical (ccmni2, 100) must NOT bypass 100ms throttle.
	if d.shouldBypassHintThrottle() {
		t.Fatal("expected shouldBypassHintThrottle() == false when underlay matches current session")
	}
}

func TestVPNStatusPendingConfigContract(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy()
	pol.Mode = contracts.ModeVPN
	pkg := contracts.DefaultWorkPackage
	runner := &mockCmdRunner{out: map[string]string{
		"cmd package list packages --user 10 -U " + pkg: "package:" + pkg + " uid:1010376\n",
		"settings get global private_dns_mode":           "off\n",
	}}
	d := &Daemon{
		runner:       runner,
		bootID:       "boot-test-vpn-2",
		policy:       pol,
		policyLoaded: true,
		state:        StateOpen,
		workCfgDir:   dir,
		resolver: &mockVPNStatusResolver{
			uid:     1010376,
			payload: []byte(`{"boot_id":"boot-test-vpn-2","running":true,"tun_if":"tun0","vpn_net_id":106,"underlay_if":"wlan0","underlay_net_id":100,"mtu":1380,"quic_udp443_mode":"allow","config_generation":7}`),
		},
	}
	stData := d.buildStatusData(context.Background())
	rawBytes, err := json.Marshal(stData)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(rawBytes)
	for _, want := range []string{`"mtu":1380`, `"quic_udp443_mode":"allow"`, `"config_generation":7`, `"pending_config":{"generation":7,"mtu":1380,"quic_udp443_mode":"allow"}`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("missing %s in status JSON: %s", want, raw)
		}
	}
}
