//go:build transport_vpn

package netfilter

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"sandbox_guard/internal/contracts"
)

func testVPNSpecOpen() GateSpec {
	return GateSpec{
		UserID:       10,
		UIDStart:     1000000,
		UIDEnd:       1099999,
		PortalDNS4:   contracts.PortalDNS4,
		EndpointV4:   "203.0.113.10",
		EndpointPort: 443,
		IPv6Enabled:  false,
		ArmRawDrop:   false,
		Open:         true,
		Session: &ActiveSession{
			ClientUID:   1010376,
			VPNNetID:    106,
			TunIf:       "tun0",
			TunIfindex:  19,
			UplinkNetID: 100,
			UplinkIf:    "wlan0",
			UplinkIndex: 12,
		},
	}
}

func TestHotPathRulesAndTCPReset(t *testing.T) {
	spec := testVPNSpecOpen()

	rawRules, err := RulesFor(4, GateHooks[0], spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawRules) != 0 {
		t.Fatalf("expected empty pass-through SBW_RAW_OUTPUT, got %v", rawRules)
	}

	outRules, err := RulesFor(4, GateHooks[1], spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(outRules) < 6 {
		t.Fatalf("expected >=6 SBW_OUTPUT rules, got %v", outRules)
	}
	if outRules[0] != "-o tun0 -m owner --uid-owner 1000000-1099999 -j RETURN" {
		t.Fatalf("unexpected rule 0: %s", outRules[0])
	}
	if outRules[1] != "-o tun0 -m mark --mark 0x6a/0xffff -j RETURN" {
		t.Fatalf("unexpected rule 1: %s", outRules[1])
	}
	wantOuter := "-o wlan0 -p tcp -d 203.0.113.10/32 --dport 443 -m owner --uid-owner 1010376 -m mark --mark 0x20064/0x2ffff -j RETURN"
	if outRules[2] != wantOuter {
		t.Fatalf("unexpected rule 2: %s\nwant: %s", outRules[2], wantOuter)
	}

	egRules, err := RulesFor(4, GateHooks[2], spec)
	if err != nil {
		t.Fatal(err)
	}
	if egRules[0] != outRules[0] || egRules[1] != outRules[1] || egRules[2] != outRules[2] {
		t.Fatalf("egress allow rules mismatch: %v", egRules[:3])
	}

	out6, err := RulesFor(6, GateHooks[1], spec)
	if err != nil || len(out6) == 0 || strings.Contains(strings.Join(out6, "\n"), "RETURN") {
		t.Fatalf("IPv6 OUTPUT must reject all work traffic, got %v (err=%v)", out6, err)
	}
}

func TestArmedRawDropAndFenceInvariantVPN(t *testing.T) {
	spec := testVPNSpecOpen()
	spec.ArmRawDrop = true
	if _, err := RulesFor(4, GateHooks[0], spec); err == nil {
		t.Fatal("expected invariant error when Open=true and ArmRawDrop=true")
	}
	spec.Open = false
	spec.Session = nil
	spec.LastVPNNetID = 106
	raw4, err := RulesFor(4, GateHooks[0], spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw4) != 5 || raw4[0] != "-m owner --uid-owner 1000000-1099999 -j DROP" {
		t.Fatalf("unexpected armed raw4 rules: %v", raw4)
	}
}

func TestActiveSessionJSONSnakeCase(t *testing.T) {
	s := testVPNSpecOpen().Session
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(b)
	for _, key := range []string{`"client_uid":1010376`, `"vpn_net_id":106`, `"tun_if":"tun0"`, `"tun_ifindex":19`, `"uplink_net_id":100`, `"uplink_if":"wlan0"`, `"uplink_index":12`} {
		if !strings.Contains(raw, key) {
			t.Fatalf("missing snake_case field %s in %s", key, raw)
		}
	}
}

func TestV251TProxyToVPNCleanupAndVerify(t *testing.T) {
	dir := t.TempDir()
	mock := newV250IPTablesMock()
	ctrl := &Controller{Runner: mock, LockPath: filepath.Join(dir, "nf.lock")}
	ctx := context.Background()

	tproxySpec := testTProxySpecOpen()
	if err := ctrl.ApplyOrVerify(ctx, tproxySpec, false); err != nil {
		t.Fatalf("apply tproxy failed: %v", err)
	}
	vpnSpec := testVPNSpecOpen()
	if err := ctrl.ApplyOrVerify(ctx, vpnSpec, false); err != nil {
		t.Fatalf("switch to vpn (TProxy cleanup + verification) failed: %v", err)
	}
	if err := ctrl.ApplyOrVerify(ctx, vpnSpec, true); err != nil {
		t.Fatalf("inspect vpn after TProxy cleanup failed: %v", err)
	}
}
