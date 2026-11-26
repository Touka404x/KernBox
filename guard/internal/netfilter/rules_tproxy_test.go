package netfilter

import (
	"strings"
	"testing"

	"sandbox_guard/internal/contracts"
)

func testTProxySpecOpen() GateSpec {
	return GateSpec{
		UserID:                 10,
		UIDStart:               1000000,
		UIDEnd:                 1099999,
		PortalDNS4:             contracts.PortalDNS4,
		EndpointV4:             "203.0.113.10",
		EndpointPort:           443,
		IPv6Enabled:            false,
		ArmRawDrop:             false,
		Open:                   true,
		Mode:                   contracts.ModeTProxy,
		TProxyPort:             1537,
		TProxyMark:             0x1a,
		KernelRejectQuicUDP443: true,
	}
}

func TestGateBatchPreservesExternalGuardAndSkipPrefix(t *testing.T) {
	spec := testTProxySpecOpen()
	spec.GuardChainOut = "SB_GUARD_OUT"
	spec.ProxySkipPrefix = "PROXY_"
	hooks := GateHooksFor(spec)

	current := ParseSave(`*filter
:OUTPUT ACCEPT [0:0]
-A OUTPUT -j SB_GUARD_OUT
-A OUTPUT -j SBW_OUTPUT
-A OUTPUT -j oem_out
COMMIT
`)
	batch := GateBatch(current, hooks[1], []string{"-m owner --uid-owner 1000000-1099999 -p tcp -j REJECT --reject-with tcp-reset"})
	if !strings.Contains(batch, "-I OUTPUT 2 -j SBW_OUTPUT\n") {
		t.Fatalf("expected position 2 hook after SB_GUARD_OUT, got:\n%s", batch)
	}
	if !strings.Contains(batch, "-D OUTPUT -j SBW_OUTPUT\n") {
		t.Fatalf("expected old jump deletion:\n%s", batch)
	}
	if strings.Contains(batch, "-D OUTPUT -j SB_GUARD_OUT") {
		t.Fatalf("must not delete SB_GUARD_OUT:\n%s", batch)
	}

	corrupted := ParseSave("-A OUTPUT -j SBW_OUTPUT\n-A OUTPUT -j SB_GUARD_OUT\n")
	batch2 := GateBatch(corrupted, hooks[1], []string{"-m owner --uid-owner 1000000-1099999 -j REJECT"})
	if !strings.Contains(batch2, "-I OUTPUT 2 -j SBW_OUTPUT\n") {
		t.Fatalf("expected healed position 2 hook, got:\n%s", batch2)
	}

	mangleCur := ParseSave(`*mangle
:OUTPUT ACCEPT [0:0]
-A OUTPUT -j PROXY_OUTPUT
-A OUTPUT -j SBW_TPROXY_OUT
COMMIT
`)
	batch3 := GateBatch(mangleCur, hooks[3], []string{"-m owner --uid-owner 1000000-1099999 -j ACCEPT"})
	if !strings.Contains(batch3, "-I OUTPUT 2 -j SBW_TPROXY_OUT\n") {
		t.Fatalf("expected TProxy hook after PROXY_OUTPUT, got:\n%s", batch3)
	}
}

func TestSameGateRuleCanonicalization(t *testing.T) {
	wantReset := "-m owner --uid-owner 1000000-1099999 -p tcp -j REJECT --reject-with tcp-reset"
	gotReset := "-p tcp -m owner --uid-owner 1000000-1099999 -m tcp -j REJECT --reject-with tcp-reset"
	if !SameGateRule(wantReset, gotReset) {
		t.Fatal("failed to match canonicalized tcp-reset rule")
	}
	gotDefault := "-p tcp -m owner --uid-owner 1000000-1099999 -m tcp -j REJECT --reject-with icmp-port-unreachable"
	if SameGateRule(wantReset, gotDefault) {
		t.Fatal("wrongly accepted icmp-port-unreachable when tcp-reset was required")
	}

	wantOuter := "-o wlan0 -p tcp -d 203.0.113.10/32 --dport 443 -m owner --uid-owner 1010376 -m mark --mark 0x20064/0x2ffff -j RETURN"
	gotOuter := "-d 203.0.113.10 -o wlan0 -p tcp -m tcp --dport 443 -m owner --uid-owner 1010376 -m mark --mark 0x00020064/0x0002ffff -j RETURN"
	if !SameGateRule(wantOuter, gotOuter) {
		t.Fatal("failed to match canonicalized outer rule")
	}

	if !SameGateRule("! -i lo -j RETURN", "! -i lo -j RETURN") {
		t.Fatal("failed to match negated interface rule")
	}
	if SameGateRule("! -i lo -j RETURN", "-i lo -j RETURN") {
		t.Fatal("wrongly matched non-negated -i lo against ! -i lo")
	}
	if SameGateRule("! -j RETURN", "! -j RETURN") {
		t.Fatal("must reject invalid ! -j rule")
	}
	if SameGateRule("-i lo -j !", "-i lo -j !") {
		t.Fatal("must reject dangling ! token")
	}
	if SameGateRule("-i lo !", "-i lo !") {
		t.Fatal("must reject trailing ! token")
	}
}

func TestTProxyRulesQuicKernelRejectAndPreBypass(t *testing.T) {
	spec := testTProxySpecOpen()
	outRules, err := RulesFor(4, GateHooks[3], spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(outRules) != 7 {
		t.Fatalf("expected 7 SBW_TPROXY_OUT rules with QUIC bypass, got %d: %v", len(outRules), outRules)
	}
	if outRules[3] != "-m owner --uid-owner 1000000-1099999 -p udp -m udp --dport 443 -j RETURN" {
		t.Fatalf("expected kernel UDP 443 RETURN at index 3, got %s", outRules[3])
	}

	preRules, err := RulesFor(4, GateHooks[4], spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(preRules) != 4 || preRules[0] != "! -i lo -j RETURN" {
		t.Fatalf("expected ! -i lo -j RETURN as rule 0 in SBW_TPROXY_PRE, got %v", preRules)
	}
	if !strings.Contains(preRules[2], "--on-ip 127.0.0.1") || !strings.Contains(preRules[3], "--on-ip 127.0.0.1") {
		t.Fatalf("expected SBW_TPROXY_PRE TCP/UDP rules to target --on-ip 127.0.0.1, got %v", preRules)
	}

	spec.KernelRejectQuicUDP443 = false
	outNoReject, err := RulesFor(4, GateHooks[3], spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(outNoReject) != 6 {
		t.Fatalf("expected 6 SBW_TPROXY_OUT rules without QUIC bypass, got %d", len(outNoReject))
	}

	// Verify Open=true IPv6 keeps ::1 loopback strictly blocked on both SBW_OUTPUT and SBW_EGRESS.
	v6OpenOut, err := RulesFor(6, GateHooks[1], spec)
	if err != nil || len(v6OpenOut) == 0 || v6OpenOut[0] != "-m owner --uid-owner 1000000-1099999 -p tcp -j REJECT --reject-with tcp-reset" {
		t.Fatalf("expected IPv6 OUTPUT to reject all work loopback/external traffic while open, got err=%v rules=%v", err, v6OpenOut)
	}
	v6OpenEg, err := RulesFor(6, GateHooks[2], spec)
	if err != nil || len(v6OpenEg) != 1 || v6OpenEg[0] != "-m owner --uid-owner 1000000-1099999 -j DROP" {
		t.Fatalf("expected IPv6 EGRESS to drop all work traffic while open, got err=%v rules=%v", err, v6OpenEg)
	}

	// Verify Open=false remains strictly fail-closed on OUTPUT/EGRESS and clears TProxy chains.
	spec.Open = false
	closedOut, err := RulesFor(4, GateHooks[3], spec)
	if err != nil || len(closedOut) != 0 {
		t.Fatalf("closed TPROXY_OUT must be empty, got err=%v rules=%v", err, closedOut)
	}
	filterClosed, err := RulesFor(4, GateHooks[1], spec)
	if err != nil || len(filterClosed) != 2 || filterClosed[1] != "-m owner --uid-owner 1000000-1099999 -j REJECT" {
		t.Fatalf("closed OUTPUT must fail-closed, got err=%v rules=%v", err, filterClosed)
	}
	spec.ArmRawDrop = true
	rawArmed, err := RulesFor(4, GateHooks[0], spec)
	if err != nil || len(rawArmed) != 1 || rawArmed[0] != "-m owner --uid-owner 1000000-1099999 -j DROP" {
		t.Fatalf("armed RAW_OUTPUT must DROP, got err=%v rules=%v", err, rawArmed)
	}
	spec.Open = true
	if _, err := RulesFor(4, GateHooks[0], spec); err == nil {
		t.Fatal("expected invariant error when Open=true and ArmRawDrop=true")
	}
}

func TestHasExternalCapture(t *testing.T) {
	m4 := ParseSave("*mangle\n:PROXY_OUTPUT - [0:0]\n-A OUTPUT -p tcp -j PROXY_OUTPUT\n")
	if !HasExternalCapture(m4, 4, "PROXY_") || HasExternalCapture(m4, 6, "PROXY_") {
		t.Fatal("unexpected HasExternalCapture result")
	}
	tpx4 := ParseSave("*mangle\n:TPX_PROXY_OUTPUT - [0:0]\n-A OUTPUT -p tcp -j TPX_PROXY_OUTPUT\n")
	if !HasExternalCapture(tpx4, 4, "TPX_") || HasExternalCapture(tpx4, 6, "TPX_") {
		t.Fatal("expected TPX_PROXY_OUTPUT to match IPv4 prefix TPX_ only")
	}
	tpx6 := ParseSave("*mangle\n:TPX_PROXY_OUTPUT6 - [0:0]\n-A OUTPUT -p tcp -j TPX_PROXY_OUTPUT6\n")
	if !HasExternalCapture(tpx6, 6, "TPX_") || HasExternalCapture(tpx6, 4, "TPX_") {
		t.Fatal("expected TPX_PROXY_OUTPUT6 to match IPv6 prefix TPX_ only")
	}
	if HasExternalCapture(m4, 4, "") {
		t.Fatal("empty prefix must return false")
	}
	onlyACL := ParseSave("*mangle\n:SBW_EGRESS - [0:0]\n")
	if HasExternalCapture(onlyACL, 4, "PROXY_") {
		t.Fatal("false positive on capture chain detection")
	}
}
