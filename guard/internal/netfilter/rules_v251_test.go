package netfilter

import (
	"strings"
	"testing"
)

func TestV251LoopbackBlockedExceptMarkedDNSAndTProxyPreReturn(t *testing.T) {
	spec := testTProxySpecOpen()

	outV4, err := RulesFor(4, GateHooks[1], spec) // SBW_OUTPUT
	if err != nil {
		t.Fatal(err)
	}
	joinedOut4 := strings.Join(outV4, "\n")
	if strings.Contains(joinedOut4, "127.0.0.1") || strings.Contains(joinedOut4, "127.0.0.0") {
		t.Fatalf("SBW_OUTPUT must NEVER allow generic 127.0.0.1/127.0.0.0 loopback access to User 0 listeners:\n%s", joinedOut4)
	}
	if outV4[0] != "-m owner --uid-owner 1000000-1099999 -m mark --mark 0x1a/0xffff -j RETURN" {
		t.Fatalf("expected marked DNS/outbound return rule first, got %q", outV4[0])
	}

	egV4, err := RulesFor(4, GateHooks[2], spec) // SBW_EGRESS
	if err != nil {
		t.Fatal(err)
	}
	joinedEg4 := strings.Join(egV4, "\n")
	if strings.Contains(joinedEg4, "127.0.0.1") {
		t.Fatalf("SBW_EGRESS must not allow unmarked 127.0.0.1:\n%s", joinedEg4)
	}

	tpOut, err := RulesFor(4, GateHooks[3], spec) // SBW_TPROXY_OUT
	if err != nil {
		t.Fatal(err)
	}
	if tpOut[2] != "-m owner --uid-owner 1000000-1099999 -d 127.0.0.0/8 -j RETURN" {
		t.Fatalf("expected 127.0.0.0/8 un-marked return (catching 127.0.0.2+ before TProxy), got %q", tpOut[2])
	}

	tpPre, err := RulesFor(4, GateHooks[4], spec) // SBW_TPROXY_PRE
	if err != nil {
		t.Fatal(err)
	}
	if tpPre[1] != "-m conntrack --ctdir REPLY -j RETURN" {
		t.Fatalf("SBW_TPROXY_PRE reply rule must use -j RETURN (not -j ACCEPT affecting User 0), got %q", tpPre[1])
	}
}

func TestV251MergeTableBatchesAndCommitOrder(t *testing.T) {
	openScript := MergeTableBatches([]string{
		"*raw\n:SBW_RAW_OUTPUT - [0:0]\n-F SBW_RAW_OUTPUT\n-I OUTPUT 1 -j SBW_RAW_OUTPUT\nCOMMIT\n",
		"*filter\n:SBW_OUTPUT - [0:0]\n-F SBW_OUTPUT\n-A SBW_OUTPUT -j RETURN\nCOMMIT\n",
		"*mangle\n:SBW_EGRESS - [0:0]\n-F SBW_EGRESS\nCOMMIT\n",
		"*mangle\n:SBW_TPROXY_OUT - [0:0]\n-F SBW_TPROXY_OUT\nCOMMIT\n",
		"*mangle\n:SBW_TPROXY_PRE - [0:0]\n-F SBW_TPROXY_PRE\nCOMMIT\n",
	}, []string{"mangle", "filter", "raw"})

	if strings.Count(openScript, "*mangle\n") != 1 {
		t.Fatalf("expected 3 mangle hooks coalesced into 1 *mangle block, got:\n%s", openScript)
	}
	mStart := strings.Index(openScript, "*mangle\n")
	fStart := strings.Index(openScript, "*filter\n")
	rStart := strings.Index(openScript, "*raw\n")
	if !(mStart >= 0 && mStart < fStart && fStart < rStart) {
		t.Fatalf("expected open order mangle -> filter -> raw, got:\n%s", openScript)
	}
	mangleBlock := openScript[mStart:fStart]
	lastDecl := strings.LastIndex(mangleBlock, "\n:")
	firstCmd := strings.Index(mangleBlock, "\n-")
	if lastDecl > firstCmd {
		t.Fatalf("all :CHAIN declarations must precede commands in *mangle:\n%s", mangleBlock)
	}
}
