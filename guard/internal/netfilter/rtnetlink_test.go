package netfilter

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"
)

func TestRTNetlinkWireRoundTrip(t *testing.T) {
	ruleMsg := encodeIPv4RuleMsg(rtmNewRule, nlmFRequest|nlmFCreate|nlmFExcl, 7, 2025, 0x1a, 0xffff, 2027)
	rules := parseIPv4Rules(ruleMsg)
	if len(rules) != 1 {
		t.Fatalf("expected 1 parsed rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Pref != 2025 || r.Mark != 0x1a || r.Mask != 0xffff || r.Table != 2027 {
		t.Fatalf("unexpected decoded IPv4 rule: %+v", r)
	}

	// Verify multi-rule dump finds matching and stale rules at pref 2025.
	staleMsg := encodeIPv4RuleMsg(rtmNewRule, nlmFRequest, 8, 2025, 0x99, 0xffff, 2027)
	otherMsg := encodeIPv4RuleMsg(rtmNewRule, nlmFRequest, 9, 32766, 0, 0, 254)
	combined := append(append([]byte(nil), ruleMsg...), staleMsg...)
	combined = append(combined, otherMsg...)
	allRules := parseIPv4Rules(combined)
	if len(allRules) != 3 {
		t.Fatalf("expected 3 parsed rules, got %d", len(allRules))
	}
	if allRules[1].Mark != 0x99 || allRules[2].Pref != 32766 {
		t.Fatalf("unexpected multi-rule parse: %+v", allRules)
	}

	// Route encode/decode round trip for local 0.0.0.0/0 dev lo table 2027.
	routeMsg := encodeIPv4LocalRouteMsg(rtmNewRoute, nlmFRequest|nlmFCreate|nlmFReplace, 10, 1, 2027)
	if !parseIPv4LocalLoRoutes(routeMsg, 1, 2027) {
		t.Fatal("expected local dev lo table 2027 route to match")
	}
	if parseIPv4LocalLoRoutes(routeMsg, 2, 2027) {
		t.Fatal("expected wrong ifindex not to match")
	}
	if parseIPv4LocalLoRoutes(routeMsg, 1, 254) {
		t.Fatal("expected wrong table not to match")
	}
	// Non-default dstLen (!= 0) must not match.
	badDst := append([]byte(nil), routeMsg...)
	badDst[17] = 24
	if parseIPv4LocalLoRoutes(badDst, 1, 2027) {
		t.Fatal("expected non-/0 local route not to match")
	}

	// Verify nlmsghdr length matches exact buffer size.
	if got := int(binary.LittleEndian.Uint32(ruleMsg[0:4])); got != len(ruleMsg) {
		t.Fatalf("rule nlmsg_len=%d != buf len %d", got, len(ruleMsg))
	}
	if got := int(binary.LittleEndian.Uint32(routeMsg[0:4])); got != len(routeMsg) {
		t.Fatalf("route nlmsg_len=%d != buf len %d", got, len(routeMsg))
	}
}

type mockRunnerCheck struct{}

func (mockRunnerCheck) Run(_ context.Context, _ time.Duration, _ string, _ string, _ ...string) (string, error) {
	return "", nil
}

func TestControllerUseNativeNetlinkSelection(t *testing.T) {
	ctrlMock := &Controller{Runner: mockRunnerCheck{}, LockPath: filepath.Join(t.TempDir(), "lock")}
	if ctrlMock.useNativeNetlink() {
		t.Fatal("useNativeNetlink must return false for mock runners")
	}
}
