package netfilter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestResolveIPTablesCompanionBin(t *testing.T) {
	mockLook := func(avail map[string]bool) func(string) (string, error) {
		return func(bin string) (string, error) {
			if avail[bin] {
				return "/system/bin/" + bin, nil
			}
			return "", errors.New("not found")
		}
	}

	got4 := resolveIPTablesCompanionBin("iptables-restore", "iptables-nft", "ip6tables-nft",
		mockLook(map[string]bool{"iptables-nft-restore": true, "iptables-restore": true}))
	if got4 != "/system/bin/iptables-nft-restore" {
		t.Fatalf("expected iptables-nft-restore, got %s", got4)
	}

	got6 := resolveIPTablesCompanionBin("ip6tables-save", "iptables", "ip6tables-legacy",
		mockLook(map[string]bool{"ip6tables-legacy-save": true}))
	if got6 != "/system/bin/ip6tables-legacy-save" {
		t.Fatalf("expected ip6tables-legacy-save, got %s", got6)
	}

	fallback := resolveIPTablesCompanionBin("iptables-restore", "iptables-nft", "ip6tables",
		mockLook(map[string]bool{"iptables-restore": true}))
	if fallback != "/system/bin/iptables-restore" {
		t.Fatalf("expected fallback iptables-restore, got %s", fallback)
	}
}

type ruleMockRunner struct {
	calls []string
	rules string
	route string
}

func (r *ruleMockRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if line == "ip -4 rule show" {
		return r.rules, nil
	}
	if strings.HasPrefix(line, "ip -4 route show table ") {
		return r.route, nil
	}
	return "", nil
}

func TestEnsureTProxyRoutingCleansStaleMarkRule(t *testing.T) {
	mr := &ruleMockRunner{
		rules: "0:\tfrom all lookup local\n2025:\tfrom all fwmark 0x99/0xffff lookup 2027\n32766:\tfrom all lookup main\n",
		route: "local default dev lo table 2027 scope host\n",
	}
	c := &Controller{Runner: mr}
	spec := testTProxySpecOpen()
	if err := c.ensureTProxyRouting(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(mr.calls, "\n")
	if !strings.Contains(joined, "ip -4 rule del pref 2025") {
		t.Fatalf("expected stale pref 2025 deletion, got:\n%s", joined)
	}
	if !strings.Contains(joined, "ip -4 rule add pref 2025 fwmark 0x1a/0xffff lookup 2027") {
		t.Fatalf("expected new mark rule installation, got:\n%s", joined)
	}
}
