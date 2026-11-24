package netfilter

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type v250TableState struct {
	Chains map[string]bool
	Rules  map[string][]string
}

type v250IPTablesMock struct {
	mu              sync.Mutex
	tables          map[int]map[string]*v250TableState
	saveAllCalls    map[int]int
	saveTableCalls  map[int]int
	restoreCalls    map[int]int
}

func newV250IPTablesMock() *v250IPTablesMock {
	initFam := func() map[string]*v250TableState {
		m := make(map[string]*v250TableState)
		for _, tbl := range []string{"raw", "filter", "mangle", "nat"} {
			m[tbl] = &v250TableState{
				Chains: map[string]bool{"INPUT": true, "OUTPUT": true, "POSTROUTING": true, "PREROUTING": true},
				Rules:  map[string][]string{},
			}
		}
		return m
	}
	return &v250IPTablesMock{
		tables:         map[int]map[string]*v250TableState{4: initFam(), 6: initFam()},
		saveAllCalls:   map[int]int{},
		saveTableCalls: map[int]int{},
		restoreCalls:   map[int]int{},
	}
}

func (m *v250IPTablesMock) renderSave(fam map[string]*v250TableState, onlyTable string) string {
	var b strings.Builder
	for _, tbl := range []string{"raw", "filter", "mangle", "nat"} {
		if onlyTable != "" && tbl != onlyTable {
			continue
		}
		st := fam[tbl]
		fmt.Fprintf(&b, "*%s\n", tbl)
		for _, builtin := range []string{"INPUT", "OUTPUT", "PREROUTING", "POSTROUTING"} {
			if st.Chains[builtin] {
				fmt.Fprintf(&b, ":%s ACCEPT [0:0]\n", builtin)
			}
		}
		for ch := range st.Chains {
			if ch == "INPUT" || ch == "OUTPUT" || ch == "PREROUTING" || ch == "POSTROUTING" {
				continue
			}
			fmt.Fprintf(&b, ":%s - [0:0]\n", ch)
		}
		for _, chain := range []string{"OUTPUT", "PREROUTING", "POSTROUTING"} {
			for _, r := range st.Rules[chain] {
				fmt.Fprintf(&b, "-A %s %s\n", chain, r)
			}
		}
		for chain, rules := range st.Rules {
			if chain == "OUTPUT" || chain == "PREROUTING" || chain == "POSTROUTING" {
				continue
			}
			for _, r := range rules {
				fmt.Fprintf(&b, "-A %s %s\n", chain, r)
			}
		}
		b.WriteString("COMMIT\n")
	}
	return b.String()
}

func (m *v250IPTablesMock) applyRestore(fam map[string]*v250TableState, script string) error {
	curTbl := ""
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || line == "COMMIT" {
			continue
		}
		if strings.HasPrefix(line, "*") {
			curTbl = strings.TrimSpace(line[1:])
			if _, ok := fam[curTbl]; !ok {
				fam[curTbl] = &v250TableState{Chains: map[string]bool{}, Rules: map[string][]string{}}
			}
			continue
		}
		st := fam[curTbl]
		if st == nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, ":"):
			ch := strings.Fields(line[1:])[0]
			st.Chains[ch] = true
		case strings.HasPrefix(line, "-F "):
			ch := strings.Fields(line)[1]
			st.Rules[ch] = nil
		case strings.HasPrefix(line, "-X "):
			ch := strings.Fields(line)[1]
			delete(st.Chains, ch)
			delete(st.Rules, ch)
		case strings.HasPrefix(line, "-I "):
			parts := strings.SplitN(line, " ", 4)
			if len(parts) == 4 {
				ch := parts[1]
				idx := 0
				_, _ = fmt.Sscanf(parts[2], "%d", &idx)
				idx--
				rule := parts[3]
				cur := st.Rules[ch]
				if idx <= 0 || len(cur) == 0 {
					st.Rules[ch] = append([]string{rule}, cur...)
				} else if idx >= len(cur) {
					st.Rules[ch] = append(cur, rule)
				} else {
					next := append([]string{}, cur[:idx]...)
					next = append(next, rule)
					next = append(next, cur[idx:]...)
					st.Rules[ch] = next
				}
			}
		case strings.HasPrefix(line, "-D "):
			parts := strings.SplitN(line, " ", 3)
			if len(parts) == 3 {
				ch, rule := parts[1], parts[2]
				var kept []string
				for _, r := range st.Rules[ch] {
					if r != rule {
						kept = append(kept, r)
					}
				}
				st.Rules[ch] = kept
			}
		case strings.HasPrefix(line, "-A "):
			parts := strings.SplitN(line, " ", 3)
			if len(parts) == 3 {
				st.Rules[parts[1]] = append(st.Rules[parts[1]], parts[2])
			}
		}
	}
	return nil
}

func (m *v250IPTablesMock) Run(_ context.Context, _ time.Duration, stdin string, name string, args ...string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if name == "ip" {
		if len(args) >= 4 && args[1] == "rule" && args[2] == "show" {
			return "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n", nil
		}
		if len(args) >= 4 && args[1] == "route" && args[2] == "show" {
			return "", nil
		}
		return "", nil
	}
	fam := 4
	if strings.HasPrefix(name, "ip6tables") {
		fam = 6
	}
	if strings.HasSuffix(name, "-save") {
		if len(args) == 2 && args[0] == "-t" {
			m.saveTableCalls[fam]++
			return m.renderSave(m.tables[fam], args[1]), nil
		}
		if len(args) == 0 {
			m.saveAllCalls[fam]++
			return m.renderSave(m.tables[fam], ""), nil
		}
	}
	if strings.HasSuffix(name, "-restore") {
		m.restoreCalls[fam]++
		return "", m.applyRestore(m.tables[fam], stdin)
	}
	return "", fmt.Errorf("unexpected cmd %s %v", name, args)
}

func TestParseSaveAllAndCombineBatches(t *testing.T) {
	sample := `# generated
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:SBW_RAW_OUTPUT - [0:0]
-A OUTPUT -j SBW_RAW_OUTPUT
COMMIT
*filter
:OUTPUT ACCEPT [0:0]
:SBW_OUTPUT - [0:0]
-A OUTPUT -j SBW_OUTPUT
-A SBW_OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
COMMIT
*mangle
:POSTROUTING ACCEPT [0:0]
:SBW_EGRESS - [0:0]
-A POSTROUTING -j SBW_EGRESS
COMMIT
`
	all := ParseSaveAll(sample)
	if len(all) != 3 {
		t.Fatalf("expected 3 tables, got %d (%+v)", len(all), all)
	}
	if len(all["raw"].Rules["OUTPUT"]) != 1 || all["raw"].Rules["OUTPUT"][0] != "-j SBW_RAW_OUTPUT" {
		t.Fatalf("unexpected raw parse: %+v", all["raw"])
	}
	if len(all["filter"].Rules["SBW_OUTPUT"]) != 1 {
		t.Fatalf("unexpected filter parse: %+v", all["filter"])
	}
	if len(all["mangle"].Rules["POSTROUTING"]) != 1 {
		t.Fatalf("unexpected mangle parse: %+v", all["mangle"])
	}

	combined := CombineBatches([]string{"*raw\nCOMMIT", "", "*filter\nCOMMIT\n"})
	if combined != "*raw\nCOMMIT\n*filter\nCOMMIT\n" {
		t.Fatalf("unexpected CombineBatches output: %q", combined)
	}
}

func TestApplyOrVerifySingleSaveAndSingleRestoreBatching(t *testing.T) {
	dir := t.TempDir()
	mock := newV250IPTablesMock()
	ctrl := &Controller{
		Runner:   mock,
		LockPath: filepath.Join(dir, "nf.lock"),
	}

	spec := testTProxySpecOpen()
	ctx := context.Background()
	if err := ctrl.ApplyOrVerify(ctx, spec, false); err != nil {
		t.Fatalf("ApplyOrVerify(apply) failed: %v", err)
	}
	if mock.saveAllCalls[4] != 2 || mock.saveAllCalls[6] != 2 {
		t.Fatalf("expected exactly 2 full-family saves per IP family (pre + verify), got v4=%d v6=%d", mock.saveAllCalls[4], mock.saveAllCalls[6])
	}
	if mock.saveTableCalls[4] != 0 || mock.saveTableCalls[6] != 0 {
		t.Fatalf("expected 0 per-table saves when iptables-save succeeds, got v4=%d v6=%d", mock.saveTableCalls[4], mock.saveTableCalls[6])
	}
	if mock.restoreCalls[4] != 1 || mock.restoreCalls[6] != 1 {
		t.Fatalf("expected 1 merged multi-table restore per IP family, got v4=%d v6=%d", mock.restoreCalls[4], mock.restoreCalls[6])
	}

	// Verify idempotent inspect mode requires 0 restores and uses 1 full-family save per family.
	if err := ctrl.ApplyOrVerify(ctx, spec, true); err != nil {
		t.Fatalf("ApplyOrVerify(inspect) failed: %v", err)
	}
	if mock.saveAllCalls[4] != 3 || mock.saveAllCalls[6] != 3 {
		t.Fatalf("expected 1 additional full-family save on inspect, got v4=%d v6=%d", mock.saveAllCalls[4], mock.saveAllCalls[6])
	}
	if mock.restoreCalls[4] != 1 || mock.restoreCalls[6] != 1 {
		t.Fatalf("expected 0 extra restores on inspect, got v4=%d v6=%d", mock.restoreCalls[4], mock.restoreCalls[6])
	}
}
