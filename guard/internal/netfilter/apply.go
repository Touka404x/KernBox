package netfilter

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/sysio"
)

type Runner interface {
	Run(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) (string, error)
}

var (
	iptOnce sync.Once
	ipt4Bin = "iptables"
	ipt6Bin = "ip6tables"
)

func resolveHostIPTablesBins() (string, string) {
	iptOnce.Do(func() {
		if runtime.GOOS != "linux" {
			return
		}
		for _, cand := range []string{"iptables", "iptables-nft", "iptables-legacy"} {
			if _, err := exec.LookPath(cand); err == nil {
				ipt4Bin = cand
				break
			}
		}
		for _, cand := range []string{"ip6tables", "ip6tables-nft", "ip6tables-legacy"} {
			if _, err := exec.LookPath(cand); err == nil {
				ipt6Bin = cand
				break
			}
		}
	})
	return ipt4Bin, ipt6Bin
}

func resolveIPTablesCompanionBin(name, v4, v6 string, lookPath func(string) (string, error)) string {
	switch {
	case name == "iptables":
		return v4
	case strings.HasPrefix(name, "iptables-") && v4 != "iptables":
		suf := strings.TrimPrefix(name, "iptables")
		if p, err := lookPath(v4 + suf); err == nil {
			return p
		}
		base := strings.TrimSuffix(strings.TrimSuffix(v4, "-nft"), "-legacy")
		if p, err := lookPath(base + suf); err == nil {
			return p
		}
	case name == "ip6tables":
		return v6
	case strings.HasPrefix(name, "ip6tables-") && v6 != "ip6tables":
		suf := strings.TrimPrefix(name, "ip6tables")
		if p, err := lookPath(v6 + suf); err == nil {
			return p
		}
		base := strings.TrimSuffix(strings.TrimSuffix(v6, "-nft"), "-legacy")
		if p, err := lookPath(base + suf); err == nil {
			return p
		}
	}
	return name
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	bin := name
	if strings.HasPrefix(name, "iptables") || strings.HasPrefix(name, "ip6tables") {
		v4, v6 := resolveHostIPTablesBins()
		bin = resolveIPTablesCompanionBin(name, v4, v6, exec.LookPath)
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return out.String(), fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, msg)
	}
	return out.String(), nil
}

type Controller struct {
	Runner   Runner
	LockPath string

	routingCleaned bool
}

func NewController() *Controller {
	return &Controller{Runner: ExecRunner{}, LockPath: contracts.SharedLockPath}
}

func (c *Controller) lockPath() string {
	if c.LockPath != "" {
		return c.LockPath
	}
	return contracts.SharedLockPath
}

func (c *Controller) toolFor(family int) (string, error) {
	switch family {
	case 4:
		return "iptables", nil
	case 6:
		return "ip6tables", nil
	default:
		return "", fmt.Errorf("invalid family %d", family)
	}
}

func (c *Controller) saveTable(ctx context.Context, family int, table string) (Save, error) {
	tool, err := c.toolFor(family)
	if err != nil {
		return Save{}, err
	}
	out, err := c.Runner.Run(ctx, 10*time.Second, "", tool+"-save", "-t", table)
	if err != nil {
		return Save{}, err
	}
	return ParseSave(out), nil
}

func (c *Controller) saveAllTables(ctx context.Context, family int) (map[string]Save, error) {
	tool, err := c.toolFor(family)
	if err != nil {
		return nil, err
	}
	out, err := c.Runner.Run(ctx, 10*time.Second, "", tool+"-save")
	if err != nil {
		return nil, err
	}
	parsed := ParseSaveAll(out)
	if len(parsed) == 0 {
		return nil, fmt.Errorf("%s-save returned no tables", tool)
	}
	return parsed, nil
}

func (c *Controller) loadFamilyTables(ctx context.Context, family int) func(table string) (Save, error) {
	all, allErr := c.saveAllTables(ctx, family)
	cache := make(map[string]Save, 4)
	if allErr == nil {
		for k, v := range all {
			cache[k] = v
		}
	}
	return func(table string) (Save, error) {
		if s, ok := cache[table]; ok {
			return s, nil
		}
		s, err := c.saveTable(ctx, family, table)
		if err == nil {
			cache[table] = s
		}
		return s, err
	}
}

func (c *Controller) restoreTable(ctx context.Context, family int, batch string) error {
	if batch == "" {
		return nil
	}
	tool, err := c.toolFor(family)
	if err != nil {
		return err
	}
	_, err = c.Runner.Run(ctx, 15*time.Second, batch, tool+"-restore", "-w", "10", "--noflush")
	return err
}

// DetectProxyCapture inspects IPv4 and IPv6 mangle tables under the shared lock to determine
// whether external proxy capture chains (<prefix>OUTPUT / <prefix>OUTPUT6) are installed.
func (c *Controller) DetectProxyCapture(ctx context.Context, prefix string) (bool, error) {
	if prefix == "" {
		return false, nil
	}
	unlock, err := sysio.AcquireFlock(c.lockPath(), 0600, 15*time.Second)
	if err != nil {
		return false, err
	}
	defer unlock()
	return c.detectProxyCaptureLocked(ctx, prefix)
}

func (c *Controller) detectProxyCaptureLocked(ctx context.Context, prefix string) (bool, error) {
	if prefix == "" {
		return false, nil
	}
	for _, family := range []int{4, 6} {
		s, err := c.saveTable(ctx, family, "mangle")
		if err != nil {
			return false, err
		}
		if HasExternalCapture(s, family, prefix) {
			return true, nil
		}
	}
	return false, nil
}

type pendingHookVerify struct {
	hook        GateHook
	expected    []string
	expectEmpty bool
}

func (c *Controller) ensureTProxyRouting(ctx context.Context, spec GateSpec) error {
	mark := spec.tproxyMark()
	table := strconv.Itoa(contracts.DefaultTProxyTable)
	pref := strconv.Itoa(contracts.DefaultTProxyPref)
	wantFw := fmt.Sprintf("fwmark 0x%x/0x%x", mark, contracts.NetIDMask)

	rulesOut, err := c.Runner.Run(ctx, 4*time.Second, "", "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	haveRule := false
	staleRules := 0
	for _, line := range strings.Split(rulesOut, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, pref+":") {
			continue
		}
		if strings.Contains(l, wantFw) && strings.Contains(l, "lookup "+table) {
			haveRule = true
		} else {
			staleRules++
		}
	}
	for i := 0; i < staleRules && i < 4; i++ {
		if _, derr := c.Runner.Run(ctx, 4*time.Second, "", "ip", "-4", "rule", "del", "pref", pref); derr != nil {
			break
		}
	}
	routeOut, rerr := c.Runner.Run(ctx, 4*time.Second, "", "ip", "-4", "route", "show", "table", table)
	haveRoute := rerr == nil && strings.Contains(routeOut, "local") && strings.Contains(routeOut, "dev lo")
	if !haveRoute {
		if _, err := c.Runner.Run(ctx, 4*time.Second, "", "ip", "-4", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", table); err != nil {
			return err
		}
	}
	if !haveRule {
		if _, err := c.Runner.Run(ctx, 4*time.Second, "", "ip", "-4", "rule", "add", "pref", pref, "fwmark",
			fmt.Sprintf("0x%x/0x%x", mark, contracts.NetIDMask), "lookup", table); err != nil {
			return err
		}
	}
	c.routingCleaned = false
	return nil
}

func (c *Controller) cleanupTProxyRouting(ctx context.Context) {
	if c.routingCleaned {
		return
	}
	table := strconv.Itoa(contracts.DefaultTProxyTable)
	pref := strconv.Itoa(contracts.DefaultTProxyPref)
	out, err := c.Runner.Run(ctx, 4*time.Second, "", "ip", "-4", "rule", "show")
	if err != nil {
		return
	}
	for i := 0; i < 4 && strings.Contains(out, "lookup "+table); i++ {
		if !strings.Contains(out, pref+":") {
			break
		}
		if _, err := c.Runner.Run(ctx, 4*time.Second, "", "ip", "-4", "rule", "del", "pref", pref, "lookup", table); err != nil {
			break
		}
		out, err = c.Runner.Run(ctx, 4*time.Second, "", "ip", "-4", "rule", "show")
		if err != nil {
			break
		}
	}
	_, _ = c.Runner.Run(ctx, 4*time.Second, "", "ip", "-4", "route", "flush", "table", table)
	c.routingCleaned = true
}

func (c *Controller) ApplyOrVerify(ctx context.Context, spec GateSpec, inspect bool) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	unlock, err := sysio.AcquireFlock(c.lockPath(), 0600, 15*time.Second)
	if err != nil {
		return err
	}
	defer unlock()

	if !inspect {
		if spec.IsTProxy() {
			if spec.Open {
				if err := c.ensureTProxyRouting(ctx, spec); err != nil {
					return fmt.Errorf("tproxy routing: %w", err)
				}
			}
		} else {
			defer c.cleanupTProxyRouting(ctx)
		}
	}

	hooks := GateHooksFor(spec)
	for _, family := range []int{4, 6} {
		getTable := c.loadFamilyTables(ctx, family)
		var batches []string
		var pendingVerify []pendingHookVerify

		for _, hook := range hooks {
			if !hookActive(hook, family, spec) {
				if hook.TProxyOnly && family == 4 {
					current, err := getTable(hook.Table)
					if err != nil {
						return err
					}
					if inspect {
						if ChainPresent(current, hook) {
							return fmt.Errorf("IPv%d %s (%s) still present outside tproxy mode", family, hook.Chain, hook.Table)
						}
						continue
					}
					if batch := RemoveBatch(current, hook); batch != "" {
						batches = append(batches, batch)
						pendingVerify = append(pendingVerify, pendingHookVerify{hook: hook, expectEmpty: true})
					}
				}
				continue
			}
			expected, err := RulesFor(family, hook, spec)
			if err != nil {
				return err
			}
			current, err := getTable(hook.Table)
			if err != nil {
				return err
			}
			if inspect {
				if !GateInstalled(current, hook, expected) {
					return fmt.Errorf("IPv%d %s (%s) failed verification", family, hook.Chain, hook.Table)
				}
				continue
			}
			if GateInstalled(current, hook, expected) {
				continue
			}
			batches = append(batches, GateBatch(current, hook, expected))
			pendingVerify = append(pendingVerify, pendingHookVerify{hook: hook, expected: expected})
		}

		if inspect || len(batches) == 0 {
			continue
		}
		tableOrder := []string{"raw", "filter", "mangle"}
		if spec.Open {
			tableOrder = []string{"mangle", "filter", "raw"}
		}
		combined := MergeTableBatches(batches, tableOrder)
		if err := c.restoreTable(ctx, family, combined); err != nil {
			return err
		}
		verifyTable := c.loadFamilyTables(ctx, family)
		for _, pv := range pendingVerify {
			current, err := verifyTable(pv.hook.Table)
			if err != nil {
				return err
			}
			if pv.expectEmpty {
				if ChainPresent(current, pv.hook) {
					return fmt.Errorf("IPv%d %s (%s) removal failed verification", family, pv.hook.Chain, pv.hook.Table)
				}
				continue
			}
			if !GateInstalled(current, pv.hook, pv.expected) {
				return fmt.Errorf("IPv%d %s (%s) failed verification", family, pv.hook.Chain, pv.hook.Table)
			}
		}
	}
	return nil
}

type RuntimeInspection struct {
	ExternalCapture bool
	RawArmed        bool
	OutputOpen      bool
	EgressOpen      bool
	VerifyErr       string
}

func (c *Controller) InspectRuntime(ctx context.Context, spec GateSpec) (RuntimeInspection, error) {
	unlock, err := sysio.AcquireFlock(c.lockPath(), 0600, 15*time.Second)
	if err != nil {
		return RuntimeInspection{}, err
	}
	defer unlock()

	extCap, err := c.detectProxyCaptureLocked(ctx, spec.ProxySkipPrefix)
	if err != nil {
		return RuntimeInspection{}, err
	}
	res := RuntimeInspection{ExternalCapture: extCap}

	raw4, err := c.saveTable(ctx, 4, "raw")
	if err == nil {
		res.RawArmed = len(raw4.Rules[contracts.ChainRawOutput]) > 0
	}
	out4, err := c.saveTable(ctx, 4, "filter")
	if err == nil {
		for _, r := range out4.Rules[contracts.ChainOutput] {
			if strings.HasSuffix(r, "-j RETURN") {
				res.OutputOpen = true
				break
			}
		}
	}
	eg4, err := c.saveTable(ctx, 4, "mangle")
	if err == nil {
		for _, r := range eg4.Rules[contracts.ChainEgress] {
			if strings.HasSuffix(r, "-j RETURN") {
				res.EgressOpen = true
				break
			}
		}
	}
	return res, nil
}
