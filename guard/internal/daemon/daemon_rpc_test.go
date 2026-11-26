package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
	"sandbox_guard/internal/oem"
	"sandbox_guard/internal/sysio"
)

type mockCmdRunner struct {
	mu    sync.Mutex
	calls []string
	out   map[string]string
}

func (m *mockCmdRunner) Run(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	cmdLine := name + " " + strings.Join(args, " ")
	m.mu.Lock()
	m.calls = append(m.calls, cmdLine)
	v, ok := m.out[cmdLine]
	m.mu.Unlock()
	if ok {
		return v, nil
	}
	return "", errors.New("unexpected command: " + cmdLine)
}

func TestDaemonRPCOperations(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy()
	pkg := contracts.DefaultWorkPackage
	svc := contracts.DefaultServiceComponent
	runner := &mockCmdRunner{out: map[string]string{
		"cmd package install-existing --user 10 com.android.chrome":                                               "Package com.android.chrome installed for user: 10\n",
		"cmd package query-activities --user 10 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER": "Activity #0:\n  ActivityInfo:\n    name=com.google.android.apps.chrome.Main\n    packageName=com.android.chrome\n",
		"settings --user 0 get secure miui_home_hide_app_list":                                                    `[{"activityName":"com.user0.App","mHashCode":1,"packageName":"com.user0","serialNumber":"0"}]`,
		"content insert --user 0 --uri content://com.miui.home.app.hide --bind packageName:s:com.android.chrome --bind activityName:s:com.google.android.apps.chrome.Main --bind serialNumber:s:1000": "",
		`settings --user 0 put secure miui_home_hide_app_list [{"activityName":"com.user0.App","mHashCode":1,"packageName":"com.user0","serialNumber":"0"},{"activityName":"com.google.android.apps.chrome.Main","mHashCode":1316322254,"packageName":"com.android.chrome","serialNumber":"1000"}]`: "",
		"cmd package list packages --user 10 -U " + pkg:                                                           "package:" + pkg + " uid:1010376\n",
		"settings get global private_dns_mode":                                                                    "off\n",
		"am start-foreground-service --user 10 -a " + pkg + ".action.RELOAD_CONFIG -n " + svc:                     "",
	}}

	d := &Daemon{
		runner:           runner,
		bootID:           "boot-test-1",
		policy:           pol,
		policyLoaded:     true,
		state:            StateBlockedLocked,
		lastGen:          4,
		workCfgDir:       dir,
		desiredStatePath: filepath.Join(dir, "desired_state.json"),
		exemptionPath:    filepath.Join(dir, "exemption.v1.json"),
		sandboxAckPath:   filepath.Join(dir, "sandbox_ack.v1.json"),
		upgradeFencePath: filepath.Join(dir, "upgrade_fence.json"),
		reconcileCh:      make(chan reconcileReq, 4),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-d.reconcileCh:
				if req.reply != nil {
					req.reply <- nil
				}
			}
		}
	}()

	// 1. IMPORT_EXISTING installs package in user 10 and syncs HideApp (HyperOS) / skips cleanly elsewhere
	respImport := d.HandleRPC(ctx, contracts.RPCRequest{
		ID:  "imp-1",
		Op:  contracts.OpImportExisting,
		Pkg: "com.android.chrome",
	})
	if !respImport.OK {
		t.Fatalf("IMPORT_EXISTING failed: %+v", respImport)
	}
	if !oem.Current().SupportsHideApps {
		for _, c := range runner.calls {
			if strings.Contains(c, "miui_home_hide_app_list") {
				t.Fatalf("non-hyperos OEM %s must not touch MIUI hide list: %s", oem.Current().Name, c)
			}
		}
	}

	// 2. RELOAD_CONFIG writes /dev/sandbox_cfg/u10.pending.json atomically with MTU 1380
	respReload := d.HandleRPC(ctx, contracts.RPCRequest{
		ID:     "rel-1",
		Op:     contracts.OpReloadConfig,
		Config: &contracts.RPCConfigOverrides{QuicUDP443Mode: "allow", LogLevel: "info"},
	})
	if !respReload.OK {
		t.Fatalf("RELOAD_CONFIG failed: %+v", respReload)
	}
	cfgBytes, err := os.ReadFile(filepath.Join(dir, "u10.pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pending contracts.PendingConfig
	if err := json.Unmarshal(cfgBytes, &pending); err != nil {
		t.Fatal(err)
	}
	if pending.MTU != contracts.SandboxMTU || pending.QuicUDP443Mode != "allow" || pending.Overrides["log_level"] != "info" {
		t.Fatalf("unexpected pending.json content: %+v", pending)
	}

	// 3. GET_STATUS reports private_dns_mode, pending_config, and snake_case session
	d.lastSession = &netfilter.ActiveSession{
		ClientUID:   1010376,
		VPNNetID:    106,
		TunIf:       "tun0",
		TunIfindex:  19,
		UplinkNetID: 100,
		UplinkIf:    "wlan0",
		UplinkIndex: 12,
	}
	respStatus := d.HandleRPC(context.Background(), contracts.RPCRequest{
		ID: "st-1",
		Op: contracts.OpGetStatus,
	})
	if !respStatus.OK {
		t.Fatalf("GET_STATUS failed: %+v", respStatus)
	}
	rawResp, err := json.Marshal(respStatus)
	if err != nil {
		t.Fatal(err)
	}
	rawStr := string(rawResp)
	for _, want := range []string{
		`"private_dns_mode":"off"`,
		`"user_id":10`,
		`"pending_config":{"generation":5,"mtu":1380,"quic_udp443_mode":"allow"}`,
		`"uplink_if":"wlan0"`,
		`"tun_if":"tun0"`,
	} {
		if !strings.Contains(rawStr, want) {
			t.Fatalf("GET_STATUS missing %s in %s", want, rawStr)
		}
	}

	// Ensure no call ever invoked /bin/sh or sh -c
	for _, c := range runner.calls {
		if strings.Contains(c, "sh -c") {
			t.Fatalf("forbidden shell invocation detected: %s", c)
		}
	}

	// 4. STOP_APP & REMOVE_APP respect protected packages and update sandbox_apps
	runner.out["am force-stop --user 10 com.android.chrome"] = ""
	runner.out["cmd package list packages -3 --user 10"] = "package:com.android.chrome\npackage:" + pkg + "\n"
	runner.out["pm uninstall --user 10 com.android.chrome"] = "Success\n"
	respStop := d.HandleRPC(ctx, contracts.RPCRequest{ID: "stp-1", Op: contracts.OpStopApp, Pkg: "com.android.chrome"})
	if !respStop.OK {
		t.Fatalf("STOP_APP failed: %+v", respStop)
	}
	if badStop := d.HandleRPC(ctx, contracts.RPCRequest{ID: "stp-2", Op: contracts.OpStopApp, Pkg: pkg}); badStop.OK {
		t.Fatalf("expected controller STOP_APP rejection")
	}
	respRemove := d.HandleRPC(ctx, contracts.RPCRequest{ID: "rm-1", Op: contracts.OpRemoveApp, Pkg: "com.android.chrome"})
	if !respRemove.OK {
		t.Fatalf("REMOVE_APP failed: %+v", respRemove)
	}
	if badRemove := d.HandleRPC(ctx, contracts.RPCRequest{ID: "rm-2", Op: contracts.OpRemoveApp, Pkg: "com.google.android.gms"}); badRemove.OK {
		t.Fatalf("expected protected GMS REMOVE_APP rejection")
	}
}

type mockVPNStatusHandle struct {
	*bytes.Reader
	uid int
}

func (m *mockVPNStatusHandle) Close() error { return nil }
func (m *mockVPNStatusHandle) StatMeta() (sysio.FileMeta, error) {
	return sysio.FileMeta{IsRegular: true, UID: m.uid, Size: int64(m.Reader.Len())}, nil
}

type mockVPNStatusResolver struct {
	payload []byte
	uid     int
}

func (m *mockVPNStatusResolver) OpenDirAbsolute(absPath string) (int, sysio.FileMeta, func() error, error) {
	return 10, sysio.FileMeta{IsDir: true, UID: 1000}, func() error { return nil }, nil
}
func (m *mockVPNStatusResolver) OpenDirBeneath(dirFD int, relPath string, how sysio.OpenHowSpec) (int, sysio.FileMeta, func() error, error) {
	return 11, sysio.FileMeta{IsDir: true, UID: 1000}, func() error { return nil }, nil
}
func (m *mockVPNStatusResolver) OpenFileBeneath(dirFD int, relPath string, how sysio.OpenHowSpec) (sysio.ReadHandle, error) {
	return &mockVPNStatusHandle{Reader: bytes.NewReader(m.payload), uid: m.uid}, nil
}

func TestPendingConfigFallbackAndVPNStatusContract(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy()
	pkg := contracts.DefaultWorkPackage
	runner := &mockCmdRunner{out: map[string]string{
		"cmd package list packages --user 10 -U " + pkg: "package:" + pkg + " uid:1010376\n",
		"settings get global private_dns_mode":           "off\n",
	}}
	d := &Daemon{
		runner:       runner,
		bootID:       "boot-test-2",
		policy:       pol,
		policyLoaded: true,
		state:        StateOpen,
		workCfgDir:   dir,
	}

	// 1. Cold start with neither pending.json nor vpn_status.json -> defaults to quic_udp443_mode="reject", mtu=1380
	d.resolver = &mockVPNStatusResolver{payload: []byte(`{}`), uid: 1010376}
	cold := d.resolvePendingConfig(true, pol, nil)
	if cold["quic_udp443_mode"] != "reject" || cold["mtu"] != 1380 {
		t.Fatalf("unexpected cold start pending_config: %+v", cold)
	}

	// 2. u10.pending.json present overrides cold-start fallback in status JSON
	pendingPayload := `{"contract_version":1,"generation":7,"user_id":10,"mtu":1380,"quic_udp443_mode":"allow"}`
	if err := os.WriteFile(filepath.Join(dir, "u10.pending.json"), []byte(pendingPayload), 0600); err != nil {
		t.Fatal(err)
	}
	stData := d.buildStatusData(context.Background())
	rawBytes, err := json.Marshal(stData)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(rawBytes)
	for _, want := range []string{`"mode":"tproxy"`, `"pending_config":{"generation":7,"mtu":1380,"quic_udp443_mode":"allow"}`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("missing %s in status JSON: %s", want, raw)
		}
	}
}

func TestRunProbeInstrumentationParsing(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy()

	makeDaemon := func(instrOut string, instrErr error) *Daemon {
		pkg := contracts.DefaultWorkPackage
		probePkg := contracts.VerifyProbePackage
		r := &mockCmdRunner{out: map[string]string{
			"cmd package list packages --user 10 -U " + pkg:      "package:" + pkg + " uid:1010376\n",
			"settings get global private_dns_mode":                "off\n",
			"cmd package list packages --user 10 " + probePkg:     "package:" + probePkg + "\n",
		}}
		if instrErr == nil {
			r.out["am instrument -w -r --user 10 -e compact true "+probePkg+"/.NetworkProbe"] = instrOut
		}
		return &Daemon{
			runner:       r,
			bootID:       "boot-probe",
			policy:       pol,
			policyLoaded: true,
			workCfgDir:   dir,
		}
	}

	// 1. INSTRUMENTATION_CODE: -1 + valid JSON -> OK=true
	dOK := makeDaemon("INSTRUMENTATION_RESULT: network={\"uid\":1010400,\"vpn\":true}\nINSTRUMENTATION_CODE: -1\n", nil)
	rOK := dOK.HandleRPC(context.Background(), contracts.RPCRequest{ID: "p1", Op: contracts.OpRunProbe})
	if !rOK.OK {
		t.Fatalf("expected RUN_PROBE OK=true, got %+v", rOK)
	}

	// 2. am instrument exits 0 but returns INSTRUMENTATION_CODE: 0 -> MUST fail with OK=false
	dFailCode := makeDaemon("INSTRUMENTATION_RESULT: error=SecurityException\nINSTRUMENTATION_CODE: 0\n", nil)
	rFailCode := dFailCode.HandleRPC(context.Background(), contracts.RPCRequest{ID: "p2", Op: contracts.OpRunProbe})
	if rFailCode.OK || !strings.Contains(rFailCode.Error, "INSTRUMENTATION_CODE: -1") {
		t.Fatalf("expected RUN_PROBE failure on INSTRUMENTATION_CODE: 0, got %+v", rFailCode)
	}

	// 3. INSTRUMENTATION_CODE: -1 with invalid JSON -> MUST fail with OK=false
	dBadJSON := makeDaemon("INSTRUMENTATION_RESULT: network={broken\nINSTRUMENTATION_CODE: -1\n", nil)
	rBadJSON := dBadJSON.HandleRPC(context.Background(), contracts.RPCRequest{ID: "p3", Op: contracts.OpRunProbe})
	if rBadJSON.OK || !strings.Contains(rBadJSON.Error, "JSON") {
		t.Fatalf("expected RUN_PROBE failure on invalid JSON, got %+v", rBadJSON)
	}

	// 4. Probe APK not installed -> OK=true with probe_apk_installed=false
	dNoAPK := &Daemon{
		runner: &mockCmdRunner{out: map[string]string{
			"cmd package list packages --user 10 -U " + contracts.DefaultWorkPackage: "package:" + contracts.DefaultWorkPackage + " uid:1010376\n",
			"settings get global private_dns_mode":                                    "off\n",
		}},
		bootID:       "boot-probe",
		policy:       pol,
		policyLoaded: true,
		workCfgDir:   dir,
	}
	rNoAPK := dNoAPK.HandleRPC(context.Background(), contracts.RPCRequest{ID: "p4", Op: contracts.OpRunProbe})
	if !rNoAPK.OK {
		t.Fatalf("expected RUN_PROBE OK=true when optional probe APK absent, got %+v", rNoAPK)
	}
}

// statefulMockIPTables simulates iptables-save / iptables-restore per (tool-family, table)
// so reconcileOnce tests exercise real netfilter.ApplyOrVerify & DetectProxyCapture end-to-end.
type statefulMockIPTables struct {
	mu     sync.Mutex
	tables map[string]map[string][]string // "4/mangle" -> chain -> []rule
}

func newStatefulMockIPTables(withExtCap bool) *statefulMockIPTables {
	m := &statefulMockIPTables{
		tables: map[string]map[string][]string{
			"4/raw":    {"OUTPUT": nil},
			"4/filter": {"OUTPUT": nil},
			"4/mangle": {"POSTROUTING": nil, "OUTPUT": nil},
			"6/raw":    {"OUTPUT": nil},
			"6/filter": {"OUTPUT": nil},
			"6/mangle": {"POSTROUTING": nil, "OUTPUT": nil},
		},
	}
	if withExtCap {
		m.tables["4/mangle"]["OUTPUT"] = []string{"-j EXT_PROXY_OUTPUT"}
		m.tables["4/mangle"]["EXT_PROXY_OUTPUT"] = []string{"-j RETURN"}
	}
	return m
}

func (s *statefulMockIPTables) Run(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	if name == "ip" {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fam := "4"
	if strings.HasPrefix(name, "ip6") {
		fam = "6"
	}
	if strings.HasSuffix(name, "-save") && len(args) >= 2 && args[0] == "-t" {
		tbl := args[1]
		chains := s.tables[fam+"/"+tbl]
		var b strings.Builder
		b.WriteString("*" + tbl + "\n")
		for ch := range chains {
			b.WriteString(":" + ch + " - [0:0]\n")
		}
		for ch, rules := range chains {
			for _, r := range rules {
				b.WriteString("-A " + ch + " " + r + "\n")
			}
		}
		b.WriteString("COMMIT\n")
		return b.String(), nil
	}
	if strings.HasSuffix(name, "-restore") {
		var tbl string
		for _, raw := range strings.Split(stdin, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || line == "COMMIT" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "*") {
				tbl = line[1:]
				continue
			}
			chains := s.tables[fam+"/"+tbl]
			if chains == nil {
				chains = map[string][]string{}
				s.tables[fam+"/"+tbl] = chains
			}
			switch {
			case strings.HasPrefix(line, ":"):
				nameEnd := strings.IndexByte(line[1:], ' ')
				if nameEnd > 0 {
					ch := line[1 : 1+nameEnd]
					if _, ok := chains[ch]; !ok {
						chains[ch] = nil
					}
				}
			case strings.HasPrefix(line, "-F "):
				ch := strings.TrimSpace(line[3:])
				chains[ch] = nil
			case strings.HasPrefix(line, "-D "):
				rest := strings.TrimSpace(line[3:])
				sp := strings.IndexByte(rest, ' ')
				if sp > 0 {
					ch := rest[:sp]
					target := strings.TrimSpace(rest[sp+1:])
					cur := chains[ch]
					next := make([]string, 0, len(cur))
					removed := false
					for _, r := range cur {
						if !removed && r == target {
							removed = true
							continue
						}
						next = append(next, r)
					}
					chains[ch] = next
				}
			case strings.HasPrefix(line, "-I "):
				rest := strings.TrimSpace(line[3:])
				fields := strings.Fields(rest)
				if len(fields) >= 2 {
					ch := fields[0]
					idx := 1
					ruleStart := 1
					if len(fields[1]) > 0 && fields[1][0] >= '0' && fields[1][0] <= '9' {
						if fields[1] == "2" {
							idx = 2
						}
						ruleStart = 2
					}
					rule := strings.Join(fields[ruleStart:], " ")
					cur := chains[ch]
					pos := idx - 1
					if pos < 0 {
						pos = 0
					}
					if pos > len(cur) {
						pos = len(cur)
					}
					next := make([]string, 0, len(cur)+1)
					next = append(next, cur[:pos]...)
					next = append(next, rule)
					next = append(next, cur[pos:]...)
					chains[ch] = next
				}
			case strings.HasPrefix(line, "-A "):
				rest := strings.TrimSpace(line[3:])
				sp := strings.IndexByte(rest, ' ')
				if sp > 0 {
					ch := rest[:sp]
					chains[ch] = append(chains[ch], strings.TrimSpace(rest[sp+1:]))
				}
			}
		}
		return "", nil
	}
	return "", errors.New("unexpected iptables call: " + name)
}
