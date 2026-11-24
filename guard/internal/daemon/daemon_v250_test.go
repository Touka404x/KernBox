package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
	"sandbox_guard/internal/oem"
)

func TestPerfConfigV250DefaultsAndNormalization(t *testing.T) {
	def := DefaultPerfConfig()
	if def.HotFreezeMinutes != 30 {
		t.Fatalf("HotFreezeMinutes = %d, want 30", def.HotFreezeMinutes)
	}
	if def.SkipAppOpsForFrozen || def.SyncTargetOnly {
		t.Fatalf("Go struct DefaultPerfConfig must preserve v2.4.0 test contract false defaults, got %+v", def)
	}
	if def.LaunchBoostMs != 1500 {
		t.Fatalf("LaunchBoostMs = %d, want 1500", def.LaunchBoostMs)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "perf.json")
	if err := os.WriteFile(path, []byte(`{
		"pause_mode": "hybrid",
		"hot_freeze_minutes": 9999,
		"skip_appops_for_frozen": true,
		"sync_target_only": true,
		"launch_boost_ms": 99999
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded := LoadPerfConfig(path)
	if loaded.PauseMode != PauseModeHybrid {
		t.Fatalf("PauseMode = %q, want hybrid", loaded.PauseMode)
	}
	if loaded.HotFreezeMinutes != 1440 {
		t.Fatalf("clamped HotFreezeMinutes = %d, want 1440", loaded.HotFreezeMinutes)
	}
	if !loaded.SkipAppOpsForFrozen || !loaded.SyncTargetOnly {
		t.Fatalf("expected bool flags true, got %+v", loaded)
	}
	if loaded.LaunchBoostMs != 5000 {
		t.Fatalf("clamped LaunchBoostMs = %d, want 5000", loaded.LaunchBoostMs)
	}

	if err := os.WriteFile(path, []byte(`{"pause_mode":"hot","hot_freeze_minutes":-5,"launch_boost_ms":-1}`), 0600); err != nil {
		t.Fatal(err)
	}
	neg := LoadPerfConfig(path)
	if neg.PauseMode != PauseModeHot || neg.HotFreezeMinutes != 0 || neg.LaunchBoostMs != 0 {
		t.Fatalf("unexpected negative clamping: %+v", neg)
	}
}

func TestStealthConfigDeviceRegionParity(t *testing.T) {
	def := DefaultStealthConfig(10, 1010376)
	wantDev := oem.Current().DefaultDeviceName
	if def.SpoofDeviceRegion || def.DeviceRegion != "" || def.MiuiRegion != "" || def.BootHWC != "" || def.DeviceName != wantDev {
		t.Fatalf("unexpected OSS device region defaults: %+v", def)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "stealth.json")
	rtPath := filepath.Join(dir, "rt_stealth.json")
	disabledFlag := filepath.Join(dir, "zygisk_disabled")

	d := &Daemon{
		stealthConfigPath:  cfgPath,
		stealthRuntimePath: rtPath,
		zygiskDisabledFlag: disabledFlag,
	}
	pol := testPolicy()
	cfg, err := d.SyncStealthConfig(pol, 1010376)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SpoofDeviceRegion || cfg.DeviceName != wantDev {
		t.Fatalf("SyncStealthConfig defaults mismatch: %+v", cfg)
	}

	// User overrides survive SyncStealthConfig.
	custom := cfg
	custom.SpoofDeviceRegion = true
	custom.DeviceRegion = "US"
	custom.MiuiRegion = "US"
	custom.BootHWC = "Global"
	raw, _ := json.Marshal(custom)
	if err := os.WriteFile(cfgPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	synced, err := d.SyncStealthConfig(pol, 1010376)
	if err != nil {
		t.Fatal(err)
	}
	if !synced.SpoofDeviceRegion || synced.DeviceRegion != "US" || synced.MiuiRegion != "US" || synced.BootHWC != "Global" {
		t.Fatalf("expected SyncStealthConfig to preserve user region settings, got %+v", synced)
	}
}

type tproxyMockIPTables struct {
	base *statefulMockIPTables
}

func (m *tproxyMockIPTables) Run(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	if name == "ip" {
		return "", nil
	}
	return m.base.Run(ctx, timeout, stdin, name, args...)
}

func TestPauseHotAndLaunchTraceAndFastAppLaunch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proxies":{}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	mainCfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(mainCfg, []byte(`{"external-controller":"`+strings.TrimPrefix(srv.URL, "http://")+`","secret":"abc"}`), 0600); err != nil {
		t.Fatal(err)
	}
	pkg := contracts.DefaultWorkPackage
	pkgList := filepath.Join(dir, "packages.list")
	if err := os.WriteFile(pkgList, []byte(
		pkg+" 10376 0 /data/user/0/"+pkg+" default 0 0\n"+
			"com.google.android.apps.bard 10395 0 /data/user/0/com.google.android.apps.bard default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}

	cgRoot := filepath.Join(dir, "cgroup")
	uidDir := filepath.Join(cgRoot, "uid_1010395")
	if err := os.MkdirAll(uidDir, 0755); err != nil {
		t.Fatal(err)
	}
	freezeFile := filepath.Join(uidDir, "cgroup.freeze")
	uclampFile := filepath.Join(uidDir, "cpu.uclamp.min")
	if err := os.WriteFile(freezeFile, []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(uclampFile, []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	perfPath := filepath.Join(dir, "perf.json")
	if err := WritePerfConfig(perfPath, PerfConfig{
		PauseMode:           PauseModeHot,
		HotFreezeMinutes:    30,
		SkipAppOpsForFrozen: true,
		SyncTargetOnly:      true,
		LaunchBoostMs:       25,
	}); err != nil {
		t.Fatal(err)
	}

	resolveCalls := 0
	failNextCachedStart := false
	resolvedComponent := "com.google.android.apps.bard/com.google.android.apps.bard.MainActivity"
	runner := &v240FlexRunner{
		out: map[string]string{
			"cmd user list -v":                       "0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running)\n1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running)\n",
			"dumpsys user --user 10":                 "  UserInfo{10:Work:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
			"cmd device_policy list-owners":          "User 10: admin=" + contracts.DefaultAdminComponent + ",ManagedProfileOwner(parentUserId=0)\n",
			"cmd package list packages --user 10 -U " + pkg: "package:" + pkg + " uid:1010376\n",
			"cmd package list packages -3 --user 10": "package:" + pkg + "\npackage:com.google.android.apps.bard\n",
			"ime list -s --user 10":                                        "",
			"dumpsys activity users":                                       "    User #10: state=RUNNING_UNLOCKED\n",
		},
		onRun: func(cmdLine string) (string, bool, error) {
			if cmdLine == "cmd package resolve-activity --brief --user 10 com.google.android.apps.bard" {
				resolveCalls++
				if resolveCalls > 1 {
					resolvedComponent = "com.google.android.apps.bard/com.google.android.apps.bard.NewEntryActivity"
				}
				return resolvedComponent + "\n", true, nil
			}
			if strings.HasPrefix(cmdLine, "am start --user 10 ") {
				if failNextCachedStart && strings.Contains(cmdLine, "MainActivity") {
					failNextCachedStart = false
					return "Error: Activity class does not exist\n", true, nil
				}
				return "Starting: Intent { ... }\n", true, nil
			}
			return "", false, nil
		},
	}

	nfMock := &tproxyMockIPTables{base: newStatefulMockIPTables(false)}
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: nfMock, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-v250",
		policy:             pol,
		policyLoaded:       true,
		state:              StateOpen,
		paused:             false,
		workCfgDir:         dir,
		packagesListPath:   pkgList,
		desiredStatePath:   filepath.Join(dir, "desired_state.json"),
		exemptionPath:      filepath.Join(dir, "exemption.v1.json"),
		sandboxAckPath:     filepath.Join(dir, "sandbox_ack.v1.json"),
		upgradeFencePath:   filepath.Join(dir, "upgrade_fence.json"),
		stealthConfigPath:  filepath.Join(dir, "stealth.json"),
		stealthRuntimePath: filepath.Join(dir, "rt_stealth.json"),
		zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
		perfConfigPath:     perfPath,
		prunedPkgsPath:     filepath.Join(dir, "pruned_pkgs.json"),
		hibernatedPkgsPath: filepath.Join(dir, "hibernated_pkgs.json"),
		cgroupRoot:         cgRoot,
		mainConfigPath:     mainCfg,
		reconcileCh:        make(chan reconcileReq, 8),
		probeTProxyReady:   func(port int) bool { return port == contracts.DefaultTProxyPort },
		userWakeTimeout:    500 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startMockReconcilePump(ctx, d)

	// 1. ctl pause-hot freezes User 10 cgroup without calling am force-stop.
	res, err := d.HandleCtl(ctx, "pause-hot", nil)
	if err != nil || res != "hot-paused" {
		t.Fatalf("ctl pause-hot = (%q, %v), want hot-paused", res, err)
	}
	if b, _ := os.ReadFile(freezeFile); strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("expected cgroup.freeze=1 after pause-hot, got %q", string(b))
	}
	if !android.ReadHibernatedState(d.hibernatedPkgsPath).HotFrozen {
		t.Fatal("expected HotFrozen=true in hibernated state")
	}

	// 2. First OpLaunchApp wakes from hot-pause, populates launcherCache + userUnlockedBoot, records trace.
	resp1 := d.HandleRPC(ctx, contracts.RPCRequest{ID: "launch-1", Op: contracts.OpLaunchApp, Pkg: "com.google.android.apps.bard"})
	if !resp1.OK {
		t.Fatalf("first OpLaunchApp failed: %+v", resp1)
	}
	if resolveCalls != 1 {
		t.Fatalf("resolveCalls = %d, want 1", resolveCalls)
	}
	if b, _ := os.ReadFile(freezeFile); strings.TrimSpace(string(b)) != "0" {
		t.Fatalf("expected cgroup.freeze=0 after OpLaunchApp thaw, got %q", string(b))
	}
	d.mu.Lock()
	unlocked := d.userUnlockedBoot
	cached := d.launcherCache["com.google.android.apps.bard"]
	stAfter1 := d.state
	d.mu.Unlock()
	if !unlocked || cached != "com.google.android.apps.bard/com.google.android.apps.bard.MainActivity" {
		t.Fatalf("expected cached boot & launcher, got unlocked=%v cached=%q", unlocked, cached)
	}
	d.waitMaintenance()
	d.mu.Lock()
	stAfter1 = d.state
	d.mu.Unlock()
	if stAfter1 != StateOpen {
		t.Fatalf("expected StateOpen after first launch, got %s", stAfter1)
	}

	// 3. Second OpLaunchApp hits FastPath & reuses launcherCache (0 additional resolve calls!).
	resp2 := d.HandleRPC(ctx, contracts.RPCRequest{ID: "launch-2", Op: contracts.OpLaunchApp, Pkg: "com.google.android.apps.bard"})
	if !resp2.OK {
		t.Fatalf("second OpLaunchApp failed: %+v", resp2)
	}
	if resolveCalls != 1 {
		t.Fatalf("expected launcherCache hit to avoid resolve-activity, got resolveCalls=%d", resolveCalls)
	}

	// Verify LaunchTrace ring via HandleCtl("perf-trace").
	traceOut, err := d.HandleCtl(ctx, "perf-trace", nil)
	if err != nil {
		t.Fatal(err)
	}
	var traces []LaunchTrace
	if err := json.Unmarshal([]byte(traceOut), &traces); err != nil || len(traces) != 2 {
		t.Fatalf("expected 2 LaunchTrace entries from perf-trace, got %d (%v): %s", len(traces), err, traceOut)
	}
	if !traces[1].FastPath {
		t.Fatalf("expected second launch trace FastPath=true, got %+v", traces[1])
	}

	// 4. Stale launcher cache eviction + fallback re-resolve when activity class changed after update.
	failNextCachedStart = true
	resp3 := d.HandleRPC(ctx, contracts.RPCRequest{ID: "launch-3", Op: contracts.OpLaunchApp, Pkg: "com.google.android.apps.bard"})
	if !resp3.OK {
		t.Fatalf("third OpLaunchApp (cache eviction retry) failed: %+v", resp3)
	}
	if resolveCalls != 2 {
		t.Fatalf("expected resolve-activity fallback on cached start error, resolveCalls=%d", resolveCalls)
	}
	d.mu.Lock()
	updatedCache := d.launcherCache["com.google.android.apps.bard"]
	d.mu.Unlock()
	if updatedCache != "com.google.android.apps.bard/com.google.android.apps.bard.NewEntryActivity" {
		t.Fatalf("expected evicted cache updated to NewEntryActivity, got %q", updatedCache)
	}

	callsAll := strings.Join(runner.callsSnapshot(), "\n")
	if strings.Contains(callsAll, "force-stop") {
		t.Fatalf("hot-freeze flow must NOT call am force-stop, got:\n%s", callsAll)
	}
}
