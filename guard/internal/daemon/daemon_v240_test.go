package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
	"sandbox_guard/internal/oem"
)

func TestPerfConfigDefaultsNormalizationAndClamping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perf.json")

	// Omitted bools stay true, out-of-range numbers clamp, unknown pause_mode normalizes to deep.
	raw := `{"pause_mode":"TURBO","auto_pause_idle_minutes":99999,"oom_score_adj":500,"locale_overrides":{"com.google.android.apps.bard":"zh-CN","bad pkg":"zh-CN","com.example.badloc":"not;ok"}}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := LoadPerfConfig(path)
	if cfg.PauseMode != PauseModeDeep || cfg.AutoPauseIdleMinutes != 1440 || cfg.OOMScoreAdj != 0 {
		t.Fatalf("unexpected clamped perf config: %+v", cfg)
	}
	if !cfg.PreserveUserLocales || !cfg.KernelRejectQuicUDP443 || !cfg.AutoPruneBloatOnStart {
		t.Fatalf("omitted bools must retain defaults: %+v", cfg)
	}
	if cfg.LocaleOverrides["com.google.android.apps.bard"] != "zh-CN" || len(cfg.LocaleOverrides) != 1 {
		t.Fatalf("unexpected cleaned locale_overrides: %+v", cfg.LocaleOverrides)
	}

	// Explicit false overrides must persist cleanly.
	if err := os.WriteFile(path, []byte(`{"pause_mode":"light","preserve_user_locales":false,"kernel_reject_quic_udp443":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg2 := LoadPerfConfig(path)
	if cfg2.PauseMode != PauseModeLight || cfg2.PreserveUserLocales || cfg2.KernelRejectQuicUDP443 {
		t.Fatalf("explicit false overrides must be honored: %+v", cfg2)
	}
}

func TestResolveExemptUIDsIncludesManagedProvisioningAndWork(t *testing.T) {
	dir := t.TempDir()
	pkg := contracts.DefaultWorkPackage
	pkgList := filepath.Join(dir, "packages.list")
	if err := os.WriteFile(pkgList, []byte(
		"com.android.managedprovisioning 10076 0 /data/user/0/com.android.managedprovisioning platform:privapp 0 0\n"+
			pkg+" 10376 0 /data/user/0/"+pkg+" default 0 0\n"+
			"com.google.android.apps.bard 10395 0 /data/user/0/com.google.android.apps.bard default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		stealthConfigPath:  filepath.Join(dir, "stealth.json"),
		stealthRuntimePath: filepath.Join(dir, "rt_stealth.json"),
		zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
		packagesListPath:   pkgList,
		policy:             contracts.Policy{UserID: 10, Serial: 1000, CallerPackage: pkg},
		policyLoaded:       true,
	}
	// Seed an older stealth.json lacking preserve_user_locales -> must default to true.
	if err := os.WriteFile(d.stealthConfigPath, []byte(`{"enabled":true,"sandbox_user_id":10,"exempt_work_uid":1010376}`), 0600); err != nil {
		t.Fatal(err)
	}

	sc, err := d.SyncStealthConfig(d.policy, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sc.ExemptWorkUID != 1010376 {
		t.Fatalf("expected backfilled exempt_work_uid 1010376 even when clientUID=0, got %d", sc.ExemptWorkUID)
	}
	if !sc.PreserveUserLocales {
		t.Fatal("stealth.json missing preserve_user_locales must default to true")
	}
	if len(sc.ExemptUIDs) != 2 || sc.ExemptUIDs[0] != 1010076 || sc.ExemptUIDs[1] != 1010376 {
		t.Fatalf("expected exempt_uids [1010076 1010376], got %v", sc.ExemptUIDs)
	}
	wantDev := oem.Current().DefaultDeviceName
	if !sc.SanitizeNetwork || !sc.SpoofBluetooth || sc.SandboxLinkIPv4 != "10.172.10.2" || sc.DeviceName != wantDev {
		t.Fatalf("expected anti-linkage defaults backfilled (want DeviceName=%q), got %+v", wantDev, sc)
	}
}

func TestDeepPauseWakesAndFlushesMihomoAndPreservesLocales(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "proxy.sh")
	if err := os.WriteFile(script, []byte("#!/system/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}

	var closedIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_, _ = w.Write([]byte(`{"connections":[
				{"id":"wp-1","metadata":{"inboundName":"sandbox-tproxy"}},
				{"id":"u0-1","metadata":{"inboundName":"tproxy-in"}}
			]}`))
		case r.Method == http.MethodDelete:
			closedIDs = append(closedIDs, strings.TrimPrefix(r.URL.Path, "/connections/"))
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	mainCfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(mainCfg, []byte(`{"external-controller":"`+strings.TrimPrefix(srv.URL, "http://")+`","secret":"abc"}`), 0600); err != nil {
		t.Fatal(err)
	}

	pkg := contracts.DefaultWorkPackage
	bloatSample := ""
	pmEnabledOut := "package:com.google.android.apps.bard\npackage:" + pkg + "\n"
	if cands := oem.Current().BloatCandidates; len(cands) > 0 {
		bloatSample = cands[0]
		pmEnabledOut = "package:" + bloatSample + "\n" + pmEnabledOut
	}

	userRunning := false
	nfMock := newStatefulMockIPTables(false)
	runner := &v240FlexRunner{
		out: map[string]string{
			"cmd user list -v":                                                  "0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running)\n1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running)\n",
			"dumpsys user --user 10":                                            "  UserInfo{10:Work:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
			"cmd device_policy list-owners":                                     "User 10: admin=" + contracts.DefaultAdminComponent + ",ManagedProfileOwner(parentUserId=0)\n",
			"cmd package list packages --user 10 -U " + pkg:                     "package:" + pkg + " uid:1010376\n",
			"cmd package list packages -3 --user 10":                            "package:" + pkg + "\npackage:com.google.android.apps.bard\n",
			"cmd locale get-app-locales com.google.android.apps.bard --user 10": "Locales for com.google.android.apps.bard for user 10 are [zh-CN]\n",
			"pm list packages -e --user 10":                                     pmEnabledOut,
			"ime list -s --user 10":                                             "com.google.android.inputmethod.latin/com.android.inputmethod.latin.LatinIME\n",
			"settings get global private_dns_mode":                              "off\n",
		},
		onRun: func(cmdLine string) (string, bool, error) {
			switch cmdLine {
			case "dumpsys activity users":
				if userRunning {
					return "    User #10: state=RUNNING_UNLOCKED\n", true, nil
				}
				return "    User #10: state=STOPPED\n", true, nil
			case "am start-user -w 10":
				userRunning = true
				return "Success\n", true, nil
			case "am stop-user -f -w 10":
				userRunning = false
				return "Success\n", true, nil
			}
			return "", false, nil
		},
	}

	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	pkgList := filepath.Join(dir, "packages.list")
	if err := os.WriteFile(pkgList, []byte(
		pkg+" 10376 0 /data/user/0/"+pkg+" default 0 0\n"+
			"com.google.android.gms 10200 0 /data/user/0/com.google.android.gms privapp 0 0\n"+
			"com.google.android.apps.bard 10395 0 /data/user/0/com.google.android.apps.bard default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}
	cgRoot := filepath.Join(dir, "cgroup")
	bardFreeze := filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze")
	if err := os.MkdirAll(filepath.Dir(bardFreeze), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bardFreeze, []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: nfMock, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-v240",
		policy:             pol,
		policyLoaded:       true,
		state:              StateBlockedLocked,
		paused:             true,
		workCfgDir:         dir,
		packagesListPath:   pkgList,
		desiredStatePath:   filepath.Join(dir, "desired_state.json"),
		exemptionPath:      filepath.Join(dir, "exemption.v1.json"),
		sandboxAckPath:     filepath.Join(dir, "sandbox_ack.v1.json"),
		upgradeFencePath:   filepath.Join(dir, "upgrade_fence.json"),
		stealthConfigPath:  filepath.Join(dir, "stealth.json"),
		stealthRuntimePath: filepath.Join(dir, "rt_stealth.json"),
		zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
		perfConfigPath:     filepath.Join(dir, "perf.json"),
		prunedPkgsPath:     filepath.Join(dir, "pruned_pkgs.json"),
		hibernatedPkgsPath: filepath.Join(dir, "hibernated_pkgs.json"),
		cgroupRoot:         cgRoot,
		mainConfigPath:     mainCfg,
		proxyCtlScript:     script,
		reconcileCh:        make(chan reconcileReq, 8),
		probeTProxyReady:   func(port int) bool { return port == contracts.DefaultTProxyPort },
		userWakeTimeout:    500 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startMockReconcilePump(ctx, d)

	// Starting from deep sleep wakes User 10, opens kernel gates promptly, and runs bloat prune + locale sync async.
	if resp := d.HandleRPC(ctx, contracts.RPCRequest{ID: "start-1", Op: contracts.OpStartVPN}); !resp.OK {
		t.Fatalf("start failed: %+v", resp)
	}
	d.waitMaintenance()
	if !userRunning {
		t.Fatal("expected User 10 to wake on OpStartVPN")
	}
	if d.lastAppliedSpec == nil || !d.lastAppliedSpec.KernelRejectQuicUDP443 {
		t.Fatalf("expected KernelRejectQuicUDP443 enabled in GateSpec, got %+v", d.lastAppliedSpec)
	}
	allCalls := strings.Join(runner.callsSnapshot(), "\n")
	if strings.Contains(allCalls, "sh -c") {
		t.Fatalf("must NEVER invoke sh -c, got:\n%s", allCalls)
	}
	if bloatSample != "" && !strings.Contains(allCalls, "pm disable-user --user 10 "+bloatSample) {
		t.Fatalf("expected bloat prune on start for %s, calls:\n%s", bloatSample, allCalls)
	}
	if !strings.Contains(allCalls, "cmd locale get-app-locales com.google.android.apps.bard --user 10") {
		t.Fatalf("expected locale preservation probe during sync, calls:\n%s", allCalls)
	}
	if strings.Contains(allCalls, "cmd locale set-app-locales com.google.android.apps.bard") {
		t.Fatalf("must NOT overwrite existing zh-CN locale on Gemini, calls:\n%s", allCalls)
	}

	// Set manual Chinese locale for Gemini via ctl -> persists to perf.json locale_overrides.
	out, err := d.HandleCtl(ctx, "set-app-locale", []string{"com.google.android.apps.bard", "zh-CN"})
	if err != nil || !strings.Contains(out, `"zh-CN"`) {
		t.Fatalf("set-app-locale failed: out=%q err=%v", out, err)
	}
	if LoadPerfConfig(d.perfConfigPath).LocaleOverrides["com.google.android.apps.bard"] != "zh-CN" {
		t.Fatal("expected zh-CN persisted in perf.json locale_overrides")
	}

	// Pausing must close gates, flush mihomo sandbox-tproxy connections, freeze user apps via cgroup v2 + hibernate (FBE unlocked!).
	if resp := d.HandleRPC(ctx, contracts.RPCRequest{ID: "pause-1", Op: contracts.OpPauseVPN}); !resp.OK {
		t.Fatalf("pause failed: %+v", resp)
	}
	if !userRunning || !d.paused || d.state != StateBlockedLocked {
		t.Fatalf("expected User 10 FBE-unlocked (running=true) & BlockedLocked, got running=%v paused=%v state=%s", userRunning, d.paused, d.state)
	}
	if b, _ := os.ReadFile(bardFreeze); string(b) != "1" {
		t.Fatalf("expected cgroup.freeze=1 after pause, got %q", string(b))
	}
	stData := d.buildStatusData(ctx)
	if hibCnt, _ := stData["hibernated_count"].(int); hibCnt == 0 {
		t.Fatalf("expected non-zero hibernated_count telemetry in status, got %v", stData["hibernated_count"])
	}
	if fUIDs, _ := stData["frozen_uids"].([]int); len(fUIDs) != 1 || fUIDs[0] != 1010395 {
		t.Fatalf("expected frozen_uids [1010395], got %v", stData["frozen_uids"])
	}
	pauseCalls := strings.Join(runner.callsSnapshot(), "\n")
	if strings.Contains(pauseCalls, "am stop-user") {
		t.Fatalf("must NEVER call am stop-user (FBE key eviction bug):\n%s", pauseCalls)
	}
	if !strings.Contains(pauseCalls, "am stop-app --user 10 com.google.android.apps.bard") {
		t.Fatalf("expected Gemini stopped via am stop-app on hibernate pause:\n%s", pauseCalls)
	}
	if len(closedIDs) != 1 || closedIDs[0] != "wp-1" {
		t.Fatalf("expected only wp-1 flushed on pause, got %v", closedIDs)
	}

	// Root LAUNCH_APP wakes paused sandbox, thaws cgroup, priority-restores Gemini + GMS before `am start --user 10`,
	// and restores remaining background packages asynchronously via maintenance worker.
	if resp := d.HandleRPC(ctx, contracts.RPCRequest{
		ID:       "launch-1",
		Op:       contracts.OpLaunchApp,
		Pkg:      "com.google.android.apps.bard",
		Activity: "com.google.android.apps.bard.shellapp.BardEntryPointActivity",
	}); !resp.OK {
		t.Fatalf("LAUNCH_APP failed: %+v", resp)
	}
	if b, _ := os.ReadFile(bardFreeze); string(b) != "0" {
		t.Fatalf("expected cgroup.freeze thawed to 0 on LAUNCH_APP, got %q", string(b))
	}
	immediateCalls := runner.callsSnapshot()
	bardRestoreIdx, gmsRestoreIdx, amStartIdx := -1, -1, -1
	for i, c := range immediateCalls {
		switch c {
		case "appops set --user 10 com.google.android.apps.bard RUN_ANY_IN_BACKGROUND allow":
			bardRestoreIdx = i
		case "appops set --user 10 com.google.android.gms RUN_ANY_IN_BACKGROUND allow":
			gmsRestoreIdx = i
		case "am start --user 10 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -f 0x10200000 -n com.google.android.apps.bard/com.google.android.apps.bard.shellapp.BardEntryPointActivity":
			amStartIdx = i
		}
	}
	if bardRestoreIdx < 0 || gmsRestoreIdx < 0 || amStartIdx < 0 || bardRestoreIdx > amStartIdx || gmsRestoreIdx > amStartIdx {
		t.Fatalf("expected bard & gms restored BEFORE am start (bard=%d gms=%d start=%d):\n%s",
			bardRestoreIdx, gmsRestoreIdx, amStartIdx, strings.Join(immediateCalls, "\n"))
	}

	d.waitMaintenance()
	if _, err := os.Stat(d.hibernatedPkgsPath); !os.IsNotExist(err) {
		t.Fatalf("expected hibernated_pkgs.json cleared after async background restore, err=%v", err)
	}
	resumeCalls := strings.Join(runner.callsSnapshot(), "\n")
	if !strings.Contains(resumeCalls, "appops set --user 10 com.android.vending RUN_ANY_IN_BACKGROUND allow") {
		t.Fatalf("expected remaining sandbox packages restored asynchronously after LAUNCH_APP:\n%s", resumeCalls)
	}
}

func TestIdleAutoPauseTrackerAndStepCheck(t *testing.T) {
	tr := &idleAutoPauseTracker{}
	// First sample establishes byte baseline without counting an idle minute (even when threshold=1).
	if tr.Observe(android.SandboxActivitySnapshot{TrafficBytes: 1000}, 1) || tr.idleMinutes != 0 {
		t.Fatal("first tick must initialize baseline without counting idle minutes")
	}
	// Heavy traffic burst resets idle counter.
	if tr.Observe(android.SandboxActivitySnapshot{TrafficBytes: 100000}, 2) || tr.idleMinutes != 0 {
		t.Fatal("expected traffic delta >32KB to reset idle counter")
	}
	// Counter reset where new counter < previous counter still detects post-reset >32KB traffic.
	if tr.Observe(android.SandboxActivitySnapshot{TrafficBytes: 40000}, 1) || tr.idleMinutes != 0 {
		t.Fatal("expected counter-reset >32KB traffic to keep sandbox awake")
	}
	// Active foreground user resets idle counter.
	if tr.Observe(android.SandboxActivitySnapshot{ForegroundUser: true, TrafficBytes: 40100}, 2) || tr.idleMinutes != 0 {
		t.Fatal("expected foreground u10 window to reset idle counter")
	}
	// Active audio resets idle counter.
	if tr.Observe(android.SandboxActivitySnapshot{AudioActive: true, TrafficBytes: 40200}, 2) || tr.idleMinutes != 0 {
		t.Fatal("expected active u10 audio to reset idle counter")
	}
	// 2 consecutive idle ticks after baseline trigger auto-pause.
	if tr.Observe(android.SandboxActivitySnapshot{TrafficBytes: 40200}, 2) {
		t.Fatal("tick 1 after baseline should not trigger threshold 2")
	}
	if !tr.Observe(android.SandboxActivitySnapshot{TrafficBytes: 41000}, 2) {
		t.Fatal("tick 2 (small noise <=32KB) should trigger threshold 2")
	}

	// Verify Daemon.stepAutoPauseCheck runs synchronously WITHOUT reconcileCh pump (zero Supervise self-deadlock).
	dir := t.TempDir()
	perfPath := filepath.Join(dir, "perf.json")
	if err := WritePerfConfig(perfPath, PerfConfig{PauseMode: PauseModeDeep, AutoPauseIdleMinutes: 1}); err != nil {
		t.Fatal(err)
	}
	nfMock := newStatefulMockIPTables(false)
	forceStoppedBard := false
	runner := &v240FlexRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10":                        "package:com.google.android.apps.bard\n",
			"dumpsys activity activities":                                   "  topResumedActivity=ActivityRecord{1 u0 com.tencent.mm/.Main t1}\n",
			"iptables -t mangle -L " + contracts.ChainTProxyOut + " -v -n -x": "0 0 ACCEPT all -- * * 0.0.0.0/0 0.0.0.0/0 owner UID match 1000000-1099999\n",
			"dumpsys audio":                                                 "",
		},
		onRun: func(cmdLine string) (string, bool, error) {
			if cmdLine == "am stop-app --user 10 com.google.android.apps.bard" {
				forceStoppedBard = true
				return "", true, nil
			}
			return "", false, nil
		},
	}
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark
	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: nfMock, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-idle",
		policy:             pol,
		policyLoaded:       true,
		state:              StateOpen,
		paused:             false,
		desiredStatePath:   filepath.Join(dir, "desired_state.json"),
		exemptionPath:      filepath.Join(dir, "exemption.v1.json"),
		perfConfigPath:     perfPath,
		hibernatedPkgsPath: filepath.Join(dir, "hibernated_idle.json"),
		reconcileCh:        make(chan reconcileReq, 4),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tr2 := &idleAutoPauseTracker{}
	// First tick establishes baseline without pausing.
	d.stepAutoPauseCheck(ctx, tr2)
	if d.paused || forceStoppedBard {
		t.Fatal("first stepAutoPauseCheck tick must only establish baseline")
	}
	// Second idle tick triggers fail-closed gate + async FBE-safe deep hibernation without blocking Supervise.
	d.stepAutoPauseCheck(ctx, tr2)
	d.waitMaintenance()
	if !d.paused || d.state != StateBlockedLocked || !forceStoppedBard {
		t.Fatalf("expected auto-pause to enter BlockedLocked + hibernate user 10 apps, got paused=%v state=%s stopped=%v", d.paused, d.state, forceStoppedBard)
	}
	if _, err := os.Stat(d.hibernatedPkgsPath); err != nil {
		t.Fatalf("expected %s created on idle auto-pause: %v", d.hibernatedPkgsPath, err)
	}
	if strings.Contains(strings.Join(runner.callsSnapshot(), "\n"), "am stop-user") {
		t.Fatal("idle auto-pause must never call am stop-user")
	}
}

func TestRouteFingerprintAndTransientBrokerAuthPreservation(t *testing.T) {
	// Route fingerprint strips uid noise and catches Wi-Fi <-> 5G gateway changes.
	fp1 := normalizeRouteGetFingerprint("1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.50 uid 0\n    cache ")
	fp2 := normalizeRouteGetFingerprint("1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.50 uid 1000")
	fp3 := normalizeRouteGetFingerprint("1.1.1.1 via 10.0.0.1 dev rmnet_data0 src 10.0.0.8 uid 0")
	if fp1 != fp2 || fp1 == fp3 || strings.Contains(fp1, "uid") {
		t.Fatalf("unexpected route fingerprints: fp1=%q fp2=%q fp3=%q", fp1, fp2, fp3)
	}

	dir := t.TempDir()
	authPath := filepath.Join(dir, "broker_auth.json")
	if err := os.WriteFile(authPath, []byte(`{"allowed_user0_uid":10376}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		brokerAuthPath: authPath,
		policyLoaded:   true,
		policy:         testPolicy(),
		runner: &v240FlexRunner{
			onRun: func(cmdLine string) (string, bool, error) {
				if strings.HasPrefix(cmdLine, "cmd package list packages --user 0") {
					return "", true, errors.New("Can't find service: package")
				}
				return "", false, nil
			},
		},
	}
	if _, err := d.RefreshBrokerAuth(context.Background()); err == nil {
		t.Fatal("expected transient binder error")
	}
	if !hasValidBrokerAuthUID(authPath) {
		t.Fatal("transient package binder error must not clobber existing valid broker_auth.json")
	}
	// Explicit missing package MUST overwrite broker_auth.json to 0 (fail closed).
	d.runner = &v240FlexRunner{
		out: map[string]string{
			"cmd package list packages --user 0 -U " + contracts.DefaultWorkPackage: "",
		},
	}
	if _, err := d.RefreshBrokerAuth(context.Background()); err == nil {
		t.Fatal("expected missing package error")
	}
	if hasValidBrokerAuthUID(authPath) {
		t.Fatal("missing package must clear broker_auth.json to 0")
	}

	// Unpaused boot must prune bloat once User 10 is RUNNING_UNLOCKED (on OEMs with bloat candidates).
	bootBloat := ""
	bootPmOut := "package:" + contracts.DefaultWorkPackage + "\n"
	if cands := oem.Current().BloatCandidates; len(cands) > 0 {
		bootBloat = cands[0]
		bootPmOut = "package:" + bootBloat + "\n" + bootPmOut
	}
	unpausedRunner := &v240FlexRunner{
		out: map[string]string{
			"getprop sys.boot_completed":    "1\n",
			"dumpsys activity users":        "    User #10: state=RUNNING_UNLOCKED\n",
			"pm list packages -e --user 10": bootPmOut,
			"ime list -s --user 10":         "",
		},
	}
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark
	dBoot := &Daemon{
		runner:         unpausedRunner,
		policy:         pol,
		policyLoaded:   true,
		paused:         false,
		perfCfg:        DefaultPerfConfig(),
		perfLoaded:     true,
		prunedPkgsPath: filepath.Join(dir, "pruned_boot.json"),
		brokerAuthPath: authPath,
	}
	// Pre-populate valid broker_auth so bootMaintain focuses strictly on unpaused boot bloat prune.
	_ = os.WriteFile(authPath, []byte(`{"allowed_user0_uid":10376}`+"\n"), 0600)
	dBoot.bootMaintain(context.Background(), false)
	if !dBoot.bloatPrunedOnce {
		t.Fatal("unpaused boot must run PruneSandboxBloat and mark bloatPrunedOnce")
	}
	if bootBloat != "" && !strings.Contains(strings.Join(unpausedRunner.callsSnapshot(), "\n"), "pm disable-user --user 10 "+bootBloat) {
		t.Fatalf("expected unpaused boot to prune bloat package %s", bootBloat)
	}

	// cancelMaintenance must immediately cancel active maintenance context.
	mctx, mcancel := context.WithCancel(context.Background())
	dBoot.mu.Lock()
	dBoot.maintCancel = mcancel
	dBoot.mu.Unlock()
	dBoot.cancelMaintenance()
	if mctx.Err() == nil {
		t.Fatal("cancelMaintenance must cancel active maintenance context immediately")
	}
}

func TestSecondLaunchAppPriorityRestoresAndPauseCancelsCleanly(t *testing.T) {
	dir := t.TempDir()
	cgRoot := filepath.Join(dir, "cgroup")
	vendFreeze := filepath.Join(cgRoot, "uid_1010396", "cgroup.freeze")
	if err := os.MkdirAll(filepath.Dir(vendFreeze), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vendFreeze, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	pkgList := filepath.Join(dir, "packages.list")
	pkg := contracts.DefaultWorkPackage
	if err := os.WriteFile(pkgList, []byte(
		pkg+" 10376 0 /data/user/0/"+pkg+" default 0 0\n"+
			"com.google.android.gms 10200 0 /data/user/0/com.google.android.gms privapp 0 0\n"+
			"com.android.vending 10396 0 /data/user/0/com.android.vending default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}
	hibPath := filepath.Join(dir, "hibernated_pkgs.json")
	if err := os.WriteFile(hibPath, []byte(`{"user_id":10,"packages":["com.android.vending","com.google.android.apps.bard","com.google.android.gms","com.google.android.googlequicksearchbox","com.google.android.gsf"],"frozen_uids":[1010396]}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	runner := &v240FlexRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.google.android.apps.bard\npackage:com.android.vending\n",
			"ime list -s --user 10":                  "",
			"cmd package resolve-activity --brief --user 10 com.android.vending": "com.android.vending/.AssetBrowserActivity\n",
		},
	}
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark
	nfMock := newStatefulMockIPTables(true)

	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: nfMock, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-launch2",
		policy:             pol,
		policyLoaded:       true,
		state:              StateOpen,
		paused:             false,
		bloatPrunedOnce:    true,
		lastPolicySyncHash: "synced",
		desiredStatePath:   filepath.Join(dir, "desired_state.json"),
		exemptionPath:      filepath.Join(dir, "exemption.v1.json"),
		sandboxAckPath:     filepath.Join(dir, "sandbox_ack.v1.json"),
		perfConfigPath:     filepath.Join(dir, "perf.json"),
		hibernatedPkgsPath: hibPath,
		packagesListPath:   pkgList,
		cgroupRoot:         cgRoot,
		reconcileCh:        make(chan reconcileReq, 8),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startMockReconcilePump(ctx, d)

	// Launching a 2nd app while sandbox is already Open must priority-restore it BEFORE `am start --user 10`
	// and finish restoring remaining hibernated packages asynchronously.
	if resp := d.HandleRPC(ctx, contracts.RPCRequest{
		ID:  "launch-vending",
		Op:  contracts.OpLaunchApp,
		Pkg: "com.android.vending",
	}); !resp.OK {
		t.Fatalf("second OpLaunchApp failed: %+v", resp)
	}
	if b, _ := os.ReadFile(vendFreeze); string(b) != "0" {
		t.Fatalf("expected cgroup.freeze thawed immediately for vending, got %q", string(b))
	}
	immediate := runner.callsSnapshot()
	vendRestoreIdx, startIdx := -1, -1
	for i, c := range immediate {
		switch c {
		case "appops set --user 10 com.android.vending RUN_ANY_IN_BACKGROUND allow":
			vendRestoreIdx = i
		case "am start --user 10 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -f 0x10200000 -n com.android.vending/.AssetBrowserActivity":
			startIdx = i
		}
	}
	if vendRestoreIdx < 0 || startIdx < 0 || vendRestoreIdx > startIdx {
		t.Fatalf("expected vending priority-restored BEFORE am start (restore=%d start=%d):\n%s",
			vendRestoreIdx, startIdx, strings.Join(immediate, "\n"))
	}
	d.waitMaintenance()
	if _, err := os.Stat(hibPath); !os.IsNotExist(err) {
		t.Fatalf("expected hibernated_pkgs.json deleted after async restore, err=%v", err)
	}
	allJoined := strings.Join(runner.callsSnapshot(), "\n")
	if !strings.Contains(allJoined, "appops set --user 10 com.google.android.googlequicksearchbox RUN_ANY_IN_BACKGROUND allow") {
		t.Fatalf("expected googlequicksearchbox restored asynchronously:\n%s", allJoined)
	}

	// Verify OpPauseVPN cancels any in-flight async maintenance cleanly and preserves hibernated_pkgs.json with zero am stop-user.
	startedRestore := make(chan struct{})
	var closeOnce sync.Once
	blockRunner := &blockingPauseCancelRunner{
		base: &v240FlexRunner{
			out: map[string]string{
				"cmd package list packages -3 --user 10": "package:com.google.android.apps.bard\npackage:com.android.vending\n",
				"ime list -s --user 10":                  "",
			},
		},
		blockCmd: "appops set --user 10 com.google.android.googlequicksearchbox RUN_ANY_IN_BACKGROUND allow",
		onBlock: func() {
			closeOnce.Do(func() { close(startedRestore) })
		},
	}
	d.runner = blockRunner
	if err := os.WriteFile(hibPath, []byte(`{"user_id":10,"packages":["com.google.android.apps.bard","com.google.android.googlequicksearchbox"]}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d.scheduleMaintenance(pol, true)
	select {
	case <-startedRestore:
	case <-ctx.Done():
		t.Fatal("timed out waiting for async maintenance restore to begin")
	}

	if resp := d.HandleRPC(ctx, contracts.RPCRequest{ID: "pause-cancel", Op: contracts.OpPauseVPN}); !resp.OK {
		t.Fatalf("OpPauseVPN failed while cancelling in-flight maintenance: %+v", resp)
	}
	d.waitMaintenance()
	if !d.paused || d.state != StateBlockedLocked {
		t.Fatalf("expected paused=true state=BlockedLocked, got paused=%v state=%s", d.paused, d.state)
	}
	stAfterPause := android.ReadHibernatedState(hibPath)
	if len(stAfterPause.Packages) == 0 {
		t.Fatalf("expected %s populated after OpPauseVPN cancelled async restore", hibPath)
	}
	pauseJoined := strings.Join(blockRunner.base.callsSnapshot(), "\n")
	if strings.Contains(pauseJoined, "am stop-user") || strings.Contains(pauseJoined, "sh -c") {
		t.Fatalf("forbidden am stop-user or sh -c during pause cancel:\n%s", pauseJoined)
	}
}

type blockingPauseCancelRunner struct {
	base     *v240FlexRunner
	blockCmd string
	onBlock  func()
}

func (b *blockingPauseCancelRunner) Run(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	if line == b.blockCmd {
		b.onBlock()
		<-ctx.Done()
		return "", ctx.Err()
	}
	return b.base.Run(ctx, timeout, stdin, name, args...)
}

type v240FlexRunner struct {
	mu    sync.Mutex
	calls []string
	out   map[string]string
	onRun func(cmdLine string) (string, bool, error)
}

func (m *v240FlexRunner) callsSnapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *v240FlexRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, line)
	if m.onRun != nil {
		if out, handled, err := m.onRun(line); handled {
			return out, err
		}
	}
	if m.out != nil {
		if v, ok := m.out[line]; ok {
			return v, nil
		}
	}
	return "", nil
}

func BenchmarkIdleAutoPauseObserve(b *testing.B) {
	tr := &idleAutoPauseTracker{}
	snap := android.SandboxActivitySnapshot{TrafficBytes: 4096}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snap.TrafficBytes += 64
		_ = tr.Observe(snap, 1000000)
	}
}
