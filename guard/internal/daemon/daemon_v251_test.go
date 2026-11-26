package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
)

type v251FailingIPTables struct {
	mu              sync.Mutex
	base            *statefulMockIPTables
	hasExtOutput    bool
	failRestoreNext bool
}

func (m *v251FailingIPTables) Run(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	if name == "ip" {
		return "", nil
	}
	m.mu.Lock()
	hasExt := m.hasExtOutput
	failNext := false
	if m.failRestoreNext && name == "iptables-restore" {
		m.failRestoreNext = false
		failNext = true
	}
	m.mu.Unlock()
	if failNext {
		return "COMMIT FAILED", errors.New("mock iptables-restore error")
	}
	if name == "iptables-save" {
		out, err := m.base.Run(ctx, timeout, stdin, name, args...)
		if err != nil {
			return out, err
		}
		if hasExt && !strings.Contains(out, "EXT_PROXY_OUTPUT") {
			if strings.Contains(out, "*mangle\n") {
				out = strings.Replace(out, "*mangle\n", "*mangle\n:EXT_PROXY_OUTPUT - [0:0]\n-A OUTPUT -j EXT_PROXY_OUTPUT\n", 1)
			} else {
				out = "*mangle\n:OUTPUT ACCEPT [0:0]\n:EXT_PROXY_OUTPUT - [0:0]\n-A OUTPUT -j EXT_PROXY_OUTPUT\nCOMMIT\n" + out
			}
		}
		return out, nil
	}
	return m.base.Run(ctx, timeout, stdin, name, args...)
}

func TestV251WakeSeqAbortsMidFlightAutoPause(t *testing.T) {
	dir := t.TempDir()
	cgRoot := filepath.Join(dir, "cgroup")
	uidDir := filepath.Join(cgRoot, "uid_1010395")
	if err := os.MkdirAll(uidDir, 0755); err != nil {
		t.Fatal(err)
	}
	freezeFile := filepath.Join(uidDir, "cgroup.freeze")
	if err := os.WriteFile(freezeFile, []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uidDir, "cgroup.procs"), []byte("12345\n"), 0644); err != nil {
		t.Fatal(err)
	}

	wakeTriggered := false
	var d *Daemon
	runner := &v240FlexRunner{
		out: map[string]string{
			"iptables -t mangle -L " + contracts.ChainTProxyOut + " -v -n -x": "Chain " + contracts.ChainTProxyOut + " (1 references)\n pkts bytes target prot opt in out source destination\n",
			"dumpsys audio":          "",
			"dumpsys activity top":   "ACTIVITY com.android.launcher3/.Launcher u0\n",
			"dumpsys activity users": "    User #10: state=RUNNING_UNLOCKED\n",
			"dumpsys window":         "",
		},
		onRun: func(cmdLine string) (string, bool, error) {
			if !wakeTriggered {
				wakeTriggered = true
				// Simulate concurrent wake bumping wakeSeq during activity check.
				d.bumpWakeSeq()
			}
			if cmdLine == "dumpsys activity users" {
				return "    User #10: state=RUNNING_UNLOCKED\n", true, nil
			}
			return "", false, nil
		},
	}

	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	d = &Daemon{
		nf:           &netfilter.Controller{Runner: &tproxyMockIPTables{base: newStatefulMockIPTables(false)}, LockPath: filepath.Join(dir, "nf.lock")},
		runner:       runner,
		bootID:       "boot-v251",
		policy:       pol,
		policyLoaded: true,
		state:        StateOpen,
		paused:       false,
		perfCfg: PerfConfig{
			PauseMode:            PauseModeHot,
			AutoPauseIdleMinutes: 5,
			HotFreezeMinutes:     30,
		},
		perfLoaded:         true,
		cgroupRoot:         cgRoot,
		asoundRoot:         filepath.Join(dir, "asound"),
		hibernatedPkgsPath: filepath.Join(dir, "hibernated_pkgs.json"),
		desiredStatePath:   filepath.Join(dir, "desired_state.json"),
		reconcileCh:        make(chan reconcileReq, 4),
	}

	tracker := &idleAutoPauseTracker{idleMinutes: 4}
	d.stepAutoPauseCheck(context.Background(), tracker)
	d.waitMaintenance()

	if !wakeTriggered {
		t.Fatal("expected wakeSeq bump trigger to fire")
	}
	if d.isPaused() {
		t.Fatal("expected stepAutoPauseCheck to abort pause when wakeSeq changed mid-flight")
	}
	if b, _ := os.ReadFile(freezeFile); strings.TrimSpace(string(b)) != "0" {
		t.Fatalf("expected cgroup.freeze to stay 0 on wake abort, got %q", string(b))
	}
}

func TestV251PauseModeHybridManualPauseAndL1ToL2Escalation(t *testing.T) {
	dir := t.TempDir()
	cgRoot := filepath.Join(dir, "cgroup")
	uidDir := filepath.Join(cgRoot, "uid_1010395")
	if err := os.MkdirAll(uidDir, 0755); err != nil {
		t.Fatal(err)
	}
	freezeFile := filepath.Join(uidDir, "cgroup.freeze")
	if err := os.WriteFile(freezeFile, []byte("0"), 0644); err != nil {
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

	runner := &v240FlexRunner{
		out: map[string]string{
			"cmd user list -v":                       "0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running)\n1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running)\n",
			"dumpsys user --user 10":                 "  UserInfo{10:Work:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
			"cmd device_policy list-owners":          "User 10: admin=" + contracts.DefaultAdminComponent + ",ManagedProfileOwner(parentUserId=0)\n",
			"cmd package list packages -3 --user 10": "package:" + pkg + "\npackage:com.google.android.apps.bard\n",
			"ime list -s --user 10":                  "",
			"dumpsys activity users":                 "    User #10: state=RUNNING_UNLOCKED\n",
		},
	}

	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	perfPath := filepath.Join(dir, "perf.json")
	if err := WritePerfConfig(perfPath, PerfConfig{
		PauseMode:           PauseModeHybrid,
		HotFreezeMinutes:    30,
		SkipAppOpsForFrozen: true,
		SyncTargetOnly:      true,
	}); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: &tproxyMockIPTables{base: newStatefulMockIPTables(false)}, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-v251",
		policy:             pol,
		policyLoaded:       true,
		state:              StateOpen,
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
		reconcileCh:        make(chan reconcileReq, 8),
		probeTProxyReady:   func(port int) bool { return port == contracts.DefaultTProxyPort },
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startMockReconcilePump(ctx, d)

	// Verify PauseModeHybrid resolves explicitly without staying literal "hybrid".
	eff := d.resolveEffectivePauseMode(PauseModeHybrid, "")
	if eff != PauseModeHot && eff != PauseModeDeep {
		t.Fatalf("resolveEffectivePauseMode(hybrid) = %q, want hot or deep", eff)
	}

	// Start in L1 hot-freeze, verify frozen, then escalate explicitly to L2 deep pause.
	if _, err := d.HandleCtl(ctx, "pause-hot", nil); err != nil {
		t.Fatalf("pause-hot failed: %v", err)
	}
	if !android.ReadHibernatedState(d.hibernatedPkgsPath).HotFrozen {
		t.Fatal("expected HotFrozen=true after pause-hot")
	}

	d.pauseSandboxWorkWithExplicitMode(ctx, true, pol, true, PauseModeDeep)
	d.mu.Lock()
	st := d.state
	d.mu.Unlock()
	if st != StateBlockedLocked || !d.isPaused() {
		t.Fatalf("expected StateBlockedLocked & paused after L2 escalation, got state=%s paused=%v", st, d.isPaused())
	}
	if android.ReadHibernatedState(d.hibernatedPkgsPath).HotFrozen {
		t.Fatal("expected HotFrozen=false after L1->L2 deep escalation")
	}
	callsAll := strings.Join(runner.callsSnapshot(), "\n")
	if !strings.Contains(callsAll, "stop-app --user 10 com.google.android.apps.bard") {
		t.Fatalf("expected stop-app during L1->L2 escalation, calls:\n%s", callsAll)
	}
}

func TestV251ReconcileOnceNetfilterErrorFailClosedArmRawDrop(t *testing.T) {
	dir := t.TempDir()
	nfMock := &v251FailingIPTables{
		base:            newStatefulMockIPTables(false),
		hasExtOutput:    true,
		failRestoreNext: true,
	}
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark
	pol.ProxySkipPrefix = "EXT_PROXY_"

	pkg := contracts.DefaultWorkPackage
	runner := &v240FlexRunner{
		out: map[string]string{
			"cmd user list -v":                         "0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running)\n1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running)\n",
			"dumpsys user --user 10":                   "  UserInfo{10:Work:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
			"cmd device_policy list-owners":            "User 10: admin=" + contracts.DefaultAdminComponent + ",ManagedProfileOwner(parentUserId=0)\n",
			"cmd package list packages --user 10 -U " + pkg: "package:" + pkg + " uid:1010376\n",
		},
	}

	d := &Daemon{
		nf:           &netfilter.Controller{Runner: nfMock, LockPath: filepath.Join(dir, "nf.lock")},
		runner:       runner,
		bootID:       "boot-v251",
		policy:       pol,
		policyLoaded: true,
		state:        StateOpen,
		paused:       false,
		cachedID: &android.VerifiedIdentity{
			UserID:    10,
			Serial:    1000,
			ClientUID: 1010376,
		},
		workCfgDir:       dir,
		desiredStatePath: filepath.Join(dir, "desired_state.json"),
		exemptionPath:    filepath.Join(dir, "exemption.v1.json"),
		sandboxAckPath:   filepath.Join(dir, "sandbox_ack.v1.json"),
		upgradeFencePath: filepath.Join(dir, "upgrade_fence.json"),
		probeTProxyReady: func(port int) bool { return port == contracts.DefaultTProxyPort },
	}

	if err := d.reconcileOnce(context.Background(), reconcileReq{refreshCert: true}); err != nil {
		t.Fatalf("unexpected error returned by reconcileOnce: %v", err)
	}

	d.mu.Lock()
	lastErr := d.lastError
	st := d.state
	lastOpen := d.lastOpen
	lastRaw := d.lastRawArmed
	curEx := d.currentExemption
	d.mu.Unlock()
	if !strings.Contains(lastErr, "mock iptables-restore error") {
		t.Fatalf("expected lastError to record mock iptables-restore error, got %q", lastErr)
	}
	if st != StateBlockedLocked {
		t.Fatalf("expected fail-closed StateBlockedLocked on netfilter error, got %s", st)
	}
	if lastOpen {
		t.Fatalf("expected lastOpen=false on netfilter error")
	}
	if !lastRaw {
		t.Fatalf("expected lastRawArmed=true when EXT_PROXY_OUTPUT present during netfilter error fallback")
	}
	if curEx == nil || curEx.State != "blocked" {
		t.Fatalf("expected currentExemption.State == blocked after netfilter error fallback, got %+v", curEx)
	}
	exBytes, err := os.ReadFile(d.exemptionPath)
	if err != nil {
		t.Fatalf("read exemption.v1.json: %v", err)
	}
	var diskEx contracts.ExemptionV1
	if err := json.Unmarshal(exBytes, &diskEx); err != nil {
		t.Fatalf("unmarshal exemption.v1.json: %v", err)
	}
	if diskEx.State != "blocked" {
		t.Fatalf("expected exemption.v1.json on disk State == blocked after netfilter error, got %q", diskEx.State)
	}
}

func TestV251NoWorldReadableDevStealthJsonWrittenOrLeftBehind(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "stealth.json")
	rtPath := filepath.Join(dir, "dev_cfg", "stealth.json")
	disabledFlag := filepath.Join(dir, "zygisk_disabled")

	if err := os.MkdirAll(filepath.Dir(rtPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rtPath, []byte(`{"stale":true}`), 0644); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		stealthConfigPath:  cfgPath,
		stealthRuntimePath: rtPath,
		zygiskDisabledFlag: disabledFlag,
	}
	if _, err := d.SyncStealthConfig(testPolicy(), 1010376); err != nil {
		t.Fatalf("SyncStealthConfig failed: %v", err)
	}
	if _, err := os.Stat(rtPath); !os.IsNotExist(err) {
		t.Fatalf("SyncStealthConfig must remove runtime stealth.json, got err=%v", err)
	}

	if err := os.WriteFile(rtPath, []byte(`{"stale":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ToggleStealth(false); err != nil {
		t.Fatalf("ToggleStealth(false) failed: %v", err)
	}
	if _, err := os.Stat(rtPath); !os.IsNotExist(err) {
		t.Fatalf("ToggleStealth(false) must remove runtime stealth.json, got err=%v", err)
	}

	if err := os.WriteFile(rtPath, []byte(`{"stale":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ToggleStealth(true); err != nil {
		t.Fatalf("ToggleStealth(true) failed: %v", err)
	}
	if _, err := os.Stat(rtPath); !os.IsNotExist(err) {
		t.Fatalf("ToggleStealth(true) must remove runtime stealth.json, got err=%v", err)
	}
}

func TestV251HotEscalateTimerRefreshAndPerfStatusReadOnly(t *testing.T) {
	dir := t.TempDir()
	cgRoot := filepath.Join(dir, "cgroup")
	uidDir := filepath.Join(cgRoot, "uid_1010395")
	if err := os.MkdirAll(uidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uidDir, "cgroup.freeze"), []byte("0"), 0644); err != nil {
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

	runner := &v240FlexRunner{
		out: map[string]string{
			"cmd user list -v":                       "0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running)\n1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running)\n",
			"dumpsys user --user 10":                 "  UserInfo{10:Work:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
			"cmd device_policy list-owners":          "User 10: admin=" + contracts.DefaultAdminComponent + ",ManagedProfileOwner(parentUserId=0)\n",
			"cmd package list packages -3 --user 10": "package:" + pkg + "\npackage:com.google.android.apps.bard\n",
			"ime list -s --user 10":                  "",
			"dumpsys activity users":                 "    User #10: state=RUNNING_UNLOCKED\n",
		},
	}

	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	perfPath := filepath.Join(dir, "perf.json")
	if err := WritePerfConfig(perfPath, PerfConfig{PauseMode: PauseModeHot, HotFreezeMinutes: 15}); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: &tproxyMockIPTables{base: newStatefulMockIPTables(false)}, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-v251",
		policy:             pol,
		policyLoaded:       true,
		state:              StateOpen,
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
		lastPolicySyncHash: "keep-hash-intact",
		reconcileCh:        make(chan reconcileReq, 8),
		timerRefreshCh:     make(chan struct{}, 1),
		probeTProxyReady:   func(port int) bool { return port == contracts.DefaultTProxyPort },
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startMockReconcilePump(ctx, d)

	// Drain any prior signal.
	select {
	case <-d.timerRefreshCh:
	default:
	}

	if _, err := d.HandleCtl(ctx, "pause-hot", nil); err != nil {
		t.Fatalf("pause-hot failed: %v", err)
	}
	select {
	case <-d.timerRefreshCh:
	default:
		t.Fatal("expected pause-hot / pauseSandboxLifecycleLocked to signal timerRefreshCh so hotEscalateTimer arms cleanly")
	}

	if _, err := d.HandleCtl(ctx, "perf-status", nil); err != nil {
		t.Fatalf("perf-status failed: %v", err)
	}
	d.mu.Lock()
	syncHash := d.lastPolicySyncHash
	d.mu.Unlock()
	if syncHash != "keep-hash-intact" {
		t.Fatalf("HandleCtl(perf-status) must remain read-only without clearing lastPolicySyncHash, got %q", syncHash)
	}
}

func TestV251StartTProxyWaitsThroughStateAckWaitWhenExtProxyActive(t *testing.T) {
	dir := t.TempDir()
	nfMock := &tproxyMockIPTables{base: newStatefulMockIPTables(true)}
	pkg := contracts.DefaultWorkPackage
	runner := &v240FlexRunner{
		out: map[string]string{
			"cmd user list -v":                       "0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running)\n1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running)\n",
			"dumpsys user --user 10":                 "  UserInfo{10:Work:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
			"cmd device_policy list-owners":          "User 10: admin=" + contracts.DefaultAdminComponent + ",ManagedProfileOwner(parentUserId=0)\n",
			"cmd package list packages --user 10 -U " + pkg: "package:" + pkg + " uid:1010376\n",
			"cmd package list packages -3 --user 10": "package:" + pkg + "\n",
			"ime list -s --user 10":                  "",
			"dumpsys activity users":                 "    User #10: state=RUNNING_UNLOCKED\n",
		},
	}

	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark
	pol.ProxySkipPrefix = "EXT_PROXY_"

	ackPath := filepath.Join(dir, "sandbox_ack.v1.json")
	exPath := filepath.Join(dir, "exemption.v1.json")

	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: nfMock, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-v251",
		policy:             pol,
		policyLoaded:       true,
		state:              StateBlockedLocked,
		paused:             false,
		userUnlockedBoot:   true,
		workCfgDir:         dir,
		desiredStatePath:   filepath.Join(dir, "desired_state.json"),
		exemptionPath:      exPath,
		sandboxAckPath:     ackPath,
		upgradeFencePath:   filepath.Join(dir, "upgrade_fence.json"),
		stealthConfigPath:  filepath.Join(dir, "stealth.json"),
		stealthRuntimePath: filepath.Join(dir, "rt_stealth.json"),
		zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
		perfConfigPath:     filepath.Join(dir, "perf.json"),
		prunedPkgsPath:     filepath.Join(dir, "pruned_pkgs.json"),
		hibernatedPkgsPath: filepath.Join(dir, "hibernated_pkgs.json"),
		cgroupRoot:         filepath.Join(dir, "cgroup"),
		reconcileCh:        make(chan reconcileReq, 8),
		timerRefreshCh:     make(chan struct{}, 1),
		probeTProxyReady:   func(port int) bool { return port == contracts.DefaultTProxyPort },
		userWakeTimeout:    500 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startMockReconcilePump(ctx, d)

	// Simulate external proxy core rewriting EXT_PROXY_OUTPUT & writing sandbox_ack.v1.json 90ms later (> dumpsys ~30ms!).
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			d.mu.Lock()
			gen := d.lastGen
			st := d.state
			d.mu.Unlock()
			if st == StateAckWait && gen > 0 {
				time.Sleep(90 * time.Millisecond)
				ack := contracts.SandboxAckV1{
					ContractVersion:   contracts.ContractVersion,
					AppliedGeneration: gen,
					BootID:            "boot-v251",
					CorePID:           5555,
				}
				b, _ := json.Marshal(ack)
				_ = os.WriteFile(ackPath, b, 0600)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	if _, _, _, err := d.startTProxySandboxWithPriorityTraced(ctx, pol, ""); err != nil {
		t.Fatalf("startTProxySandboxWithPriorityTraced failed during StateAckWait: %v", err)
	}
	d.waitMaintenance()
	d.mu.Lock()
	finalState := d.state
	d.mu.Unlock()
	if finalState != StateOpen {
		t.Fatalf("expected StateOpen after StateAckWait resolved, got %s", finalState)
	}
}

func TestV251DesiredStateSerializationNoDivergence(t *testing.T) {
	dir := t.TempDir()
	dsPath := filepath.Join(dir, "desired_state.json")
	d := &Daemon{
		bootID:           "boot-v251",
		policy:           testPolicy(),
		policyLoaded:     true,
		state:            StateOpen,
		paused:           false,
		desiredStatePath: dsPath,
		reconcileCh:      make(chan reconcileReq, 4),
	}

	const iterations = 60
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			d.mu.Lock()
			d.state = StateOpen
			ws := d.wakeSeq
			d.mu.Unlock()
			_ = d.tryAutoPauseDesiredState(ws)
			if i%3 == 0 {
				_, _, _ = d.setDesiredPaused(true, false, false)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if _, _, err := d.setDesiredPaused(false, true, false); err != nil {
				t.Errorf("setDesiredPaused(false) failed: %v", err)
			}
			if i%5 == 0 {
				if _, _, err := d.setDesiredPaused(true, false, false); err != nil {
					t.Errorf("setDesiredPaused(true) failed: %v", err)
				}
			}
		}
	}()
	wg.Wait()

	raw, err := os.ReadFile(dsPath)
	if err != nil {
		t.Fatalf("read desired_state.json: %v", err)
	}
	var ds contracts.DesiredState
	if err := json.Unmarshal(raw, &ds); err != nil {
		t.Fatalf("unmarshal desired_state.json: %v", err)
	}
	if ds.Paused != d.isPaused() {
		t.Fatalf("disk desired_state.json paused=%v diverged from d.isPaused()=%v", ds.Paused, d.isPaused())
	}

	// Verify final sequential transitions leave disk and memory in sync.
	if _, _, err := d.setDesiredPaused(true, false, false); err != nil {
		t.Fatalf("final pause failed: %v", err)
	}
	raw, _ = os.ReadFile(dsPath)
	_ = json.Unmarshal(raw, &ds)
	if !ds.Paused || !d.isPaused() {
		t.Fatalf("expected paused=true on both disk (%v) and memory (%v)", ds.Paused, d.isPaused())
	}
	if _, _, err := d.setDesiredPaused(false, true, false); err != nil {
		t.Fatalf("final resume failed: %v", err)
	}
	raw, _ = os.ReadFile(dsPath)
	_ = json.Unmarshal(raw, &ds)
	if ds.Paused || d.isPaused() {
		t.Fatalf("expected paused=false on both disk (%v) and memory (%v)", ds.Paused, d.isPaused())
	}
}
