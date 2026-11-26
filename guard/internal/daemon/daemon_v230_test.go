package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
)

type flexMockRunner struct {
	mu    sync.Mutex
	calls []string
	out   map[string]string
	onRun func(cmdLine string)
}

func (m *flexMockRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, line)
	if m.onRun != nil {
		m.onRun(line)
	}
	if m.out != nil {
		if v, ok := m.out[line]; ok {
			return v, nil
		}
	}
	return "", nil
}

func startMockReconcilePump(ctx context.Context, d *Daemon) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-d.reconcileCh:
				err := d.reconcileOnce(ctx, req)
				if req.reply != nil {
					req.reply <- err
				}
			}
		}
	}()
}

func TestSyncAndToggleStealthConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "stealth.json")
	rtPath := filepath.Join(dir, "rt_stealth.json")
	disFlag := filepath.Join(dir, "zygisk_disabled")

	// Seed custom override to verify preservation.
	custom := `{"enabled":true,"sandbox_user_id":10,"exempt_work_uid":0,"timezone":"Asia/Tokyo","locale":"ja-JP","sim_operator":"44020","sim_operator_name":"SoftBank","sim_country_iso":"jp"}`
	if err := os.WriteFile(cfgPath, []byte(custom), 0600); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		stealthConfigPath:  cfgPath,
		stealthRuntimePath: rtPath,
		zygiskDisabledFlag: disFlag,
		policy:             contracts.Policy{UserID: 10, Serial: 1000},
		policyLoaded:       true,
	}

	cfg, err := d.SyncStealthConfig(d.policy, 1010376)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SimOperator != "44020" || cfg.SimOperatorName != "SoftBank" || cfg.ExemptWorkUID != 1010376 || !cfg.Enabled {
		t.Fatalf("unexpected merged stealth cfg: %+v", cfg)
	}
	if _, err := os.Stat(rtPath); !os.IsNotExist(err) {
		t.Fatalf("expected runtime stealth mirror %s NOT to exist (prevent self-exposure), got err=%v", rtPath, err)
	}

	// Toggle off -> creates zygisk_disabled & sets enabled=false.
	offCfg, err := d.ToggleStealth(false)
	if err != nil {
		t.Fatal(err)
	}
	if offCfg.Enabled {
		t.Fatal("expected enabled=false after ToggleStealth(false)")
	}
	if _, err := os.Stat(disFlag); err != nil {
		t.Fatalf("expected disabled flag created: %v", err)
	}
	stOff := d.ReadStealthStatus()
	if stOff["active_on_boot"] != false || stOff["zygisk_disabled"] != true {
		t.Fatalf("unexpected stealth status off: %+v", stOff)
	}

	// Toggle on -> deletes flag & re-enables.
	onCfg, err := d.ToggleStealth(true)
	if err != nil {
		t.Fatal(err)
	}
	if !onCfg.Enabled {
		t.Fatal("expected enabled=true after ToggleStealth(true)")
	}
	if _, err := os.Stat(disFlag); !os.IsNotExist(err) {
		t.Fatalf("expected disabled flag removed, got err=%v", err)
	}
}

func TestTProxyStartAutoStartsProxyAndPauseStopsApps(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "proxy.sh")
	if err := os.WriteFile(script, []byte("#!/system/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}

	tproxyUp := false
	nfMock := newStatefulMockIPTables(false)
	pkg := contracts.DefaultWorkPackage
	runner := &flexMockRunner{
		out: map[string]string{
			"cmd user list -v":                       "0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running) (current)\n1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running) (profile-owner)\n",
			"dumpsys user --user 10":                 "  UserInfo{10:Work:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
			"dumpsys activity users":                 "    User #0: state=RUNNING_UNLOCKED\n    User #10: state=RUNNING_UNLOCKED\n",
			"cmd device_policy list-owners":          "User 10: admin=" + contracts.DefaultAdminComponent + ",ManagedProfileOwner(parentUserId=0)\n",
			"cmd package list packages --user 10 -U " + pkg: "package:" + pkg + " uid:1010376\n",
			"cmd package list packages -3 --user 10": "package:" + pkg + "\npackage:com.google.android.apps.bard\n",
			"settings get global private_dns_mode":   "off\n",
		},
		onRun: func(cmdLine string) {
			if cmdLine == "sh "+script+" start" {
				tproxyUp = true
			}
		},
	}

	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: nfMock, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-v230",
		policy:             pol,
		policyLoaded:       true,
		state:              StateBlockedLocked,
		paused:             true,
		workCfgDir:         dir,
		desiredStatePath:   filepath.Join(dir, "desired_state.json"),
		exemptionPath:      filepath.Join(dir, "exemption.v1.json"),
		sandboxAckPath:     filepath.Join(dir, "sandbox_ack.v1.json"),
		upgradeFencePath:   filepath.Join(dir, "upgrade_fence.json"),
		stealthConfigPath:  filepath.Join(dir, "stealth.json"),
		stealthRuntimePath: filepath.Join(dir, "rt_stealth.json"),
		zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
		proxyCtlScript:     script,
		reconcileCh:        make(chan reconcileReq, 8),
		probeTProxyReady:   func(port int) bool { return tproxyUp && port == contracts.DefaultTProxyPort },
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startMockReconcilePump(ctx, d)

	// Starting sandbox when proxy core is stopped must invoke `sh <script> start`.
	respStart := d.HandleRPC(ctx, contracts.RPCRequest{ID: "s1", Op: contracts.OpStartVPN})
	if !respStart.OK {
		t.Fatalf("START_VPN failed: %+v", respStart)
	}
	if !tproxyUp {
		t.Fatal("expected TProxy proxy auto-start script to run")
	}

	// Pausing sandbox must close gate and stop User 10 background apps excluding work package.
	runner.mu.Lock()
	runner.calls = nil
	runner.mu.Unlock()
	respPause := d.HandleRPC(ctx, contracts.RPCRequest{ID: "p1", Op: contracts.OpPauseVPN})
	if !respPause.OK {
		t.Fatalf("PAUSE_VPN failed: %+v", respPause)
	}
	if d.state != StateBlockedLocked || !d.paused {
		t.Fatalf("expected BlockedLocked paused=true, got state=%s paused=%v", d.state, d.paused)
	}
	runner.mu.Lock()
	joined := strings.Join(runner.calls, "\n")
	runner.mu.Unlock()
	if !strings.Contains(joined, "am stop-app --user 10 com.google.android.apps.bard") {
		t.Fatalf("expected pause to stop User 10 bard app, calls:\n%s", joined)
	}
	if strings.Contains(joined, "am stop-app --user 10 "+pkg) || strings.Contains(joined, "am force-stop --user 10 "+pkg) {
		t.Fatalf("must not stop/force-stop bridge package:\n%s", joined)
	}
}

func TestOpInstallApkRPCAndPolicySync(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "demo.apk")
	if err := os.WriteFile(apk, []byte("PK\x03\x04test-apk"), 0600); err != nil {
		t.Fatal(err)
	}

	runner := &flexMockRunner{
		out: map[string]string{
			"pm install-create --user 10 -r":     "Success: created install session [987]\n",
			"pm install-commit 987":                 "Success\n",
			"cmd package list packages -3 --user 10": "package:" + contracts.DefaultWorkPackage + "\npackage:com.demo.app\n",
			"cmd package query-activities --user 10 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER": "",
			"settings --user 0 get secure miui_home_hide_app_list":                                                      "[]",
		},
	}

	d := &Daemon{
		runner:             runner,
		policy:             testPolicy(),
		policyLoaded:       true,
		stealthConfigPath:  filepath.Join(dir, "stealth.json"),
		stealthRuntimePath: filepath.Join(dir, "rt_stealth.json"),
		zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
		apkStagingDirs:     []string{dir},
	}

	resp := d.HandleRPC(context.Background(), contracts.RPCRequest{
		ID:       "inst-1",
		Op:       contracts.OpInstallApk,
		ApkPaths: []string{apk},
	})
	if !resp.OK {
		t.Fatalf("OpInstallApk failed: %+v", resp)
	}
	b, _ := json.Marshal(resp)
	s := string(b)
	if !strings.Contains(s, `"session_id":"987"`) || !strings.Contains(s, `"hide_synced":true`) {
		t.Fatalf("unexpected INSTALL_APK response: %s", s)
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "cmd locale set-app-locales com.demo.app --user 10 --locales en-US") {
		t.Fatalf("expected auto locale sync for newly installed app:\n%s", joined)
	}
}
