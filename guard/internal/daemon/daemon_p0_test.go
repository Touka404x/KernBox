package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/contracts"
)

type permissiveAppopsRunner struct {
	mu    sync.Mutex
	calls []string
}

func (p *permissiveAppopsRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	p.mu.Lock()
	p.calls = append(p.calls, line)
	p.mu.Unlock()
	if line == "cmd package list packages -3 --user 10" {
		return "package:com.demo.app\n", nil
	}
	return "", nil
}

func TestCustomProxyPathsResolutionOnEmptyDaemonFields(t *testing.T) {
	dir := t.TempDir()
	customDir := filepath.Join(dir, "singbox")
	pol := contracts.Policy{
		ProxyBaseDir: customDir,
	}
	d := &Daemon{bootID: "boot-custom-1"}
	if got := d.resolvedMainConfigPath(pol); got != customDir+"/config.json" {
		t.Fatalf("expected custom config path, got %s", got)
	}
	if got := pol.EffectiveProxyAckPath(); got != customDir+"/sandbox_ack.v1.json" {
		t.Fatalf("expected custom ack path, got %s", got)
	}
	if got := pol.EffectiveProxyCtlScript(); got != customDir+"/proxy.sh" {
		t.Fatalf("expected custom proxy.sh path, got %s", got)
	}
}

func TestHandleCtlReloadPolicyPropagatesMissingPolicyError(t *testing.T) {
	d := &Daemon{
		reconcileCh: make(chan reconcileReq, 1),
	}
	// Unless a live /data/adb/sandbox_guard/policy.json exists on this host, ReadPolicy must error rather than return "reloaded".
	if _, statErr := os.Stat(contracts.PolicyPath); statErr != nil {
		if _, err := d.HandleCtl(context.Background(), "reload-policy", nil); err == nil {
			t.Fatal("expected HandleCtl reload-policy to fail when policy.json is missing")
		}
	}
}

func TestPrewarmSandboxAppCodePathInvokesCmdPackagePath(t *testing.T) {
	runner := &mockCmdRunner{
		out: map[string]string{
			"cmd package path --user 10 com.example.sandbox": "package:/nonexistent/data/app/~~abc/com.example.sandbox-xyz/base.apk\n",
		},
	}
	android.PrewarmSandboxAppCodePath(context.Background(), runner, 10, "com.example.sandbox")
	if len(runner.calls) != 1 || runner.calls[0] != "cmd package path --user 10 com.example.sandbox" {
		t.Fatalf("unexpected cmd package path calls: %v", runner.calls)
	}
}

func TestApplyPresetFileRejectsUnknownFieldsAndSyncPoliciesHonorsSpoofLocale(t *testing.T) {
	dir := t.TempDir()
	unknownPreset := filepath.Join(dir, "typo.json")
	if err := os.WriteFile(unknownPreset, []byte(`{"name":"typo","unknown_field":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		stealthConfigPath:  filepath.Join(dir, "stealth.json"),
		stealthRuntimePath: filepath.Join(dir, "runtime_stealth.json"),
		zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
	}
	if _, err := d.ApplyPresetFile(context.Background(), unknownPreset); err == nil {
		t.Fatal("expected ApplyPresetFile to reject unknown JSON field")
	}

	if err := os.WriteFile(d.stealthConfigPath, []byte(`{"enabled":true,"sandbox_user_id":10,"spoof_locale":false,"spoof_bluetooth":false,"locale":"en-US"}`), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &permissiveAppopsRunner{}
	d.runner = runner
	if _, err := d.syncPolicies(context.Background(), testPolicy()); err != nil {
		t.Fatalf("syncPolicies failed: %v", err)
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "cmd locale ") {
			t.Fatalf("syncPolicies must skip cmd locale when spoof_locale=false, got: %v", runner.calls)
		}
	}
}

func TestCustomExemptionLockAndAckCustomPIDKey(t *testing.T) {
	pol := contracts.Policy{
		ProxyExemptionPath:     "/data/adb/custom_guard/exemption.v1.json",
		ProxyNetfilterLockPath: "/data/adb/.custom_netfilter.lock",
	}
	if got := pol.EffectiveExemptionPath(); got != "/data/adb/custom_guard/exemption.v1.json" {
		t.Fatalf("EffectiveExemptionPath=%q", got)
	}
	if got := pol.EffectiveNetfilterLockPath(); got != "/data/adb/.custom_netfilter.lock" {
		t.Fatalf("EffectiveNetfilterLockPath=%q", got)
	}
	d := &Daemon{}
	if got := d.resolvedExemptionPath(pol); got != "/data/adb/custom_guard/exemption.v1.json" {
		t.Fatalf("resolvedExemptionPath=%q", got)
	}

	ack, err := ParseSandboxAck([]byte(`{"contract_version":1,"applied_generation":42,"boot_id":"boot-1","proxy_pid":9876}`), "boot-1")
	if err != nil {
		t.Fatalf("expected custom *_pid ack accepted, got err=%v", err)
	}
	if ack.WriterPID() != 9876 || ack.AppliedGeneration != 42 {
		t.Fatalf("unexpected ack parsed: %+v", ack)
	}
	if _, err := ParseSandboxAck([]byte(`{"contract_version":1,"applied_generation":42,"boot_id":"boot-1","core_pid":10,"bogus":"x"}`), "boot-1"); err == nil {
		t.Fatal("expected unknown non-*_pid key rejected")
	}
}

type adminExcludeRunner struct {
	mu    sync.Mutex
	calls []string
}

func (a *adminExcludeRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	a.mu.Lock()
	a.calls = append(a.calls, line)
	a.mu.Unlock()
	if line == "cmd package list packages -3 --user 10" {
		return "package:com.android.chrome\npackage:com.legacy.dpc\npackage:com.sandbox.controller\npackage:com.sandbox.verify\n", nil
	}
	return "", nil
}

func TestAdminPackageExcludedFromSandboxAppsAndProtectedFromStopRemove(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy()
	pol.AdminComponent = "com.legacy.dpc/.AdminReceiver"
	if got := pol.EffectiveAdminPackage(); got != "com.legacy.dpc" {
		t.Fatalf("EffectiveAdminPackage=%q, want com.legacy.dpc", got)
	}
	runner := &adminExcludeRunner{}
	d := &Daemon{
		bootID:            "boot-admin-1",
		policy:            pol,
		policyLoaded:      true,
		runner:            runner,
		hibernatedPkgsPath:   filepath.Join(dir, "hibernated.json"),
		perfConfigPath:    filepath.Join(dir, "perf.json"),
		stealthConfigPath: filepath.Join(dir, "stealth.json"),
		zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
		stealthBootTriesPath: filepath.Join(dir, "stealth_boot_tries"),
	}
	data := d.buildStatusData(context.Background())
	apps, ok := data["sandbox_apps"].([]string)
	if !ok {
		t.Fatalf("unexpected sandbox_apps type: %T", data["sandbox_apps"])
	}
	if len(apps) != 1 || apps[0] != "com.android.chrome" {
		t.Fatalf("expected [com.android.chrome], got %v", apps)
	}

	stopResp := d.HandleRPC(context.Background(), contracts.RPCRequest{ID: "stop-1", Op: contracts.OpStopApp, Pkg: "com.legacy.dpc"})
	if stopResp.OK || !strings.Contains(stopResp.Error, "profile owner") {
		t.Fatalf("expected OpStopApp to refuse profile owner package, got %+v", stopResp)
	}
	remResp := d.HandleRPC(context.Background(), contracts.RPCRequest{ID: "rem-1", Op: contracts.OpRemoveApp, Pkg: "com.legacy.dpc"})
	if remResp.OK || !strings.Contains(remResp.Error, "profile owner") {
		t.Fatalf("expected OpRemoveApp to refuse profile owner package, got %+v", remResp)
	}
}

func TestPolicyGuardChainValidation(t *testing.T) {
	p := testPolicy()
	p.GuardChainOut = "LGC_PRIVACY"
	p.GuardChainPost = "LGC_EGRESS"
	if err := p.NormalizeAndValidate(); err != nil {
		t.Fatalf("expected valid guard chains accepted, got %v", err)
	}
	p.GuardChainOut = "bad chain"
	if err := p.NormalizeAndValidate(); err == nil {
		t.Fatal("expected invalid guard_chain_out rejected")
	}
	p = testPolicy()
	p.GuardChainPost = "lowercase_bad"
	if err := p.NormalizeAndValidate(); err == nil {
		t.Fatal("expected invalid guard_chain_post rejected")
	}
}

type playStoreStatusRunner struct {
	enabled bool
}

func (r *playStoreStatusRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	if line == "cmd package list packages -3 --user 10" {
		return "package:com.android.chrome\npackage:com.sandbox.controller\n", nil
	}
	if line == "cmd package list packages -e --user 10 com.android.vending" {
		if r.enabled {
			return "package:com.android.vending\n", nil
		}
		return "", nil
	}
	return "", nil
}

func TestBuildStatusDataPrependsEnabledPlayStore(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy()
	d := &Daemon{
		bootID:               "boot-play-1",
		policy:               pol,
		policyLoaded:         true,
		runner:               &playStoreStatusRunner{enabled: true},
		hibernatedPkgsPath:   filepath.Join(dir, "hibernated.json"),
		perfConfigPath:       filepath.Join(dir, "perf.json"),
		stealthConfigPath:    filepath.Join(dir, "stealth.json"),
		zygiskDisabledFlag:   filepath.Join(dir, "zygisk_disabled"),
		stealthBootTriesPath: filepath.Join(dir, "stealth_boot_tries"),
	}
	apps := d.buildStatusData(context.Background())["sandbox_apps"].([]string)
	if len(apps) != 2 || apps[0] != "com.android.vending" || apps[1] != "com.android.chrome" {
		t.Fatalf("expected Play Store prepended, got %v", apps)
	}

	d.runner = &playStoreStatusRunner{enabled: false}
	d.invalidateStatusCaches()
	appsNoPlay := d.buildStatusData(context.Background())["sandbox_apps"].([]string)
	if len(appsNoPlay) != 1 || appsNoPlay[0] != "com.android.chrome" {
		t.Fatalf("expected Play Store omitted when disabled, got %v", appsNoPlay)
	}
}
