package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/contracts"
)

type permissiveAppopsRunner struct {
	calls []string
}

func (p *permissiveAppopsRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	p.calls = append(p.calls, line)
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
