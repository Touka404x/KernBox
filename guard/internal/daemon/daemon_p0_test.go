package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/contracts"
)

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
