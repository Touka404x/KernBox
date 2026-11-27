package android

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type trickyMockRunner struct {
	out   string
	err   error
	calls int
}

func (m *trickyMockRunner) Run(_ context.Context, _ time.Duration, _ string, _ string, _ ...string) (string, error) {
	m.calls++
	return m.out, m.err
}

func TestSyncTrickyStoreTargetsNoopWhenAbsent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	runner := &trickyMockRunner{out: "2023-10-01\n"}
	res, err := SyncTrickyStoreTargets(context.Background(), runner, missing, []string{"com.android.chrome"}, "com.sandbox.controller")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Active || res.Updated || res.PatchSeeded {
		t.Fatalf("expected inactive no-op result, got %+v", res)
	}
	if runner.calls != 0 {
		t.Fatalf("expected 0 runner calls when tricky_store absent, got %d", runner.calls)
	}
}

func TestSyncTrickyStoreTargetsLifecycleAndPreservation(t *testing.T) {
	tsDir := filepath.Join(t.TempDir(), "tricky_store")
	modDir := filepath.Join(t.TempDir(), "modules", "tricky_store")
	if err := os.MkdirAll(tsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(modDir, 0755); err != nil {
		t.Fatal(err)
	}

	runner := &trickyMockRunner{out: "2023-10-01\n"}
	ctx := context.Background()

	// 1. Initial sync seeds target.txt + security_patch.txt (YYYYMMDD), excludes callerPkg.
	res1, err := SyncTrickyStoreTargets(ctx, runner, tsDir, []string{
		"com.sandbox.controller",
		"com.android.chrome",
		"com.sandbox.verify",
		"bad pkg name",
	}, "com.sandbox.controller")
	if err != nil {
		t.Fatalf("initial sync failed: %v", err)
	}
	if !res1.Active || !res1.Updated || !res1.PatchSeeded {
		t.Fatalf("unexpected res1=%+v", res1)
	}
	rawTarget, err := os.ReadFile(filepath.Join(tsDir, "target.txt"))
	if err != nil {
		t.Fatal(err)
	}
	targetStr := string(rawTarget)
	if !strings.Contains(targetStr, "com.android.chrome\n") ||
		!strings.Contains(targetStr, "com.sandbox.verify\n") ||
		!strings.Contains(targetStr, "com.google.android.gms\n") ||
		!strings.Contains(targetStr, "com.android.vending\n") {
		t.Fatalf("missing expected managed packages in target.txt:\n%s", targetStr)
	}
	if strings.Contains(targetStr, "com.sandbox.controller") {
		t.Fatalf("caller package must never be written to target.txt:\n%s", targetStr)
	}
	rawPatch, err := os.ReadFile(filepath.Join(tsDir, "security_patch.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(rawPatch) != "20231001\n" {
		t.Fatalf("security_patch.txt = %q, want 20231001\\n", string(rawPatch))
	}

	// 2. Idempotent second run does not rewrite target.txt or call getprop again.
	callsBefore := runner.calls
	res2, err := SyncTrickyStoreTargets(ctx, runner, tsDir, []string{
		"com.android.chrome",
		"com.sandbox.verify",
	}, "com.sandbox.controller")
	if err != nil {
		t.Fatalf("second sync failed: %v", err)
	}
	if res2.Updated || res2.PatchSeeded || runner.calls != callsBefore {
		t.Fatalf("expected zero-write idempotency, got res2=%+v calls=%d/%d", res2, runner.calls, callsBefore)
	}

	// 3. Preserve user custom lines & !/? modifiers while pruning removed packages; keep custom security_patch.txt.
	customTarget := "# user rules\ncom.google.android.gms!\nio.custom.app?\n" + targetStr
	if err := os.WriteFile(filepath.Join(tsDir, "target.txt"), []byte(customTarget), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tsDir, "security_patch.txt"), []byte("20250101\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res3, err := SyncTrickyStoreTargets(ctx, runner, tsDir, []string{"com.android.chrome"}, "com.sandbox.controller")
	if err != nil {
		t.Fatalf("third sync failed: %v", err)
	}
	if !res3.Updated || res3.PatchSeeded {
		t.Fatalf("unexpected res3=%+v", res3)
	}
	afterRaw, err := os.ReadFile(filepath.Join(tsDir, "target.txt"))
	if err != nil {
		t.Fatal(err)
	}
	afterStr := string(afterRaw)
	if !strings.Contains(afterStr, "# user rules\n") ||
		!strings.Contains(afterStr, "com.google.android.gms!\n") ||
		!strings.Contains(afterStr, "io.custom.app?\n") {
		t.Fatalf("user lines lost:\n%s", afterStr)
	}
	if strings.Contains(afterStr, "com.sandbox.verify") {
		t.Fatalf("removed package still present:\n%s", afterStr)
	}
	if strings.Count(afterStr, "com.google.android.gms") != 1 {
		t.Fatalf("user explicit com.google.android.gms! must suppress duplicate bare entry:\n%s", afterStr)
	}
	if pAfter, _ := os.ReadFile(filepath.Join(tsDir, "security_patch.txt")); string(pAfter) != "20250101\n" {
		t.Fatalf("custom security_patch.txt was overwritten: %q", string(pAfter))
	}

	// 4. ProbeTrickyStoreStatus detects disable flag & keybox.xml cleanly.
	st1 := ProbeTrickyStoreStatus(tsDir, modDir)
	if !st1.Installed || !st1.Active || st1.KeyboxPresent {
		t.Fatalf("unexpected status st1=%+v", st1)
	}
	if err := os.WriteFile(filepath.Join(tsDir, "keybox.xml"), []byte("<AndroidAttestation/>"), 0600); err != nil {
		t.Fatal(err)
	}
	st2 := ProbeTrickyStoreStatus(tsDir, modDir)
	if !st2.KeyboxPresent || !st2.Active {
		t.Fatalf("expected KeyboxPresent=true, got %+v", st2)
	}
	if err := os.WriteFile(filepath.Join(modDir, "disable"), []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	st3 := ProbeTrickyStoreStatus(tsDir, modDir)
	if st3.Active {
		t.Fatalf("expected Active=false when disable marker present, got %+v", st3)
	}
}
