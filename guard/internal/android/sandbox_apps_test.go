package android

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

type sandboxRecRunner struct {
	mu    sync.Mutex
	calls []string
	out   map[string]string
	err   map[string]error
}

func (r *sandboxRecRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	r.mu.Lock()
	r.calls = append(r.calls, line)
	r.mu.Unlock()
	if r.err != nil {
		if e, ok := r.err[line]; ok {
			return r.out[line], e
		}
	}
	if r.out != nil {
		if o, ok := r.out[line]; ok {
			return o, nil
		}
	}
	return "", nil
}

func TestStopSandboxAppsExcludesBridgePackage(t *testing.T) {
	r := &sandboxRecRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:" + contracts.DefaultWorkPackage + "\npackage:com.google.android.apps.bard\npackage:com.example.jp\n",
		},
	}
	stopped, err := StopSandboxApps(context.Background(), r, 10, contracts.DefaultWorkPackage)
	if err != nil {
		t.Fatal(err)
	}
	if stopped < 5 {
		t.Fatalf("expected >=5 stopped packages, got %d", stopped)
	}
	joined := strings.Join(r.calls, "\n")
	if strings.Contains(joined, "am force-stop --user 10 "+contracts.DefaultWorkPackage) {
		t.Fatalf("must exclude bridge package from force-stop, got:\n%s", joined)
	}
	if !strings.Contains(joined, "am force-stop --user 10 com.google.android.apps.bard") ||
		!strings.Contains(joined, "am force-stop --user 10 com.example.jp") ||
		!strings.Contains(joined, "am force-stop --user 10 com.android.vending") {
		t.Fatalf("expected force-stop for Google & user apps, got:\n%s", joined)
	}
}

func TestSyncSandboxAppPoliciesSetsLocaleAndAppOps(t *testing.T) {
	r := &sandboxRecRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:" + contracts.DefaultWorkPackage + "\npackage:com.custom.jp\npackage:com.android.chrome\n",
		},
	}
	res, err := SyncSandboxAppPoliciesWithOpts(context.Background(), r, 10, PolicySyncOptions{
		CallerPackage:       contracts.DefaultWorkPackage,
		DefaultLocale:       "ja-JP",
		BluetoothDeviceName: "Pixel-Test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.LocaleApps == 0 || res.LocationApps == 0 || len(res.Errors) != 0 {
		t.Fatalf("unexpected sync result: %+v", res)
	}
	joined := strings.Join(r.calls, "\n")
	if strings.Contains(joined, "sh -c") {
		t.Fatalf("must not invoke sh -c:\n%s", joined)
	}
	if !strings.Contains(joined, "cmd locale set-app-locales com.custom.jp --user 10 --locales ja-JP") ||
		!strings.Contains(joined, "cmd locale set-app-locales com.google.android.apps.bard --user 10 --locales ja-JP") ||
		!strings.Contains(joined, "cmd locale set-app-locales com.google.android.gms --user 10 --locales ja-JP") ||
		!strings.Contains(joined, "cmd role add-role-holder --user 10 android.app.role.BROWSER com.android.chrome") ||
		!strings.Contains(joined, "settings --user 10 put secure bluetooth_name Pixel-Test") ||
		!strings.Contains(joined, "appops set --user 10 --uid com.google.android.gms FINE_LOCATION ignore") {
		t.Fatalf("missing expected locale/role/bt/appops calls:\n%s", joined)
	}
	if extra := oem.Current().ExtraLocationDenyPackages; len(extra) > 0 {
		if !strings.Contains(joined, "appops set --user 10 --uid "+extra[0]+" COARSE_LOCATION ignore") {
			t.Fatalf("missing OEM extra location deny call for %s:\n%s", extra[0], joined)
		}
	}
	if strings.Contains(joined, "set-app-locales "+contracts.DefaultWorkPackage) {
		t.Fatalf("unexpected locale call on work bridge:\n%s", joined)
	}
}

func TestSyncSandboxAppPoliciesAndroid12MissingLocaleService(t *testing.T) {
	r := &sandboxRecRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.custom.app\n",
		},
		err: map[string]error{
			"cmd locale set-app-locales com.android.vending --user 10 --locales ja-JP": errors.New("Can't find service: locale"),
		},
	}
	res, err := SyncSandboxAppPoliciesWithOpts(context.Background(), r, 10, PolicySyncOptions{DefaultLocale: "ja-JP"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.LocaleUnsupported || res.LocationApps == 0 || len(res.Errors) != 0 {
		t.Fatalf("expected clean graceful skip on Android 12 without cmd locale, got %+v", res)
	}
}

func TestSyncSandboxAppPoliciesPreservesUserLocalesAndOverrides(t *testing.T) {
	r := &sandboxRecRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10":                          "package:com.google.android.apps.bard\npackage:com.demo.cleared\npackage:com.demo.new\n",
			"cmd locale get-app-locales com.google.android.apps.bard --user 10": "Locales for com.google.android.apps.bard for user 10 are [zh-CN]\n",
			"cmd locale get-app-locales com.demo.new --user 10":                 "Locales for com.demo.new for user 10 are []\n",
		},
	}

	res, err := SyncSandboxAppPoliciesWithOpts(context.Background(), r, 10, PolicySyncOptions{
		DefaultLocale:       "ja-JP",
		PreserveUserLocales: true,
		LocaleOverrides: map[string]string{
			"com.demo.cleared": "",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.LocalePreserved < 2 || res.LocaleApps < 1 {
		t.Fatalf("expected bard + cleared preserved and com.demo.new set, got %+v", res)
	}
	joined := strings.Join(r.calls, "\n")
	if strings.Contains(joined, "cmd locale set-app-locales com.google.android.apps.bard") {
		t.Fatalf("must NEVER overwrite non-empty zh-CN Gemini locale:\n%s", joined)
	}
	if strings.Contains(joined, "cmd locale set-app-locales com.demo.cleared") {
		t.Fatalf("explicit empty override must suppress set-app-locales:\n%s", joined)
	}
	if !strings.Contains(joined, "cmd locale set-app-locales com.demo.new --user 10 --locales ja-JP") {
		t.Fatalf("expected unset com.demo.new to receive ja-JP:\n%s", joined)
	}

	// Error on get-app-locales when PreserveUserLocales=true must fail safe (do NOT overwrite).
	rErr := &sandboxRecRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.google.android.apps.bard\n",
		},
		err: map[string]error{
			"cmd locale get-app-locales com.google.android.apps.bard --user 10": os.ErrDeadlineExceeded,
		},
	}
	resErr, _ := SyncSandboxAppPoliciesWithOpts(context.Background(), rErr, 10, PolicySyncOptions{
		DefaultLocale:       "ja-JP",
		PreserveUserLocales: true,
	})
	if strings.Contains(strings.Join(rErr.calls, "\n"), "cmd locale set-app-locales com.google.android.apps.bard") {
		t.Fatalf("must NOT overwrite Gemini locale when get-app-locales errors:\n%s", strings.Join(rErr.calls, "\n"))
	}
	if len(resErr.Errors) == 0 {
		t.Fatal("expected get-app-locales failure recorded in res.Errors")
	}

	if _, err := SyncSandboxAppPoliciesWithOpts(context.Background(), r, 10, PolicySyncOptions{DefaultLocale: "ja-JP;rm -rf /"}); err == nil {
		t.Fatal("must reject invalid locale tag containing shell chars")
	}
}

func TestSetSandboxAppLocaleValidation(t *testing.T) {
	r := &sandboxRecRunner{}
	if err := SetSandboxAppLocale(context.Background(), r, 10, "com.google.android.apps.bard", "zh-CN"); err != nil {
		t.Fatal(err)
	}
	if err := SetSandboxAppLocale(context.Background(), r, 10, "com.google.android.apps.bard", "clear"); err != nil {
		t.Fatal(err)
	}
	if err := SetSandboxAppLocale(context.Background(), r, 0, "com.google.android.apps.bard", "zh-CN"); err == nil {
		t.Fatal("must reject user 0")
	}
	for _, ex := range oem.Current().ExcludedCloneUsers {
		if err := SetSandboxAppLocale(context.Background(), r, ex, "com.google.android.apps.bard", "zh-CN"); err == nil {
			t.Fatalf("must reject excluded clone user %d", ex)
		}
	}
	if err := SetSandboxAppLocale(context.Background(), r, 10, "com.google.android.apps.bard", "bad;id"); err == nil {
		t.Fatal("must reject invalid locale")
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "cmd locale set-app-locales com.google.android.apps.bard --user 10 --locales zh-CN") ||
		!strings.Contains(joined, "cmd locale set-app-locales com.google.android.apps.bard --user 10 --locales ") {
		t.Fatalf("unexpected locale calls:\n%s", joined)
	}
}

func TestInstallSandboxAPKsStagesSplitAndCommits(t *testing.T) {
	dir := t.TempDir()
	baseApk := filepath.Join(dir, "base.apk")
	splitApk := filepath.Join(dir, "split.apk")
	if err := os.WriteFile(baseApk, []byte("APK-BASE-1234"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(splitApk, []byte("APK-SPLIT"), 0600); err != nil {
		t.Fatal(err)
	}

	r := &sandboxRecRunner{
		out: map[string]string{
			"pm install-create --user 10 -r": "Success: created install session [4242]\n",
			"pm install-commit 4242":         "Success\n",
		},
	}
	res, err := InstallSandboxAPKs(context.Background(), r, 10, []string{baseApk, splitApk}, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionID != "4242" || len(res.Files) != 2 {
		t.Fatalf("unexpected install result: %+v", res)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "pm install-write -S 13 4242 split_0.apk "+baseApk) ||
		!strings.Contains(joined, "pm install-write -S 9 4242 split_1.apk "+splitApk) ||
		!strings.Contains(joined, "pm install-commit 4242") {
		t.Fatalf("missing install steps:\n%s", joined)
	}

	// Reject paths outside allowed staging dir
	if _, err := InstallSandboxAPKs(context.Background(), r, 10, []string{filepath.Join(t.TempDir(), "other.apk")}, []string{dir}); err == nil {
		t.Fatal("accepted apk outside allowed staging directory")
	}
}

func TestListSandboxApps(t *testing.T) {
	r := &sandboxRecRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.zeta.app\npackage:com.sandbox.controller\npackage:com.alpha.app\npackage:com.sandbox.verify\npackage:com.zeta.app\n",
		},
	}
	apps, err := ListSandboxApps(context.Background(), r, 10, "com.sandbox.controller", "com.sandbox.verify")
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 || apps[0] != "com.alpha.app" || apps[1] != "com.zeta.app" {
		t.Fatalf("unexpected sandbox apps list: %v", apps)
	}
	if _, err := ListSandboxApps(context.Background(), r, 0, "com.sandbox.controller"); err == nil {
		t.Fatal("expected forbidden user 0 error")
	}
}

func TestStopAndRemoveSandboxApp(t *testing.T) {
	r := &sandboxRecRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.example.chat\npackage:com.google.android.gms\n",
			"pm uninstall --user 10 com.example.chat": "Success\n",
		},
	}
	if err := StopSandboxApp(context.Background(), r, 10, "com.example.chat", "com.sandbox.controller"); err != nil {
		t.Fatal(err)
	}
	if err := StopSandboxApp(context.Background(), r, 10, "com.sandbox.controller", "com.sandbox.controller"); err == nil {
		t.Fatal("expected controller stop rejection")
	}
	if err := StopSandboxApp(context.Background(), r, 0, "com.example.chat", "com.sandbox.controller"); err == nil {
		t.Fatal("expected forbidden user 0 error")
	}

	out, err := RemoveSandboxApp(context.Background(), r, 10, "com.example.chat", "com.sandbox.controller")
	if err != nil || out != "Success" {
		t.Fatalf("expected clean uninstall, got out=%q err=%v", out, err)
	}
	for _, prot := range []string{"com.sandbox.controller", "com.sandbox.verify", "com.google.android.gms", "com.android.vending"} {
		if _, err := RemoveSandboxApp(context.Background(), r, 10, prot, "com.sandbox.controller"); err == nil {
			t.Fatalf("expected protected package %s rejection", prot)
		}
	}
	if _, err := RemoveSandboxApp(context.Background(), r, 10, "com.not.installed", "com.sandbox.controller"); err == nil {
		t.Fatal("expected non-installed package rejection")
	}
}

type streamingMockRunner struct {
	mu          sync.Mutex
	calls       []string
	streamBytes [][]byte
	abandonErr  error
	failWrite   bool
}

func (s *streamingMockRunner) Run(ctx context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	s.mu.Lock()
	s.calls = append(s.calls, line)
	s.mu.Unlock()
	if name == "pm" && len(args) > 0 && args[0] == "install-create" {
		return "Success: created install session [8801]\n", nil
	}
	if name == "pm" && len(args) > 0 && args[0] == "install-abandon" {
		s.abandonErr = ctx.Err()
		return "Success\n", nil
	}
	return "Success\n", nil
}

func (s *streamingMockRunner) RunWithStdinReader(_ context.Context, _ time.Duration, stdin io.Reader, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	s.mu.Lock()
	s.calls = append(s.calls, line)
	s.mu.Unlock()
	if stdin != nil {
		data, _ := io.ReadAll(stdin)
		s.mu.Lock()
		s.streamBytes = append(s.streamBytes, data)
		s.mu.Unlock()
	}
	if s.failWrite {
		return "Failure", errors.New("write error")
	}
	return "Success\n", nil
}

func TestInstallSandboxAPKsStreamsViaStdinAndAbandonsOnCancelledCtx(t *testing.T) {
	dir := t.TempDir()
	baseApk := filepath.Join(dir, "base.apk")
	if err := os.WriteFile(baseApk, []byte("PK-STREAM-APK"), 0600); err != nil {
		t.Fatal(err)
	}

	rr := &streamingMockRunner{}
	res, err := InstallSandboxAPKs(context.Background(), rr, 10, []string{baseApk}, []string{dir})
	if err != nil {
		t.Fatalf("InstallSandboxAPKs streaming failed: %v", err)
	}
	if res.SessionID != "8801" || len(rr.streamBytes) != 1 || string(rr.streamBytes[0]) != "PK-STREAM-APK" {
		t.Fatalf("unexpected streamed install result: res=%+v bytes=%q", res, rr.streamBytes)
	}
	if !strings.Contains(strings.Join(rr.calls, "\n"), "pm install-write -S 13 8801 split_0.apk -") {
		t.Fatalf("expected '-' stdin install-write call, got: %v", rr.calls)
	}

	// Cancelled parent context must still abandon session with non-cancelled ctx.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	rrFail := &streamingMockRunner{failWrite: true}
	if _, err := InstallSandboxAPKs(cctx, rrFail, 10, []string{baseApk}, []string{dir}); err == nil {
		t.Fatal("expected write failure")
	}
	if rrFail.abandonErr != nil {
		t.Fatalf("expected abandon ctx non-cancelled, got %v", rrFail.abandonErr)
	}
}

func TestSyncSandboxAppPoliciesSkipLocaleWhenDisabled(t *testing.T) {
	r := &sandboxRecRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.custom.app\n",
		},
	}
	res, err := SyncSandboxAppPoliciesWithOpts(context.Background(), r, 10, PolicySyncOptions{
		DefaultLocale: "en-US",
		SkipLocale:    true,
	})
	if err != nil {
		t.Fatalf("SyncSandboxAppPoliciesWithOpts failed: %v", err)
	}
	if res.LocationApps == 0 {
		t.Fatalf("expected appops still enforced when SkipLocale=true, got %+v", res)
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "cmd locale ") {
		t.Fatalf("expected zero cmd locale invocations when SkipLocale=true, got %v", r.calls)
	}
}
