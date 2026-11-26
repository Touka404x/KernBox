package android

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

func TestV252StopAppPreserveStoppedAndFallback(t *testing.T) {
	ctx := context.Background()

	// Normal Android 13+: uses `am stop-app` and NEVER calls `am force-stop`.
	normalRunner := &v250LifecycleMockRunner{
		onRun: func(cmd string) (string, bool, error) {
			return "", true, nil
		},
	}
	if err := stopPackagePreserveStopped(ctx, normalRunner, "10", "com.google.android.googlequicksearchbox"); err != nil {
		t.Fatalf("stopPackagePreserveStopped normal failed: %v", err)
	}
	calls := strings.Join(normalRunner.callsSnapshot(), "\n")
	if !strings.Contains(calls, "am stop-app --user 10 com.google.android.googlequicksearchbox") ||
		strings.Contains(calls, "force-stop") {
		t.Fatalf("expected am stop-app without force-stop, got:\n%s", calls)
	}

	// Older Android returning Unknown command: falls back to `am force-stop`.
	fallbackRunner := &v250LifecycleMockRunner{
		onRun: func(cmd string) (string, bool, error) {
			if strings.HasPrefix(cmd, "am stop-app ") {
				return "Unknown command: stop-app", true, errors.New("exit status 1")
			}
			return "", true, nil
		},
	}
	if err := stopPackagePreserveStopped(ctx, fallbackRunner, "10", "com.android.chrome"); err != nil {
		t.Fatalf("stopPackagePreserveStopped fallback failed: %v", err)
	}
	fbCalls := strings.Join(fallbackRunner.callsSnapshot(), "\n")
	if !strings.Contains(fbCalls, "am stop-app --user 10 com.android.chrome") ||
		!strings.Contains(fbCalls, "am force-stop --user 10 com.android.chrome") {
		t.Fatalf("expected fallback from stop-app to force-stop, got:\n%s", fbCalls)
	}

	// Transient failure (non-unsupported error): must NOT fall back to force-stop.
	errRunner := &v250LifecycleMockRunner{
		onRun: func(cmd string) (string, bool, error) {
			if strings.HasPrefix(cmd, "am stop-app ") {
				return "binder timeout", true, errors.New("timeout")
			}
			return "", true, nil
		},
	}
	if err := stopPackagePreserveStopped(ctx, errRunner, "10", "com.android.chrome"); err == nil {
		t.Fatal("expected error when stop-app fails transiently")
	}
	if strings.Contains(strings.Join(errRunner.callsSnapshot(), "\n"), "force-stop") {
		t.Fatal("must not call force-stop on transient stop-app error")
	}
}

func TestV252CompanionHostPriorityRestoreAndStoppedFallback(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	hibPath := filepath.Join(dir, "hibernated.json")

	if err := writeHibernatedState(hibPath, HibernatedState{
		UserID: 10,
		Packages: []string{
			"com.android.vending",
			"com.google.android.apps.bard",
			"com.google.android.googlequicksearchbox",
			"com.google.android.gms",
		},
		RestrictedAppOpsPkgs: []string{
			"com.google.android.apps.bard",
			"com.google.android.googlequicksearchbox",
			"com.google.android.gms",
			"com.android.vending",
		},
	}); err != nil {
		t.Fatal(err)
	}

	mock := &v250LifecycleMockRunner{}
	_, remaining, err := RestoreHibernatedPriorityEx(ctx, mock, 10, hibPath,
		[]string{"com.google.android.apps.bard"},
		LifecycleOptions{SyncTargetOnly: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(remaining, []string{"com.android.vending"}) {
		t.Fatalf("remaining = %v, want [com.android.vending]", remaining)
	}
	calls := strings.Join(mock.callsSnapshot(), "\n")
	if !strings.Contains(calls, "appops set --user 10 com.google.android.googlequicksearchbox RUN_ANY_IN_BACKGROUND allow") {
		t.Fatalf("expected companion host googlequicksearchbox restored synchronously under SyncTargetOnly=true, got:\n%s", calls)
	}

	// Self-heal when googlequicksearchbox is already stopped=true.
	stoppedRunner := &v250LifecycleMockRunner{
		onRun: func(cmd string) (string, bool, error) {
			if cmd == "dumpsys package com.google.android.googlequicksearchbox" {
				return "  User 0: ceDataInode=1 stopped=false\n  User 10: ceDataInode=2 stopped=true enabled=0\n", true, nil
			}
			return "Starting: Intent { act=android.intent.action.VIEW }\n", true, nil
		},
	}
	handled, ferr := LaunchViaCompanionFallbackIfHostStopped(ctx, stoppedRunner, 10, "com.google.android.apps.bard")
	if !handled || ferr != nil {
		t.Fatalf("LaunchViaCompanionFallbackIfHostStopped(stopped=true) = (%v, %v), want (true, nil)", handled, ferr)
	}
	scalls := strings.Join(stoppedRunner.callsSnapshot(), "\n")
	if !strings.Contains(scalls, "am start --user 10 -a android.intent.action.VIEW -d https://bard.google.com/android?source=bardshell -p com.google.android.googlequicksearchbox -f 0x10200000") {
		t.Fatalf("expected direct bard deeplink launch to wake host, got:\n%s", scalls)
	}

	// When host is stopped=false, fallback returns handled=false so normal LAUNCHER launch runs.
	awakeRunner := &v250LifecycleMockRunner{
		onRun: func(cmd string) (string, bool, error) {
			if cmd == "dumpsys package com.google.android.googlequicksearchbox" {
				return "  User 10: ceDataInode=2 stopped=false enabled=0\n", true, nil
			}
			return "", true, nil
		},
	}
	handledAwake, ferrAwake := LaunchViaCompanionFallbackIfHostStopped(ctx, awakeRunner, 10, "com.google.android.apps.bard")
	if handledAwake || ferrAwake != nil {
		t.Fatalf("LaunchViaCompanionFallbackIfHostStopped(stopped=false) = (%v, %v), want (false, nil)", handledAwake, ferrAwake)
	}
}

func TestV252ThawAllUserCgroupsAndProtectedFiltering(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cgRoot := filepath.Join(root, "cgroup")
	pkgList := filepath.Join(root, "packages.list")
	hibPath := filepath.Join(root, "hib.json")

	// Include User 0, User 10 protected & unrecorded UIDs, and User 999.
	for _, tc := range []struct {
		dir string
		val string
	}{
		{"uid_10123", "1"},
		{"uid_99910123", "1"},
		{"uid_1010395", "1"},
		{"uid_1010397", "1"},
		{"uid_1010201", "0"},
		{"uid_1010376", "0"},
	} {
		p := filepath.Join(cgRoot, tc.dir, "cgroup.freeze")
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(tc.val), 0644); err != nil {
			t.Fatal(err)
		}
	}

	thawed := ThawAllUserCgroups(cgRoot, 10)
	if !reflect.DeepEqual(thawed, []int{1010395, 1010397}) {
		t.Fatalf("ThawAllUserCgroups = %v, want [1010395 1010397]", thawed)
	}
	if b, _ := os.ReadFile(filepath.Join(cgRoot, "uid_10123", "cgroup.freeze")); string(b) != "1" {
		t.Fatal("ThawAllUserCgroups must NOT touch User 0")
	}
	if b, _ := os.ReadFile(filepath.Join(cgRoot, "uid_99910123", "cgroup.freeze")); string(b) != "1" {
		t.Fatal("ThawAllUserCgroups must NOT touch User 999")
	}
	if len(ThawAllUserCgroups(cgRoot, 0)) != 0 || len(ThawAllUserCgroups(cgRoot, 999)) != 0 {
		t.Fatal("ThawAllUserCgroups must reject forbidden users 0 and 999")
	}

	// Verify Hibernation filters process-only names & protects ext.services/remoteprovisioner/lbe/AdminPackage.
	if err := os.WriteFile(pkgList, []byte(
		"com.google.android.apps.bard 10395 0 /data/user/0/com.google.android.apps.bard default 0 0\n"+
			"com.example.workdpc 10376 0 /data/user/0/com.example.workdpc default 0 0\n"+
			"com.google.android.ext.services 10201 0 /data/user/0/com.google.android.ext.services default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}
	filtered := filterEligibleRunningPackages(
		[]string{"android.process.acore", "com.google.process.gapps", "com.google.android.gms.unstable", "com.google.android.apps.bard"},
		nil, pkgList,
	)
	if !reflect.DeepEqual(filtered, []string{"com.google.android.apps.bard"}) {
		t.Fatalf("filterEligibleRunningPackages = %v, want [com.google.android.apps.bard]", filtered)
	}

	// Verify HibernateSandboxUserEx respects AdminPackage and protected system services.
	mock := &v250LifecycleMockRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.google.android.apps.bard\npackage:com.example.workdpc\npackage:com.sandbox.controller\n",
			"ime list -s --user 10":                  "",
		},
	}
	if _, err := HibernateSandboxUserEx(ctx, mock, 10, hibPath, LifecycleOptions{
		CallerPackage:       "com.sandbox.controller",
		AdminPackage:        "com.example.workdpc",
		PackagesListPath:    pkgList,
		CgroupRoot:          cgRoot,
		SkipAppOpsForFrozen: true,
	}); err != nil {
		t.Fatal(err)
	}
	st := ReadHibernatedState(hibPath)
	for _, pkg := range st.Packages {
		if pkg == "com.example.workdpc" || pkg == "com.google.android.ext.services" || pkg == "android.process.acore" {
			t.Fatalf("unexpected protected/process package %q in hibernated state: %+v", pkg, st.Packages)
		}
	}

	// Verify L1 HotFreeze calls am make-uid-idle before freezing and clears stale HotFrozen when 0 UIDs frozen.
	_ = writeHibernatedState(hibPath, HibernatedState{
		UserID:     10,
		Packages:   []string{"com.google.android.apps.bard"},
		FrozenUIDs: []int{1010395},
		HotFrozen:  true,
	})
	hotMock := &v250LifecycleMockRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.google.android.apps.bard\n",
			"ime list -s --user 10":                  "",
		},
	}
	_ = time.Millisecond
	n, err := HotFreezeSandboxUserWithOpts(ctx, hotMock, 10, hibPath, pkgList, cgRoot, "com.sandbox.controller", "com.example.workdpc")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("HotFreezeSandboxUserWithOpts frozen=%d, want 1", n)
	}
	hotCalls := strings.Join(hotMock.callsSnapshot(), "\n")
	if !strings.Contains(hotCalls, "am make-uid-idle --user 10 com.google.android.apps.bard") {
		t.Fatalf("expected am make-uid-idle before cgroup freeze, got:\n%s", hotCalls)
	}
}

type fakeCgroupMemFS struct {
	files map[string]string
}

func (f *fakeCgroupMemFS) ReadFile(path string) ([]byte, error) {
	v, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(v), nil
}

func (f *fakeCgroupMemFS) WriteFile(path string, data []byte) error {
	f.files[path] = string(data)
	return nil
}

func TestAndroidRegressionAuditedFixes(t *testing.T) {
	ctx := context.Background()

	// 1. ParseAudioActiveForUser handles u/pid:<uid>/<pid> and case-insensitive STARTED.
	if !ParseAudioActiveForUser("  AudioTrack u/pid:1010395/4321 state:STARTED", 1000000, 1099999) {
		t.Fatal("expected ParseAudioActiveForUser to detect u/pid and STARTED")
	}

	// 2. InspectCgroupV2Freeze + UnfreezeCgroupV2 handle parent uid_<uid>/cgroup.freeze.
	memFS := &fakeCgroupMemFS{
		files: map[string]string{
			"/sys/fs/cgroup/uid_1010376/cgroup.freeze":          "1\n",
			"/sys/fs/cgroup/uid_1010376/pid_6206/cgroup.freeze": "0\n",
		},
	}
	fst := InspectCgroupV2Freeze(memFS, 1010376, 6206)
	if !fst.Frozen || fst.FreezePath != "/sys/fs/cgroup/uid_1010376/cgroup.freeze" {
		t.Fatalf("expected parent freeze detected, got %+v", fst)
	}
	if err := UnfreezeCgroupV2(memFS, 1010376, 6206, fst); err != nil {
		t.Fatal(err)
	}
	if memFS.files["/sys/fs/cgroup/uid_1010376/cgroup.freeze"] != "0" {
		t.Fatalf("expected parent cgroup thawed, got %q", memFS.files["/sys/fs/cgroup/uid_1010376/cgroup.freeze"])
	}

	// 3. StopSandboxApp rejects protected system/GMS packages.
	for _, prot := range []string{"android", "com.google.android.gms", contracts.ManagedProvisioningPkg} {
		if err := StopSandboxApp(ctx, &v250LifecycleMockRunner{}, 10, prot, "com.sandbox.controller"); err == nil {
			t.Fatalf("expected StopSandboxApp to reject protected package %s", prot)
		}
	}

	// 4. ResolveFreezableUIDs excludes another package sharing an appID with a protected package.
	dir := t.TempDir()
	pkgList := filepath.Join(dir, "packages.list")
	if err := os.WriteFile(pkgList, []byte(
		"com.google.android.gms 10200 0 /data/user/0/com.google.android.gms privapp 0 0\n"+
			"com.shared.gms.helper 10200 0 /data/user/0/com.shared.gms.helper default 0 0\n"+
			"com.normal.app 10411 0 /data/user/0/com.normal.app default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}
	uids := ResolveFreezableUIDs(pkgList, 10, []string{"com.shared.gms.helper", "com.normal.app"})
	if len(uids) != 1 || uids[0] != 1010411 {
		t.Fatalf("expected shared protected appID 10200 skipped and [1010411] returned, got %v", uids)
	}

	// 5. RestoreSandboxBloat retains packages in pruned_pkgs.json when pm enable fails.
	prunedPath := filepath.Join(dir, "pruned_pkgs.json")
	if err := writePrunedState(prunedPath, PrunedState{
		UserID:   10,
		Packages: []string{"com.bloat.one"},
	}); err != nil {
		t.Fatal(err)
	}
	failBloatRunner := &v250LifecycleMockRunner{
		onRun: func(cmd string) (string, bool, error) {
			if cmd == "pm enable --user 10 com.bloat.one" {
				return "", true, errors.New("binder timeout")
			}
			return "", false, nil
		},
	}
	if _, err := RestoreSandboxBloat(ctx, failBloatRunner, 10, prunedPath); err == nil {
		t.Fatal("expected RestoreSandboxBloat error when all recorded packages fail pm enable")
	}
	retained := readPrunedState(prunedPath)
	if len(retained.Packages) != 1 || retained.Packages[0] != "com.bloat.one" {
		t.Fatalf("expected failed bloat pkg retained in state, got %+v", retained)
	}
	_ = oem.Current()
}
