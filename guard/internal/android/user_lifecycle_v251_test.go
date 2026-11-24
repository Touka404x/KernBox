package android

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

type v251MockRunner struct {
	mu    sync.Mutex
	out   map[string]string
	calls []string
}

func (r *v251MockRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	cmdLine := name
	if len(args) > 0 {
		cmdLine += " " + strings.Join(args, " ")
	}
	r.mu.Lock()
	r.calls = append(r.calls, cmdLine)
	resp, ok := r.out[cmdLine]
	if !ok && strings.HasPrefix(cmdLine, "pm install-create") {
		resp = r.out["pm install-create"]
	}
	r.mu.Unlock()
	return resp, nil
}

func (r *v251MockRunner) callsSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

func TestV251RestrictedAppOpsPkgsNonStrandingAndGMSSyncRestore(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "hibernated_pkgs.json")
	pkgListPath := filepath.Join(dir, "packages.list")
	cgRoot := filepath.Join(dir, "cgroup")

	// Only bard & gms have cgroup.freeze; nocgroup.app has no cgroup dir and must fall back
	// to hibernateSinglePackage (restricting its AppOps and recording RestrictedAppOpsPkgs).
	for _, uidDir := range []string{"uid_1010395", "uid_1010301"} {
		p := filepath.Join(cgRoot, uidDir)
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "cgroup.freeze"), []byte("0"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(pkgListPath, []byte(
		contracts.DefaultWorkPackage+" 10376 0 /data/user/0/"+contracts.DefaultWorkPackage+" default 0 0\n"+
			"com.google.android.apps.bard 10395 0 /data/user/0/com.google.android.apps.bard default 0 0\n"+
			"com.google.android.gms 10301 0 /data/user/0/com.google.android.gms default 0 0\n"+
			"com.nocgroup.app 10412 0 /data/user/0/com.nocgroup.app default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}

	r := &v251MockRunner{
		out: map[string]string{
			"cmd user list -v":                       "0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running)\n1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running)\n",
			"dumpsys user --user 10":                 "  UserInfo{10:Work:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
			"cmd package list packages --user 10 -3": "package:" + contracts.DefaultWorkPackage + "\npackage:com.google.android.apps.bard\npackage:com.nocgroup.app\n",
			"cmd package list packages -3 --user 10": "package:" + contracts.DefaultWorkPackage + "\npackage:com.google.android.apps.bard\npackage:com.nocgroup.app\n",
			"ime list -s --user 10":                  "",
		},
	}

	ctx := context.Background()
	opts := LifecycleOptions{
		PackagesListPath:    pkgListPath,
		CgroupRoot:          cgRoot,
		SkipAppOpsForFrozen: true,
		SyncTargetOnly:      true,
	}
	count, err := HibernateSandboxUserEx(ctx, r, 10, statePath, opts)
	if err != nil {
		t.Fatalf("HibernateSandboxUserEx failed: %v", err)
	}
	if count == 0 {
		t.Fatal("expected hibernated package count > 0")
	}

	st := ReadHibernatedState(statePath)
	if len(st.RestrictedAppOpsPkgs) == 0 {
		t.Fatalf("expected RestrictedAppOpsPkgs populated for fallback/GMS packages, got %+v", st)
	}
	hasNoCgroup := false
	for _, p := range st.RestrictedAppOpsPkgs {
		if p == "com.nocgroup.app" {
			hasNoCgroup = true
		}
	}
	if !hasNoCgroup {
		t.Fatalf("expected com.nocgroup.app in RestrictedAppOpsPkgs, got %+v", st.RestrictedAppOpsPkgs)
	}

	// Priority restore with SyncTargetOnly=true MUST still restore GMS/GSF synchronously if restricted,
	// while keeping com.nocgroup.app in remaining so it is never stranded.
	callsBefore := len(r.callsSnapshot())
	_, remaining, err := RestoreHibernatedPriorityEx(ctx, r, 10, statePath, []string{"com.google.android.apps.bard"}, opts)
	if err != nil {
		t.Fatalf("RestoreHibernatedPriorityEx failed: %v", err)
	}
	hasRemainingNoCgroup := false
	for _, remPkg := range remaining {
		if remPkg == "com.nocgroup.app" {
			hasRemainingNoCgroup = true
		}
		if remPkg == "com.google.android.gms" || remPkg == "com.google.android.apps.bard" {
			t.Fatalf("expected %s to be restored synchronously, not in remaining %v", remPkg, remaining)
		}
	}
	if !hasRemainingNoCgroup {
		t.Fatalf("expected com.nocgroup.app in remaining, got %v", remaining)
	}

	priorityCalls := strings.Join(r.callsSnapshot()[callsBefore:], "\n")
	if !strings.Contains(priorityCalls, "com.google.android.gms") {
		t.Fatalf("expected GMS synchronous restore under SyncTargetOnly=true, calls:\n%s", priorityCalls)
	}

	// Remaining restore must un-restrict com.nocgroup.app cleanly and delete state file.
	restoredRem, err := RestoreHibernatedSandboxUserWithOpts(ctx, r, 10, statePath, cgRoot)
	if err != nil {
		t.Fatalf("RestoreHibernatedSandboxUserWithOpts failed: %v", err)
	}
	if restoredRem == 0 {
		t.Fatal("expected remaining restore count > 0")
	}
	allAfter := strings.Join(r.callsSnapshot(), "\n")
	if !strings.Contains(allAfter, "appops set --user 10 com.nocgroup.app RUN_ANY_IN_BACKGROUND allow") {
		t.Fatalf("expected RUN_ANY_IN_BACKGROUND allow for com.nocgroup.app, calls:\n%s", allAfter)
	}
	if _, statErr := os.Stat(statePath); !os.IsNotExist(statErr) {
		t.Fatalf("expected statePath cleared after full restore, statErr=%v", statErr)
	}
}

func TestV251BoostUIDLaunchOverlappingTimer(t *testing.T) {
	cgRoot := t.TempDir()
	uidDir := filepath.Join(cgRoot, "uid_1010395")
	if err := os.MkdirAll(uidDir, 0755); err != nil {
		t.Fatal(err)
	}
	uclampPath := filepath.Join(uidDir, "cpu.uclamp.min")
	if err := os.WriteFile(uclampPath, []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	if !BoostUIDLaunch(cgRoot, 1010395, 100*time.Millisecond) {
		t.Fatal("first BoostUIDLaunch returned false")
	}
	raw, _ := os.ReadFile(uclampPath)
	if strings.TrimSpace(string(raw)) == "0" {
		t.Fatalf("expected non-zero cpu.uclamp.min during active boost, got %q", string(raw))
	}

	// Overlap second boost before the first timer fires.
	time.Sleep(45 * time.Millisecond)
	if !BoostUIDLaunch(cgRoot, 1010395, 180*time.Millisecond) {
		t.Fatal("second BoostUIDLaunch returned false")
	}

	// Wait past the first timer deadline (~115ms since first boost) but well within second (~180ms from 45ms).
	time.Sleep(75 * time.Millisecond)
	rawMid, _ := os.ReadFile(uclampPath)
	if strings.TrimSpace(string(rawMid)) == "0" {
		t.Fatalf("older timer prematurely reverted overlapping BoostUIDLaunch! uclamp=%q", string(rawMid))
	}

	// Wait past second timer deadline and confirm clean revert to 0.
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		rawEnd, _ := os.ReadFile(uclampPath)
		if strings.TrimSpace(string(rawEnd)) == "0" {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	rawFinal, _ := os.ReadFile(uclampPath)
	t.Fatalf("expected cpu.uclamp.min to revert to 0 after second boost expired, got %q", string(rawFinal))
}

func TestV251InstallSandboxAPKsSymlinkRejectionAndNoGrantAll(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "staging")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(allowed, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}

	legitAPK := filepath.Join(allowed, "app.apk")
	outsideAPK := filepath.Join(outside, "evil.apk")
	if err := os.WriteFile(legitAPK, []byte("PK\x03\x04dummy-apk"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideAPK, []byte("PK\x03\x04outside-apk"), 0644); err != nil {
		t.Fatal(err)
	}

	r := &v251MockRunner{
		out: map[string]string{
			"pm install-create": "Success: created install session [42]\n",
		},
	}

	// Reject outside path even without symlink.
	if _, err := InstallSandboxAPKs(context.Background(), r, 10, []string{outsideAPK}, []string{allowed}); err == nil {
		t.Fatal("expected InstallSandboxAPKs to reject APK outside allowed staging dir")
	}

	// Reject symlink escaping allowed dir when OS permits creating symlinks.
	symAPK := filepath.Join(allowed, "escape.apk")
	if err := os.Symlink(outsideAPK, symAPK); err == nil {
		if _, err := InstallSandboxAPKs(context.Background(), r, 10, []string{symAPK}, []string{allowed}); err == nil {
			t.Fatal("expected InstallSandboxAPKs to reject symlinked APK escaping staging dir")
		}
	}

	// Legitimate install must succeed without passing `-g` (grant-all runtime permissions).
	res, err := InstallSandboxAPKs(context.Background(), r, 10, []string{legitAPK}, []string{allowed})
	if err != nil {
		t.Fatalf("legit InstallSandboxAPKs failed: %v", err)
	}
	if res.SessionID == "" {
		t.Fatalf("expected non-empty session id, got %+v", res)
	}
	for _, call := range r.callsSnapshot() {
		if strings.HasPrefix(call, "pm install-create") && strings.Contains(" "+call+" ", " -g ") {
			t.Fatalf("pm install-create must never pass -g auto-grant flag, got: %q", call)
		}
	}
}

func TestV251ScanUserProcsNestedPidSubcgroups(t *testing.T) {
	root := t.TempDir()
	cgRoot := filepath.Join(root, "cgroup")
	procRoot := filepath.Join(root, "proc")
	pkgList := filepath.Join(root, "packages.list")
	statePath := filepath.Join(root, "hibernated.json")

	// Android 13 libprocessgroup places PIDs in uid_<uid>/pid_<pid>/cgroup.procs (parent cgroup.procs is empty).
	appPidDir := filepath.Join(cgRoot, "uid_1010395", "pid_4242")
	isoPidDir := filepath.Join(cgRoot, "uid_1099001", "pid_4343")
	if err := os.MkdirAll(appPidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(isoPidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze"), []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "uid_1099001", "cgroup.freeze"), []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appPidDir, "cgroup.procs"), []byte("4242\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isoPidDir, "cgroup.procs"), []byte("4343\n"), 0644); err != nil {
		t.Fatal(err)
	}

	for pid, cmd := range map[string]string{
		"4242": "com.google.android.apps.bard\x00",
		"4343": "com.android.webview:sandboxed_process0\x00",
	} {
		pdir := filepath.Join(procRoot, pid)
		if err := os.MkdirAll(pdir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pdir, "cmdline"), []byte(cmd), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(pkgList, []byte(
		contracts.DefaultWorkPackage+" 10376 0 /data/user/0/"+contracts.DefaultWorkPackage+" default 0 0\n"+
			"com.google.android.apps.bard 10395 0 /data/user/0/com.google.android.apps.bard default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}

	if got := CountRunningUserProcessesWithRoot(cgRoot, 10); got != 2 {
		t.Fatalf("CountRunningUserProcessesWithRoot nested pid_* = %d, want 2", got)
	}
	entries := scanUserProcEntriesWithRootFS(cgRoot, procRoot, 10)
	if len(entries) != 2 {
		t.Fatalf("scanUserProcEntriesWithRootFS nested pid_* = %+v, want 2", entries)
	}

	r := &v251MockRunner{
		out: map[string]string{
			"iptables -t mangle -L " + contracts.ChainTProxyOut + " -v -n -x": "Chain " + contracts.ChainTProxyOut + " (1 references)\n pkts bytes target prot opt in out source destination\n",
			"dumpsys audio":                          "",
			"dumpsys activity top":                   "ACTIVITY com.google.android.apps.bard/.MainActivity u10\n",
			"cmd package list packages -3 --user 10": "package:" + contracts.DefaultWorkPackage + "\npackage:com.google.android.apps.bard\n",
			"ime list -s --user 10":                  "",
		},
	}
	snap, err := InspectSandboxActivityFast(context.Background(), r, 10, cgRoot, filepath.Join(root, "asound"), 0, false)
	if err != nil {
		t.Fatalf("InspectSandboxActivityFast failed: %v", err)
	}
	if !snap.ForegroundUser {
		t.Fatalf("expected InspectSandboxActivityFast to probe foreground user when pid_* cgroup has processes")
	}

	// Verify HotFreezeSandboxUserWithOpts discovers nested PIDs and freezes regular + isolated UIDs (parent uid_*/cgroup.procs empty).
	frozenCount, err := HotFreezeSandboxUserWithOpts(context.Background(), r, 10, statePath, pkgList, cgRoot)
	if err != nil {
		t.Fatalf("HotFreezeSandboxUserWithOpts failed: %v", err)
	}
	if frozenCount == 0 {
		t.Fatal("expected HotFreezeSandboxUserWithOpts to freeze UIDs when pid_* cgroups active")
	}
	if b, _ := os.ReadFile(filepath.Join(cgRoot, "uid_1099001", "cgroup.freeze")); strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("expected isolated uid_1099001 frozen via nested pid_* scan, got %q", string(b))
	}
}

func TestV251DiscoverRunningPackagesFiltersSystemAndIsolatedUIDs(t *testing.T) {
	root := t.TempDir()
	cgRoot := filepath.Join(root, "cgroup")
	procRoot := filepath.Join(root, "proc")

	cases := []struct {
		uid     int
		pid     string
		cmdline string
	}{
		{1001000, "5101", "com.android.systemui\x00"},
		{1001002, "5102", "com.android.bluetooth\x00"},
		{1010395, "5103", "com.google.android.apps.bard\x00"},
		{1099001, "5104", "com.google.android.webview:sandboxed_process0\x00"},
	}
	for _, tc := range cases {
		uidDir := filepath.Join(cgRoot, "uid_"+strconv.Itoa(tc.uid))
		if err := os.MkdirAll(uidDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(uidDir, "cgroup.procs"), []byte(tc.pid+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		pdir := filepath.Join(procRoot, tc.pid)
		if err := os.MkdirAll(pdir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pdir, "cmdline"), []byte(tc.cmdline), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Count all processes via scanUserProcEntriesWithRootFS while discoverRunningUserPackages filters to [MinAppID..89999].
	all := scanUserProcEntriesWithRootFS(cgRoot, procRoot, 10)
	if len(all) != 4 {
		t.Fatalf("scanUserProcEntriesWithRootFS got %d entries, want 4", len(all))
	}
	pkgs := discoverRunningUserPackagesWithRootFS(cgRoot, procRoot, 10)
	if len(pkgs) != 1 || pkgs[0] != "com.google.android.apps.bard" {
		t.Fatalf("discoverRunningUserPackagesWithRootFS = %v, want [com.google.android.apps.bard]", pkgs)
	}
	protected := hibernationProtectedPkgSet()
	baseWant := []string{
		"com.android.settings",
		"com.google.android.webview",
		"com.android.packageinstaller",
		"com.android.certinstaller",
	}
	for _, pkg := range append(baseWant, oem.Current().ExtraProtectedPackages...) {
		if !protected[pkg] {
			t.Fatalf("expected %s in hibernationProtectedPkgSet() on OEM %s", pkg, oem.Current().Name)
		}
	}
}
