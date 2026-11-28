package android

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/contracts"
)

type v250LifecycleMockRunner struct {
	mu    sync.Mutex
	out   map[string]string
	onRun func(cmdLine string) (string, bool, error)
	calls []string
}

func (m *v250LifecycleMockRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	m.mu.Lock()
	m.calls = append(m.calls, line)
	fn := m.onRun
	outMap := m.out
	m.mu.Unlock()
	if fn != nil {
		if out, handled, err := fn(line); handled {
			return out, err
		}
	}
	if outMap != nil {
		if v, ok := outMap[line]; ok {
			return v, nil
		}
	}
	return "", nil
}

func (m *v250LifecycleMockRunner) callsSnapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

func TestScanUserProcEntriesCgroupFastPath(t *testing.T) {
	dir := t.TempDir()
	cgRoot := filepath.Join(dir, "cgroup")
	procRoot := filepath.Join(dir, "proc")

	// User 10 UIDs (1000000..1099999) + User 0 (10123) + XSpace User 999 (99910123).
	if err := os.MkdirAll(filepath.Join(cgRoot, "uid_1010123"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cgRoot, "uid_1010456"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cgRoot, "uid_10123"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cgRoot, "uid_99910123"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "uid_1010123", "cgroup.procs"), []byte("4321\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "uid_1010456", "cgroup.procs"), []byte("4322\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "uid_10123", "cgroup.procs"), []byte("1001\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "uid_99910123", "cgroup.procs"), []byte("9001\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(procRoot, "4321"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(procRoot, "4322"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "4321", "cmdline"), []byte("com.google.android.apps.bard:bg\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "4322", "cmdline"), []byte("com.android.vending\x00"), 0644); err != nil {
		t.Fatal(err)
	}

	if got := CountRunningUserProcessesWithRoot(cgRoot, 10); got != 2 {
		t.Fatalf("CountRunningUserProcessesWithRoot(user=10) = %d, want 2", got)
	}
	if got := CountRunningUserProcessesWithRoot(cgRoot, 0); got != 0 {
		t.Fatalf("CountRunningUserProcessesWithRoot(user=0) = %d, want 0", got)
	}
	if got := CountRunningUserProcessesWithRoot(cgRoot, 999); got != 0 {
		t.Fatalf("CountRunningUserProcessesWithRoot(user=999) = %d, want 0", got)
	}

	entries := scanUserProcEntriesWithRootFS(cgRoot, procRoot, 10)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d (%+v)", len(entries), entries)
	}
	pkgs := map[string]int{}
	for _, e := range entries {
		pkgs[e.pkg] = e.pid
	}
	if pkgs["com.google.android.apps.bard"] != 4321 || pkgs["com.android.vending"] != 4322 {
		t.Fatalf("unexpected cgroup fast scan packages: %+v", pkgs)
	}
}

func BenchmarkScanUserProcEntriesCgroup(b *testing.B) {
	dir := b.TempDir()
	cgRoot := filepath.Join(dir, "cgroup")
	procRoot := filepath.Join(dir, "proc")
	for i := 0; i < 480; i++ {
		uidDir := filepath.Join(cgRoot, fmt.Sprintf("uid_%d", 10000+i))
		_ = os.MkdirAll(uidDir, 0755)
		_ = os.WriteFile(filepath.Join(uidDir, "cgroup.procs"), []byte(strconv.Itoa(1000+i)+"\n"), 0644)
	}
	for i := 0; i < 20; i++ {
		uid := 1010100 + i
		pid := 20000 + i
		uidDir := filepath.Join(cgRoot, fmt.Sprintf("uid_%d", uid))
		_ = os.MkdirAll(uidDir, 0755)
		_ = os.WriteFile(filepath.Join(uidDir, "cgroup.procs"), []byte(strconv.Itoa(pid)+"\n"), 0644)
		pDir := filepath.Join(procRoot, strconv.Itoa(pid))
		_ = os.MkdirAll(pDir, 0755)
		_ = os.WriteFile(filepath.Join(pDir, "cmdline"), []byte("com.example.benchapp\x00"), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entries := scanUserProcEntriesWithRootFS(cgRoot, procRoot, 10)
		if len(entries) != 20 {
			b.Fatalf("expected 20 entries, got %d", len(entries))
		}
	}
}

func TestInspectSandboxActivityFastShortCircuits(t *testing.T) {
	ctx := context.Background()

	t.Run("zero_procs_cgroup_short_circuit", func(t *testing.T) {
		dir := t.TempDir()
		cgRoot := filepath.Join(dir, "cgroup")
		if err := os.MkdirAll(filepath.Join(cgRoot, "uid_10123"), 0755); err != nil {
			t.Fatal(err)
		}
		mock := &v250LifecycleMockRunner{}
		snap, err := InspectSandboxActivityFast(ctx, mock, 10, cgRoot, "", 999, true)
		if err != nil {
			t.Fatal(err)
		}
		if snap.ForegroundUser || snap.AudioActive || snap.TrafficBytes != 999 {
			t.Fatalf("unexpected snapshot: %+v", snap)
		}
		if calls := mock.callsSnapshot(); len(calls) != 0 {
			t.Fatalf("expected zero subprocess calls when cgroup shows 0 User 10 procs, got %v", calls)
		}
	})

	t.Run("high_traffic_delta_short_circuit", func(t *testing.T) {
		dir := t.TempDir()
		cgRoot := filepath.Join(dir, "cgroup")
		if err := os.MkdirAll(filepath.Join(cgRoot, "uid_1010395"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cgRoot, "uid_1010395", "cgroup.procs"), []byte("5001\n"), 0644); err != nil {
			t.Fatal(err)
		}
		mock := &v250LifecycleMockRunner{
			out: map[string]string{
				"iptables -t mangle -L " + contracts.ChainTProxyOut + " -v -n -x": "100 65536 ACCEPT all -- * * 0.0.0.0/0 0.0.0.0/0 owner UID match 1000000-1099999\n",
			},
		}
		snap, err := InspectSandboxActivityFast(ctx, mock, 10, cgRoot, "", 1024, true)
		if err != nil {
			t.Fatal(err)
		}
		if snap.TrafficBytes != 65536 {
			t.Fatalf("TrafficBytes = %d, want 65536", snap.TrafficBytes)
		}
		calls := mock.callsSnapshot()
		if len(calls) != 1 || !strings.HasPrefix(calls[0], "iptables ") {
			t.Fatalf("expected only iptables call before short-circuit, got %v", calls)
		}
	})

	t.Run("asound_closed_and_top_conclusive_short_circuit", func(t *testing.T) {
		dir := t.TempDir()
		cgRoot := filepath.Join(dir, "cgroup")
		asoundRoot := filepath.Join(dir, "asound")
		if err := os.MkdirAll(filepath.Join(cgRoot, "uid_1010395"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cgRoot, "uid_1010395", "cgroup.procs"), []byte("5001\n"), 0644); err != nil {
			t.Fatal(err)
		}
		pcmDir := filepath.Join(asoundRoot, "card0", "pcm0p", "sub0")
		if err := os.MkdirAll(pcmDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pcmDir, "status"), []byte("closed\n"), 0644); err != nil {
			t.Fatal(err)
		}

		mock := &v250LifecycleMockRunner{
			out: map[string]string{
				"iptables -t mangle -L " + contracts.ChainTProxyOut + " -v -n -x": "10 2048 ACCEPT all -- * * 0.0.0.0/0 0.0.0.0/0 owner UID match 1000000-1099999\n",
				"dumpsys activity top":                                          "TASK 10:com.google.android.apps.bard/com.google.android.apps.bard.Main u10 id=55\n",
			},
		}
		snap, err := InspectSandboxActivityFast(ctx, mock, 10, cgRoot, asoundRoot, 1024, true)
		if err != nil {
			t.Fatal(err)
		}
		if !snap.ForegroundUser || snap.AudioActive {
			t.Fatalf("expected ForegroundUser=true AudioActive=false, got %+v", snap)
		}
		joined := strings.Join(mock.callsSnapshot(), "\n")
		if !strings.Contains(joined, "dumpsys audio") {
			t.Fatalf("expected dumpsys audio to run even with closed /proc/asound (BT A2DP safety), got:\n%s", joined)
		}
		if strings.Contains(joined, "dumpsys activity activities") {
			t.Fatalf("expected dumpsys activity activities skipped via top short-circuit, got:\n%s", joined)
		}
	})
}

func TestHibernateAndRestoreV250FastPaths(t *testing.T) {
	dir := t.TempDir()
	cgRoot := filepath.Join(dir, "cgroup")
	pkgList := filepath.Join(dir, "packages.list")
	statePath := filepath.Join(dir, "hibernated.json")

	if err := os.WriteFile(pkgList, []byte(
		"com.google.android.apps.bard 10395 0 /data/user/0/com.google.android.apps.bard default 0 0\n"+
			"com.example.nofreeze 10401 0 /data/user/0/com.example.nofreeze default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cgRoot, "uid_1010395"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze"), []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := &v250LifecycleMockRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.google.android.apps.bard\npackage:com.example.nofreeze\n",
			"ime list -s --user 10":                  "",
		},
	}

	ctx := context.Background()
	n, err := HibernateSandboxUserEx(ctx, mock, 10, statePath, LifecycleOptions{
		PackagesListPath:    pkgList,
		CgroupRoot:          cgRoot,
		SkipAppOpsForFrozen: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected >=1 hibernated package")
	}
	st := ReadHibernatedState(statePath)
	foundSkippedBard := false
	for _, p := range st.SkippedAppOpsPkgs {
		if p == "com.google.android.apps.bard" {
			foundSkippedBard = true
		}
	}
	if !foundSkippedBard {
		t.Fatalf("expected bard in SkippedAppOpsPkgs, got %+v", st.SkippedAppOpsPkgs)
	}
	freezeVal, err := os.ReadFile(filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze"))
	if err != nil || strings.TrimSpace(string(freezeVal)) != "1" {
		t.Fatalf("expected cgroup.freeze=1 after hibernate, got %q (%v)", string(freezeVal), err)
	}

	hibCalls := strings.Join(mock.callsSnapshot(), "\n")
	if strings.Contains(hibCalls, "appops set --user 10 com.google.android.apps.bard") {
		t.Fatalf("expected appops skipped for frozen bard, got:\n%s", hibCalls)
	}
	if !strings.Contains(hibCalls, "appops set --user 10 com.example.nofreeze") {
		t.Fatalf("expected appops still run for non-frozen nofreeze pkg, got:\n%s", hibCalls)
	}

	// Now restore with SyncTargetOnly:true targeting ONLY bard.
	restoreMock := &v250LifecycleMockRunner{}
	restoredNow, remaining, err := RestoreHibernatedPriorityEx(ctx, restoreMock, 10, statePath,
		[]string{"com.google.android.apps.bard"},
		LifecycleOptions{CgroupRoot: cgRoot, SyncTargetOnly: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if restoredNow < 1 || len(remaining) == 0 {
		t.Fatalf("expected bard (+GMS/GSF) restored synchronously while chrome/nofreeze stay in remaining, got restoredNow=%d remaining=%v", restoredNow, remaining)
	}
	thawVal, err := os.ReadFile(filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze"))
	if err != nil || strings.TrimSpace(string(thawVal)) != "0" {
		t.Fatalf("expected cgroup.freeze=0 after restore, got %q (%v)", string(thawVal), err)
	}
	restCalls := strings.Join(restoreMock.callsSnapshot(), "\n")
	if strings.Contains(restCalls, "com.google.android.apps.bard") {
		t.Fatalf("expected skipped appops for frozen bard on restore, got:\n%s", restCalls)
	}
	if !strings.Contains(restCalls, "com.google.android.gms") || strings.Contains(restCalls, "com.android.chrome") {
		t.Fatalf("expected restricted GMS restored synchronously and Chrome deferred when SyncTargetOnly=true, got:\n%s", restCalls)
	}
}

func TestHotFreezeSandboxUserWithOpts(t *testing.T) {
	ctx := context.Background()
	if _, err := HotFreezeSandboxUserWithOpts(ctx, &v250LifecycleMockRunner{}, 0, "", "", ""); err == nil {
		t.Fatal("must reject User 0 hot-freeze")
	}
	if _, err := HotFreezeSandboxUserWithOpts(ctx, &v250LifecycleMockRunner{}, 999, "", "", ""); err == nil {
		t.Fatal("must reject User 999 hot-freeze")
	}

	dir := t.TempDir()
	cgRoot := filepath.Join(dir, "cgroup")
	pkgList := filepath.Join(dir, "packages.list")
	statePath := filepath.Join(dir, "hibernated.json")
	if err := os.WriteFile(pkgList, []byte("com.google.android.apps.bard 10395 0 /data/user/0/com.google.android.apps.bard default 0 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cgRoot, "uid_1010395"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze"), []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := &v250LifecycleMockRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:com.google.android.apps.bard\n",
			"ime list -s --user 10":                  "",
		},
	}
	frozenCount, err := HotFreezeSandboxUserWithOpts(ctx, mock, 10, statePath, pkgList, cgRoot)
	if err != nil {
		t.Fatal(err)
	}
	if frozenCount != 1 {
		t.Fatalf("frozenCount = %d, want 1", frozenCount)
	}
	if b, _ := os.ReadFile(filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze")); strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("expected cgroup.freeze=1, got %q", string(b))
	}
	st := ReadHibernatedState(statePath)
	if !st.HotFrozen || len(st.FrozenUIDs) != 1 || st.FrozenUIDs[0] != 1010395 {
		t.Fatalf("unexpected HotFrozen state: %+v", st)
	}
	joined := strings.Join(mock.callsSnapshot(), "\n")
	if strings.Contains(joined, "force-stop") || strings.Contains(joined, "appops") {
		t.Fatalf("L1 HotFreeze must NEVER call force-stop or appops, got:\n%s", joined)
	}
}

func TestReadMemoryPSIAvg10AndBoostUIDLaunch(t *testing.T) {
	dir := t.TempDir()
	psiPath := filepath.Join(dir, "memory.psi")
	if err := os.WriteFile(psiPath, []byte("some avg10=12.50 avg60=3.10 avg300=1.00 total=100\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if v, ok := ReadMemoryPSIAvg10(psiPath); !ok || v != 12.50 {
		t.Fatalf("ReadMemoryPSIAvg10 = (%v, %v), want (12.50, true)", v, ok)
	}
	if _, ok := ReadMemoryPSIAvg10(filepath.Join(dir, "missing")); ok {
		t.Fatal("expected ok=false for missing PSI file")
	}

	cgRoot := filepath.Join(dir, "cgroup")
	for _, uid := range []int{10395, 99910395, 1001000, 1095000, 1010395} {
		p := filepath.Join(cgRoot, fmt.Sprintf("uid_%d", uid), "cpu.uclamp.min")
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("0"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if BoostUIDLaunch(cgRoot, 10395, 30*time.Millisecond) {
		t.Fatal("must reject User 0 UID boost")
	}
	if BoostUIDLaunch(cgRoot, 99910395, 30*time.Millisecond) {
		t.Fatal("must reject User 999 UID boost")
	}
	if BoostUIDLaunch(cgRoot, 1001000, 30*time.Millisecond) {
		t.Fatal("must reject system appID < MinAppID")
	}
	if BoostUIDLaunch(cgRoot, 1095000, 30*time.Millisecond) {
		t.Fatal("must reject isolated appID >= 90000")
	}
	if !BoostUIDLaunch(cgRoot, 1010395, 30*time.Millisecond) {
		t.Fatal("expected sandbox UID 1010395 boost to succeed")
	}
	uclampPath := filepath.Join(cgRoot, "uid_1010395", "cpu.uclamp.min")
	if b, _ := os.ReadFile(uclampPath); strings.TrimSpace(string(b)) != "80" {
		t.Fatalf("expected immediate boost cpu.uclamp.min=80, got %q", string(b))
	}
	time.Sleep(120 * time.Millisecond)
	if b, _ := os.ReadFile(uclampPath); strings.TrimSpace(string(b)) != "0" {
		t.Fatalf("expected restored cpu.uclamp.min=0 after boost window, got %q", string(b))
	}
}
