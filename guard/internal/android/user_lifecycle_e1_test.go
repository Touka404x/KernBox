package android

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHotFreezeSandboxUserIdleVsUnsupportedVsActive(t *testing.T) {
	ctx := context.Background()

	// Case 1: cgroup freeze supported and 0 running freezable processes -> 0, nil (no spurious error).
	t.Run("idle_sandbox_with_cgroup_support_returns_zero_nil", func(t *testing.T) {
		dir := t.TempDir()
		cgRoot := filepath.Join(dir, "cgroup")
		pkgList := filepath.Join(dir, "packages.list")
		statePath := filepath.Join(dir, "hibernated.json")
		if err := os.MkdirAll(filepath.Join(cgRoot, "uid_0"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cgRoot, "uid_0", "cgroup.freeze"), []byte("0"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pkgList, []byte("com.idle.app 10410 0 /data/user/0/com.idle.app default 0 0\n"), 0600); err != nil {
			t.Fatal(err)
		}
		mock := &v250LifecycleMockRunner{
			out: map[string]string{
				"cmd package list packages -3 --user 10": "package:com.idle.app\n",
			},
		}
		n, err := HotFreezeSandboxUserWithOpts(ctx, mock, 10, statePath, pkgList, cgRoot)
		if err != nil {
			t.Fatalf("expected nil error for idle sandbox with cgroup support, got %v", err)
		}
		if n != 0 {
			t.Fatalf("expected 0 frozen UIDs, got %d", n)
		}
	})

	// Case 2: zero cgroup freeze support -> must still return error so caller falls back to hibernation.
	t.Run("unsupported_cgroup_still_errors", func(t *testing.T) {
		dir := t.TempDir()
		cgRoot := filepath.Join(dir, "cgroup_empty")
		pkgList := filepath.Join(dir, "packages.list")
		if err := os.MkdirAll(cgRoot, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pkgList, []byte("com.idle.app 10410 0 /data/user/0/com.idle.app default 0 0\n"), 0600); err != nil {
			t.Fatal(err)
		}
		mock := &v250LifecycleMockRunner{
			out: map[string]string{
				"cmd package list packages -3 --user 10": "package:com.idle.app\n",
			},
		}
		if _, err := HotFreezeSandboxUserWithOpts(ctx, mock, 10, "", pkgList, cgRoot); err == nil {
			t.Fatal("expected error when no cgroup freeze control exists")
		}
	})

	// Case 3: cgroup freeze supported globally, active process exists for UID without freeze node -> error.
	t.Run("active_process_without_freeze_node_errors", func(t *testing.T) {
		dir := t.TempDir()
		cgRoot := filepath.Join(dir, "cgroup")
		pkgList := filepath.Join(dir, "packages.list")
		if err := os.MkdirAll(filepath.Join(cgRoot, "uid_0"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cgRoot, "uid_0", "cgroup.freeze"), []byte("0"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(cgRoot, "uid_1010410"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cgRoot, "uid_1010410", "cgroup.procs"), []byte("7788\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pkgList, []byte("com.running.app 10410 0 /data/user/0/com.running.app default 0 0\n"), 0600); err != nil {
			t.Fatal(err)
		}
		mock := &v250LifecycleMockRunner{
			out: map[string]string{
				"cmd package list packages -3 --user 10": "package:com.running.app\n",
			},
		}
		if _, err := HotFreezeSandboxUserWithOpts(ctx, mock, 10, "", pkgList, cgRoot); err == nil {
			t.Fatal("expected error when running sandbox UID lacks writable cgroup.freeze")
		}
	})
}

func TestInspectSandboxActivityFastAttributesAudioViaDumpsys(t *testing.T) {
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
	// Host User 0 playback makes /proc/asound report RUNNING, while dumpsys audio shows only UID 10200 (User 0).
	if err := os.WriteFile(filepath.Join(pcmDir, "status"), []byte("state: RUNNING\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := &v250LifecycleMockRunner{
		out: map[string]string{
			"dumpsys audio":        "AudioPlaybackConfiguration piid:12 uid:10200 state:STARTED\n",
			"dumpsys activity top": "TASK 0:com.user0.music/.Main u0 id=11\n",
		},
	}
	snap, err := InspectSandboxActivityFast(context.Background(), mock, 10, cgRoot, asoundRoot, 0, false)
	if err != nil {
		t.Fatalf("InspectSandboxActivityFast failed: %v", err)
	}
	if snap.AudioActive {
		t.Fatal("must not attribute host User 0 /proc/asound playback to sandbox AudioActive")
	}
	if !strings.Contains(strings.Join(mock.callsSnapshot(), "\n"), "dumpsys audio") {
		t.Fatal("expected dumpsys audio to run even when /proc/asound is RUNNING")
	}
}

func TestMilletCgroupV1GlobalFrozenGroupNeverThawsGlobalState(t *testing.T) {
	fs := &fakeCgroupFS{files: map[string][]byte{
		"/sys/fs/cgroup/freezer/frozen/cgroup.procs": []byte("999\n4421\n"),
		"/sys/fs/cgroup/freezer/frozen/freezer.state": []byte("FROZEN\n"),
	}}
	st := InspectCgroupV1Freeze(fs, 1010376, 4421)
	if !st.Frozen || !st.InFrozenGroup {
		t.Fatalf("expected frozen in global group, got %+v", st)
	}
	if st.FreezePath != "" {
		t.Fatalf("FreezePath must stay empty for shared global frozen group, got %q", st.FreezePath)
	}
	if err := UnfreezeCgroupV1(fs, 1010376, 4421, st); err != nil {
		t.Fatalf("UnfreezeCgroupV1 failed: %v", err)
	}
	if string(fs.files["/sys/fs/cgroup/freezer/frozen/freezer.state"]) != "FROZEN\n" {
		t.Fatalf("must NEVER overwrite shared global frozen/freezer.state, got %q", string(fs.files["/sys/fs/cgroup/freezer/frozen/freezer.state"]))
	}
	if string(fs.files["/sys/fs/cgroup/freezer/cgroup.procs"]) != "4421" {
		t.Fatalf("expected pid 4421 migrated to /sys/fs/cgroup/freezer/cgroup.procs, got %q", string(fs.files["/sys/fs/cgroup/freezer/cgroup.procs"]))
	}

	// Also verify /dev/freezer prefix migrates back to /dev/freezer root.
	fsDev := &fakeCgroupFS{files: map[string][]byte{
		"/dev/freezer/frozen/tasks": []byte("5510\n"),
	}}
	stDev := InspectCgroupV1Freeze(fsDev, 1010376, 5510)
	if err := UnfreezeCgroupV1(fsDev, 1010376, 5510, stDev); err != nil {
		t.Fatalf("UnfreezeCgroupV1 /dev/freezer failed: %v", err)
	}
	if string(fsDev.files["/dev/freezer/cgroup.procs"]) != "5510" {
		t.Fatalf("expected pid 5510 migrated to /dev/freezer/cgroup.procs, got %q", string(fsDev.files["/dev/freezer/cgroup.procs"]))
	}
}
