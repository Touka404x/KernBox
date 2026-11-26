package android

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sandbox_guard/internal/contracts"
)

func TestParseUserStateFromActivityUsers(t *testing.T) {
	sample := "    User #0: state=RUNNING_UNLOCKED\n    User #10: state=STOPPED\n    User #999: state=RUNNING_UNLOCKED\n"
	if got := ParseUserStateFromActivityUsers(sample, 10); got != "STOPPED" {
		t.Fatalf("got %q want STOPPED", got)
	}
	if got := ParseUserStateFromActivityUsers(sample, 0); got != "RUNNING_UNLOCKED" {
		t.Fatalf("got %q want RUNNING_UNLOCKED", got)
	}
}

func TestStartAndStopSandboxUserLifecycle(t *testing.T) {
	// Reject User 0 and XSpace 999.
	if err := StartSandboxUserAndWait(context.Background(), &sandboxRecRunner{}, 0, 50*time.Millisecond); err == nil {
		t.Fatal("must reject User 0 start")
	}
	if err := StartSandboxUserAndWait(context.Background(), &sandboxRecRunner{}, 999, 50*time.Millisecond); err == nil {
		t.Fatal("must reject User 999 start")
	}
	if _, err := StopSandboxUserDeep(context.Background(), &sandboxRecRunner{}, 0); err == nil {
		t.Fatal("must reject User 0 stop")
	}
	if _, err := StopSandboxUserDeep(context.Background(), &sandboxRecRunner{}, 999); err == nil {
		t.Fatal("must reject User 999 stop")
	}

	// Fast path: already RUNNING_UNLOCKED does not invoke am start-user.
	fastRunner := &sandboxRecRunner{
		out: map[string]string{
			"dumpsys activity users": "    User #0: state=RUNNING_UNLOCKED\n    User #10: state=RUNNING_UNLOCKED\n",
		},
	}
	if err := StartSandboxUserAndWait(context.Background(), fastRunner, 10, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(fastRunner.calls, "\n"), "am start-user") {
		t.Fatalf("fast path must skip am start-user when already unlocked: %v", fastRunner.calls)
	}

	// Wake path: initially STOPPED -> calls `am start-user -w 10` -> transitions to RUNNING_UNLOCKED.
	started := false
	r := &dynamicLifecycleRunner{
		onRun: func(cmd string) (string, error) {
			if cmd == "dumpsys activity users" {
				if started {
					return "    User #10: state=RUNNING_UNLOCKED\n", nil
				}
				return "    User #10: state=STOPPED\n", nil
			}
			if cmd == "am start-user -w 10" {
				started = true
				return "Success\n", nil
			}
			return "", nil
		},
	}
	if err := StartSandboxUserAndWait(context.Background(), r, 10, time.Second); err != nil {
		t.Fatalf("wake path failed: %v", err)
	}
	if !started {
		t.Fatal("expected am start-user -w 10 to be invoked")
	}

	// Timeout / fast-fail path: stays RUNNING_LOCKED -> returns error cleanly without waiting full timeout.
	lockedRunner := &sandboxRecRunner{
		out: map[string]string{
			"dumpsys activity users": "    User #10: state=RUNNING_LOCKED\n",
		},
	}
	if err := StartSandboxUserAndWait(context.Background(), lockedRunner, 10, 5*time.Second); err == nil || !strings.Contains(err.Error(), "RUNNING_LOCKED") {
		t.Fatalf("expected fast RUNNING_LOCKED error when user stays encrypted locked, got %v", err)
	}

	// FBE-safe Root In-Place Hibernation: NEVER invokes `am stop-user` or `sh -c`,
	// silences background/wakelock/standby/jobs/procs while protecting DefaultWorkPackage & active IME,
	// writes statePath, and RestoreHibernatedSandboxUser restores permissions cleanly.
	dir := t.TempDir()
	hibPath := filepath.Join(dir, "hibernated_pkgs.json")
	pkgList := filepath.Join(dir, "packages.list")
	if err := os.WriteFile(pkgList, []byte(
		contracts.DefaultWorkPackage+" 10376 0 /data/user/0/"+contracts.DefaultWorkPackage+" default 0 0\n"+
			"com.google.android.gms 10200 0 /data/user/0/com.google.android.gms privapp 0 0\n"+
			"com.google.android.apps.bard 10395 0 /data/user/0/com.google.android.apps.bard default 0 0\n"+
			"com.custom.ime 10399 0 /data/user/0/com.custom.ime default 0 0\n",
	), 0600); err != nil {
		t.Fatal(err)
	}
	cgRoot := filepath.Join(dir, "cgroup")
	bardFreeze := filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze")
	gmsFreeze := filepath.Join(cgRoot, "uid_1010200", "cgroup.freeze")
	workFreeze := filepath.Join(cgRoot, "uid_1010376", "cgroup.freeze")
	for _, fp := range []string{bardFreeze, gmsFreeze, workFreeze} {
		if err := os.MkdirAll(filepath.Dir(fp), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fp, []byte("0"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	hibRunner := &sandboxRecRunner{
		out: map[string]string{
			"cmd package list packages -3 --user 10": "package:" + contracts.DefaultWorkPackage + "\npackage:com.google.android.apps.bard\npackage:com.custom.ime\n",
			"ime list -s --user 10":                  "com.custom.ime/.Input\n",
		},
	}
	cnt, err := HibernateSandboxUserWithOpts(context.Background(), hibRunner, 10, hibPath, pkgList, cgRoot)
	if err != nil {
		t.Fatal(err)
	}
	if cnt == 0 {
		t.Fatal("expected non-zero hibernated package count")
	}
	joined := strings.Join(hibRunner.calls, "\n")
	if strings.Contains(joined, "am stop-user") {
		t.Fatalf("HibernateSandboxUser must NEVER invoke am stop-user (would lock FBE keys):\n%s", joined)
	}
	if strings.Contains(joined, "sh -c") {
		t.Fatalf("HibernateSandboxUser must NEVER invoke sh -c:\n%s", joined)
	}
	if !strings.Contains(joined, "appops set --user 10 com.google.android.apps.bard RUN_ANY_IN_BACKGROUND ignore") ||
		!strings.Contains(joined, "appops set --user 10 com.google.android.apps.bard WAKE_LOCK ignore") ||
		!strings.Contains(joined, "am set-standby-bucket --user 10 com.google.android.apps.bard restricted") ||
		!strings.Contains(joined, "cmd jobscheduler cancel -u 10 com.google.android.apps.bard") ||
		!strings.Contains(joined, "am stop-app --user 10 com.google.android.apps.bard") {
		t.Fatalf("missing expected hibernation commands on Gemini:\n%s", joined)
	}
	if strings.Contains(joined, "stop-app --user 10 "+contracts.DefaultWorkPackage) ||
		strings.Contains(joined, "force-stop --user 10 "+contracts.DefaultWorkPackage) ||
		strings.Contains(joined, "stop-app --user 10 com.custom.ime") ||
		strings.Contains(joined, "force-stop --user 10 com.custom.ime") {
		t.Fatalf("must protect WorkPackage and active IME:\n%s", joined)
	}
	if b, _ := os.ReadFile(bardFreeze); string(b) != "1" {
		t.Fatalf("expected Gemini UID 1010395 cgroup.freeze=1, got %q", string(b))
	}
	if b, _ := os.ReadFile(gmsFreeze); string(b) != "0" {
		t.Fatalf("must NEVER freeze GMS UID 1010200 in cgroup, got %q", string(b))
	}
	if b, _ := os.ReadFile(workFreeze); string(b) != "0" {
		t.Fatalf("must NEVER freeze WorkPackage UID 1010376 in cgroup, got %q", string(b))
	}
	if st := ReadHibernatedState(hibPath); len(st.FrozenUIDs) != 1 || st.FrozenUIDs[0] != 1010395 {
		t.Fatalf("expected FrozenUIDs [1010395], got %+v", st.FrozenUIDs)
	}

	restoreRunner := &sandboxRecRunner{}
	rcnt, err := RestoreHibernatedSandboxUserWithOpts(context.Background(), restoreRunner, 10, hibPath, cgRoot)
	if err != nil || rcnt != cnt {
		t.Fatalf("RestoreHibernatedSandboxUserWithOpts got count=%d err=%v (want %d)", rcnt, err, cnt)
	}
	if b, _ := os.ReadFile(bardFreeze); string(b) != "0" {
		t.Fatalf("expected Gemini UID 1010395 thawed to 0, got %q", string(b))
	}
	rJoined := strings.Join(restoreRunner.calls, "\n")
	if !strings.Contains(rJoined, "appops set --user 10 com.google.android.apps.bard RUN_ANY_IN_BACKGROUND allow") ||
		!strings.Contains(rJoined, "appops set --user 10 com.google.android.apps.bard WAKE_LOCK allow") ||
		!strings.Contains(rJoined, "am set-standby-bucket --user 10 com.google.android.apps.bard active") {
		t.Fatalf("missing restore commands:\n%s", rJoined)
	}
	if _, err := os.Stat(hibPath); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed after restore, err=%v", hibPath, err)
	}

	// Root app launcher: direct component + resolve-activity fallback + shell injection guard.
	launchRunner := &sandboxRecRunner{
		out: map[string]string{
			"cmd package resolve-activity --brief --user 10 com.android.vending": "priority=0\ncom.android.vending/.AssetBrowserActivity\n",
		},
	}
	if err := LaunchSandboxAppAsRoot(context.Background(), launchRunner, 10, "com.google.android.apps.bard", ".MainActivity"); err != nil {
		t.Fatal(err)
	}
	if err := LaunchSandboxAppAsRoot(context.Background(), launchRunner, 10, "com.android.vending", ""); err != nil {
		t.Fatal(err)
	}
	lJoined := strings.Join(launchRunner.calls, "\n")
	if !strings.Contains(lJoined, "am start --user 10 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -f 0x10200000 -n com.google.android.apps.bard/.MainActivity") ||
		!strings.Contains(lJoined, "am start --user 10 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -f 0x10200000 -n com.android.vending/.AssetBrowserActivity") {
		t.Fatalf("missing expected root launch calls:\n%s", lJoined)
	}
	if err := LaunchSandboxAppAsRoot(context.Background(), launchRunner, 10, "com.android.vending", ".Main;id"); err == nil {
		t.Fatal("must reject invalid activity class with shell chars")
	}
}

type dynamicLifecycleRunner struct {
	mu    sync.Mutex
	calls []string
	onRun func(cmd string) (string, error)
}

func (d *dynamicLifecycleRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	d.mu.Lock()
	d.calls = append(d.calls, cmd)
	d.mu.Unlock()
	return d.onRun(cmd)
}

func TestInspectParsers(t *testing.T) {
	actU10 := "  topResumedActivity=ActivityRecord{12ab34 u10 com.google.android.apps.bard/.Main t52}\n"
	actU0 := "  topResumedActivity=ActivityRecord{12ab34 u0 com.tencent.mm/.ui.LauncherUI t10}\n"
	actU100 := "  topResumedActivity=ActivityRecord{12ab34 u100 foo/.Bar t1}\n"
	if !ParseTopActivityIsUser(actU10, 10) {
		t.Fatal("failed to detect u10 foreground activity")
	}
	if ParseTopActivityIsUser(actU0, 10) || ParseTopActivityIsUser(actU100, 10) {
		t.Fatal("false positive on u0 or u100")
	}

	ipt := `Chain ` + contracts.ChainTProxyOut + ` (1 references)
 pkts      bytes target     prot opt in     out     source               destination
    2      144 MARK       tcp  --  *      *       0.0.0.0/0            127.0.0.1            owner UID match 1000000-1099999 tcp dpt:53 MARK xset 0x1a/0xffff
    2      144 RETURN     all  --  *      *       0.0.0.0/0            127.0.0.1            owner UID match 1000000-1099999
    1       88 RETURN     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            owner UID match 1000000-1099999 udp dpt:443
  797   225412 MARK       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            owner UID match 1000000-1099999 MARK xset 0x1a/0xffff
   43    26170 MARK       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            owner UID match 1000000-1099999 MARK xset 0x1a/0xffff
  840   251582 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            owner UID match 1000000-1099999
`
	wantBytes := uint64(144 + 88 + 251582)
	if got := ParseIptablesChainBytes(ipt, 1000000, 1099999); got != wantBytes {
		t.Fatalf("got bytes=%d want=%d", got, wantBytes)
	}

	audioActive := "  AudioPlaybackConfiguration piid:45 type:android.media.MediaPlayer u/pid:1010395/30815 uid:1010395 state:started attr:...\n"
	audioIdle := "  AudioPlaybackConfiguration piid:12 uid:1010395 state:paused\n"
	audioU0 := "  AudioPlaybackConfiguration piid:15 uid:10262 state:started\n"
	if !ParseAudioActiveForUser(audioActive, 1000000, 1099999) {
		t.Fatal("failed to detect active u10 audio")
	}
	if ParseAudioActiveForUser(audioIdle, 1000000, 1099999) || ParseAudioActiveForUser(audioU0, 1000000, 1099999) {
		t.Fatal("false positive on paused or User 0 audio")
	}

	// InspectSandboxActivity must fail closed (return error) if any of its 3 probes fails.
	for _, failCmd := range []string{
		"dumpsys activity activities",
		"iptables -t mangle -L " + contracts.ChainTProxyOut + " -v -n -x",
		"dumpsys audio",
	} {
		probeRunner := &dynamicLifecycleRunner{
			onRun: func(cmd string) (string, error) {
				if cmd == failCmd {
					return "", errors.New("ipc failed")
				}
				return "", nil
			},
		}
		if _, err := InspectSandboxActivity(context.Background(), probeRunner, 10); err == nil {
			t.Fatalf("InspectSandboxActivity must error when %q fails", failCmd)
		}
	}
}

func TestRestoreHibernatedPriorityAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	hibPath := filepath.Join(dir, "hibernated_pkgs.json")
	cgRoot := filepath.Join(dir, "cgroup")
	bardFreeze := filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze")
	vendFreeze := filepath.Join(cgRoot, "uid_1010396", "cgroup.freeze")
	for _, fp := range []string{bardFreeze, vendFreeze} {
		if err := os.MkdirAll(filepath.Dir(fp), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fp, []byte("1"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := writeHibernatedState(hibPath, HibernatedState{
		UserID: 10,
		Packages: []string{
			"com.android.vending",
			"com.google.android.apps.bard",
			"com.google.android.gms",
			"com.google.android.googlequicksearchbox",
			"com.google.android.gsf",
		},
		FrozenUIDs: []int{1010395, 1010396},
	}); err != nil {
		t.Fatal(err)
	}

	prioRunner := &sandboxRecRunner{}
	restoredNow, remaining, err := RestoreHibernatedPriorityWithOpts(context.Background(), prioRunner, 10, hibPath, cgRoot, []string{"com.google.android.apps.bard"})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bardFreeze); string(b) != "0" {
		t.Fatalf("expected bard UID thawed immediately, got %q", string(b))
	}
	if b, _ := os.ReadFile(vendFreeze); string(b) != "0" {
		t.Fatalf("expected vending UID thawed immediately alongside all cgroups, got %q", string(b))
	}
	if restoredNow != 4 {
		t.Fatalf("expected 4 priority packages restored synchronously (bard, googlequicksearchbox, gms, gsf), got %d", restoredNow)
	}
	wantRem := []string{"com.android.vending"}
	if !reflect.DeepEqual(remaining, wantRem) {
		t.Fatalf("remaining = %v want %v", remaining, wantRem)
	}
	prioJoined := strings.Join(prioRunner.calls, "\n")
	if !strings.Contains(prioJoined, "appops set --user 10 com.google.android.apps.bard RUN_ANY_IN_BACKGROUND allow") ||
		!strings.Contains(prioJoined, "appops set --user 10 com.google.android.googlequicksearchbox RUN_ANY_IN_BACKGROUND allow") ||
		!strings.Contains(prioJoined, "appops set --user 10 com.google.android.gms RUN_ANY_IN_BACKGROUND allow") ||
		!strings.Contains(prioJoined, "appops set --user 10 com.google.android.gsf RUN_ANY_IN_BACKGROUND allow") {
		t.Fatalf("missing priority restore calls:\n%s", prioJoined)
	}
	if strings.Contains(prioJoined, "com.android.vending") {
		t.Fatalf("non-priority package com.android.vending must wait for async pass:\n%s", prioJoined)
	}
	midState := ReadHibernatedState(hibPath)
	if !reflect.DeepEqual(midState.Packages, wantRem) || len(midState.FrozenUIDs) != 0 {
		t.Fatalf("unexpected intermediate hibernated state: %+v", midState)
	}

	fullRunner := &sandboxRecRunner{}
	remCount, err := RestoreHibernatedSandboxUserWithOpts(context.Background(), fullRunner, 10, hibPath, cgRoot)
	if err != nil || remCount != 1 {
		t.Fatalf("expected remaining 1 package restored, got count=%d err=%v", remCount, err)
	}
	if _, err := os.Stat(hibPath); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed after remaining restore, err=%v", hibPath, err)
	}

	// Verify bounded 4-worker concurrency in HibernateSandboxUserWithOpts.
	var inFlight, maxInFlight atomic.Int32
	concRunner := &dynamicLifecycleRunner{
		onRun: func(cmd string) (string, error) {
			if cmd == "cmd package list packages -3 --user 10" {
				return "package:com.example.app1\npackage:com.example.app2\npackage:com.example.app3\npackage:com.example.app4\npackage:com.example.app5\npackage:com.example.app6\npackage:com.example.app7\npackage:com.example.app8\n", nil
			}
			if strings.Contains(cmd, "RUN_ANY_IN_BACKGROUND ignore") && strings.Contains(cmd, "com.example.app") {
				cur := inFlight.Add(1)
				for {
					prev := maxInFlight.Load()
					if cur <= prev || maxInFlight.CompareAndSwap(prev, cur) {
						break
					}
				}
				time.Sleep(15 * time.Millisecond)
				inFlight.Add(-1)
			}
			return "", nil
		},
	}
	pkgList := filepath.Join(dir, "packages.list")
	_ = os.WriteFile(pkgList, []byte(""), 0600)
	hibCnt, err := HibernateSandboxUserWithOpts(context.Background(), concRunner, 10, hibPath, pkgList, cgRoot)
	if err != nil || hibCnt < 8 {
		t.Fatalf("expected >=8 hibernated packages, got %d err=%v", hibCnt, err)
	}
	peak := maxInFlight.Load()
	if peak < 2 || peak > sandboxWorkerPoolSize {
		t.Fatalf("expected peak worker concurrency in [2,%d], got %d", sandboxWorkerPoolSize, peak)
	}
	concJoined := strings.Join(concRunner.calls, "\n")
	if strings.Contains(concJoined, "am stop-user") || strings.Contains(concJoined, "sh -c") {
		t.Fatalf("forbidden am stop-user or sh -c detected:\n%s", concJoined)
	}

	// Verify pre-cancelled context does NOT wipe hibernated_pkgs.json.
	if err := writeHibernatedState(hibPath, HibernatedState{
		UserID:   10,
		Packages: []string{"com.android.vending", "com.google.android.apps.bard"},
	}); err != nil {
		t.Fatal(err)
	}
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, _, err := RestoreHibernatedPriorityWithOpts(cctx, &sandboxRecRunner{}, 10, hibPath, cgRoot, nil); err != nil {
		t.Fatal(err)
	}
	if stAfter := ReadHibernatedState(hibPath); len(stAfter.Packages) != 2 {
		t.Fatalf("cancelled restore must preserve pending packages in %s, got %+v", hibPath, stAfter.Packages)
	}

	// Verify com.android.chrome is included alongside target app + GMS/GSF in priority restore.
	if err := writeHibernatedState(hibPath, HibernatedState{
		UserID: 10,
		Packages: []string{
			"com.android.chrome",
			"com.android.vending",
			"com.google.android.apps.bard",
			"com.google.android.gms",
		},
	}); err != nil {
		t.Fatal(err)
	}
	chromeRunner := &sandboxRecRunner{}
	chRestored, chRem, err := RestoreHibernatedPriorityWithOpts(context.Background(), chromeRunner, 10, hibPath, cgRoot, []string{"com.google.android.apps.bard"})
	if err != nil || chRestored != 3 || !reflect.DeepEqual(chRem, []string{"com.android.vending"}) {
		t.Fatalf("chrome priority restore mismatch: restored=%d rem=%v err=%v", chRestored, chRem, err)
	}
	chJoined := strings.Join(chromeRunner.calls, "\n")
	if !strings.Contains(chJoined, "appops set --user 10 com.android.chrome RUN_ANY_IN_BACKGROUND allow") {
		t.Fatalf("expected Chrome priority-restored with Gemini:\n%s", chJoined)
	}
}

type noopLifecycleRunner struct{}

func (noopLifecycleRunner) Run(_ context.Context, _ time.Duration, _ string, _ string, _ ...string) (string, error) {
	return "", nil
}

func BenchmarkHibernateAndPriorityRestore(b *testing.B) {
	dir := b.TempDir()
	hibPath := filepath.Join(dir, "hib_bench.json")
	cgRoot := filepath.Join(dir, "cgroup")
	pkgs := []string{
		"com.android.vending",
		"com.google.android.apps.bard",
		"com.google.android.gms",
		"com.google.android.googlequicksearchbox",
		"com.google.android.gsf",
		"com.google.android.apps.subscriptions.red",
	}
	freezeFile := filepath.Join(cgRoot, "uid_1010395", "cgroup.freeze")
	_ = os.MkdirAll(filepath.Dir(freezeFile), 0755)
	_ = os.WriteFile(freezeFile, []byte("1"), 0644)

	r := noopLifecycleRunner{}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		_ = writeHibernatedState(hibPath, HibernatedState{
			UserID:     10,
			Packages:   pkgs,
			FrozenUIDs: []int{1010395},
		})
		_ = os.WriteFile(freezeFile, []byte("1"), 0644)
		b.StartTimer()
		_, _, _ = RestoreHibernatedPriorityWithOpts(ctx, r, 10, hibPath, cgRoot, []string{"com.google.android.apps.bard"})
	}
}
