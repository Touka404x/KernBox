package android

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
	"sandbox_guard/internal/sysio"
)

const sandboxWorkerPoolSize = 4

var (
	actUserStateRegex = regexp.MustCompile(`(?m)^\s*User #([0-9]+):\s*state=([A-Z_]+)`)
	audioUIDRegex     = regexp.MustCompile(`\buid[:=\s]+([0-9]+)\b`)
	hibFileMu         sync.Mutex
)

type SandboxActivitySnapshot struct {
	UserState      string `json:"user_state"`
	ForegroundUser bool   `json:"foreground_user"`
	AudioActive    bool   `json:"audio_active"`
	TrafficBytes   uint64 `json:"traffic_bytes"`
}

type HibernatedState struct {
	UserID               int      `json:"user_id"`
	Packages             []string `json:"packages"`
	FrozenUIDs           []int    `json:"frozen_uids,omitempty"`
	HotFrozen            bool     `json:"hot_frozen,omitempty"`
	SkippedAppOpsPkgs    []string `json:"skipped_appops_pkgs,omitempty"`
	RestrictedAppOpsPkgs []string `json:"restricted_appops_pkgs,omitempty"`
	UpdatedAt            string   `json:"updated_at"`
}

// LifecycleOptions configures v2.5.0+ hibernation/restore fast paths.
type LifecycleOptions struct {
	CallerPackage       string
	PackagesListPath    string
	CgroupRoot          string
	SkipAppOpsForFrozen bool
	SyncTargetOnly      bool
}

var baseHibernationProtectedPkgs = map[string]bool{
	contracts.DefaultWorkPackage:             true,
	contracts.ManagedProvisioningPkg:         true,
	"android":                                true,
	"com.android.systemui":                   true,
	"com.android.settings":                   true,
	"com.android.phone":                      true,
	"com.android.bluetooth":                  true,
	"com.android.webview":                    true,
	"com.google.android.webview":             true,
	"com.android.packageinstaller":           true,
	"com.google.android.packageinstaller":    true,
	"com.android.certinstaller":              true,
	"com.android.providers.media":            true,
	"com.android.providers.media.module":     true,
	"com.android.externalstorage":            true,
	"com.android.documentsui":                true,
	"com.google.android.documentsui":         true,
	"com.android.keychain":                   true,
	"com.android.permissioncontroller":       true,
	"com.google.android.permissioncontroller": true,
	"com.android.se":                         true,
	"com.android.providers.settings":         true,
	"com.android.providers.downloads":        true,
	"com.android.networkstack":               true,
	"com.android.networkstack.process":       true,
}

func hibernationProtectedPkgSet(extra ...string) map[string]bool {
	out := make(map[string]bool, len(baseHibernationProtectedPkgs)+len(oem.Current().ExtraProtectedPackages)+len(extra))
	for k, v := range baseHibernationProtectedPkgs {
		out[k] = v
	}
	for _, pkg := range oem.Current().ExtraProtectedPackages {
		if contracts.ValidPackageName(pkg) {
			out[pkg] = true
		}
	}
	for _, pkg := range extra {
		if contracts.ValidPackageName(pkg) {
			out[pkg] = true
		}
	}
	return out
}

// ParseUserStateFromActivityUsers extracts state=... for userID from `dumpsys activity users`.
func ParseUserStateFromActivityUsers(output string, userID int) string {
	want := strconv.Itoa(userID)
	for _, m := range actUserStateRegex.FindAllStringSubmatch(output, -1) {
		if len(m) == 3 && m[1] == want {
			return strings.TrimSpace(m[2])
		}
	}
	return ""
}

// StartSandboxUserAndWait wakes a stopped/quiet sandbox user (e.g., after deep pause or boot)
// and waits up to timeout until dumpsys activity users reports state=RUNNING_UNLOCKED.
func StartSandboxUserAndWait(ctx context.Context, r Runner, userID int, timeout time.Duration) error {
	if oem.IsForbiddenUser(userID) {
		return fmt.Errorf("refusing to start forbidden user %d", userID)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	u := strconv.Itoa(userID)

	if out, err := r.Run(ctx, 4*time.Second, "", "dumpsys", "activity", "users"); err == nil {
		if ParseUserStateFromActivityUsers(out, userID) == "RUNNING_UNLOCKED" {
			return nil
		}
	}

	if _, err := r.Run(ctx, 8*time.Second, "", "am", "start-user", "-w", u); err != nil {
		// Fallback for older/vendor shells where `cmd user start-user` is preferred.
		if _, err2 := r.Run(ctx, 8*time.Second, "", "cmd", "user", "start-user", u); err2 != nil {
			return fmt.Errorf("start sandbox user %d: %w / %v", userID, err, err2)
		}
	}

	deadline := time.Now().Add(timeout)
	lockedSeen := 0
	lastState := ""
	for {
		out, err := r.Run(ctx, 4*time.Second, "", "dumpsys", "activity", "users")
		if err == nil {
			lastState = ParseUserStateFromActivityUsers(out, userID)
			if lastState == "RUNNING_UNLOCKED" {
				return nil
			}
			if lastState == "RUNNING_LOCKED" {
				lockedSeen++
				if lockedSeen >= 2 {
					return fmt.Errorf("工作资料处于加密锁定状态，请点按通知或解锁手机屏幕一次后重试 (user=%d state=%s)", userID, lastState)
				}
			}
		}
		if time.Now().After(deadline) {
			if lastState == "" {
				lastState = "UNKNOWN"
			}
			if lastState == "RUNNING_LOCKED" {
				return fmt.Errorf("工作资料处于加密锁定状态，请点按通知或解锁手机屏幕一次后重试 (user=%d state=%s)", userID, lastState)
			}
			return fmt.Errorf("sandbox user %d did not reach RUNNING_UNLOCKED within %s (state=%s)", userID, timeout, lastState)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(120 * time.Millisecond):
		}
	}
}

type userProcEntry struct {
	pid int
	uid int
	pkg string
}

func cgroupHasAnyUIDDirs(cgroupRoot string) bool {
	if strings.TrimSpace(cgroupRoot) == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	entries, err := os.ReadDir(cgroupRoot)
	if err != nil {
		return false
	}
	for _, ent := range entries {
		if ent.IsDir() && strings.HasPrefix(ent.Name(), "uid_") {
			return true
		}
	}
	return false
}

func scanUserProcEntries(userID int) []userProcEntry {
	return scanUserProcEntriesWithRootFS("/sys/fs/cgroup", "/proc", userID)
}

func scanUserProcEntriesWithRoot(cgroupRoot string, userID int) []userProcEntry {
	return scanUserProcEntriesWithRootFS(cgroupRoot, "/proc", userID)
}

func scanUserProcEntriesWithRootFS(cgroupRoot, procRoot string, userID int) []userProcEntry {
	if oem.IsForbiddenUser(userID) {
		return nil
	}
	if strings.TrimSpace(cgroupRoot) == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	if strings.TrimSpace(procRoot) == "" {
		procRoot = "/proc"
	}
	uidStart := userID * contracts.AndroidUserWidth
	uidEnd := uidStart + contracts.AndroidUserWidth - 1

	readCmdPkg := func(pid int) string {
		cmdBytes, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
		if err != nil || len(cmdBytes) == 0 {
			return ""
		}
		procName := strings.TrimSpace(strings.SplitN(string(cmdBytes), "\x00", 2)[0])
		cand, _, _ := strings.Cut(procName, ":")
		if contracts.ValidPackageName(cand) {
			return cand
		}
		return ""
	}

	if cgEntries, err := os.ReadDir(cgroupRoot); err == nil {
		hasUIDDirs := false
		var matchedDirs []struct {
			name string
			uid  int
		}
		for _, ent := range cgEntries {
			if !ent.IsDir() || !strings.HasPrefix(ent.Name(), "uid_") {
				continue
			}
			hasUIDDirs = true
			uid, uerr := strconv.Atoi(strings.TrimPrefix(ent.Name(), "uid_"))
			if uerr != nil || uid < uidStart || uid > uidEnd {
				continue
			}
			matchedDirs = append(matchedDirs, struct {
				name string
				uid  int
			}{name: ent.Name(), uid: uid})
		}
		if hasUIDDirs {
			var procs []userProcEntry
			seenPID := make(map[int]struct{})
			appendProcsFile := func(uid int, procsFile string) {
				procsBytes, perr := os.ReadFile(procsFile)
				if perr != nil {
					return
				}
				for _, f := range strings.Fields(string(procsBytes)) {
					pid, ierr := strconv.Atoi(f)
					if ierr != nil || pid <= 1 {
						continue
					}
					if _, dup := seenPID[pid]; dup {
						continue
					}
					seenPID[pid] = struct{}{}
					procs = append(procs, userProcEntry{
						pid: pid,
						uid: uid,
						pkg: readCmdPkg(pid),
					})
				}
			}
			for _, md := range matchedDirs {
				uidPath := filepath.Join(cgroupRoot, md.name)
				appendProcsFile(md.uid, filepath.Join(uidPath, "cgroup.procs"))
				if subEnts, serr := os.ReadDir(uidPath); serr == nil {
					for _, se := range subEnts {
						if se.IsDir() && strings.HasPrefix(se.Name(), "pid_") {
							appendProcsFile(md.uid, filepath.Join(uidPath, se.Name(), "cgroup.procs"))
						}
					}
				}
			}
			return procs
		}
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var procs []userProcEntry
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 1 {
			continue
		}
		statusBytes, err := os.ReadFile(filepath.Join(procRoot, ent.Name(), "status"))
		if err != nil {
			continue
		}
		uid := -1
		for _, line := range strings.Split(string(statusBytes), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if parsed, perr := strconv.Atoi(fields[1]); perr == nil {
						uid = parsed
					}
				}
				break
			}
		}
		if uid < uidStart || uid > uidEnd {
			continue
		}
		procs = append(procs, userProcEntry{pid: pid, uid: uid, pkg: readCmdPkg(pid)})
	}
	return procs
}

// discoverRunningUserPackages inspects /sys/fs/cgroup (falling back to /proc/<pid>) to find active packages in userID.
func discoverRunningUserPackages(userID int) []string {
	return discoverRunningUserPackagesWithRoot("/sys/fs/cgroup", userID)
}

func discoverRunningUserPackagesWithRoot(cgroupRoot string, userID int) []string {
	return discoverRunningUserPackagesWithRootFS(cgroupRoot, "/proc", userID)
}

func discoverRunningUserPackagesWithRootFS(cgroupRoot, procRoot string, userID int) []string {
	seen := make(map[string]bool)
	for _, p := range scanUserProcEntriesWithRootFS(cgroupRoot, procRoot, userID) {
		appID := p.uid % contracts.AndroidUserWidth
		if appID < contracts.MinAppID || appID >= 90000 {
			continue
		}
		if p.pkg != "" {
			seen[p.pkg] = true
		}
	}
	out := make([]string, 0, len(seen))
	for pkg := range seen {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out
}

// CountRunningUserProcesses returns the live count of OS processes owned by userID.
func CountRunningUserProcesses(userID int) int {
	return CountRunningUserProcessesWithRoot("/sys/fs/cgroup", userID)
}

// CountRunningUserProcessesWithRoot counts userID processes via cgroup v2 uid dirs (O(uid_10*)) with /proc fallback.
func CountRunningUserProcessesWithRoot(cgroupRoot string, userID int) int {
	return len(scanUserProcEntriesWithRoot(cgroupRoot, userID))
}

func killStraySandboxProcesses(userID int, protected map[string]bool) int {
	return killStraySandboxProcessesWithRoot("/sys/fs/cgroup", userID, protected)
}

func killStraySandboxProcessesWithRoot(cgroupRoot string, userID int, protected map[string]bool) int {
	killed := 0
	for _, p := range scanUserProcEntriesWithRoot(cgroupRoot, userID) {
		appID := p.uid % contracts.AndroidUserWidth
		if appID >= 90000 {
			if killPIDHardForUser(p.pid, userID) == nil {
				killed++
			}
			continue
		}
		if p.pkg == "" || protected[p.pkg] {
			continue
		}
		if killPIDHardForUser(p.pid, userID) == nil {
			killed++
		}
	}
	return killed
}

// ResolveFreezableUIDs maps hibernated user-facing packages to userID-scoped UIDs via packages.list,
// strictly skipping GMS/GSF and protected system packages so system_server Binder IPC never blocks.
func ResolveFreezableUIDs(packagesListPath string, userID int, pkgs []string, extraProtected ...string) []int {
	if oem.IsForbiddenUser(userID) || len(pkgs) == 0 {
		return nil
	}
	if packagesListPath == "" {
		packagesListPath = contracts.PackagesListPath
	}
	protected := hibernationProtectedPkgSet(extraProtected...)
	wantPkg := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		if !contracts.ValidPackageName(p) || protected[p] ||
			p == "com.google.android.gms" || p == "com.google.android.gsf" {
			continue
		}
		wantPkg[p] = true
	}
	if len(wantPkg) == 0 {
		return nil
	}
	f, err := os.Open(packagesListPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[int]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || !wantPkg[fields[0]] {
			continue
		}
		rawID, perr := strconv.Atoi(fields[1])
		if perr != nil || rawID < 0 {
			continue
		}
		appID := rawID % contracts.AndroidUserWidth
		if appID >= contracts.MinAppID && appID < 90000 {
			seen[userID*contracts.AndroidUserWidth+appID] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	sort.Ints(out)
	return out
}

// SetCgroupFreezeUIDs freezes or thaws User-N cgroup v2 (or cgroup v1 freezer fallback) UID
// hierarchies strictly within [minApp, 99999].
func SetCgroupFreezeUIDs(cgroupRoot string, userID int, uids []int, freeze bool) []int {
	if oem.IsForbiddenUser(userID) || len(uids) == 0 {
		return nil
	}
	if strings.TrimSpace(cgroupRoot) == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	val := []byte("0")
	v1Val := []byte("THAWED")
	if freeze {
		val = []byte("1")
		v1Val = []byte("FROZEN")
	}
	uidMin := userID*contracts.AndroidUserWidth + contracts.MinAppID
	uidMax := userID*contracts.AndroidUserWidth + 99999
	var updated []int
	for _, uid := range uids {
		if uid < uidMin || uid > uidMax {
			continue
		}
		freezeFile := filepath.Join(cgroupRoot, fmt.Sprintf("uid_%d", uid), "cgroup.freeze")
		if _, err := os.Stat(freezeFile); err == nil {
			if os.WriteFile(freezeFile, val, 0644) == nil {
				updated = append(updated, uid)
			}
			continue
		}
		v1File := filepath.Join(cgroupRoot, "freezer", fmt.Sprintf("uid_%d", uid), "freezer.state")
		if _, err := os.Stat(v1File); err == nil {
			if os.WriteFile(v1File, v1Val, 0644) == nil {
				updated = append(updated, uid)
			}
			continue
		}
		if cgroupRoot == "/sys/fs/cgroup" {
			devFreezer := filepath.Join("/dev/freezer", fmt.Sprintf("uid_%d", uid), "freezer.state")
			if _, err := os.Stat(devFreezer); err == nil {
				if os.WriteFile(devFreezer, v1Val, 0644) == nil {
					updated = append(updated, uid)
				}
			}
		}
	}
	return updated
}

func mergeUniqueInts(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		seen[v] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// ReadHibernatedState reads persisted hibernation state from statePath (returns zero value if absent).
func ReadHibernatedState(path string) HibernatedState {
	return readHibernatedState(path)
}

func readHibernatedState(path string) HibernatedState {
	if path == "" {
		return HibernatedState{}
	}
	hibFileMu.Lock()
	b, err := sysio.ReadRootOwnedSmallFile(path, contracts.MaxSmallFileBytes)
	hibFileMu.Unlock()
	if err == nil {
		var st HibernatedState
		if json.Unmarshal(b, &st) == nil {
			return st
		}
	}
	return HibernatedState{}
}

func writeHibernatedState(path string, st HibernatedState) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	hibFileMu.Lock()
	defer hibFileMu.Unlock()
	return sysio.WriteAtomic(path, append(b, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
}

func removeHibernatedState(path string) {
	if path == "" {
		return
	}
	hibFileMu.Lock()
	defer hibFileMu.Unlock()
	for i := 0; i < 4; i++ {
		err := os.Remove(path)
		if err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func runPackagePool(ctx context.Context, pkgs []string, workers int, fn func(pkg string)) {
	if len(pkgs) == 0 {
		return
	}
	if workers <= 0 {
		workers = 1
	}
	if workers > len(pkgs) {
		workers = len(pkgs)
	}
	if workers == 1 {
		for _, pkg := range pkgs {
			if ctx.Err() != nil {
				return
			}
			fn(pkg)
		}
		return
	}
	ch := make(chan string, len(pkgs))
	for _, pkg := range pkgs {
		ch <- pkg
	}
	close(ch)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for pkg := range ch {
				if ctx.Err() != nil {
					return
				}
				fn(pkg)
			}
		}()
	}
	wg.Wait()
}

func hibernateSinglePackage(ctx context.Context, r Runner, u, pkg string) {
	_, _ = r.Run(ctx, 3*time.Second, "", "appops", "set", "--user", u, pkg, "RUN_ANY_IN_BACKGROUND", "ignore")
	_, _ = r.Run(ctx, 3*time.Second, "", "appops", "set", "--user", u, pkg, "WAKE_LOCK", "ignore")
	_, _ = r.Run(ctx, 3*time.Second, "", "am", "set-standby-bucket", "--user", u, pkg, "restricted")
	_, _ = r.Run(ctx, 3*time.Second, "", "cmd", "jobscheduler", "cancel", "-u", u, pkg)
	_, _ = r.Run(ctx, 3*time.Second, "", "am", "force-stop", "--user", u, pkg)
}

func restoreSinglePackage(ctx context.Context, r Runner, u, pkg string) {
	_, _ = r.Run(ctx, 3*time.Second, "", "appops", "set", "--user", u, pkg, "RUN_ANY_IN_BACKGROUND", "allow")
	_, _ = r.Run(ctx, 3*time.Second, "", "appops", "set", "--user", u, pkg, "WAKE_LOCK", "allow")
	_, _ = r.Run(ctx, 3*time.Second, "", "am", "set-standby-bucket", "--user", u, pkg, "active")
}

func hibernateSinglePackageNoAppOps(ctx context.Context, r Runner, u, pkg string) {
	_, _ = r.Run(ctx, 3*time.Second, "", "cmd", "jobscheduler", "cancel", "-u", u, pkg)
	_, _ = r.Run(ctx, 3*time.Second, "", "am", "force-stop", "--user", u, pkg)
}

func resolvePkgUIDMap(packagesListPath string, userID int, pkgs []string, extraProtected ...string) map[string]int {
	if oem.IsForbiddenUser(userID) || len(pkgs) == 0 {
		return nil
	}
	if strings.TrimSpace(packagesListPath) == "" {
		packagesListPath = contracts.PackagesListPath
	}
	protected := hibernationProtectedPkgSet(extraProtected...)
	wantPkg := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		if !contracts.ValidPackageName(p) || protected[p] ||
			p == "com.google.android.gms" || p == "com.google.android.gsf" {
			continue
		}
		wantPkg[p] = true
	}
	if len(wantPkg) == 0 {
		return nil
	}
	f, err := os.Open(packagesListPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	out := make(map[string]int, len(wantPkg))
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || !wantPkg[fields[0]] {
			continue
		}
		rawID, perr := strconv.Atoi(fields[1])
		if perr != nil || rawID < 0 {
			continue
		}
		appID := rawID % contracts.AndroidUserWidth
		if appID >= contracts.MinAppID && appID < 90000 {
			out[fields[0]] = userID*contracts.AndroidUserWidth + appID
		}
	}
	return out
}

func hasCgroupFreezeControl(cgroupRoot string, uid int) bool {
	if strings.TrimSpace(cgroupRoot) == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, fmt.Sprintf("uid_%d", uid), "cgroup.freeze")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot, "freezer", fmt.Sprintf("uid_%d", uid), "freezer.state")); err == nil {
		return true
	}
	if cgroupRoot == "/sys/fs/cgroup" {
		if _, err := os.Stat(filepath.Join("/dev/freezer", fmt.Sprintf("uid_%d", uid), "freezer.state")); err == nil {
			return true
		}
	}
	return false
}

// HasAnyCgroupFreezeSupport reports whether any writable per-UID cgroup v2 or cgroup v1 freezer
// hierarchy exists under cgroupRoot (or /dev/freezer for legacy cgroup v1 Android mounts).
func HasAnyCgroupFreezeSupport(cgroupRoot string, userID int) bool {
	if strings.TrimSpace(cgroupRoot) == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	roots := []string{cgroupRoot, filepath.Join(cgroupRoot, "freezer")}
	if cgroupRoot == "/sys/fs/cgroup" {
		roots = append(roots, "/dev/freezer")
	}
	uidMin := userID*contracts.AndroidUserWidth + contracts.MinAppID
	uidMax := userID*contracts.AndroidUserWidth + 99999
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() || !strings.HasPrefix(ent.Name(), "uid_") {
				continue
			}
			uid, perr := strconv.Atoi(strings.TrimPrefix(ent.Name(), "uid_"))
			if perr != nil {
				continue
			}
			if uid == 0 || (userID > 0 && uid >= uidMin && uid <= uidMax) {
				if _, err := os.Stat(filepath.Join(root, ent.Name(), "cgroup.freeze")); err == nil {
					return true
				}
				if _, err := os.Stat(filepath.Join(root, ent.Name(), "freezer.state")); err == nil {
					return true
				}
			}
		}
	}
	return false
}

// HibernateSandboxUser executes FBE-safe Root In-Place Hibernation with default kernel paths.
func HibernateSandboxUser(ctx context.Context, r Runner, userID int, statePath string) (int, error) {
	return HibernateSandboxUserWithOpts(ctx, r, userID, statePath, contracts.PackagesListPath, "")
}

// HibernateSandboxUserWithOpts preserves v2.4.0 FBE-safe hibernation semantics across direct callers.
func HibernateSandboxUserWithOpts(ctx context.Context, r Runner, userID int, statePath, packagesListPath, cgroupRoot string) (int, error) {
	return HibernateSandboxUserEx(ctx, r, userID, statePath, LifecycleOptions{
		PackagesListPath:    packagesListPath,
		CgroupRoot:          cgroupRoot,
		SkipAppOpsForFrozen: false,
	})
}

// HibernateSandboxUserEx executes FBE-safe Root In-Place Hibernation without calling `am stop-user`
// (keeping User N RUNNING_UNLOCKED and Android FBE CE keys loaded).
// When SkipAppOpsForFrozen is enabled and uid_<uid>/cgroup.freeze exists for a non-GMS package,
// redundant appops/standby-bucket Binder CLI forks are skipped in favor of kernel cgroup.freeze.
func HibernateSandboxUserEx(ctx context.Context, r Runner, userID int, statePath string, opts LifecycleOptions) (int, error) {
	if oem.IsForbiddenUser(userID) {
		return 0, fmt.Errorf("refusing to hibernate forbidden user %d", userID)
	}
	u := strconv.Itoa(userID)
	thirdOut, _ := r.Run(ctx, 5*time.Second, "", "cmd", "package", "list", "packages", "-3", "--user", u)
	thirdPkgs := parsePackageList(thirdOut)
	runningPkgs := discoverRunningUserPackagesWithRoot(opts.CgroupRoot, userID)

	imeOut, _ := r.Run(ctx, 4*time.Second, "", "ime", "list", "-s", "--user", u)
	imeProtected := parseIMEPkgs(imeOut)

	protected := hibernationProtectedPkgSet(opts.CallerPackage)
	for k, v := range imeProtected {
		protected[k] = v
	}

	targets := mergeSortedUnique(thirdPkgs, coreSandboxApps, []string{"com.google.android.gsf"}, runningPkgs)
	eligible := make([]string, 0, len(targets))
	for _, pkg := range targets {
		if !contracts.ValidPackageName(pkg) || protected[pkg] {
			continue
		}
		eligible = append(eligible, pkg)
	}

	pkgUIDs := resolvePkgUIDMap(opts.PackagesListPath, userID, eligible, opts.CallerPackage)
	freezeCapable := make(map[string]bool, len(pkgUIDs))
	freezableUIDSet := make(map[int]struct{}, len(pkgUIDs))
	for pkg, uid := range pkgUIDs {
		freezableUIDSet[uid] = struct{}{}
		if opts.SkipAppOpsForFrozen && hasCgroupFreezeControl(opts.CgroupRoot, uid) {
			freezeCapable[pkg] = true
		}
	}

	var mu sync.Mutex
	hibernated := make([]string, 0, len(eligible))
	skippedAppOps := make([]string, 0, len(eligible))
	restrictedAppOps := make([]string, 0, len(eligible))
	actuallySkipped := make(map[string]bool, len(eligible))
	runPackagePool(ctx, eligible, sandboxWorkerPoolSize, func(pkg string) {
		skipOps := freezeCapable[pkg]
		mu.Lock()
		hibernated = append(hibernated, pkg)
		if skipOps {
			actuallySkipped[pkg] = true
		} else {
			restrictedAppOps = append(restrictedAppOps, pkg)
		}
		mu.Unlock()
		if skipOps {
			hibernateSinglePackageNoAppOps(ctx, r, u, pkg)
		} else {
			hibernateSinglePackage(ctx, r, u, pkg)
		}
	})
	_ = killStraySandboxProcessesWithRoot(opts.CgroupRoot, userID, protected)

	freezableUIDs := make([]int, 0, len(freezableUIDSet))
	for uid := range freezableUIDSet {
		freezableUIDs = append(freezableUIDs, uid)
	}
	sort.Ints(freezableUIDs)
	frozenNow := SetCgroupFreezeUIDs(opts.CgroupRoot, userID, freezableUIDs, true)
	frozenSet := make(map[int]bool, len(frozenNow))
	for _, uid := range frozenNow {
		frozenSet[uid] = true
	}

	// If force-stop caused Android to destroy uid_<uid>/cgroup.freeze before SetCgroupFreezeUIDs ran,
	// fall back to full appops + standby restriction so zero packages end up both unrestricted & unfrozen.
	var fallbackPkgs []string
	for pkg := range actuallySkipped {
		uid := pkgUIDs[pkg]
		if !frozenSet[uid] {
			fallbackPkgs = append(fallbackPkgs, pkg)
		}
	}
	if len(fallbackPkgs) > 0 {
		runPackagePool(ctx, fallbackPkgs, sandboxWorkerPoolSize, func(pkg string) {
			hibernateSinglePackage(ctx, r, u, pkg)
		})
		for _, pkg := range fallbackPkgs {
			delete(actuallySkipped, pkg)
			restrictedAppOps = append(restrictedAppOps, pkg)
		}
	}
	for pkg := range actuallySkipped {
		skippedAppOps = append(skippedAppOps, pkg)
	}

	sort.Strings(hibernated)
	sort.Strings(restrictedAppOps)

	if statePath != "" {
		prev := readHibernatedState(statePath)
		merged := mergeSortedUnique(prev.Packages, hibernated)
		mergedFrozen := mergeUniqueInts(prev.FrozenUIDs, frozenNow)
		mergedRestricted := mergeSortedUnique(prev.RestrictedAppOpsPkgs, restrictedAppOps)
		restrictedMap := make(map[string]bool, len(mergedRestricted))
		for _, p := range mergedRestricted {
			restrictedMap[p] = true
		}
		var mergedSkipped []string
		for _, p := range mergeSortedUnique(prev.SkippedAppOpsPkgs, skippedAppOps) {
			if !restrictedMap[p] {
				mergedSkipped = append(mergedSkipped, p)
			}
		}
		sort.Strings(merged)
		_ = writeHibernatedState(statePath, HibernatedState{
			UserID:               userID,
			Packages:             merged,
			FrozenUIDs:           mergedFrozen,
			HotFrozen:            false,
			SkippedAppOpsPkgs:    mergedSkipped,
			RestrictedAppOpsPkgs: mergedRestricted,
			UpdatedAt:            time.Now().UTC().Format(time.RFC3339),
		})
	}
	return len(hibernated), nil
}

// HotFreezeSandboxUserWithOpts performs L1 zero-kill cgroup.freeze + MADV_PAGEOUT memory reclaim
// so frozen User 10 apps consume 0% CPU and minimal RAM while resuming at exact pixel state in <0.5ms.
func HotFreezeSandboxUserWithOpts(ctx context.Context, r Runner, userID int, statePath, packagesListPath, cgroupRoot string, extraProtected ...string) (int, error) {
	if oem.IsForbiddenUser(userID) {
		return 0, fmt.Errorf("refusing to hot-freeze forbidden user %d", userID)
	}
	u := strconv.Itoa(userID)
	var thirdOut, imeOut string
	var listWg sync.WaitGroup
	listWg.Add(2)
	go func() {
		defer listWg.Done()
		thirdOut, _ = r.Run(ctx, 5*time.Second, "", "cmd", "package", "list", "packages", "-3", "--user", u)
	}()
	go func() {
		defer listWg.Done()
		imeOut, _ = r.Run(ctx, 4*time.Second, "", "ime", "list", "-s", "--user", u)
	}()
	listWg.Wait()

	thirdPkgs := parsePackageList(thirdOut)
	initialEntries := scanUserProcEntriesWithRoot(cgroupRoot, userID)
	runningSeen := make(map[string]bool)
	isolatedUIDSet := make(map[int]struct{})
	for _, pe := range initialEntries {
		appID := pe.uid % contracts.AndroidUserWidth
		if pe.pkg != "" && appID >= contracts.MinAppID && appID < 90000 {
			runningSeen[pe.pkg] = true
		}
		if appID >= 90000 {
			isolatedUIDSet[pe.uid] = struct{}{}
		}
	}
	var runningPkgs []string
	for p := range runningSeen {
		runningPkgs = append(runningPkgs, p)
	}

	imeProtected := parseIMEPkgs(imeOut)
	protected := hibernationProtectedPkgSet(extraProtected...)
	for k, v := range imeProtected {
		protected[k] = v
	}

	targets := mergeSortedUnique(thirdPkgs, coreSandboxApps, runningPkgs)
	eligible := make([]string, 0, len(targets))
	for _, pkg := range targets {
		if !contracts.ValidPackageName(pkg) || protected[pkg] || pkg == "com.google.android.gms" || pkg == "com.google.android.gsf" {
			continue
		}
		eligible = append(eligible, pkg)
	}
	pkgUIDs := resolvePkgUIDMap(packagesListPath, userID, eligible, extraProtected...)
	uidSet := make(map[int]struct{}, len(pkgUIDs)+len(isolatedUIDSet))
	for _, uid := range pkgUIDs {
		uidSet[uid] = struct{}{}
	}
	for uid := range isolatedUIDSet {
		uidSet[uid] = struct{}{}
	}
	freezableUIDs := make([]int, 0, len(uidSet))
	for uid := range uidSet {
		freezableUIDs = append(freezableUIDs, uid)
	}
	sort.Ints(freezableUIDs)

	// Cancel scheduled background jobs best-effort before freezing UIDs so JobScheduler doesn't stall system_server.
	var cancelTargets []string
	for _, pkg := range runningPkgs {
		if !protected[pkg] {
			cancelTargets = append(cancelTargets, pkg)
		}
	}
	runPackagePool(ctx, cancelTargets, sandboxWorkerPoolSize, func(pkg string) {
		_, _ = r.Run(ctx, 2*time.Second, "", "cmd", "jobscheduler", "cancel", "-u", u, pkg)
	})

	// Freeze cgroups FIRST, then scan cgroup.procs and reclaim pages with pidfd + UID verification.
	frozenNow := SetCgroupFreezeUIDs(cgroupRoot, userID, freezableUIDs, true)
	if len(freezableUIDs) > 0 && len(frozenNow) == 0 {
		if !HasAnyCgroupFreezeSupport(cgroupRoot, userID) {
			return 0, errors.New("no writable cgroup freeze control found for sandbox UIDs")
		}
		freezableSet := make(map[int]bool, len(freezableUIDs))
		for _, uid := range freezableUIDs {
			freezableSet[uid] = true
		}
		hasRunningFreezable := false
		for _, pe := range scanUserProcEntriesWithRoot(cgroupRoot, userID) {
			if freezableSet[pe.uid] {
				hasRunningFreezable = true
				break
			}
		}
		if hasRunningFreezable {
			return 0, errors.New("no writable cgroup freeze control found for active sandbox UIDs")
		}
		return 0, nil
	}
	frozenSet := make(map[int]bool, len(frozenNow))
	for _, uid := range frozenNow {
		frozenSet[uid] = true
	}
	if len(frozenSet) > 0 {
		for _, pe := range scanUserProcEntriesWithRoot(cgroupRoot, userID) {
			if frozenSet[pe.uid] {
				_ = ReclaimProcessMemoryForUser(pe.pid, userID)
			}
		}
	}

	if statePath != "" {
		prev := readHibernatedState(statePath)
		merged := mergeSortedUnique(prev.Packages, eligible)
		mergedFrozen := mergeUniqueInts(prev.FrozenUIDs, frozenNow)
		prevRestricted := make(map[string]bool, len(prev.RestrictedAppOpsPkgs))
		for _, p := range prev.RestrictedAppOpsPkgs {
			prevRestricted[p] = true
		}
		var newSkipped []string
		for _, p := range eligible {
			if !prevRestricted[p] {
				newSkipped = append(newSkipped, p)
			}
		}
		mergedSkipped := mergeSortedUnique(prev.SkippedAppOpsPkgs, newSkipped)
		_ = writeHibernatedState(statePath, HibernatedState{
			UserID:               userID,
			Packages:             merged,
			FrozenUIDs:           mergedFrozen,
			HotFrozen:            len(frozenNow) > 0,
			SkippedAppOpsPkgs:    mergedSkipped,
			RestrictedAppOpsPkgs: prev.RestrictedAppOpsPkgs,
			UpdatedAt:            time.Now().UTC().Format(time.RFC3339),
		})
	}
	return len(frozenNow), nil
}

// RestoreHibernatedSandboxUser thaws frozen cgroups and restores permissions with default paths.
func RestoreHibernatedSandboxUser(ctx context.Context, r Runner, userID int, statePath string) (int, error) {
	return RestoreHibernatedSandboxUserWithOpts(ctx, r, userID, statePath, "")
}

// RestoreHibernatedSandboxUserWithOpts thaws frozen cgroup UIDs first, restores background/wakelock/standby
// permissions for recorded packages via bounded parallel workers, and clears statePath.
func RestoreHibernatedSandboxUserWithOpts(ctx context.Context, r Runner, userID int, statePath, cgroupRoot string) (int, error) {
	n, _, err := RestoreHibernatedPriorityWithOpts(ctx, r, userID, statePath, cgroupRoot, nil)
	return n, err
}

// RestoreHibernatedPriorityWithOpts preserves v2.4.0 synchronous restore semantics for priorityPkgs + GMS/GSF/Chrome.
func RestoreHibernatedPriorityWithOpts(ctx context.Context, r Runner, userID int, statePath, cgroupRoot string, priorityPkgs []string) (int, []string, error) {
	return RestoreHibernatedPriorityEx(ctx, r, userID, statePath, priorityPkgs, LifecycleOptions{
		CgroupRoot:     cgroupRoot,
		SyncTargetOnly: false,
	})
}

// RestoreHibernatedPriorityEx immediately thaws all frozen cgroup UIDs (<0.5ms),
// restores only priorityPkgs (plus GMS/GSF when restricted, and Chrome when SyncTargetOnly is false),
// skips appops restore calls for packages whose appops were not restricted, and returns (restoredNow, remaining, nil).
func RestoreHibernatedPriorityEx(ctx context.Context, r Runner, userID int, statePath string, priorityPkgs []string, opts LifecycleOptions) (int, []string, error) {
	if oem.IsForbiddenUser(userID) {
		return 0, nil, fmt.Errorf("refusing to restore forbidden user %d", userID)
	}
	if statePath == "" {
		statePath = contracts.HibernatedPkgsPath
	}
	st := readHibernatedState(statePath)
	if len(st.FrozenUIDs) > 0 {
		_ = SetCgroupFreezeUIDs(opts.CgroupRoot, userID, st.FrozenUIDs, false)
	}
	if len(st.Packages) == 0 {
		removeHibernatedState(statePath)
		return 0, nil, nil
	}

	restrictedSet := make(map[string]bool, len(st.Packages))
	if len(st.RestrictedAppOpsPkgs) > 0 {
		for _, pkg := range st.RestrictedAppOpsPkgs {
			restrictedSet[pkg] = true
		}
	} else {
		skipped := make(map[string]bool, len(st.SkippedAppOpsPkgs))
		for _, pkg := range st.SkippedAppOpsPkgs {
			skipped[pkg] = true
		}
		for _, pkg := range st.Packages {
			if !skipped[pkg] {
				restrictedSet[pkg] = true
			}
		}
	}

	protected := hibernationProtectedPkgSet(opts.CallerPackage)
	var prioSet map[string]bool
	if len(priorityPkgs) > 0 {
		prioSet = make(map[string]bool, len(priorityPkgs)+3)
		// Always restore GMS & GSF synchronously if they were appops-restricted so Play/FCM/Gemini work cleanly.
		if !opts.SyncTargetOnly || restrictedSet["com.google.android.gms"] {
			prioSet["com.google.android.gms"] = true
		}
		if !opts.SyncTargetOnly || restrictedSet["com.google.android.gsf"] {
			prioSet["com.google.android.gsf"] = true
		}
		if !opts.SyncTargetOnly {
			prioSet["com.android.chrome"] = true
		}
		for _, pkg := range priorityPkgs {
			if contracts.ValidPackageName(pkg) && !protected[pkg] {
				prioSet[pkg] = true
			}
		}
	}

	seen := make(map[string]bool, len(st.Packages))
	var toRestore []string
	var remaining []string
	for _, pkg := range st.Packages {
		if !contracts.ValidPackageName(pkg) || protected[pkg] || seen[pkg] {
			continue
		}
		seen[pkg] = true
		if prioSet == nil || prioSet[pkg] {
			toRestore = append(toRestore, pkg)
		} else {
			remaining = append(remaining, pkg)
		}
	}

	u := strconv.Itoa(userID)
	var mu sync.Mutex
	restoredSet := make(map[string]bool, len(toRestore))
	runPackagePool(ctx, toRestore, sandboxWorkerPoolSize, func(pkg string) {
		if restrictedSet[pkg] {
			restoreSinglePackage(ctx, r, u, pkg)
		}
		if ctx.Err() == nil {
			mu.Lock()
			restoredSet[pkg] = true
			mu.Unlock()
		}
	})

	pendingSet := make(map[string]bool, len(toRestore)+len(remaining))
	for _, pkg := range toRestore {
		if !restoredSet[pkg] {
			pendingSet[pkg] = true
		}
	}
	for _, pkg := range remaining {
		pendingSet[pkg] = true
	}
	var stillPending []string
	var stillSkipped []string
	var stillRestricted []string
	if len(pendingSet) > 0 {
		stillPending = make([]string, 0, len(pendingSet))
		for pkg := range pendingSet {
			stillPending = append(stillPending, pkg)
			if restrictedSet[pkg] {
				stillRestricted = append(stillRestricted, pkg)
			} else {
				stillSkipped = append(stillSkipped, pkg)
			}
		}
		sort.Strings(stillPending)
		sort.Strings(stillRestricted)
		sort.Strings(stillSkipped)
	}

	if len(stillPending) == 0 && ctx.Err() == nil {
		removeHibernatedState(statePath)
	} else {
		_ = writeHibernatedState(statePath, HibernatedState{
			UserID:               userID,
			Packages:             stillPending,
			FrozenUIDs:           nil,
			HotFrozen:            false,
			SkippedAppOpsPkgs:    stillSkipped,
			RestrictedAppOpsPkgs: stillRestricted,
			UpdatedAt:            time.Now().UTC().Format(time.RFC3339),
		})
	}
	return len(restoredSet), stillPending, nil
}

// LaunchComponentAsRoot starts an explicit pkg/activity inside userID via root argv invocation (zero sh -c).
func LaunchComponentAsRoot(ctx context.Context, r Runner, userID int, comp string) error {
	if oem.IsForbiddenUser(userID) {
		return fmt.Errorf("refusing to launch app in forbidden user %d", userID)
	}
	p, cls, ok := strings.Cut(comp, "/")
	if !ok || !contracts.ValidPackageName(p) || !contracts.ValidComponentClass(cls) {
		return fmt.Errorf("invalid component %q", comp)
	}
	u := strconv.Itoa(userID)
	out, err := r.Run(ctx, 5*time.Second, "", "am", "start", "--user", u,
		"-a", "android.intent.action.MAIN",
		"-c", "android.intent.category.LAUNCHER",
		"-f", "0x10200000",
		"-n", p+"/"+cls)
	if err != nil {
		return err
	}
	if strings.Contains(out, "Error:") || strings.Contains(out, "Exception") {
		return fmt.Errorf("am start %s: %s", comp, strings.TrimSpace(out))
	}
	return nil
}

// ResolveLauncherComponent queries the primary LAUNCHER component (pkg/cls) for pkg inside userID.
func ResolveLauncherComponent(ctx context.Context, r Runner, userID int, pkg string) (string, error) {
	if oem.IsForbiddenUser(userID) {
		return "", fmt.Errorf("refusing to resolve component in forbidden user %d", userID)
	}
	if !contracts.ValidPackageName(pkg) {
		return "", fmt.Errorf("invalid package name %q", pkg)
	}
	u := strconv.Itoa(userID)
	resOut, err := r.Run(ctx, 4*time.Second, "", "cmd", "package", "resolve-activity", "--brief", "--user", u, pkg)
	if err != nil {
		return "", fmt.Errorf("resolve launcher activity for %s: %w", pkg, err)
	}
	resolved := ""
	for _, row := range strings.Split(resOut, "\n") {
		line := strings.TrimSpace(row)
		p, cls, ok := strings.Cut(line, "/")
		if !ok || !contracts.ValidPackageName(p) || !contracts.ValidComponentClass(cls) {
			continue
		}
		resolved = p + "/" + cls
	}
	if resolved == "" {
		return "", fmt.Errorf("no launcher activity found for %s in user %s", pkg, u)
	}
	return resolved, nil
}

// LaunchSandboxAppAsRoot directly starts an application inside userID via root argv invocation (zero sh -c),
// falling back to `cmd package resolve-activity --brief --user <u> <pkg>` when activity is unset or invalid.
func LaunchSandboxAppAsRoot(ctx context.Context, r Runner, userID int, pkg, activity string) error {
	if oem.IsForbiddenUser(userID) {
		return fmt.Errorf("refusing to launch app in forbidden user %d", userID)
	}
	if !contracts.ValidPackageName(pkg) {
		return fmt.Errorf("invalid package name %q", pkg)
	}
	if activity != "" && !contracts.ValidComponentClass(activity) {
		return fmt.Errorf("invalid activity class %q", activity)
	}
	if activity != "" {
		if err := LaunchComponentAsRoot(ctx, r, userID, pkg+"/"+activity); err == nil {
			return nil
		}
	}
	resolved, err := ResolveLauncherComponent(ctx, r, userID, pkg)
	if err != nil {
		return err
	}
	return LaunchComponentAsRoot(ctx, r, userID, resolved)
}

// StopSandboxUserDeep preserves FBE key unlock status by performing FBE-safe Root In-Place Hibernation
// rather than `am stop-user` (which evicts Android 13 FBE CE keys and triggers manual unlock prompts).
func StopSandboxUserDeep(ctx context.Context, r Runner, userID int) (int, error) {
	return HibernateSandboxUser(ctx, r, userID, contracts.HibernatedPkgsPath)
}

// ParseTopActivityIsUser inspects `dumpsys activity activities` or `dumpsys activity top` lines for `u<userID>` / `userId=<userID>`.
func ParseTopActivityIsUser(section string, userID int) bool {
	if oem.IsForbiddenUser(userID) {
		return false
	}
	u := strconv.Itoa(userID)
	tokenRe := regexp.MustCompile(`(?:\bu` + u + `\b|\buserId=` + u + `\b)`)
	for _, raw := range strings.Split(section, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if tokenRe.MatchString(line) {
			return true
		}
	}
	return false
}

// ParseIptablesChainBytes extracts exact cumulative byte count for uidStart-uidEnd terminal rules (RETURN/ACCEPT)
// from `iptables -t mangle -L SBW_TPROXY_OUT -v -n -x` output, skipping non-terminating MARK rules to avoid 2x counting.
func ParseIptablesChainBytes(section string, uidStart, uidEnd int) uint64 {
	uidTag := fmt.Sprintf("%d-%d", uidStart, uidEnd)
	var total uint64
	for _, raw := range strings.Split(section, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "Chain ") || strings.HasPrefix(line, "pkts ") {
			continue
		}
		if !strings.Contains(line, uidTag) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		target := fields[2]
		if target == "MARK" {
			continue
		}
		bytesVal, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		total += bytesVal
	}
	return total
}

// ParseAudioActiveForUser detects active playback/capture sessions owned by [uidStart, uidEnd] in `dumpsys audio`.
func ParseAudioActiveForUser(section string, uidStart, uidEnd int) bool {
	for _, raw := range strings.Split(section, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !strings.Contains(line, "state:started") {
			continue
		}
		for _, m := range audioUIDRegex.FindAllStringSubmatch(line, -1) {
			if len(m) != 2 {
				continue
			}
			uid, err := strconv.Atoi(m[1])
			if err == nil && uid >= uidStart && uid <= uidEnd {
				return true
			}
		}
	}
	return false
}

// checkAsoundAnyActive reads /proc/asound PCM status files without forking.
// Returns (checked=true, active=false) only when >=1 PCM status file was read and ALL report "closed".
func checkAsoundAnyActive(asoundRoot string) (checked bool, active bool) {
	if strings.TrimSpace(asoundRoot) == "" {
		asoundRoot = "/proc/asound"
	}
	matches, err := filepath.Glob(filepath.Join(asoundRoot, "card*", "pcm*", "sub*", "status"))
	if err != nil || len(matches) == 0 {
		return false, false
	}
	readCount := 0
	for _, path := range matches {
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		readCount++
		txt := strings.ToLower(strings.TrimSpace(string(b)))
		if txt != "closed" && !strings.HasPrefix(txt, "closed\n") && !strings.HasPrefix(txt, "state: closed") {
			return true, true
		}
	}
	return readCount > 0, false
}

func extractResumedActivityLines(actOut string) string {
	var resumedLines strings.Builder
	for _, raw := range strings.Split(actOut, "\n") {
		if strings.Contains(raw, "topResumedActivity") ||
			strings.Contains(raw, "mResumedActivity") ||
			strings.Contains(raw, "ResumedActivity:") {
			resumedLines.WriteString(raw)
			resumedLines.WriteByte('\n')
		}
	}
	return resumedLines.String()
}

func extractTopActivityLines(topOut string) (lines string, conclusive bool) {
	var b strings.Builder
	for _, raw := range strings.Split(topOut, "\n") {
		t := strings.TrimSpace(raw)
		if strings.HasPrefix(t, "TASK ") || strings.HasPrefix(t, "ACTIVITY ") {
			b.WriteString(t)
			b.WriteByte('\n')
			conclusive = true
			continue
		}
		if strings.Contains(t, "topResumedActivity") || strings.Contains(t, "mResumedActivity") {
			b.WriteString(t)
			b.WriteByte('\n')
			conclusive = true
		}
	}
	return b.String(), conclusive
}

// InspectSandboxActivityFast uses zero-fork cgroup/asound short-circuits and traffic delta before
// falling back to `dumpsys activity top` / `dumpsys audio` / `dumpsys activity activities`.
func InspectSandboxActivityFast(
	ctx context.Context,
	r Runner,
	userID int,
	cgroupRoot, asoundRoot string,
	lastTrafficBytes uint64,
	haveBaseline bool,
) (SandboxActivitySnapshot, error) {
	if oem.IsForbiddenUser(userID) {
		return SandboxActivitySnapshot{}, fmt.Errorf("invalid sandbox user %d", userID)
	}
	if strings.TrimSpace(cgroupRoot) == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	if cgroupHasAnyUIDDirs(cgroupRoot) && CountRunningUserProcessesWithRoot(cgroupRoot, userID) == 0 {
		return SandboxActivitySnapshot{
			ForegroundUser: false,
			AudioActive:    false,
			TrafficBytes:   lastTrafficBytes,
		}, nil
	}

	uidStart := userID * contracts.AndroidUserWidth
	uidEnd := uidStart + contracts.AndroidUserWidth - 1

	pktOut, errPkt := r.Run(ctx, 4*time.Second, "", "iptables", "-t", "mangle", "-L", contracts.ChainTProxyOut, "-v", "-n", "-x")
	if errPkt != nil {
		return SandboxActivitySnapshot{}, fmt.Errorf("iptables %s: %w", contracts.ChainTProxyOut, errPkt)
	}
	trafficBytes := ParseIptablesChainBytes(pktOut, uidStart, uidEnd)
	if haveBaseline {
		var delta uint64
		if trafficBytes >= lastTrafficBytes {
			delta = trafficBytes - lastTrafficBytes
		} else {
			delta = trafficBytes
		}
		if delta > 32768 {
			return SandboxActivitySnapshot{
				TrafficBytes: trafficBytes,
			}, nil
		}
	}

	var audOut, topOut string
	var errAud, errTop error
	var probeWg sync.WaitGroup
	probeWg.Add(2)
	go func() {
		defer probeWg.Done()
		audOut, errAud = r.Run(ctx, 4*time.Second, "", "dumpsys", "audio")
	}()
	go func() {
		defer probeWg.Done()
		topOut, errTop = r.Run(ctx, 3*time.Second, "", "dumpsys", "activity", "top")
	}()
	probeWg.Wait()

	if errAud != nil {
		return SandboxActivitySnapshot{}, fmt.Errorf("dumpsys audio: %w", errAud)
	}
	audioActive := ParseAudioActiveForUser(audOut, uidStart, uidEnd)

	fgUser := false
	if errTop == nil {
		if topLines, conclusive := extractTopActivityLines(topOut); conclusive {
			fgUser = ParseTopActivityIsUser(topLines, userID)
			return SandboxActivitySnapshot{
				ForegroundUser: fgUser,
				TrafficBytes:   trafficBytes,
				AudioActive:    audioActive,
			}, nil
		}
	}

	actOut, errAct := r.Run(ctx, 4*time.Second, "", "dumpsys", "activity", "activities")
	if errAct != nil {
		return SandboxActivitySnapshot{}, fmt.Errorf("dumpsys activity activities: %w", errAct)
	}
	fgUser = ParseTopActivityIsUser(extractResumedActivityLines(actOut), userID)
	return SandboxActivitySnapshot{
		ForegroundUser: fgUser,
		TrafficBytes:   trafficBytes,
		AudioActive:    audioActive,
	}, nil
}

// InspectSandboxActivity samples foreground activity, iptables byte counters, and active audio using
// direct argv invocations (zero shell invocation / zero sh -c) for idle auto-pause.
func InspectSandboxActivity(ctx context.Context, r Runner, userID int) (SandboxActivitySnapshot, error) {
	if oem.IsForbiddenUser(userID) {
		return SandboxActivitySnapshot{}, fmt.Errorf("invalid sandbox user %d", userID)
	}
	uidStart := userID * contracts.AndroidUserWidth
	uidEnd := uidStart + contracts.AndroidUserWidth - 1

	actOut, err1 := r.Run(ctx, 4*time.Second, "", "dumpsys", "activity", "activities")
	if err1 != nil {
		return SandboxActivitySnapshot{}, fmt.Errorf("dumpsys activity activities: %w", err1)
	}
	pktOut, err2 := r.Run(ctx, 4*time.Second, "", "iptables", "-t", "mangle", "-L", contracts.ChainTProxyOut, "-v", "-n", "-x")
	if err2 != nil {
		return SandboxActivitySnapshot{}, fmt.Errorf("iptables %s: %w", contracts.ChainTProxyOut, err2)
	}
	audOut, err3 := r.Run(ctx, 4*time.Second, "", "dumpsys", "audio")
	if err3 != nil {
		return SandboxActivitySnapshot{}, fmt.Errorf("dumpsys audio: %w", err3)
	}

	return SandboxActivitySnapshot{
		ForegroundUser: ParseTopActivityIsUser(extractResumedActivityLines(actOut), userID),
		TrafficBytes:   ParseIptablesChainBytes(pktOut, uidStart, uidEnd),
		AudioActive:    ParseAudioActiveForUser(audOut, uidStart, uidEnd),
	}, nil
}
