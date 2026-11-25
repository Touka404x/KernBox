package android

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

type uidBoostState struct {
	origVal string
	timer   *time.Timer
}

var (
	uidBoostMu sync.Mutex
	uidBoosts  = make(map[int]*uidBoostState)
)

type anonMapRange struct {
	start uintptr
	len   uint64
}

func parseAnonPrivateMaps(mapsPath string, maxRegions int) []anonMapRange {
	if maxRegions <= 0 {
		maxRegions = 128
	}
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	const maxScanCandidates = 1024
	var ranges []anonMapRange
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		// Only reclaim anonymous private read-write mappings (rw-p, zero inode, no backing pathname).
		if fields[1] != "rw-p" || fields[4] != "0" {
			continue
		}
		if len(fields) >= 6 {
			path := fields[5]
			if path != "[anon:libc_malloc]" && !strings.HasPrefix(path, "[anon:scudo") && !strings.HasPrefix(path, "[anon:dalvik-") {
				continue
			}
		}
		dash := strings.IndexByte(fields[0], '-')
		if dash <= 0 {
			continue
		}
		start, err1 := strconv.ParseUint(fields[0][:dash], 16, 64)
		end, err2 := strconv.ParseUint(fields[0][dash+1:], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		size := end - start
		if size < 64*1024 {
			continue
		}
		ranges = append(ranges, anonMapRange{
			start: uintptr(start),
			len:   size,
		})
		if len(ranges) >= maxScanCandidates {
			break
		}
	}
	if len(ranges) > maxRegions {
		sort.Slice(ranges, func(i, j int) bool {
			return ranges[i].len > ranges[j].len
		})
		ranges = ranges[:maxRegions]
	}
	return ranges
}

// ReadMemoryPSIAvg10 parses `some avg10=X.XX` from /proc/pressure/memory (or path).
func ReadMemoryPSIAvg10(path string) (float64, bool) {
	if strings.TrimSpace(path) == "" {
		path = "/proc/pressure/memory"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, tok := range strings.Fields(line)[1:] {
			if strings.HasPrefix(tok, "avg10=") {
				v, perr := strconv.ParseFloat(strings.TrimPrefix(tok, "avg10="), 64)
				if perr == nil {
					return v, true
				}
			}
		}
	}
	return 0, false
}

// BoostUIDLaunch applies a bounded transient cpu.uclamp.min boost strictly to sandbox uid_<uid>
// in [MinAppID, 89999] (never User 0 or system UIDs) and asynchronously restores the prior value.
func BoostUIDLaunch(cgroupRoot string, uid int, duration time.Duration) bool {
	if uid < contracts.AndroidUserWidth || oem.IsForbiddenUser(uid/contracts.AndroidUserWidth) {
		return false
	}
	appID := uid % contracts.AndroidUserWidth
	if appID < contracts.MinAppID || appID >= 90000 {
		return false
	}
	if strings.TrimSpace(cgroupRoot) == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	if duration <= 0 {
		duration = 1500 * time.Millisecond
	}
	if duration > 5*time.Second {
		duration = 5 * time.Second
	}
	uclampFile := filepath.Join(cgroupRoot, fmt.Sprintf("uid_%d", uid), "cpu.uclamp.min")
	uidBoostMu.Lock()
	defer uidBoostMu.Unlock()

	origVal := "0"
	hadPrev := false
	if prev, exists := uidBoosts[uid]; exists {
		hadPrev = true
		origVal = prev.origVal
		if prev.timer != nil {
			prev.timer.Stop()
		}
	} else {
		origBytes, err := os.ReadFile(uclampFile)
		if err != nil {
			return false
		}
		if s := strings.TrimSpace(string(origBytes)); s != "" {
			origVal = s
		}
	}
	if err := os.WriteFile(uclampFile, []byte("50"), 0644); err != nil {
		if hadPrev {
			delete(uidBoosts, uid)
			_ = os.WriteFile(uclampFile, []byte(origVal), 0644)
		}
		return false
	}
	entry := &uidBoostState{origVal: origVal}
	entry.timer = time.AfterFunc(duration, func() {
		uidBoostMu.Lock()
		defer uidBoostMu.Unlock()
		if uidBoosts[uid] == entry {
			delete(uidBoosts, uid)
			_ = os.WriteFile(uclampFile, []byte(origVal), 0644)
		}
	})
	uidBoosts[uid] = entry
	return true
}

// PrewarmSandboxAppFiles resolves installed APK + ART oat/vdex paths from packages.list
// and hints the kernel page cache with FADV_WILLNEED (best-effort, non-blocking).
func PrewarmSandboxAppFiles(packagesListPath, pkg string) {
	if !contracts.ValidPackageName(pkg) {
		return
	}
	if strings.TrimSpace(packagesListPath) == "" {
		packagesListPath = contracts.PackagesListPath
	}
	f, err := os.Open(packagesListPath)
	if err != nil {
		return
	}
	var codePath string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 4 && fields[0] == pkg {
			codePath = fields[3]
			break
		}
	}
	_ = f.Close()
	if codePath == "" || !strings.HasPrefix(codePath, "/data/app/") {
		return
	}
	appDir := codePath
	if strings.HasSuffix(appDir, ".apk") {
		appDir = filepath.Dir(appDir)
	}
	PrewarmFiles([]string{
		filepath.Join(appDir, "base.apk"),
		filepath.Join(appDir, "oat", "arm64", "base.odex"),
		filepath.Join(appDir, "oat", "arm64", "base.vdex"),
	})
}

// PrewarmSandboxAppCodePath queries Android PackageManager for the true /data/app/... code path
// and hints the kernel page cache with FADV_WILLNEED (best-effort, non-blocking).
func PrewarmSandboxAppCodePath(ctx context.Context, r Runner, userID int, pkg string) {
	if r == nil || oem.IsForbiddenUser(userID) || !contracts.ValidPackageName(pkg) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	out, err := r.Run(ctx, 3*time.Second, "", "cmd", "package", "path", "--user", strconv.Itoa(userID), pkg)
	if err != nil {
		return
	}
	var codePath string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "package:") {
			continue
		}
		cand := strings.TrimSpace(strings.TrimPrefix(l, "package:"))
		if strings.HasPrefix(cand, "/data/app/") {
			codePath = cand
			break
		}
	}
	if codePath == "" {
		return
	}
	appDir := codePath
	if strings.HasSuffix(appDir, ".apk") {
		appDir = filepath.Dir(appDir)
	}
	PrewarmFiles([]string{
		filepath.Join(appDir, "base.apk"),
		filepath.Join(appDir, "oat", "arm64", "base.odex"),
		filepath.Join(appDir, "oat", "arm64", "base.vdex"),
	})
}
