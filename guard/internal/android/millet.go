package android

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sandbox_guard/internal/contracts"
)

type CgroupFS interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte) error
}

type osCgroupFS struct{}

func (osCgroupFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (osCgroupFS) WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

type FreezeState struct {
	Frozen        bool
	FreezePath    string
	InFrozenGroup bool
	Evidence      string
}

// InspectCgroupV2Freeze checks Kernel 5.10 MIUI Millet cgroup v2 paths ONLY
// (/sys/fs/cgroup/uid_<uid>/pid_<pid>/cgroup.freeze, /proc/<pid>/cgroup -> cgroup.freeze,
// and /sys/fs/cgroup/frozen/cgroup.procs). NEVER touches legacy /sys/fs/cgroup/freezer.
func InspectCgroupV2Freeze(fs CgroupFS, clientUID, pid int) FreezeState {
	if fs == nil {
		fs = osCgroupFS{}
	}
	if pid <= 0 || clientUID <= 0 {
		return FreezeState{}
	}
	pidStr := strconv.Itoa(pid)
	directPath := fmt.Sprintf("/sys/fs/cgroup/uid_%d/pid_%d/cgroup.freeze", clientUID, pid)
	if data, err := fs.ReadFile(directPath); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			return FreezeState{
				Frozen:     true,
				FreezePath: directPath,
				Evidence:   directPath + "=1",
			}
		}
	}

	if cgData, err := fs.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
		for _, line := range strings.Split(string(cgData), "\n") {
			if strings.HasPrefix(line, "0::") {
				rel := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
				if rel != "" && !strings.Contains(rel, "..") {
					p := filepath.ToSlash(filepath.Join("/sys/fs/cgroup", rel, "cgroup.freeze"))
					if d, err := fs.ReadFile(p); err == nil && strings.TrimSpace(string(d)) == "1" {
						return FreezeState{
							Frozen:     true,
							FreezePath: p,
							Evidence:   p + "=1",
						}
					}
				}
			}
		}
	}

	if frozenProcs, err := fs.ReadFile("/sys/fs/cgroup/frozen/cgroup.procs"); err == nil {
		for _, row := range strings.Split(string(frozenProcs), "\n") {
			if strings.TrimSpace(row) == pidStr {
				return FreezeState{
					Frozen:        true,
					InFrozenGroup: true,
					Evidence:      "/sys/fs/cgroup/frozen/cgroup.procs contains " + pidStr,
				}
			}
		}
	}

	return FreezeState{}
}

// UnfreezeCgroupV2 unfreezes a Millet-frozen process via cgroup v2 paths.
func UnfreezeCgroupV2(fs CgroupFS, clientUID, pid int, st FreezeState) error {
	if fs == nil {
		fs = osCgroupFS{}
	}
	var errs []error
	if st.FreezePath != "" {
		if err := fs.WriteFile(st.FreezePath, []byte("0")); err != nil {
			errs = append(errs, err)
		}
	} else {
		directPath := fmt.Sprintf("/sys/fs/cgroup/uid_%d/pid_%d/cgroup.freeze", clientUID, pid)
		if _, err := fs.ReadFile(directPath); err == nil {
			if err := fs.WriteFile(directPath, []byte("0")); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if st.InFrozenGroup {
		if err := fs.WriteFile("/sys/fs/cgroup/unfrozen/cgroup.procs", []byte(strconv.Itoa(pid))); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// EnsureWorkPermissions enforces deviceidle whitelist, RUN_ANY_IN_BACKGROUND, and POST_NOTIFICATION allow.
func EnsureWorkPermissions(ctx context.Context, r Runner, userID int, workPkg string) []string {
	if !contracts.ValidPackageName(workPkg) {
		workPkg = contracts.DefaultWorkPackage
	}
	u := strconv.Itoa(userID)
	var errs []string
	cmds := [][]string{
		{"dumpsys", "deviceidle", "whitelist", "+" + workPkg},
		{"cmd", "appops", "set", "--user", u, workPkg, "RUN_ANY_IN_BACKGROUND", "allow"},
		{"cmd", "appops", "set", "--user", u, workPkg, "POST_NOTIFICATION", "allow"},
	}
	for _, args := range cmds {
		if _, err := r.Run(ctx, 4*time.Second, "", args[0], args[1:]...); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

// FindWorkServicePID locates <workPkg>:background (or <workPkg>) running as exact clientUID.
func FindWorkServicePID(clientUID int, workPkg string) (int, bool, error) {
	if clientUID <= 0 {
		return 0, false, nil
	}
	if !contracts.ValidPackageName(workPkg) {
		workPkg = contracts.DefaultWorkPackage
	}
	svcProc := workPkg + contracts.DefaultServiceProcessSuffix
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false, err
	}
	for _, proc := range procs {
		pid, err := strconv.Atoi(proc.Name())
		if err != nil || pid <= 0 {
			continue
		}
		base := filepath.Join("/proc", proc.Name())
		data, err := os.ReadFile(filepath.Join(base, "cmdline"))
		if err != nil {
			continue
		}
		name, _, _ := strings.Cut(string(data), "\x00")
		if name != svcProc && name != workPkg {
			continue
		}
		status, err := os.ReadFile(filepath.Join(base, "status"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, false, err
		}
		if SameWorkProcessUID(string(status), clientUID) {
			return pid, true, nil
		}
	}
	return 0, false, nil
}

func SameWorkProcessUID(status string, uid int) bool {
	want := strconv.Itoa(uid)
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0] == "Uid:" {
			return fields[1] == want && fields[2] == want
		}
	}
	return false
}

// InspectCgroupV1Freeze checks legacy cgroup v1 freezer paths for Linux 4.19 / 5.4 kernels
// when cgroup v2 cgroup.freeze nodes are not present.
func InspectCgroupV1Freeze(fs CgroupFS, clientUID, pid int) FreezeState {
	if fs == nil {
		fs = osCgroupFS{}
	}
	if pid <= 0 || clientUID <= 0 {
		return FreezeState{}
	}
	pidStr := strconv.Itoa(pid)
	for _, uidStatePath := range []string{
		fmt.Sprintf("/sys/fs/cgroup/freezer/uid_%d/freezer.state", clientUID),
		fmt.Sprintf("/dev/freezer/uid_%d/freezer.state", clientUID),
	} {
		if data, err := fs.ReadFile(uidStatePath); err == nil {
			s := strings.ToUpper(strings.TrimSpace(string(data)))
			if s == "FROZEN" || s == "FREEZING" {
				return FreezeState{
					Frozen:     true,
					FreezePath: uidStatePath,
					Evidence:   uidStatePath + "=" + s,
				}
			}
		}
	}
	for _, frozenPair := range [][2]string{
		{"/sys/fs/cgroup/freezer/frozen/tasks", "/sys/fs/cgroup/freezer/frozen/freezer.state"},
		{"/sys/fs/cgroup/freezer/frozen/cgroup.procs", "/sys/fs/cgroup/freezer/frozen/freezer.state"},
		{"/dev/freezer/frozen/tasks", "/dev/freezer/frozen/freezer.state"},
		{"/dev/freezer/frozen/cgroup.procs", "/dev/freezer/frozen/freezer.state"},
	} {
		tasksPath := frozenPair[0]
		if procs, err := fs.ReadFile(tasksPath); err == nil {
			for _, row := range strings.Split(string(procs), "\n") {
				if strings.TrimSpace(row) == pidStr {
					// Never record the shared global frozen/freezer.state as FreezePath:
					// thawing a global freezer group would thaw unrelated host processes.
					return FreezeState{
						Frozen:        true,
						FreezePath:    "",
						InFrozenGroup: true,
						Evidence:      tasksPath + " contains " + pidStr,
					}
				}
			}
		}
	}
	return FreezeState{}
}

// UnfreezeCgroupV1 unfreezes a cgroup v1 freezer group / uid state for kernel_compat builds.
func UnfreezeCgroupV1(fs CgroupFS, clientUID, pid int, st FreezeState) error {
	if fs == nil {
		fs = osCgroupFS{}
	}
	var errs []error
	uidFrozenSuffix := fmt.Sprintf("/uid_%d/freezer.state", clientUID)
	if !st.InFrozenGroup && st.FreezePath != "" && strings.HasSuffix(st.FreezePath, uidFrozenSuffix) {
		if err := fs.WriteFile(st.FreezePath, []byte("THAWED")); err != nil {
			errs = append(errs, err)
		}
	} else if clientUID > 0 {
		for _, uidStatePath := range []string{
			fmt.Sprintf("/sys/fs/cgroup/freezer/uid_%d/freezer.state", clientUID),
			fmt.Sprintf("/dev/freezer/uid_%d/freezer.state", clientUID),
		} {
			if _, err := fs.ReadFile(uidStatePath); err == nil {
				if err := fs.WriteFile(uidStatePath, []byte("THAWED")); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if st.InFrozenGroup && pid > 0 {
		pidBytes := []byte(strconv.Itoa(pid))
		rootDir := "/sys/fs/cgroup/freezer"
		if strings.HasPrefix(st.Evidence, "/dev/freezer/") {
			rootDir = "/dev/freezer"
		}
		if err := fs.WriteFile(rootDir+"/cgroup.procs", pidBytes); err != nil {
			if err2 := fs.WriteFile(rootDir+"/tasks", pidBytes); err2 != nil {
				errs = append(errs, err2)
			}
		}
	}
	return errors.Join(errs...)
}
