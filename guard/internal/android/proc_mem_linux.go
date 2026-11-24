//go:build linux && !kernel_compat

package android

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

const (
	sysProcessMadvise uintptr = 440
	madvPageout       uintptr = 21
)

type sysIovec struct {
	Base uintptr
	Len  uint64
}

func verifyProcUIDRange(pid, userID int) bool {
	if oem.IsForbiddenUser(userID) {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	uidMin := userID*contracts.AndroidUserWidth + contracts.MinAppID
	uidMax := userID*contracts.AndroidUserWidth + 99999
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line[4:])
			if len(fields) == 0 {
				return false
			}
			uid, uerr := strconv.Atoi(fields[0])
			return uerr == nil && uid >= uidMin && uid <= uidMax
		}
	}
	return false
}

// ReclaimProcessMemory asks the Linux kernel via process_madvise(MADV_PAGEOUT) to pageout frozen
// private anonymous mappings without user-range binding (for legacy callers).
func ReclaimProcessMemory(pid int) error {
	return ReclaimProcessMemoryForUser(pid, -1)
}

// ReclaimProcessMemoryForUser opens pidfd first, validates /proc/<pid>/status Uid belongs
// strictly to sandbox userID (eliminating PID-reuse races), parses the largest anonymous heaps,
// and invokes process_madvise(MADV_PAGEOUT).
func ReclaimProcessMemoryForUser(pid, userID int) error {
	if pid <= 1 || pid == os.Getpid() {
		return nil
	}
	if runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64" {
		return unix.ENOSYS
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(pidfd) }()

	if userID >= 0 && !verifyProcUIDRange(pid, userID) {
		return unix.EPERM
	}
	ranges := parseAnonPrivateMaps(fmt.Sprintf("/proc/%d/maps", pid), 128)
	if len(ranges) == 0 {
		return nil
	}

	iovecs := make([]sysIovec, len(ranges))
	for i, r := range ranges {
		iovecs[i] = sysIovec{Base: r.start, Len: r.len}
	}
	const chunk = 64
	var lastSoftErr error
	for off := 0; off < len(iovecs); off += chunk {
		end := off + chunk
		if end > len(iovecs) {
			end = len(iovecs)
		}
		_, _, errno := unix.Syscall6(
			sysProcessMadvise,
			uintptr(pidfd),
			uintptr(unsafe.Pointer(&iovecs[off])),
			uintptr(end-off),
			madvPageout,
			0,
			0,
		)
		if errno != 0 {
			if errno == unix.EINVAL || errno == unix.ENOMEM || errno == unix.EFAULT {
				lastSoftErr = errno
				continue
			}
			return errno
		}
	}
	return lastSoftErr
}

// PrewarmFiles advises the kernel page cache with FADV_WILLNEED using O_NOFOLLOW safety.
func PrewarmFiles(paths []string) {
	for _, p := range paths {
		if p == "" {
			continue
		}
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		_ = unix.Fadvise(fd, 0, 0, unix.FADV_WILLNEED)
		_ = unix.Close(fd)
	}
}
