//go:build linux && kernel_compat

package android

import (
	"golang.org/x/sys/unix"

	"sandbox_guard/internal/oem"
)

// ReclaimProcessMemory is a no-op on Linux < 5.10 kernels without process_madvise(2).
func ReclaimProcessMemory(pid int) error {
	_ = pid
	return nil
}

// ReclaimProcessMemoryForUser validates user ownership and returns nil on Linux < 5.10
// kernels without process_madvise(2) (syscall 440) or pidfd_open(2).
func ReclaimProcessMemoryForUser(pid, userID int) error {
	_ = pid
	if userID >= 0 && oem.IsForbiddenUser(userID) {
		return unix.EPERM
	}
	return nil
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
