//go:build linux

package sysio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func isUnprivilegedGoTest() bool {
	return testing.Testing() && os.Geteuid() != 0
}

func platformReadOnlyNonBlockCloexec() uint64 {
	return uint64(unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC)
}

func platformReadOnlyDirCloexec() uint64 {
	return uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC)
}

type linuxResolver struct{}

func defaultResolver() SafeResolver { return linuxResolver{} }

type linuxHandle struct {
	file *os.File
	fd   int
}

func (h *linuxHandle) Read(p []byte) (int, error) { return h.file.Read(p) }
func (h *linuxHandle) Close() error               { return h.file.Close() }

func (h *linuxHandle) StatMeta() (FileMeta, error) {
	return fstatMeta(h.fd)
}

func fstatMeta(fd int) (FileMeta, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return FileMeta{}, err
	}
	typ := st.Mode & unix.S_IFMT
	return FileMeta{
		IsRegular: typ == unix.S_IFREG,
		IsDir:     typ == unix.S_IFDIR,
		UID:       int(st.Uid),
		Perm:      uint32(st.Mode) & 0777,
		Size:      st.Size,
	}, nil
}

func mapOpenat2Err(err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
		return fmt.Errorf("%w: %v", ErrSymlinkBlocked, err)
	}
	return err
}

func (linuxResolver) OpenDirAbsolute(absPath string) (int, FileMeta, func() error, error) {
	fd, err := unix.Open(absPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, FileMeta{}, nil, mapOpenat2Err(err)
	}
	meta, err := fstatMeta(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, FileMeta{}, nil, err
	}
	return fd, meta, func() error { return unix.Close(fd) }, nil
}

// ReadRootOwnedSmallFile reads a root-owned 0600-max regular file with O_NOFOLLOW.
func ReadRootOwnedSmallFile(path string, maxBytes int64) ([]byte, error) {
	return ReadRootOwnedSmallFilePerm(path, maxBytes, 0077)
}

// ReadRootOwnedSmallFilePerm reads a root-owned regular file enforcing forbidPermMask == 0.
func ReadRootOwnedSmallFilePerm(path string, maxBytes int64, forbidPermMask uint32) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, mapOpenat2Err(err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	meta, err := fstatMeta(fd)
	if err != nil {
		return nil, err
	}
	if !meta.IsRegular {
		return nil, ErrNotRegularFile
	}
	expectedUID := 0
	if isUnprivilegedGoTest() {
		expectedUID = os.Geteuid()
	}
	if meta.UID != expectedUID {
		return nil, fmt.Errorf("%w: %s uid=%d", ErrInvalidOwner, path, meta.UID)
	}
	if meta.Perm&forbidPermMask != 0 {
		return nil, fmt.Errorf("file %s has unsafe permissions %04o", path, meta.Perm)
	}
	if meta.Size > maxBytes {
		return nil, fmt.Errorf("%w: %s size=%d", ErrFileTooLarge, path, meta.Size)
	}
	data := make([]byte, 0, minInt64(meta.Size, maxBytes)+1)
	buf := make([]byte, 4096)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if int64(len(data)+n) > maxBytes {
				return nil, fmt.Errorf("%w: %s", ErrFileTooLarge, path)
			}
			data = append(data, buf[:n]...)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, rerr
		}
	}
	return data, nil
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// Lsetfilecon applies a SELinux context without following symlinks.
func Lsetfilecon(path, seCtx string) error {
	if seCtx == "" {
		return nil
	}
	err := unix.Lsetxattr(path, "security.selinux", append([]byte(seCtx), 0), 0)
	if err == nil {
		return nil
	}
	out, cerr := exec.Command("/system/bin/chcon", seCtx, path).CombinedOutput()
	if cerr != nil {
		if isUnprivilegedGoTest() {
			return nil
		}
		return fmt.Errorf("lsetxattr security.selinux (%v) and chcon (%v: %s)", err, cerr, strings.TrimSpace(string(out)))
	}
	return nil
}

// AcquireFlock acquires an exclusive advisory flock with O_NOFOLLOW and bounded timeout.
func AcquireFlock(path string, perm os.FileMode, timeout time.Duration) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("flock timeout on %s", path)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

// TryFlockNonBlocking tries to lock path without waiting.
func TryFlockNonBlocking(path string, perm os.FileMode) (func(), bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, false, nil
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, true, nil
}

// MonotonicNowNs returns Linux CLOCK_MONOTONIC nanoseconds.
func MonotonicNowNs() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Now().UnixNano()
	}
	return ts.Nano()
}

func fchownFile(f *os.File, uid, gid int) error {
	if uid < 0 && gid < 0 {
		return nil
	}
	if isUnprivilegedGoTest() {
		return nil
	}
	return unix.Fchown(int(f.Fd()), uid, gid)
}
