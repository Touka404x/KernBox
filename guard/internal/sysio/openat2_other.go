//go:build !linux

package sysio

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

func platformReadOnlyNonBlockCloexec() uint64 { return 0x80800 }
func platformReadOnlyDirCloexec() uint64      { return 0xa0000 }

type hostStubResolver struct{}

func defaultResolver() SafeResolver { return hostStubResolver{} }

func (hostStubResolver) OpenDirAbsolute(absPath string) (int, FileMeta, func() error, error) {
	return -1, FileMeta{}, nil, errors.New("openat2 only supported on linux")
}

func (hostStubResolver) OpenDirBeneath(dirFD int, relPath string, how OpenHowSpec) (int, FileMeta, func() error, error) {
	return -1, FileMeta{}, nil, errors.New("openat2 only supported on linux")
}

func (hostStubResolver) OpenFileBeneath(dirFD int, relPath string, how OpenHowSpec) (ReadHandle, error) {
	return nil, errors.New("openat2 only supported on linux")
}

func ReadRootOwnedSmallFile(path string, maxBytes int64) ([]byte, error) {
	return ReadRootOwnedSmallFilePerm(path, maxBytes, 0077)
}

func ReadRootOwnedSmallFilePerm(path string, maxBytes int64, forbidPermMask uint32) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlinkBlocked, path)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegularFile
	}
	if info.Size() > maxBytes {
		return nil, ErrFileTooLarge
	}
	return os.ReadFile(path)
}

func Lsetfilecon(path, seCtx string) error {
	return nil
}

var (
	hostLocksMu sync.Mutex
	hostLocks   = map[string]*sync.Mutex{}
)

func AcquireFlock(path string, perm os.FileMode, timeout time.Duration) (func(), error) {
	hostLocksMu.Lock()
	mu, ok := hostLocks[path]
	if !ok {
		mu = &sync.Mutex{}
		hostLocks[path] = mu
	}
	hostLocksMu.Unlock()
	mu.Lock()
	return func() { mu.Unlock() }, nil
}

func TryFlockNonBlocking(path string, perm os.FileMode) (func(), bool, error) {
	hostLocksMu.Lock()
	mu, ok := hostLocks[path]
	if !ok {
		mu = &sync.Mutex{}
		hostLocks[path] = mu
	}
	hostLocksMu.Unlock()
	if !mu.TryLock() {
		return nil, false, nil
	}
	return func() { mu.Unlock() }, true, nil
}

var startTime = time.Now()

func MonotonicNowNs() int64 {
	return time.Since(startTime).Nanoseconds()
}

func fchownFile(f *os.File, uid, gid int) error {
	return nil
}
