//go:build linux && kernel_compat

package sysio

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func splitSafeRelPath(relPath string) ([]string, error) {
	if relPath == "" || strings.HasPrefix(relPath, "/") || strings.ContainsRune(relPath, '\\') || strings.ContainsRune(relPath, 0) {
		return nil, fmt.Errorf("%w: invalid relative path %q", ErrSymlinkBlocked, relPath)
	}
	parts := strings.Split(relPath, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, fmt.Errorf("%w: unsafe path component in %q", ErrSymlinkBlocked, relPath)
		}
		out = append(out, p)
	}
	return out, nil
}

// walkNoFollowComponents walks relPath beneath dirFD component-by-component with O_NOFOLLOW
// so Linux 4.19 / 5.4 kernels lacking openat2 retain full symlink/escape confinement.
func openBeneathNoFollow(dirFD int, relPath string, leafFlags int) (int, error) {
	parts, err := splitSafeRelPath(relPath)
	if err != nil {
		return -1, err
	}
	curFD := dirFD
	ownCur := false
	closeCur := func() {
		if ownCur && curFD >= 0 {
			_ = unix.Close(curFD)
		}
	}
	for i := 0; i < len(parts)-1; i++ {
		nextFD, err := unix.Openat(curFD, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeCur()
		if err != nil {
			return -1, mapOpenat2Err(err)
		}
		curFD = nextFD
		ownCur = true
	}
	leafFD, err := unix.Openat(curFD, parts[len(parts)-1], leafFlags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	closeCur()
	if err != nil {
		return -1, mapOpenat2Err(err)
	}
	return leafFD, nil
}

func (linuxResolver) OpenDirBeneath(dirFD int, relPath string, how OpenHowSpec) (int, FileMeta, func() error, error) {
	fd, err := openBeneathNoFollow(dirFD, relPath, int(how.Flags)|unix.O_DIRECTORY)
	if err != nil {
		return -1, FileMeta{}, nil, err
	}
	meta, err := fstatMeta(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, FileMeta{}, nil, err
	}
	return fd, meta, func() error { return unix.Close(fd) }, nil
}

func (linuxResolver) OpenFileBeneath(dirFD int, relPath string, how OpenHowSpec) (ReadHandle, error) {
	fd, err := openBeneathNoFollow(dirFD, relPath, int(how.Flags))
	if err != nil {
		return nil, err
	}
	return &linuxHandle{
		file: os.NewFile(uintptr(fd), filepath.Base(relPath)),
		fd:   fd,
	}, nil
}
