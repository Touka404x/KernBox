//go:build linux && !kernel_compat

package sysio

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func (linuxResolver) OpenDirBeneath(dirFD int, relPath string, how OpenHowSpec) (int, FileMeta, func() error, error) {
	uHow := unix.OpenHow{
		Flags:   how.Flags,
		Mode:    how.Mode,
		Resolve: how.Resolve,
	}
	fd, err := unix.Openat2(dirFD, relPath, &uHow)
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

func (linuxResolver) OpenFileBeneath(dirFD int, relPath string, how OpenHowSpec) (ReadHandle, error) {
	uHow := unix.OpenHow{
		Flags:   how.Flags,
		Mode:    how.Mode,
		Resolve: how.Resolve,
	}
	fd, err := unix.Openat2(dirFD, relPath, &uHow)
	if err != nil {
		return nil, mapOpenat2Err(err)
	}
	return &linuxHandle{
		file: os.NewFile(uintptr(fd), filepath.Base(relPath)),
		fd:   fd,
	}, nil
}
