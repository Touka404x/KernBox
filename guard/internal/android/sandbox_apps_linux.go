//go:build linux

package android

import (
	"os"
	"syscall"
)

func openRegularFileNoFollow(cleanPath string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(cleanPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, os.ErrInvalid
	}
	return f, st, nil
}
