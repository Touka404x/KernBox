//go:build !linux

package android

import (
	"fmt"
	"os"
)

func openRegularFileNoFollow(cleanPath string) (*os.File, os.FileInfo, error) {
	lst, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, nil, err
	}
	if lst.Mode()&os.ModeSymlink != 0 || !lst.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", cleanPath)
	}
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, os.ErrInvalid
	}
	return f, st, nil
}
