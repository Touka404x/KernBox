package sysio

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sandbox_guard/internal/contracts"
)

// WriteAtomicOptions specifies ownership, permissions, and SELinux label applied before rename.
type WriteAtomicOptions struct {
	Perm    os.FileMode
	UID     int // -1 to skip chown
	GID     int // -1 to skip chown
	SELinux string
}

// WriteAtomic writes data via a synced temporary file, applying chmod, chown, and lsetfilecon
// BEFORE atomically renaming into path so readers never observe half-written or mislabeled files.
func WriteAtomic(path string, data []byte, opts WriteAtomicOptions) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}

	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := f.Chmod(opts.Perm); err != nil {
		cleanup()
		return err
	}
	if err := fchownFile(f, opts.UID, opts.GID); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if opts.SELinux != "" {
		if err := Lsetfilecon(tmp, opts.SELinux); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := renameAtomicTemp(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// ReadBootID reads /proc/sys/kernel/random/boot_id.
func ReadBootID() (string, error) {
	data, err := os.ReadFile(contracts.ProcBootID)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return "", fmt.Errorf("empty boot_id")
	}
	return id, nil
}
