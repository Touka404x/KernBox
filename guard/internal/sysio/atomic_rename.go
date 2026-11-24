package sysio

import (
	"os"
	"runtime"
	"sync"
	"time"
)

var writeRenameMu sync.Mutex

// renameAtomicTemp serializes atomic file replacements inside the process and
// retries transient Windows NTFS sharing/access-denied rename races.
func renameAtomicTemp(tmp, path string) error {
	writeRenameMu.Lock()
	defer writeRenameMu.Unlock()

	err := os.Rename(tmp, path)
	if err == nil || runtime.GOOS != "windows" {
		return err
	}
	for attempt := 0; attempt < 5; attempt++ {
		time.Sleep(2 * time.Millisecond)
		if err = os.Rename(tmp, path); err == nil {
			return nil
		}
	}
	return err
}
