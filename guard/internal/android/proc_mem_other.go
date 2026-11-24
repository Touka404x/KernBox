//go:build !linux

package android

// ReclaimProcessMemory is a no-op outside Linux.
func ReclaimProcessMemory(pid int) error {
	_ = pid
	return nil
}

// ReclaimProcessMemoryForUser is a no-op outside Linux.
func ReclaimProcessMemoryForUser(pid, userID int) error {
	_, _ = pid, userID
	return nil
}

// PrewarmFiles is a no-op outside Linux.
func PrewarmFiles(paths []string) {
	_ = paths
}
