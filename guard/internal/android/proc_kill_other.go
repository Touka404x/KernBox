//go:build !linux

package android

func killPIDHard(pid int) error {
	_ = pid
	return nil
}

func killPIDHardForUser(pid, userID int) error {
	_, _ = pid, userID
	return nil
}
