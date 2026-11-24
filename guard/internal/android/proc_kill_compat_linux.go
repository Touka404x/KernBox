//go:build linux && kernel_compat

package android

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

func killPIDHard(pid int) error {
	return killPIDHardForUser(pid, -1)
}

func readProcStartTime(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	s := string(b)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 || rparen+2 >= len(s) {
		return "", fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	// Field 22 in /proc/<pid>/stat (0-indexed 19 after comm ') ') is starttime.
	fields := strings.Fields(s[rparen+2:])
	if len(fields) <= 19 {
		return "", fmt.Errorf("short /proc/%d/stat", pid)
	}
	return fields[19], nil
}

func verifyProcStatusUID(pid, userID int) bool {
	if oem.IsForbiddenUser(userID) {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	uidMin := userID*contracts.AndroidUserWidth + contracts.MinAppID
	uidMax := userID*contracts.AndroidUserWidth + 99999
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line[4:])
			if len(fields) == 0 {
				return false
			}
			uid, uerr := strconv.Atoi(fields[0])
			return uerr == nil && uid >= uidMin && uid <= uidMax
		}
	}
	return false
}

// killPIDHardForUser performs two-phase starttime + UID verification before
// SIGKILL when pidfd_open(2) is unavailable (Linux 4.19 / 5.4 kernels).
func killPIDHardForUser(pid, userID int) error {
	if pid <= 1 || pid == os.Getpid() {
		return nil
	}
	if userID >= 0 {
		if oem.IsForbiddenUser(userID) {
			return unix.EPERM
		}
		startBefore, err := readProcStartTime(pid)
		if err != nil {
			return err
		}
		if !verifyProcStatusUID(pid, userID) {
			return unix.EPERM
		}
		startAfter, err := readProcStartTime(pid)
		if err != nil {
			return err
		}
		if startBefore != startAfter {
			return unix.ESRCH
		}
	}
	return unix.Kill(pid, unix.SIGKILL)
}
