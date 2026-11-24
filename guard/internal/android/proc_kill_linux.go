//go:build linux && !kernel_compat

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

func killPIDHardForUser(pid, userID int) error {
	if pid <= 1 || pid == os.Getpid() {
		return nil
	}
	if userID >= 0 {
		if oem.IsForbiddenUser(userID) {
			return unix.EPERM
		}
		pidfd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(pidfd) }()

		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			return err
		}
		uidMin := userID*contracts.AndroidUserWidth + contracts.MinAppID
		uidMax := userID*contracts.AndroidUserWidth + 99999
		matched := false
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line[4:])
				if len(fields) > 0 {
					if uid, uerr := strconv.Atoi(fields[0]); uerr == nil && uid >= uidMin && uid <= uidMax {
						matched = true
					}
				}
				break
			}
		}
		if !matched {
			return unix.EPERM
		}
		return unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
	}
	return unix.Kill(pid, unix.SIGKILL)
}
