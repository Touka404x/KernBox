//go:build linux

package sysio

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

type PeerCredentials struct {
	PID     int
	UID     int
	GID     int
	Context string
}

// GetUnixPeerCreds inspects SO_PEERCRED and SO_PEERSEC atomically on an accepted Unix stream socket.
func GetUnixPeerCreds(conn net.Conn) (PeerCredentials, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return PeerCredentials{}, fmt.Errorf("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerCredentials{}, err
	}
	var (
		creds PeerCredentials
		opErr error
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			opErr = fmt.Errorf("getsockopt SO_PEERCRED: %w", err)
			return
		}
		sec, err := unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_PEERSEC)
		if err != nil {
			opErr = fmt.Errorf("getsockopt SO_PEERSEC: %w", err)
			return
		}
		creds = PeerCredentials{
			PID:     int(ucred.Pid),
			UID:     int(ucred.Uid),
			GID:     int(ucred.Gid),
			Context: sec,
		}
	}); err != nil {
		return PeerCredentials{}, err
	}
	if opErr != nil {
		return PeerCredentials{}, opErr
	}
	return creds, nil
}

// SetUmask sets the process umask and returns the previous mask.
func SetUmask(mask int) int {
	return unix.Umask(mask)
}
