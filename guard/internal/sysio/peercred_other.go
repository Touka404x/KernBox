//go:build !linux

package sysio

import (
	"errors"
	"net"
)

type PeerCredentials struct {
	PID     int
	UID     int
	GID     int
	Context string
}

func GetUnixPeerCreds(conn net.Conn) (PeerCredentials, error) {
	return PeerCredentials{}, errors.New("SO_PEERCRED/SO_PEERSEC only supported on linux")
}

func SetUmask(mask int) int {
	return 0077
}
