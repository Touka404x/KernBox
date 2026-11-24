//go:build linux && arm64

package sysio

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxArm64Openat2Constants(t *testing.T) {
	if unix.SYS_OPENAT2 != SysOpenat2Arm64 {
		t.Fatalf("SYS_OPENAT2 = %d, want %d", unix.SYS_OPENAT2, SysOpenat2Arm64)
	}
	if unix.RESOLVE_NO_SYMLINKS != ResolveNoSymlinks || unix.RESOLVE_BENEATH != ResolveBeneath {
		t.Fatalf("resolve flags mismatch: got %#x/%#x", unix.RESOLVE_NO_SYMLINKS, unix.RESOLVE_BENEATH)
	}
	how := RequiredVPNStatusOpenHow()
	if how.Flags != uint64(unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC) {
		t.Fatalf("unexpected flags: %#x", how.Flags)
	}
}
