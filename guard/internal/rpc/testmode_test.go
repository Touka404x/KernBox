package rpc

import "sandbox_guard/internal/sysio"

func init() {
	sysio.EnableUnprivilegedTestMode()
}
