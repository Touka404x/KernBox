package daemon

import "sandbox_guard/internal/sysio"

func init() {
	sysio.EnableUnprivilegedTestMode()
}
