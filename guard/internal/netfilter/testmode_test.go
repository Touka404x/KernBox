package netfilter

import "sandbox_guard/internal/sysio"

func init() {
	sysio.EnableUnprivilegedTestMode()
}
