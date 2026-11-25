package main

import "sandbox_guard/internal/sysio"

func init() {
	sysio.EnableUnprivilegedTestMode()
}
