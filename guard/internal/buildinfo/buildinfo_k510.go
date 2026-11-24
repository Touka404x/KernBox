//go:build !kernel_compat

package buildinfo

const (
	kernelTier     = "k510"
	openatMode     = "openat2"
	processReclaim = "process_madvise_madv_pageout"
)
