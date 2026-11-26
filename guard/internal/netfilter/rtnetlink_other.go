//go:build !linux

package netfilter

func nativeEnsureTProxyRouting(_ uint32, _, _ int) error {
	return errNetlinkUnsupported
}

func nativeVerifyTProxyRouting(_ uint32, _, _ int) error {
	return errNetlinkUnsupported
}

func nativeCleanupTProxyRouting(_, _ int) error {
	return errNetlinkUnsupported
}
