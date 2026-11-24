//go:build !transport_vpn

package netfilter

import "errors"

func vpnTransportCompiled() bool { return false }

func vpnRulesFor(family int, hook GateHook, spec GateSpec) ([]string, error) {
	return nil, errors.New("vpn transport disabled in TProxy-only build")
}
