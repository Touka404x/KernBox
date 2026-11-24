//go:build !transport_vpn

package buildinfo

const transportTier = "tproxy"

var supportedModes = []string{"tproxy"}
