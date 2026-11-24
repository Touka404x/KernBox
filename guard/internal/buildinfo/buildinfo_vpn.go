//go:build transport_vpn

package buildinfo

const transportTier = "tproxy+vpn"

var supportedModes = []string{"tproxy", "vpn"}
