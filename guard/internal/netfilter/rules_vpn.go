//go:build transport_vpn

package netfilter

import (
	"fmt"

	"sandbox_guard/internal/contracts"
)

func vpnTransportCompiled() bool { return true }

func vpnRulesFor(family int, hook GateHook, spec GateSpec) ([]string, error) {
	portal := spec.PortalDNS4
	if portal == "" {
		portal = contracts.PortalDNS4
	}
	endpoint := spec.EndpointV4
	port := spec.EndpointPort
	if port == 0 {
		port = contracts.EndpointPort
	}
	ownerMatch := fmt.Sprintf("-m owner --uid-owner %d-%d", spec.UIDStart, spec.UIDEnd)
	vpnNetID := spec.effectiveVPNNetID()
	vpnMark := ""
	if vpnNetID > 0 {
		vpnMark = fmt.Sprintf("-m mark --mark 0x%x/0x%x", vpnNetID, contracts.NetIDMask)
	}

	switch hook.Chain {
	case contracts.ChainRawOutput:
		if !spec.ArmRawDrop {
			return nil, nil
		}
		rules := []string{ownerMatch + " -j DROP"}
		if family == 4 {
			rules = append(rules,
				fmt.Sprintf("-d %s/32 -p udp --dport 53 -j DROP", portal),
				fmt.Sprintf("-d %s/32 -p tcp --dport 53 -j DROP", portal),
				fmt.Sprintf("-d %s/32 -p tcp --dport 853 -j DROP", portal),
			)
		}
		if vpnMark != "" {
			rules = append(rules, vpnMark+" -j DROP")
		}
		return rules, nil

	case contracts.ChainOutput:
		var rules []string
		if family == 4 && spec.Open && spec.Session != nil {
			s := spec.Session
			outerMark := s.UplinkNetID | contracts.ProtectedVPNBit
			outerMask := contracts.NetIDMask | contracts.ProtectedVPNBit
			rules = append(rules,
				fmt.Sprintf("-o %s %s -j RETURN", s.TunIf, ownerMatch),
				fmt.Sprintf("-o %s -m mark --mark 0x%x/0x%x -j RETURN", s.TunIf, s.VPNNetID, contracts.NetIDMask),
			)
			if endpoint != "" {
				rules = append(rules, fmt.Sprintf("-o %s -p tcp -d %s/32 --dport %d -m owner --uid-owner %d -m mark --mark 0x%x/0x%x -j RETURN",
					s.UplinkIf, endpoint, port, s.ClientUID, outerMark, outerMask))
			}
		}
		// VPN mode has no IPv6 tunnel; always fail-closed for family == 6 even if IPv6Enabled is set.
		rules = append(rules,
			ownerMatch+" -p tcp -j REJECT --reject-with tcp-reset",
			ownerMatch+" -j REJECT",
		)
		if family == 4 {
			rules = append(rules,
				fmt.Sprintf("-d %s/32 -p tcp --dport 53 -j REJECT --reject-with tcp-reset", portal),
				fmt.Sprintf("-d %s/32 -p udp --dport 53 -j REJECT", portal),
				fmt.Sprintf("-d %s/32 -p tcp --dport 853 -j REJECT --reject-with tcp-reset", portal),
			)
		}
		if vpnMark != "" {
			rules = append(rules,
				vpnMark+" -p tcp -j REJECT --reject-with tcp-reset",
				vpnMark+" -j REJECT",
			)
		}
		return rules, nil

	case contracts.ChainEgress:
		var rules []string
		if family == 4 && spec.Open && spec.Session != nil {
			s := spec.Session
			outerMark := s.UplinkNetID | contracts.ProtectedVPNBit
			outerMask := contracts.NetIDMask | contracts.ProtectedVPNBit
			rules = append(rules,
				fmt.Sprintf("-o %s %s -j RETURN", s.TunIf, ownerMatch),
				fmt.Sprintf("-o %s -m mark --mark 0x%x/0x%x -j RETURN", s.TunIf, s.VPNNetID, contracts.NetIDMask),
			)
			if endpoint != "" {
				rules = append(rules, fmt.Sprintf("-o %s -p tcp -d %s/32 --dport %d -m owner --uid-owner %d -m mark --mark 0x%x/0x%x -j RETURN",
					s.UplinkIf, endpoint, port, s.ClientUID, outerMark, outerMask))
			}
		}
		rules = append(rules, ownerMatch+" -j DROP")
		if family == 4 {
			rules = append(rules,
				fmt.Sprintf("-d %s/32 -p udp --dport 53 -j DROP", portal),
				fmt.Sprintf("-d %s/32 -p tcp --dport 53 -j DROP", portal),
				fmt.Sprintf("-d %s/32 -p tcp --dport 853 -j DROP", portal),
			)
		}
		if vpnMark != "" {
			rules = append(rules, vpnMark+" -j DROP")
		}
		return rules, nil
	}
	return nil, fmt.Errorf("unknown hook chain %q", hook.Chain)
}
