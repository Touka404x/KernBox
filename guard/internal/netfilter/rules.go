package netfilter

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

type GateHook struct {
	Table      string
	Builtin    string
	Chain      string
	MainGuard  string
	TProxyOnly bool
	SkipPrefix string
}

var GateHooks = []GateHook{
	{Table: "raw", Builtin: "OUTPUT", Chain: contracts.ChainRawOutput},
	{Table: "filter", Builtin: "OUTPUT", Chain: contracts.ChainOutput},
	{Table: "mangle", Builtin: "POSTROUTING", Chain: contracts.ChainEgress},
	{Table: "mangle", Builtin: "OUTPUT", Chain: contracts.ChainTProxyOut, TProxyOnly: true},
	{Table: "mangle", Builtin: "PREROUTING", Chain: contracts.ChainTProxyPre, TProxyOnly: true},
}

// GateHooksFor returns hooks configured for optional external proxy capture chains.
func GateHooksFor(spec GateSpec) []GateHook {
	hooks := make([]GateHook, len(GateHooks))
	copy(hooks, GateHooks)
	if spec.GuardChainOut != "" {
		hooks[1].MainGuard = spec.GuardChainOut
	}
	if spec.GuardChainPost != "" {
		hooks[2].MainGuard = spec.GuardChainPost
	}
	if spec.ProxySkipPrefix != "" {
		hooks[3].SkipPrefix = spec.ProxySkipPrefix
		hooks[4].SkipPrefix = spec.ProxySkipPrefix
	}
	return hooks
}

func hookActive(h GateHook, family int, spec GateSpec) bool {
	if !h.TProxyOnly {
		return true
	}
	return family == 4 && spec.IsTProxy()
}

type ActiveSession struct {
	ClientUID   int    `json:"client_uid"`
	VPNNetID    int    `json:"vpn_net_id"`
	TunIf       string `json:"tun_if"`
	TunIfindex  int    `json:"tun_ifindex"`
	UplinkNetID int    `json:"uplink_net_id"`
	UplinkIf    string `json:"uplink_if"`
	UplinkIndex int    `json:"uplink_index"`
}

func (s *ActiveSession) Validate(userID int) error {
	if s == nil {
		return errors.New("nil active session")
	}
	if !contracts.ValidClientUID(userID, s.ClientUID) {
		return fmt.Errorf("invalid client_uid %d for user %d", s.ClientUID, userID)
	}
	if s.VPNNetID < 100 || s.VPNNetID > contracts.NetIDMask {
		return fmt.Errorf("invalid vpn_net_id %d", s.VPNNetID)
	}
	if s.UplinkNetID < 100 || s.UplinkNetID > contracts.NetIDMask || s.VPNNetID == s.UplinkNetID {
		return fmt.Errorf("invalid uplink_net_id %d (vpn=%d)", s.UplinkNetID, s.VPNNetID)
	}
	if !contracts.TunIfRegex.MatchString(s.TunIf) || len(s.TunIf) > 15 {
		return fmt.Errorf("invalid tun interface %q", s.TunIf)
	}
	if !contracts.UplinkIfRegex.MatchString(s.UplinkIf) || len(s.UplinkIf) > 15 {
		return fmt.Errorf("invalid uplink interface %q", s.UplinkIf)
	}
	if s.TunIfindex <= 0 || s.UplinkIndex <= 0 || s.TunIfindex == s.UplinkIndex {
		return fmt.Errorf("invalid ifindexes tun=%d uplink=%d", s.TunIfindex, s.UplinkIndex)
	}
	return nil
}

type GateSpec struct {
	UserID       int
	UIDStart     int
	UIDEnd       int
	PortalDNS4   string
	EndpointV4   string
	EndpointPort int
	IPv6Enabled  bool
	ArmRawDrop   bool
	Open         bool
	Session      *ActiveSession
	LastVPNNetID int

	Mode       string
	TProxyPort int
	TProxyMark uint32

	ProxySkipPrefix  string
	GuardChainOut    string
	GuardChainPost   string

	// KernelRejectQuicUDP443 skips TPROXY marking for sandbox UDP dport 443 in SBW_TPROXY_OUT
	// so SBW_OUTPUT rejects QUIC directly in kernel space without userspace bounce.
	KernelRejectQuicUDP443 bool
}

func (g GateSpec) IsTProxy() bool { return g.Mode == contracts.ModeTProxy }

func (g GateSpec) tproxyPort() int {
	if g.TProxyPort == 0 {
		return contracts.DefaultTProxyPort
	}
	return g.TProxyPort
}

func (g GateSpec) tproxyMark() uint32 {
	if g.TProxyMark == 0 {
		return contracts.DefaultTProxyMark
	}
	return g.TProxyMark
}

func (g GateSpec) effectiveVPNNetID() int {
	if g.IsTProxy() {
		return 0
	}
	if g.Session != nil && g.Session.VPNNetID >= 100 && g.Session.VPNNetID <= contracts.NetIDMask {
		return g.Session.VPNNetID
	}
	if g.LastVPNNetID >= 100 && g.LastVPNNetID <= contracts.NetIDMask {
		return g.LastVPNNetID
	}
	return 0
}

func (g GateSpec) Validate() error {
	if oem.IsForbiddenUser(g.UserID) {
		return fmt.Errorf("invalid user_id %d", g.UserID)
	}
	wantStart := g.UserID * contracts.AndroidUserWidth
	wantEnd := wantStart + contracts.AndroidUserWidth - 1
	if g.UIDStart != wantStart || g.UIDEnd != wantEnd {
		return fmt.Errorf("uid range %d-%d does not match user %d", g.UIDStart, g.UIDEnd, g.UserID)
	}
	switch g.Mode {
	case "", contracts.ModeVPN:
		if !vpnTransportCompiled() {
			return errors.New("vpn mode requires build with -tags transport_vpn; use mode=tproxy")
		}
	case contracts.ModeTProxy:
		if err := contracts.ValidateTProxyParams(g.tproxyPort(), g.tproxyMark()); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported gate mode %q", g.Mode)
	}
	if g.Open {
		if g.ArmRawDrop {
			return errors.New("cannot open while SBW_RAW_OUTPUT is armed")
		}
		if !g.IsTProxy() {
			if err := g.Session.Validate(g.UserID); err != nil {
				return err
			}
		}
	}
	return nil
}

func tproxyMarkSpec(mark uint32) string {
	return fmt.Sprintf("0x%x/0x%x", mark, contracts.NetIDMask)
}

func tproxyRulesFor(family int, hook GateHook, spec GateSpec) ([]string, error) {
	ownerMatch := fmt.Sprintf("-m owner --uid-owner %d-%d", spec.UIDStart, spec.UIDEnd)
	mk := tproxyMarkSpec(spec.tproxyMark())
	port := spec.tproxyPort()

	switch hook.Chain {
	case contracts.ChainRawOutput:
		if !spec.ArmRawDrop {
			return nil, nil
		}
		return []string{ownerMatch + " -j DROP"}, nil

	case contracts.ChainTProxyOut:
		if family != 4 || !spec.Open {
			return nil, nil
		}
		rules := []string{
			fmt.Sprintf("%s -d 127.0.0.1/32 -p tcp -m tcp --dport 53 -j MARK --set-xmark %s", ownerMatch, mk),
			fmt.Sprintf("%s -d 127.0.0.1/32 -p udp -m udp --dport 53 -j MARK --set-xmark %s", ownerMatch, mk),
			fmt.Sprintf("%s -d 127.0.0.0/8 -j RETURN", ownerMatch),
		}
		if spec.KernelRejectQuicUDP443 {
			rules = append(rules, fmt.Sprintf("%s -p udp -m udp --dport 443 -j RETURN", ownerMatch))
		}
		rules = append(rules,
			fmt.Sprintf("%s -p tcp -j MARK --set-xmark %s", ownerMatch, mk),
			fmt.Sprintf("%s -p udp -j MARK --set-xmark %s", ownerMatch, mk),
			ownerMatch+" -j ACCEPT",
		)
		return rules, nil

	case contracts.ChainTProxyPre:
		if family != 4 || !spec.Open {
			return nil, nil
		}
		return []string{
			"! -i lo -j RETURN",
			"-m conntrack --ctdir REPLY -j RETURN",
			fmt.Sprintf("-i lo -p tcp -m mark --mark %s -j TPROXY --on-port %d --on-ip 127.0.0.1 --tproxy-mark %s", mk, port, mk),
			fmt.Sprintf("-i lo -p udp -m mark --mark %s -j TPROXY --on-port %d --on-ip 127.0.0.1 --tproxy-mark %s", mk, port, mk),
		}, nil

	case contracts.ChainOutput:
		var rules []string
		if spec.Open && family == 4 {
			rules = append(rules, fmt.Sprintf("%s -m mark --mark %s -j RETURN", ownerMatch, mk))
		}
		rules = append(rules,
			ownerMatch+" -p tcp -j REJECT --reject-with tcp-reset",
			ownerMatch+" -j REJECT",
		)
		return rules, nil

	case contracts.ChainEgress:
		var rules []string
		if spec.Open && family == 4 {
			rules = append(rules, fmt.Sprintf("-o lo %s -m mark --mark %s -j RETURN", ownerMatch, mk))
		}
		rules = append(rules, ownerMatch+" -j DROP")
		return rules, nil
	}
	return nil, fmt.Errorf("unknown hook chain %q", hook.Chain)
}

func RulesFor(family int, hook GateHook, spec GateSpec) ([]string, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if family != 4 && family != 6 {
		return nil, fmt.Errorf("unsupported IP family %d", family)
	}
	if spec.IsTProxy() {
		return tproxyRulesFor(family, hook, spec)
	}
	if hook.TProxyOnly {
		return nil, nil
	}
	return vpnRulesFor(family, hook, spec)
}

type Save struct {
	Chains []string
	Rules  map[string][]string
}

func parseSaveLineInto(s *Save, raw string) {
	line := strings.TrimSpace(raw)
	if strings.HasPrefix(line, "[") {
		if idx := strings.Index(line, "] "); idx > 0 {
			line = line[idx+2:]
		}
	}
	switch {
	case strings.HasPrefix(line, ":"):
		fields := strings.Fields(line[1:])
		if len(fields) > 0 {
			s.Chains = append(s.Chains, fields[0])
		}
	case strings.HasPrefix(line, "-A "):
		fields := strings.SplitN(line, " ", 3)
		if len(fields) == 3 {
			s.Rules[fields[1]] = append(s.Rules[fields[1]], fields[2])
		}
	}
}

func ParseSave(text string) Save {
	s := Save{Rules: map[string][]string{}}
	for _, raw := range strings.Split(text, "\n") {
		parseSaveLineInto(&s, raw)
	}
	return s
}

func ParseSaveAll(text string) map[string]Save {
	tables := make(map[string]Save)
	curTable := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || line == "COMMIT" {
			continue
		}
		if strings.HasPrefix(line, "*") {
			tbl := strings.TrimSpace(line[1:])
			if tbl != "" {
				curTable = tbl
				if _, ok := tables[curTable]; !ok {
					tables[curTable] = Save{Rules: map[string][]string{}}
				}
			}
			continue
		}
		if curTable == "" {
			continue
		}
		s := tables[curTable]
		parseSaveLineInto(&s, line)
		tables[curTable] = s
	}
	return tables
}

func CombineBatches(batches []string) string {
	var b strings.Builder
	for _, chunk := range batches {
		if chunk == "" {
			continue
		}
		b.WriteString(chunk)
		if !strings.HasSuffix(chunk, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func MergeTableBatches(batches []string, tableOrder []string) string {
	type tableAcc struct {
		seenDecl map[string]bool
		decls    []string
		cmds     []string
	}
	acc := make(map[string]*tableAcc, 4)
	var extraOrder []string

	for _, chunk := range batches {
		if chunk == "" {
			continue
		}
		curTbl := ""
		for _, raw := range strings.Split(chunk, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || line == "COMMIT" {
				continue
			}
			if strings.HasPrefix(line, "*") {
				curTbl = strings.TrimSpace(line[1:])
				if curTbl != "" && acc[curTbl] == nil {
					acc[curTbl] = &tableAcc{seenDecl: map[string]bool{}}
					extraOrder = append(extraOrder, curTbl)
				}
				continue
			}
			if curTbl == "" {
				continue
			}
			ta := acc[curTbl]
			if strings.HasPrefix(line, ":") {
				fields := strings.Fields(line[1:])
				if len(fields) > 0 && !ta.seenDecl[fields[0]] {
					ta.seenDecl[fields[0]] = true
					ta.decls = append(ta.decls, line)
				}
				continue
			}
			ta.cmds = append(ta.cmds, line)
		}
	}

	emitted := make(map[string]bool, len(acc))
	var b strings.Builder
	writeTable := func(tbl string) {
		ta := acc[tbl]
		if ta == nil || emitted[tbl] || (len(ta.decls) == 0 && len(ta.cmds) == 0) {
			return
		}
		emitted[tbl] = true
		b.WriteByte('*')
		b.WriteString(tbl)
		b.WriteByte('\n')
		for _, d := range ta.decls {
			b.WriteString(d)
			b.WriteByte('\n')
		}
		for _, c := range ta.cmds {
			b.WriteString(c)
			b.WriteByte('\n')
		}
		b.WriteString("COMMIT\n")
	}
	for _, tbl := range tableOrder {
		writeTable(tbl)
	}
	for _, tbl := range extraOrder {
		writeTable(tbl)
	}
	return b.String()
}

func jumpTarget(spec string) string {
	fields := strings.Fields(spec)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-j" || fields[i] == "-g" {
			return fields[i+1]
		}
	}
	return ""
}

// HasExternalCapture reports whether an external proxy core capture chain
// (matching <prefix>*OUTPUT / <prefix>*OUTPUT6) is currently installed in mangle.
func HasExternalCapture(mangle Save, family int, prefix string) bool {
	if prefix == "" {
		return false
	}
	suffix := "OUTPUT"
	if family == 6 {
		suffix = "OUTPUT6"
	}
	matches := func(name string) bool {
		return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
	}
	for _, c := range mangle.Chains {
		if matches(c) {
			return true
		}
	}
	for _, r := range mangle.Rules["OUTPUT"] {
		if matches(jumpTarget(r)) {
			return true
		}
	}
	return false
}

func hookIndex(rules []string, hook GateHook) int {
	idx := 0
	if hook.MainGuard != "" && len(rules) > 0 && rules[0] == "-j "+hook.MainGuard {
		idx = 1
	}
	if hook.SkipPrefix != "" {
		for idx < len(rules) && strings.HasPrefix(jumpTarget(rules[idx]), hook.SkipPrefix) {
			idx++
		}
	}
	return idx
}

func GateBatch(current Save, hook GateHook, rules []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%s\n:%s - [0:0]\n-F %s\n", hook.Table, hook.Chain, hook.Chain)

	var remaining []string
	for _, rule := range current.Rules[hook.Builtin] {
		if jumpTarget(rule) == hook.Chain {
			fmt.Fprintf(&b, "-D %s %s\n", hook.Builtin, rule)
			continue
		}
		remaining = append(remaining, rule)
	}
	pos := hookIndex(remaining, hook) + 1
	for _, rule := range rules {
		fmt.Fprintf(&b, "-A %s %s\n", hook.Chain, rule)
	}
	fmt.Fprintf(&b, "-I %s %d -j %s\nCOMMIT\n", hook.Builtin, pos, hook.Chain)
	return b.String()
}

func ChainPresent(current Save, hook GateHook) bool {
	for _, c := range current.Chains {
		if c == hook.Chain {
			return true
		}
	}
	for _, r := range current.Rules[hook.Builtin] {
		if jumpTarget(r) == hook.Chain {
			return true
		}
	}
	return false
}

func RemoveBatch(current Save, hook GateHook) string {
	if !ChainPresent(current, hook) {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*%s\n", hook.Table)
	chainDeclared := false
	for _, c := range current.Chains {
		if c == hook.Chain {
			chainDeclared = true
		}
	}
	if !chainDeclared {
		fmt.Fprintf(&b, ":%s - [0:0]\n", hook.Chain)
	}
	for _, rule := range current.Rules[hook.Builtin] {
		if jumpTarget(rule) == hook.Chain {
			fmt.Fprintf(&b, "-D %s %s\n", hook.Builtin, rule)
		}
	}
	fmt.Fprintf(&b, "-F %s\n-X %s\nCOMMIT\n", hook.Chain, hook.Chain)
	return b.String()
}

func GateInstalled(current Save, hook GateHook, expected []string) bool {
	rules := current.Rules[hook.Builtin]
	idx := hookIndex(rules, hook)
	if len(rules) <= idx || rules[idx] != "-j "+hook.Chain {
		return false
	}
	jumps := 0
	for _, r := range rules {
		if jumpTarget(r) == hook.Chain {
			jumps++
		}
	}
	if jumps != 1 {
		return false
	}
	actual := current.Rules[hook.Chain]
	if len(actual) != len(expected) {
		return false
	}
	for i, want := range expected {
		if !SameGateRule(want, actual[i]) {
			return false
		}
	}
	return true
}

func SameGateRule(expected, actual string) bool {
	parse := func(line string) (map[string]string, string, bool) {
		fields := strings.Fields(line)
		parsed := make(map[string]string)
		rejectWith := ""
		for i := 0; i < len(fields); {
			neg := false
			if fields[i] == "!" {
				neg = true
				i++
			}
			if i+1 >= len(fields) {
				return nil, "", false
			}
			k, v := fields[i], fields[i+1]
			i += 2
			if v == "!" {
				return nil, "", false
			}
			if neg {
				if k == "-m" || k == "-j" || k == "-g" || k == "--reject-with" {
					return nil, "", false
				}
				k = "!" + k
			}
			switch k {
			case "-m":
				if v != "tcp" && v != "udp" && v != "owner" && v != "mark" && v != "conntrack" {
					return nil, "", false
				}
				continue
			case "--reject-with":
				rejectWith = v
				continue
			case "-d":
				v = strings.TrimSuffix(strings.TrimSuffix(v, "/32"), "/128")
			case "--mark", "--set-xmark", "--tproxy-mark":
				parts := strings.Split(v, "/")
				if len(parts) != 2 {
					return nil, "", false
				}
				mark, err := strconv.ParseUint(parts[0], 0, 32)
				mask, maskErr := strconv.ParseUint(parts[1], 0, 32)
				if err != nil || maskErr != nil {
					return nil, "", false
				}
				v = fmt.Sprintf("0x%x/0x%x", mark, mask)
			}
			if _, exists := parsed[k]; exists {
				return nil, "", false
			}
			parsed[k] = v
		}
		return parsed, rejectWith, true
	}

	want, wantReject, ok := parse(expected)
	got, gotReject, ok2 := parse(actual)
	if !ok || !ok2 || len(want) != len(got) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	if wantReject != "" {
		return gotReject == wantReject
	}
	return gotReject == "" || gotReject == "icmp-port-unreachable" || gotReject == "icmp6-port-unreachable"
}
