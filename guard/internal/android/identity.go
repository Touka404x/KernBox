package android

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
	"sandbox_guard/internal/oem"
)

type Runner interface {
	Run(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) (string, error)
}

var (
	ErrWorkVPNMissing = errors.New("no active Android VPN record for the sandbox controller package")

	networkRecord         = regexp.MustCompile(`^NetworkAgentInfo\{network\{([0-9]+)\}`)
	networkInterface      = regexp.MustCompile(`\bInterfaceName:\s*([a-zA-Z0-9_]+)(?:\s|,|\})`)
	networkOwner          = regexp.MustCompile(`\bOwnerUid:\s*([0-9]+)\b`)
	networkUnderlying     = regexp.MustCompile(`\bunderlying\{\[([0-9]+)\]\}`)
	networkUnderlyingCaps = regexp.MustCompile(`\bUnderlyingNetworks:\s*\[([0-9]+)\]`)
	userListIDRegex       = regexp.MustCompile(`(?:^|\s)id=([0-9]+),`)
	userInfoIDRegex       = regexp.MustCompile(`UserInfo\{([0-9]+):[^}]*\}`)
	userSerialRegex       = regexp.MustCompile(`\bserialNo=([0-9]+)\b`)
	userTypeRegex         = regexp.MustCompile(`\btype=([^,\s]+)`)
	userParentRegex       = regexp.MustCompile(`\bparentId=([0-9]+)\b`)
)

const (
	userFlagDisabled  = 0x40
	userFlagQuietMode = 0x80
)

type DiscoveredProfile struct {
	UserID int
	Serial int
}

// DiscoverManagedProfile scans `cmd user list -v` and `dumpsys user` to find the single
// active Android MANAGED profile with parentId=0, strictly rejecting user 999 / CLONE.
func DiscoverManagedProfile(ctx context.Context, r Runner) (DiscoveredProfile, error) {
	listOut, err := r.Run(ctx, 5*time.Second, "", "cmd", "user", "list", "-v")
	if err != nil {
		return DiscoveredProfile{}, fmt.Errorf("cmd user list -v: %w", err)
	}
	var candidateIDs []int
	for _, row := range strings.Split(listOut, "\n") {
		line := strings.TrimSpace(row)
		var idStr string
		if m := userListIDRegex.FindStringSubmatch(line); len(m) == 2 {
			idStr = m[1]
		} else if m := userInfoIDRegex.FindStringSubmatch(line); len(m) == 2 {
			idStr = m[1]
		} else {
			continue
		}
		uid, err := strconv.Atoi(idStr)
		if err != nil || oem.IsForbiddenUser(uid) {
			continue
		}
		typMatch := userTypeRegex.FindStringSubmatch(line)
		if len(typMatch) != 2 {
			continue
		}
		typ := typMatch[1]
		if typ != "profile.MANAGED" && typ != "android.os.usertype.profile.MANAGED" {
			continue
		}
		parentMatch := userParentRegex.FindStringSubmatch(line)
		if len(parentMatch) == 2 && parentMatch[1] != "0" {
			continue
		}
		candidateIDs = append(candidateIDs, uid)
	}
	if len(candidateIDs) == 0 {
		return DiscoveredProfile{}, errors.New("no Android managed profile (parentId=0) found")
	}
	if len(candidateIDs) > 1 {
		return DiscoveredProfile{}, fmt.Errorf("ambiguous managed profiles found: %v", candidateIDs)
	}
	uid := candidateIDs[0]
	// Obtain serialNo from `dumpsys user --user <u>` and verify parentId=0 on its UserInfo line.
	dump, err := r.Run(ctx, 5*time.Second, "", "dumpsys", "user", "--user", strconv.Itoa(uid))
	if err != nil {
		return DiscoveredProfile{}, fmt.Errorf("dumpsys user --user %d: %w", uid, err)
	}
	serial, err := parseUserSerialFromDump(dump, uid)
	if err != nil || !WorkUserMatches(dump, uid, serial) {
		return DiscoveredProfile{}, fmt.Errorf("dumpsys user failed parentId=0/serialNo check for user %d: %v", uid, err)
	}
	return DiscoveredProfile{UserID: uid, Serial: serial}, nil
}

func parseUserSerialFromDump(dump string, user int) (int, error) {
	prefix := fmt.Sprintf("UserInfo{%d:", user)
	for _, row := range strings.Split(dump, "\n") {
		line := strings.TrimSpace(row)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		m := userSerialRegex.FindStringSubmatch(line)
		if len(m) != 2 {
			continue
		}
		serial, err := strconv.Atoi(m[1])
		if err != nil || serial <= 0 {
			return 0, fmt.Errorf("invalid serialNo in %q", line)
		}
		return serial, nil
	}
	return 0, fmt.Errorf("UserInfo{%d:...} serialNo not found in dumpsys user", user)
}

// DiscoverUser0Package resolves User 0 UID and base.apk path for the configured controller package.
func DiscoverUser0Package(ctx context.Context, r Runner, pkg string) (uid int, apkPath string, err error) {
	listOut, err := r.Run(ctx, 5*time.Second, "", "cmd", "package", "list", "packages", "--user", "0", "-U", pkg)
	if err != nil {
		return 0, "", err
	}
	uid, err = ParsePackageUIDLine(listOut, pkg)
	if err != nil || !contracts.ValidUser0AppUID(uid) {
		return 0, "", fmt.Errorf("invalid User 0 UID %d for %s: %v", uid, pkg, err)
	}
	pathOut, err := r.Run(ctx, 5*time.Second, "", "cmd", "package", "path", "--user", "0", pkg)
	if err != nil {
		return 0, "", err
	}
	apkPath, err = ParsePackageAPKPath(pathOut)
	if err != nil {
		return 0, "", err
	}
	return uid, apkPath, nil
}

func ParsePackageUIDLine(output, pkg string) (int, error) {
	prefix := "package:" + pkg + " uid:"
	for _, row := range strings.Split(output, "\n") {
		line := strings.TrimSpace(row)
		if strings.HasPrefix(line, prefix) {
			rest := strings.TrimPrefix(line, prefix)
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				continue
			}
			// Handle comma-separated multiple UIDs if present by picking exact integer.
			uidStr := strings.Split(fields[0], ",")[0]
			return strconv.Atoi(uidStr)
		}
	}
	return 0, fmt.Errorf("package %s UID not found", pkg)
}

func ParsePackageAPKPath(output string) (string, error) {
	var fallback string
	for _, row := range strings.Split(output, "\n") {
		line := strings.TrimSpace(row)
		if !strings.HasPrefix(line, "package:") {
			continue
		}
		p := strings.TrimPrefix(line, "package:")
		if strings.Contains(p, "..") || !strings.HasPrefix(p, "/") {
			continue
		}
		if strings.HasSuffix(p, "/base.apk") {
			return p, nil
		}
		if fallback == "" && strings.HasSuffix(p, ".apk") {
			fallback = p
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", errors.New("no APK path found")
}

func WorkUserMatches(dump string, user, serial int) bool {
	if oem.IsForbiddenUser(user) || serial <= 0 {
		return false
	}
	prefix := fmt.Sprintf("UserInfo{%d:", user)
	for _, line := range strings.Split(dump, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) &&
			strings.Contains(trimmed, fmt.Sprintf(" serialNo=%d ", serial)) &&
			strings.Contains(trimmed+" ", " parentId=0 ") {
			return true
		}
	}
	return false
}

func WorkUserAllowsRun(dump string, user, serial int) bool {
	if !WorkUserMatches(dump, user, serial) {
		return false
	}
	prefix := "UserInfo{" + strconv.Itoa(user) + ":"
	selected := false
	managed, enabled, unlocked := false, false, false
	for _, row := range strings.Split(dump, "\n") {
		line := strings.TrimSpace(row)
		if strings.HasPrefix(line, "UserInfo{") {
			if selected {
				break
			}
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			selected = true
			if strings.Contains(line, "<removing>") || strings.Contains(line, "<partial>") || strings.Contains(line, "<pre-created>") {
				return false
			}
		}
		if !selected {
			continue
		}
		switch {
		case line == "Type: android.os.usertype.profile.MANAGED":
			managed = true
		case strings.HasPrefix(line, "Flags: "):
			fields := strings.Fields(strings.TrimPrefix(line, "Flags: "))
			if len(fields) > 0 {
				flags, err := strconv.ParseUint(fields[0], 0, 32)
				enabled = err == nil && flags&(userFlagDisabled|userFlagQuietMode) == 0
			}
		case line == "State: RUNNING_UNLOCKED":
			unlocked = true
		}
	}
	return managed && enabled && unlocked
}

func WorkDPCMatches(owners string, user int, adminComp ...string) bool {
	if oem.IsForbiddenUser(user) {
		return false
	}
	wantAdmin := contracts.DefaultAdminComponent
	if len(adminComp) > 0 && strings.TrimSpace(adminComp[0]) != "" {
		wantAdmin = strings.TrimSpace(adminComp[0])
	}
	matched := false
	prefix := strconv.Itoa(user) + ":"
	for _, row := range strings.Split(owners, "\n") {
		fields := strings.Fields(row)
		if len(fields) != 3 || fields[0] != "User" || fields[1] != prefix {
			continue
		}
		flags := strings.Split(fields[2], ",")
		if flags[0] != "admin="+wantAdmin {
			return false
		}
		for _, flag := range flags[1:] {
			switch {
			case flag == "ProfileOwner", flag == "ManagedProfileOwner(parentUserId=0)":
				matched = true
			case flag == "DeviceOwner", strings.HasPrefix(flag, "ManagedProfileOwner("):
				return false
			}
		}
	}
	return matched
}

func WorkPackageCanRun(dump string, user int) bool {
	prefix := "User " + strconv.Itoa(user) + ": "
	for _, row := range strings.Split(dump, "\n") {
		fields, ok := strings.CutPrefix(strings.TrimSpace(row), prefix)
		if !ok {
			continue
		}
		state := make(map[string]string)
		for _, field := range strings.Fields(fields) {
			if key, value, ok := strings.Cut(field, "="); ok {
				state[key] = value
			}
		}
		return state["installed"] == "true" && state["hidden"] == "false" &&
			state["suspended"] == "false" && state["stopped"] == "false" &&
			(state["enabled"] == "0" || state["enabled"] == "1")
	}
	return false
}

func VerifyWorkLockdown(ctx context.Context, r Runner, user int, callerPkg ...string) error {
	pkg := contracts.DefaultWorkPackage
	if len(callerPkg) > 0 && contracts.ValidPackageName(callerPkg[0]) {
		pkg = callerPkg[0]
	}
	u := strconv.Itoa(user)
	for key, expected := range map[string]string{
		"always_on_vpn_app":      pkg,
		"always_on_vpn_lockdown": "1",
	} {
		val, err := r.Run(ctx, 4*time.Second, "", "settings", "--user", u, "get", "secure", key)
		if err != nil || strings.TrimSpace(val) != expected {
			return fmt.Errorf("always-on lockdown check failed on %s=%q", key, strings.TrimSpace(val))
		}
	}
	wl, err := r.Run(ctx, 4*time.Second, "", "settings", "--user", u, "get", "secure", "always_on_vpn_lockdown_whitelist")
	if v := strings.TrimSpace(wl); err != nil || (v != "" && v != "null") {
		return fmt.Errorf("always-on lockdown has bypass whitelist %q", v)
	}
	return nil
}

func WorkClientUID(ctx context.Context, r Runner, user int, callerPkg ...string) (int, error) {
	if oem.IsForbiddenUser(user) {
		return 0, fmt.Errorf("invalid user %d", user)
	}
	pkg := contracts.DefaultWorkPackage
	if len(callerPkg) > 0 && contracts.ValidPackageName(callerPkg[0]) {
		pkg = callerPkg[0]
	}
	u := strconv.Itoa(user)
	out, err := r.Run(ctx, 4*time.Second, "", "cmd", "package", "list", "packages", "--user", u, "-U", pkg)
	if err != nil {
		return 0, err
	}
	uid, err := ParsePackageUIDLine(out, pkg)
	if err != nil || !contracts.ValidClientUID(user, uid) {
		return 0, fmt.Errorf("invalid work client UID %d for user %d", uid, user)
	}
	return uid, nil
}

// VerifiedIdentity caches boot-static profile/DPC/AlwaysOnVpn verification.
type VerifiedIdentity struct {
	UserID    int
	Serial    int
	ClientUID int
}

// VerifyStaticIdentity verifies managed profile, parentId=0, serial, RUNNING_UNLOCKED,
// DPM ProfileOwner, AlwaysOnVpn lockdown, vpn_management ownership, and work client UID.
func VerifyStaticIdentity(ctx context.Context, r Runner, policy contracts.Policy) (VerifiedIdentity, error) {
	if err := policy.NormalizeAndValidate(); err != nil {
		return VerifiedIdentity{}, err
	}
	callerPkg := policy.EffectiveCallerPackage()
	adminComp := policy.EffectiveAdminComponent()
	u := strconv.Itoa(policy.UserID)

	usersOut, err := r.Run(ctx, 4*time.Second, "", "cmd", "user", "list", "-v")
	if err != nil {
		return VerifiedIdentity{}, err
	}
	managed := false
	for _, entry := range strings.Split(usersOut, "\n") {
		m := userListIDRegex.FindStringSubmatch(strings.TrimSpace(entry))
		idMatch := len(m) == 2 && m[1] == u
		if idMatch &&
			(strings.Contains(entry, "type=profile.MANAGED,") || strings.Contains(entry, "type=android.os.usertype.profile.MANAGED,")) &&
			strings.Contains(entry, "(running)") {
			managed = true
			break
		}
	}
	if !managed {
		return VerifiedIdentity{}, fmt.Errorf("user %d is not a running managed profile", policy.UserID)
	}

	userDump, err := r.Run(ctx, 4*time.Second, "", "dumpsys", "user", "--user", u)
	if err != nil || !WorkUserAllowsRun(userDump, policy.UserID, policy.Serial) {
		return VerifiedIdentity{}, fmt.Errorf("user %d failed serial/parentId=0/RUNNING_UNLOCKED check", policy.UserID)
	}

	ownersOut, err := r.Run(ctx, 4*time.Second, "", "cmd", "device_policy", "list-owners")
	if err != nil || !WorkDPCMatches(ownersOut, policy.UserID, adminComp) {
		return VerifiedIdentity{}, errors.New("device_policy owner check failed")
	}

	if !policy.IsTProxy() {
		if err := VerifyWorkLockdown(ctx, r, policy.UserID, callerPkg); err != nil {
			return VerifiedIdentity{}, err
		}

		vpnOwners, err := r.Run(ctx, 4*time.Second, "", "dumpsys", "vpn_management")
		if err != nil {
			return VerifiedIdentity{}, err
		}
		vpnBound := false
		wantLine := u + ": " + callerPkg
		for _, line := range strings.Split(vpnOwners, "\n") {
			if strings.TrimSpace(line) == wantLine {
				vpnBound = true
				break
			}
		}
		if !vpnBound {
			return VerifiedIdentity{}, fmt.Errorf("vpn_management does not bind work profile VPN to %s", callerPkg)
		}
	}

	clientUID, err := WorkClientUID(ctx, r, policy.UserID, callerPkg)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	return VerifiedIdentity{UserID: policy.UserID, Serial: policy.Serial, ClientUID: clientUID}, nil
}

func regexMatch(pattern *regexp.Regexp, line string) string {
	groups := pattern.FindStringSubmatch(line)
	if len(groups) != 2 {
		return ""
	}
	return groups[1]
}

// ParseWorkNetworks extracts the unique Android VPN session and its dedicated physical underlay
// from `dumpsys connectivity` output.
func ParseWorkNetworks(dump string, uid int) (*netfilter.ActiveSession, error) {
	type observedNet struct {
		iface     string
		vpn       bool
		connected bool
	}
	nets := make(map[int]observedNet)
	var work *netfilter.ActiveSession
	started := false
	for _, row := range strings.Split(dump, "\n") {
		line := strings.TrimSpace(row)
		if line == "Current Networks:" {
			started = true
			continue
		}
		if !started {
			continue
		}
		if len(row) > 0 && row[0] != ' ' && row[0] != '\t' {
			break
		}
		id, err := strconv.Atoi(regexMatch(networkRecord, line))
		if err != nil {
			continue
		}
		linkStart := strings.Index(line, " lp{")
		capsStart := strings.Index(line, " nc{")
		if linkStart < 0 || capsStart <= linkStart {
			continue
		}
		if _, dup := nets[id]; dup {
			return nil, errors.New("duplicate netId in connectivity output")
		}
		header, link, caps := line[:linkStart], line[linkStart:capsStart], line[capsStart:]
		iface := regexMatch(networkInterface, link)
		isVPN := strings.Contains(header, " ni{VPN ") || strings.Contains(header, " ni{VPN[")
		connected := strings.Contains(header, " CONNECTED")
		nets[id] = observedNet{iface: iface, vpn: isVPN, connected: connected}
		if !isVPN || !connected || regexMatch(networkOwner, caps) != strconv.Itoa(uid) {
			continue
		}
		if work != nil {
			return nil, errors.New("multiple active VPN records for work package")
		}
		under := regexMatch(networkUnderlying, header)
		if under == "" {
			under = regexMatch(networkUnderlyingCaps, caps)
		}
		underID, err := strconv.Atoi(under)
		if err != nil || !contracts.TunIfRegex.MatchString(iface) {
			return nil, errors.New("work VPN requires one explicit underlying network and TUN")
		}
		work = &netfilter.ActiveSession{
			ClientUID:   uid,
			VPNNetID:    id,
			TunIf:       iface,
			UplinkNetID: underID,
		}
	}
	if work == nil {
		for _, network := range nets {
			if network.connected && !network.vpn && contracts.UplinkIfRegex.MatchString(network.iface) {
				return nil, ErrWorkVPNMissing
			}
		}
		return nil, errors.New("no recognized Android physical network")
	}
	under, ok := nets[work.UplinkNetID]
	if !ok || !under.connected || under.vpn || !contracts.UplinkIfRegex.MatchString(under.iface) {
		return nil, errors.New("work VPN underlying network is not a recognized physical interface")
	}
	work.UplinkIf = under.iface
	return work, nil
}

// LiveIface represents a local OS interface snapshot for zero-dumpsys single-uplink fast path.
type LiveIface struct {
	Name       string
	Index      int
	Up         bool
	HasIPv4    bool
	HasGateway bool
	IPv4CIDRs  []string
}

func inspectNetInterface(ifc net.Interface) (LiveIface, bool) {
	if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
		return LiveIface{}, false
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return LiveIface{}, false
	}
	li := LiveIface{Name: ifc.Name, Index: ifc.Index, Up: true}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipNet.IP.To4()
		if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
			continue
		}
		li.HasIPv4 = true
		li.IPv4CIDRs = append(li.IPv4CIDRs, ipNet.String())
	}
	if li.Index <= 0 {
		li.Index = InterfaceIndex(ifc.Name)
	}
	return li, true
}

// ReadLiveIfaces reads local network interfaces without spawning any subprocesses.
func ReadLiveIfaces() ([]LiveIface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []LiveIface
	for _, ifc := range ifaces {
		if !contracts.TunIfRegex.MatchString(ifc.Name) && !contracts.UplinkIfRegex.MatchString(ifc.Name) {
			continue
		}
		if li, ok := inspectNetInterface(ifc); ok {
			out = append(out, li)
		}
	}
	return out, nil
}

func InterfaceIndex(name string) int {
	val, err := os.ReadFile(filepath.Join("/sys/class/net", name, "ifindex"))
	if err != nil {
		return 0
	}
	var idx int
	_, _ = fmt.Sscan(strings.TrimSpace(string(val)), &idx)
	return idx
}

func hasTunGatewayCIDR(ifc LiveIface) bool {
	for _, cidr := range ifc.IPv4CIDRs {
		if strings.HasPrefix(cidr, contracts.TunGateway4+"/") {
			return true
		}
	}
	return false
}

// VerifyLiveIfaceUpIPv4 checks a single named interface via net.InterfaceByName without external processes.
func VerifyLiveIfaceUpIPv4(name string, requireTunGW bool) (LiveIface, bool) {
	if name == "" || name == "lo" {
		return LiveIface{}, false
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil || ifc == nil {
		return LiveIface{}, false
	}
	li, ok := inspectNetInterface(*ifc)
	if !ok || !li.HasIPv4 || li.Index <= 0 {
		return LiveIface{}, false
	}
	if requireTunGW && !hasTunGatewayCIDR(li) {
		return LiveIface{}, false
	}
	return li, true
}

func validFastStatus(bootID string, status *contracts.VPNStatus) bool {
	if status == nil || !status.Running || bootID == "" || status.BootID != bootID {
		return false
	}
	if !contracts.TunIfRegex.MatchString(status.TunIf) {
		return false
	}
	if status.UnderlayIf == "" || status.UnderlayIf == status.TunIf || status.UnderlayIf == "lo" ||
		!contracts.UplinkIfRegex.MatchString(status.UnderlayIf) {
		return false
	}
	if status.VPNNetID < 100 || status.VPNNetID > contracts.NetIDMask ||
		status.UnderlayNetID < 100 || status.UnderlayNetID > contracts.NetIDMask ||
		status.VPNNetID == status.UnderlayNetID {
		return false
	}
	return true
}

// TryFastStatusSession resolves an ActiveSession in <15ms from verified vpn_status.json
// and live interfaces, including multi-uplink states where wlan0 and cellular coexist.
func TryFastStatusSession(bootID string, clientUID int, status *contracts.VPNStatus, ifaces []LiveIface) (*netfilter.ActiveSession, bool) {
	if !validFastStatus(bootID, status) {
		return nil, false
	}
	var tunIface, uplinkIface *LiveIface
	for i := range ifaces {
		ifc := &ifaces[i]
		if !ifc.Up || !ifc.HasIPv4 || ifc.Index <= 0 {
			continue
		}
		if ifc.Name == status.TunIf && hasTunGatewayCIDR(*ifc) {
			tunIface = ifc
		} else if ifc.Name == status.UnderlayIf {
			uplinkIface = ifc
		}
	}
	if tunIface == nil || uplinkIface == nil {
		return nil, false
	}
	sess := &netfilter.ActiveSession{
		ClientUID:   clientUID,
		VPNNetID:    status.VPNNetID,
		TunIf:       tunIface.Name,
		TunIfindex:  tunIface.Index,
		UplinkNetID: status.UnderlayNetID,
		UplinkIf:    uplinkIface.Name,
		UplinkIndex: uplinkIface.Index,
	}
	if err := sess.Validate(clientUID / contracts.AndroidUserWidth); err != nil {
		return nil, false
	}
	return sess, true
}

// ResolveFastStatusSession checks status.TunIf and status.UnderlayIf via net.InterfaceByName
// (zero external dumpsys processes) when vpn_status.json identifies an active physical underlay.
func ResolveFastStatusSession(bootID string, clientUID int, status *contracts.VPNStatus) (*netfilter.ActiveSession, bool) {
	if !validFastStatus(bootID, status) {
		return nil, false
	}
	tun, ok1 := VerifyLiveIfaceUpIPv4(status.TunIf, true)
	if !ok1 {
		return nil, false
	}
	uplink, ok2 := VerifyLiveIfaceUpIPv4(status.UnderlayIf, false)
	if !ok2 {
		return nil, false
	}
	return TryFastStatusSession(bootID, clientUID, status, []LiveIface{tun, uplink})
}

// TryFastSingleUplinkSession resolves an ActiveSession in <15ms with 0 dumpsys calls when
// exactly one physical uplink is active and vpn_status.json matches the current boot & interfaces.
// Returns (session, multiUplink, ok). When multiUplink is true or ok is false, caller uses dumpsys connectivity.
func TryFastSingleUplinkSession(bootID string, clientUID int, status *contracts.VPNStatus, ifaces []LiveIface) (*netfilter.ActiveSession, bool, bool) {
	var tuns []LiveIface
	var uplinks []LiveIface
	for _, ifc := range ifaces {
		if !ifc.Up || !ifc.HasIPv4 || ifc.Index <= 0 {
			continue
		}
		switch {
		case contracts.TunIfRegex.MatchString(ifc.Name):
			if hasTunGatewayCIDR(ifc) {
				tuns = append(tuns, ifc)
			}
		case contracts.UplinkIfRegex.MatchString(ifc.Name):
			uplinks = append(uplinks, ifc)
		}
	}
	if len(uplinks) > 1 {
		return nil, true, false
	}
	if len(uplinks) != 1 || len(tuns) != 1 {
		return nil, false, false
	}
	sess, ok := TryFastStatusSession(bootID, clientUID, status, ifaces)
	return sess, false, ok
}

// DiscoverSessionFromConnectivity performs bounded dumpsys connectivity + TUN IP + route checks.
func DiscoverSessionFromConnectivity(ctx context.Context, r Runner, id VerifiedIdentity, verifyRoutes bool, endpoints ...string) (*netfilter.ActiveSession, error) {
	endpointV4 := ""
	if len(endpoints) > 0 {
		endpointV4 = strings.TrimSpace(endpoints[0])
	}
	portalDNS4 := contracts.PortalDNS4
	if len(endpoints) > 1 && strings.TrimSpace(endpoints[1]) != "" {
		portalDNS4 = strings.TrimSpace(endpoints[1])
	}

	state, err := r.Run(ctx, 4*time.Second, "", "dumpsys", "connectivity")
	if err != nil {
		return nil, fmt.Errorf("dumpsys connectivity: %w", err)
	}
	sess, err := ParseWorkNetworks(state, id.ClientUID)
	if err != nil {
		return nil, err
	}
	sess.TunIfindex = InterfaceIndex(sess.TunIf)
	sess.UplinkIndex = InterfaceIndex(sess.UplinkIf)
	if err := sess.Validate(id.UserID); err != nil {
		return nil, err
	}

	linkOut, err := r.Run(ctx, 4*time.Second, "", "ip", "-4", "addr", "show", "dev", sess.TunIf)
	if err != nil || !strings.Contains(linkOut, "inet "+contracts.TunGateway4+"/30 ") {
		return nil, fmt.Errorf("TUN %s missing %s/30", sess.TunIf, contracts.TunGateway4)
	}

	if verifyRoutes {
		innerUID := id.UserID*contracts.AndroidUserWidth + contracts.MinAppID
		if innerUID == id.ClientUID {
			innerUID++
		}
		if err := CheckWorkRoute(ctx, r, contracts.FakeIPProbe, innerUID, sess.UplinkNetID, sess.TunIf); err != nil {
			return nil, fmt.Errorf("work UID route (%s): %w", contracts.FakeIPProbe, err)
		}
		if endpointV4 != "" {
			outerMark := sess.UplinkNetID | contracts.ProtectedVPNBit | contracts.ExplicitNetworkBit
			if err := CheckWorkRoute(ctx, r, endpointV4, sess.ClientUID, outerMark, sess.UplinkIf); err != nil {
				return nil, fmt.Errorf("outer route: %w", err)
			}
		}
		dnsMark := sess.VPNNetID | contracts.ExplicitNetworkBit | contracts.ProtectedVPNBit | contracts.SystemPermission
		if err := CheckWorkRoute(ctx, r, portalDNS4, 1051, dnsMark, sess.TunIf); err != nil {
			return nil, fmt.Errorf("delegated DNS route: %w", err)
		}
	}
	return sess, nil
}

func CheckWorkRoute(ctx context.Context, r Runner, address string, uid, mark int, iface string) error {
	out, err := r.Run(ctx, 4*time.Second, "", "ip", "-4", "route", "get", address, "mark", fmt.Sprintf("0x%x", mark), "uid", strconv.Itoa(uid))
	if err != nil || !strings.Contains(" "+strings.TrimSpace(out)+" ", " dev "+iface+" ") {
		return fmt.Errorf("route to %s did not resolve to %s", address, iface)
	}
	return nil
}
