package contracts

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"sandbox_guard/internal/buildinfo"
	"sandbox_guard/internal/oem"
)

var Version = buildinfo.Version

const (
	ModeVPN    = "vpn"
	ModeTProxy = "tproxy"

	DefaultTProxyPort    = 1537
	DefaultTProxyMark    = 0x1a
	DefaultTProxyTable   = 2027
	DefaultTProxyPref    = 2025
	DefaultSandboxInName = "sandbox-tproxy"

	GuardHome          = "/data/adb/sandbox_guard"
	GuardBin           = GuardHome + "/sandbox_guard"
	BrokerBin          = GuardHome + "/sandbox_broker"
	StagingDir         = GuardHome + "/staging"
	ModuleDir          = "/data/adb/modules/sandbox_guard"
	PolicyPath         = GuardHome + "/policy.json"
	ExemptionPath      = GuardHome + "/exemption.v1.json"
	UpgradeFencePath   = GuardHome + "/upgrade_fence.json"
	DesiredStatePath   = GuardHome + "/desired_state.json"
	DaemonLockPath     = GuardHome + "/daemon.lock"
	CtlSockPath        = GuardHome + "/ctl.sock"
	StealthConfigPath  = GuardHome + "/stealth.json"
	PerfConfigPath     = GuardHome + "/perf.json"
	PrunedPkgsPath     = GuardHome + "/pruned_pkgs.json"
	HibernatedPkgsPath   = GuardHome + "/hibernated_pkgs.json"
	StealthBootTriesPath = GuardHome + "/stealth_boot_tries"
	ZygiskDisabledFlag   = ModuleDir + "/zygisk_disabled"

	MainBase        = "/data/adb/sandbox_proxy"
	MainConfigPath  = MainBase + "/config.json"
	MainCtlScript   = MainBase + "/proxy.sh"
	SandboxAckPath  = MainBase + "/sandbox_ack.v1.json"
	MainCorePIDPath = MainBase + "/core.pid"
	MainStatusPath  = MainBase + "/status.json"
	SharedLockPath  = "/data/adb/.sandbox_netfilter.lock"

	ManagedProvisioningPkg = "com.android.managedprovisioning"

	BrokerSockDir      = "/dev/socket/sandbox_ctrl"
	BrokerSockPath     = BrokerSockDir + "/ctrl.sock"
	PrivDir            = "/dev/socket/sandbox_priv"
	GuardSockPath      = PrivDir + "/guard.sock"
	BrokerAuthPath     = PrivDir + "/broker_auth.json"
	WorkCfgDir         = "/dev/sandbox_cfg"
	StealthRuntimePath = WorkCfgDir + "/stealth.json"

	SELinuxSockDir   = "u:object_r:sandbox_ctrl_sock_dir:s0"
	SELinuxSockFile  = "u:object_r:sandbox_ctrl_sock:s0"
	SELinuxPrivDir   = "u:object_r:sandbox_priv_dir:s0"
	SELinuxPrivFile  = "u:object_r:sandbox_priv_file:s0"
	SELinuxPrivSock  = "u:object_r:sandbox_priv_sock:s0"
	SELinuxCfgDir    = "u:object_r:sandbox_cfg_dir:s0"
	SELinuxCfgFile   = "u:object_r:sandbox_cfg_file:s0"
	SELinuxBrokerCtx = "u:r:sandbox_broker:s0"

	DefaultWorkPackage          = "com.sandbox.controller"
	DefaultAdminReceiverClass   = ".SandboxAdminReceiver"
	DefaultServiceClass         = ".service.TunService"
	DefaultAdminComponent       = DefaultWorkPackage + "/" + DefaultAdminReceiverClass
	DefaultServiceComponent     = DefaultWorkPackage + "/" + DefaultServiceClass
	DefaultServiceProcessSuffix = ":background"
	VerifyProbePackage          = "com.sandbox.verify"

	ActionStartVPN     = "com.sandbox.controller.action.START_VPN"
	ActionPauseVPN     = "com.sandbox.controller.action.PAUSE_VPN"
	ActionReloadConfig = "com.sandbox.controller.action.RELOAD_CONFIG"
	PackagesListPath   = "/data/system/packages.list"
	UsersSystemDir     = "/data/system/users"
	NetdMiscDir        = "/data/misc/net"
	ProcNetTCP         = "/proc/net/tcp"
	ProcBootID         = "/proc/sys/kernel/random/boot_id"
	ProcSelfAttrCurrent = "/proc/self/attr/current"

	PortalDNS4   = "172.19.0.2"
	TunGateway4  = "172.19.0.1"
	FakeIPProbe  = "198.19.0.1"
	FakeIPRange  = "198.19.0.1/16"
	EndpointPort = 443
	SandboxMTU   = 1380

	AndroidUserWidth         = 100000
	MinAppID                 = 10000
	MaxAppID                 = 19999
	ContractVersion          = 1
	DefaultUpgradeTTLSeconds = 90
	MaxUpgradeTTLSeconds     = 300
	MaxRPCLineBytes          = 8192
	MaxRPCRespBytes          = 65536
	MaxVPNStatusBytes        = 4096
	MaxSmallFileBytes        = 16384

	NetIDMask          = 0xffff
	ExplicitNetworkBit = 0x10000
	ProtectedVPNBit    = 0x20000
	SystemPermission   = 0xc0000

	ChainRawOutput = "SBW_RAW_OUTPUT"
	ChainOutput    = "SBW_OUTPUT"
	ChainEgress    = "SBW_EGRESS"
	ChainTProxyOut = "SBW_TPROXY_OUT"
	ChainTProxyPre = "SBW_TPROXY_PRE"
)

// StringMatcher keeps the Regex.MatchString contract without importing regexp.
type StringMatcher func(string) bool

func (m StringMatcher) MatchString(s string) bool { return m(s) }

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isASCIIAlnum(b byte) bool {
	return isASCIIAlpha(b) || isASCIIDigit(b)
}

func isValidPackageNameStr(s string) bool {
	if len(s) == 0 || !isASCIIAlpha(s[0]) {
		return false
	}
	dots := 0
	segLen := 1
	for i := 1; i < len(s); i++ {
		b := s[i]
		if b == '.' {
			if segLen == 0 {
				return false
			}
			dots++
			segLen = 0
			continue
		}
		if !isASCIIAlnum(b) && b != '_' {
			return false
		}
		segLen++
	}
	return dots > 0 && segLen > 0
}

func isValidLocaleTagStr(s string) bool {
	if len(s) < 2 {
		return false
	}
	i := 0
	for i < len(s) && isASCIIAlpha(s[i]) {
		i++
	}
	if i < 2 || i > 3 {
		return false
	}
	for i < len(s) {
		if s[i] != '-' {
			return false
		}
		i++
		start := i
		for i < len(s) && isASCIIAlnum(s[i]) {
			i++
		}
		subLen := i - start
		if subLen < 2 || subLen > 8 {
			return false
		}
	}
	return true
}

func isValidSHA256HexStr(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return false
		}
	}
	return true
}

func isAllDigitsRange(s string, minLen, maxLen int) bool {
	if len(s) < minLen || (maxLen >= 0 && len(s) > maxLen) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isASCIIDigit(s[i]) {
			return false
		}
	}
	return true
}

func isValidTunIfStr(s string) bool {
	return strings.HasPrefix(s, "tun") && isAllDigitsRange(s[3:], 1, 10)
}

func isValidUplinkIfStr(s string) bool {
	if s == "umts_router" {
		return true
	}
	for _, p := range []string{"wlan", "v4-wlan", "rmnet_data", "ccmni", "v4-ccmni", "seth_lte", "v4-seth_lte", "wwan", "ncm", "usb", "eth", "rndis"} {
		if strings.HasPrefix(s, p) {
			return isAllDigitsRange(s[len(p):], 1, -1)
		}
	}
	for _, p := range []string{"rmnet_mhi", "rmnet_usb", "rmnet_ipa", "rmnet"} {
		if strings.HasPrefix(s, p) {
			return isAllDigitsRange(s[len(p):], 0, -1)
		}
	}
	if strings.HasPrefix(s, "v4-rmnet") {
		rest := s[len("v4-rmnet"):]
		for i := 0; i < len(rest); i++ {
			b := rest[i]
			if !((b >= 'a' && b <= 'z') || isASCIIDigit(b) || b == '_') {
				return false
			}
		}
		return true
	}
	return false
}

func isValidBootIDStr(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(isASCIIDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') || b == '-') {
			return false
		}
	}
	return true
}

func isValidComponentClassStr(s string) bool {
	if len(s) < 1 || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(isASCIIAlnum(b) || b == '_' || b == '.' || b == '$') {
			return false
		}
	}
	return true
}

func isValidChainPrefixStr(s string) bool {
	if len(s) < 2 || len(s) > 21 || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		b := s[i]
		if !((b >= 'A' && b <= 'Z') || isASCIIDigit(b) || b == '_') {
			return false
		}
	}
	return true
}

func isValidInboundTokenStr(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(isASCIIAlnum(b) || b == '.' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

var (
	PackageNameRegex    = StringMatcher(isValidPackageNameStr)
	LocaleTagRegex      = StringMatcher(isValidLocaleTagStr)
	SHA256HexRegex      = StringMatcher(isValidSHA256HexStr)
	TunIfRegex          = StringMatcher(isValidTunIfStr)
	UplinkIfRegex       = StringMatcher(isValidUplinkIfStr)
	BootIDRegex         = StringMatcher(isValidBootIDStr)
	ComponentClassRegex = StringMatcher(isValidComponentClassStr)
	ChainPrefixRegex    = StringMatcher(isValidChainPrefixStr)
	InboundTokenRegex   = StringMatcher(isValidInboundTokenStr)
)

// Policy is the root-pinned configuration in /data/adb/sandbox_guard/policy.json.
type Policy struct {
	UserID           int    `json:"user_id"`
	Serial           int    `json:"serial"`
	CallerPackage    string `json:"caller_package,omitempty"`
	CallerCertSHA256 string `json:"caller_cert_sha256"`
	AdminComponent   string `json:"admin_component,omitempty"`
	ServiceComponent string `json:"service_component,omitempty"`
	PortalDNS4       string `json:"portal_dns4,omitempty"`
	EndpointV4       string `json:"endpoint_v4,omitempty"`
	EndpointPort     int    `json:"endpoint_port,omitempty"`
	IPv6Enabled      bool   `json:"ipv6_enabled"`
	Mode             string `json:"mode,omitempty"`
	TProxyPort       int    `json:"tproxy_port,omitempty"`
	TProxyMark       uint32 `json:"tproxy_mark,omitempty"`

	// Optional proxy-core integration knobs (decoupled from any hardcoded upstream layout).
	ProxyBaseDir           string `json:"proxy_base_dir,omitempty"`
	ProxyCtlScript         string `json:"proxy_ctl_script,omitempty"`
	ProxyConfigPath        string `json:"proxy_config_path,omitempty"`
	ProxyAckPath           string `json:"proxy_ack_path,omitempty"`
	ProxyCorePIDPath       string `json:"proxy_core_pid_path,omitempty"`
	ProxyInboundName       string `json:"proxy_inbound_name,omitempty"`
	ProxyCoreProcess       string `json:"proxy_core_process,omitempty"`
	ProxySkipPrefix        string `json:"proxy_skip_prefix,omitempty"`
	ProxyExemptionPath     string `json:"proxy_exemption_path,omitempty"`
	ProxyNetfilterLockPath string `json:"proxy_netfilter_lock_path,omitempty"`
	GuardChainOut          string `json:"guard_chain_out,omitempty"`
	GuardChainPost         string `json:"guard_chain_post,omitempty"`
}

func ValidateTProxyParams(port int, mark uint32) error {
	if port < 1024 || port > 65535 {
		return fmt.Errorf("tproxy_port %d out of range 1024..65535", port)
	}
	if mark == 0 || mark > 0xffff || mark == 0x14 || mark == 0x19 {
		return fmt.Errorf("invalid tproxy_mark 0x%x", mark)
	}
	return nil
}

func (p Policy) IsTProxy() bool { return p.Mode == ModeTProxy }

func (p Policy) EffectiveCallerPackage() string {
	if p.CallerPackage != "" {
		return p.CallerPackage
	}
	return DefaultWorkPackage
}

func (p Policy) EffectiveAdminComponent() string {
	if p.AdminComponent != "" {
		return p.AdminComponent
	}
	return p.EffectiveCallerPackage() + "/" + DefaultAdminReceiverClass
}

func (p Policy) EffectiveAdminPackage() string {
	comp := p.EffectiveAdminComponent()
	if idx := strings.IndexByte(comp, '/'); idx > 0 {
		return comp[:idx]
	}
	return p.EffectiveCallerPackage()
}

func (p Policy) EffectiveServiceComponent() string {
	if p.ServiceComponent != "" {
		return p.ServiceComponent
	}
	return p.EffectiveCallerPackage() + "/" + DefaultServiceClass
}

func (p Policy) EffectiveProxyBaseDir() string {
	if p.ProxyBaseDir != "" {
		return p.ProxyBaseDir
	}
	return MainBase
}

func (p Policy) EffectiveProxyCtlScript() string {
	if p.ProxyCtlScript != "" {
		return p.ProxyCtlScript
	}
	return p.EffectiveProxyBaseDir() + "/proxy.sh"
}

func (p Policy) EffectiveProxyConfigPath() string {
	if p.ProxyConfigPath != "" {
		return p.ProxyConfigPath
	}
	return p.EffectiveProxyBaseDir() + "/config.json"
}

func (p Policy) EffectiveProxyAckPath() string {
	if p.ProxyAckPath != "" {
		return p.ProxyAckPath
	}
	return p.EffectiveProxyBaseDir() + "/sandbox_ack.v1.json"
}

func (p Policy) EffectiveProxyCorePIDPath() string {
	if p.ProxyCorePIDPath != "" {
		return p.ProxyCorePIDPath
	}
	return p.EffectiveProxyBaseDir() + "/core.pid"
}

func (p Policy) EffectiveProxyInboundName() string {
	if p.ProxyInboundName != "" {
		return p.ProxyInboundName
	}
	return DefaultSandboxInName
}

func (p Policy) EffectiveExemptionPath() string {
	if p.ProxyExemptionPath != "" {
		return p.ProxyExemptionPath
	}
	return ExemptionPath
}

func (p Policy) EffectiveNetfilterLockPath() string {
	if p.ProxyNetfilterLockPath != "" {
		return p.ProxyNetfilterLockPath
	}
	return SharedLockPath
}

func ValidAbsoluteSafePath(p string) bool {
	if len(p) < 2 || len(p) > 512 || !strings.HasPrefix(p, "/") {
		return false
	}
	return !strings.Contains(p, "..") && !strings.ContainsAny(p, "\x00\r\n\t;&|$`'\"\\ ")
}

func ValidComponentName(comp string) bool {
	pkg, cls, ok := strings.Cut(comp, "/")
	if !ok {
		return false
	}
	return ValidPackageName(pkg) && ValidComponentClass(cls)
}

func ValidIPv4Literal(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

func (p *Policy) NormalizeAndValidate() error {
	if p == nil {
		return errors.New("policy is nil")
	}
	if oem.IsForbiddenUser(p.UserID) || p.UserID > 21473 {
		return fmt.Errorf("invalid managed profile user_id: %d", p.UserID)
	}
	if p.Serial <= 0 {
		return fmt.Errorf("invalid profile serial: %d", p.Serial)
	}
	p.CallerPackage = strings.TrimSpace(p.CallerPackage)
	if p.CallerPackage == "" {
		p.CallerPackage = DefaultWorkPackage
	}
	if !ValidPackageName(p.CallerPackage) {
		return fmt.Errorf("invalid caller_package %q", p.CallerPackage)
	}
	p.CallerCertSHA256 = strings.ToLower(strings.TrimSpace(p.CallerCertSHA256))
	p.CallerCertSHA256 = strings.ReplaceAll(p.CallerCertSHA256, ":", "")
	if !SHA256HexRegex.MatchString(p.CallerCertSHA256) {
		return errors.New("policy requires 64-hex caller_cert_sha256")
	}
	if p.AdminComponent != "" && !ValidComponentName(p.AdminComponent) {
		return fmt.Errorf("invalid admin_component %q", p.AdminComponent)
	}
	if p.ServiceComponent != "" && !ValidComponentName(p.ServiceComponent) {
		return fmt.Errorf("invalid service_component %q", p.ServiceComponent)
	}
	if p.PortalDNS4 == "" {
		p.PortalDNS4 = PortalDNS4
	}
	if !ValidIPv4Literal(p.PortalDNS4) {
		return fmt.Errorf("invalid portal_dns4 %q", p.PortalDNS4)
	}
	if p.EndpointV4 != "" && !ValidIPv4Literal(p.EndpointV4) {
		return fmt.Errorf("invalid endpoint_v4 %q", p.EndpointV4)
	}
	if p.EndpointPort < 0 || p.EndpointPort > 65535 {
		return fmt.Errorf("invalid endpoint_port %d", p.EndpointPort)
	}
	if p.EndpointV4 != "" && p.EndpointPort == 0 {
		p.EndpointPort = EndpointPort
	}
	switch p.Mode {
	case "", ModeTProxy:
		if p.Mode == "" {
			if p.EndpointV4 != "" {
				p.Mode = ModeVPN
			} else {
				p.Mode = ModeTProxy
			}
		}
		if p.Mode == ModeTProxy {
			if p.TProxyPort == 0 {
				p.TProxyPort = DefaultTProxyPort
			}
			if p.TProxyMark == 0 {
				p.TProxyMark = DefaultTProxyMark
			}
			if err := ValidateTProxyParams(p.TProxyPort, p.TProxyMark); err != nil {
				return err
			}
		}
	case ModeVPN:
		if p.EndpointPort == 0 {
			p.EndpointPort = EndpointPort
		}
	default:
		return fmt.Errorf("unsupported mode %q", p.Mode)
	}
	for _, pathOpt := range []string{p.ProxyBaseDir, p.ProxyCtlScript, p.ProxyConfigPath, p.ProxyAckPath, p.ProxyCorePIDPath, p.ProxyExemptionPath, p.ProxyNetfilterLockPath} {
		if pathOpt != "" && !ValidAbsoluteSafePath(pathOpt) {
			return fmt.Errorf("unsafe proxy path %q", pathOpt)
		}
	}
	if p.ProxySkipPrefix != "" && !ChainPrefixRegex.MatchString(p.ProxySkipPrefix) {
		return fmt.Errorf("invalid proxy_skip_prefix %q", p.ProxySkipPrefix)
	}
	if p.GuardChainOut != "" && !ChainPrefixRegex.MatchString(p.GuardChainOut) {
		return fmt.Errorf("invalid guard_chain_out %q", p.GuardChainOut)
	}
	if p.GuardChainPost != "" && !ChainPrefixRegex.MatchString(p.GuardChainPost) {
		return fmt.Errorf("invalid guard_chain_post %q", p.GuardChainPost)
	}
	if p.ProxyInboundName != "" && !InboundTokenRegex.MatchString(p.ProxyInboundName) {
		return fmt.Errorf("invalid proxy_inbound_name %q", p.ProxyInboundName)
	}
	if p.ProxyCoreProcess != "" && !InboundTokenRegex.MatchString(p.ProxyCoreProcess) {
		return fmt.Errorf("invalid proxy_core_process %q", p.ProxyCoreProcess)
	}
	if p.IPv6Enabled {
		return errors.New("ipv6_enabled must be false until IPv6 sandbox isolation is implemented")
	}
	return nil
}

func (p Policy) UIDRange() (int, int) {
	start := p.UserID * AndroidUserWidth
	return start, start + AndroidUserWidth - 1
}

type ExemptionV1 struct {
	ContractVersion int    `json:"contract_version"`
	Generation      uint64 `json:"generation"`
	BootID          string `json:"boot_id"`
	State           string `json:"state"`
	UserID          int    `json:"user_id"`
	Serial          int    `json:"serial"`
	UIDStart        int    `json:"uid_start"`
	UIDEnd          int    `json:"uid_end"`
	ClientUID       int    `json:"client_uid"`
	VPNNetID        int    `json:"vpn_net_id"`
	TunIf           string `json:"tun_if"`
	TunIfindex      int    `json:"tun_ifindex"`
	PortalDNS4      string `json:"portal_dns4"`
	EndpointV4      string `json:"endpoint_v4"`
	EndpointPort    int    `json:"endpoint_port"`
	IPv6Enabled     bool   `json:"ipv6_enabled"`
	Mode            string `json:"mode,omitempty"`
	TProxyPort      int    `json:"tproxy_port,omitempty"`
	TProxyMark      uint32 `json:"tproxy_mark,omitempty"`
}

type SandboxAckV1 struct {
	ContractVersion   int    `json:"contract_version"`
	AppliedGeneration uint64 `json:"applied_generation"`
	BootID            string `json:"boot_id"`
	CorePID           int    `json:"core_pid,omitempty"`
	PID               int    `json:"pid,omitempty"`
}

func (a SandboxAckV1) WriterPID() int {
	if a.CorePID > 0 {
		return a.CorePID
	}
	return a.PID
}

type SwitchTimingsMs struct {
	T0 int64 `json:"t0"`
	T1 int64 `json:"t1"`
	T2 int64 `json:"t2"`
	T3 int64 `json:"t3"`
}

type VPNStatus struct {
	BootID           string          `json:"boot_id"`
	TSMonoNs         int64           `json:"ts_mono_ns"`
	Running          bool            `json:"running"`
	TunIf            string          `json:"tun_if"`
	VPNNetID         int             `json:"vpn_net_id"`
	UnderlayIf       string          `json:"underlay_if"`
	UnderlayNetID    int             `json:"underlay_net_id"`
	UnderlayHandle   int64           `json:"underlay_handle"`
	EndpointV4       string          `json:"endpoint_v4"`
	EndpointPort     int             `json:"endpoint_port"`
	LastSwitchMs     SwitchTimingsMs `json:"last_switch_ms"`
	ExitIP           string          `json:"exit_ip"`
	Error            string          `json:"error"`
	MTU              int             `json:"mtu,omitempty"`
	QUICUDP443Mode   string          `json:"quic_udp443_mode,omitempty"`
	ConfigGeneration int64           `json:"config_generation,omitempty"`
}

type BrokerAuth struct {
	AllowedUser0UID int `json:"allowed_user0_uid"`
}

type PendingConfig struct {
	Version        int               `json:"version"`
	Generation     uint64            `json:"generation"`
	TSMonoNs       int64             `json:"ts_mono_ns"`
	MTU            int               `json:"mtu"`
	QuicUDP443Mode string            `json:"quic_udp443_mode"`
	Overrides      map[string]string `json:"overrides,omitempty"`
}

type UpgradeFence struct {
	BootID      string `json:"boot_id"`
	Active      bool   `json:"active"`
	UntilMonoNs int64  `json:"until_mono_ns"`
	TTLSeconds  int    `json:"ttl_seconds"`
}

type DesiredState struct {
	Paused bool `json:"paused"`
}

const (
	OpGetStatus      = "GET_STATUS"
	OpImportExisting = "IMPORT_EXISTING"
	OpInstallApk     = "INSTALL_APK"
	OpStartVPN       = "START_VPN"
	OpPauseVPN       = "PAUSE_VPN"
	OpReloadConfig   = "RELOAD_CONFIG"
	OpSyncHideApps   = "SYNC_HIDE_APPS"
	OpRunProbe       = "RUN_PROBE"
	OpLaunchApp      = "LAUNCH_APP"
	OpStopApp        = "STOP_APP"
	OpRemoveApp      = "REMOVE_APP"
)

type RPCConfigOverrides struct {
	QuicUDP443Mode string `json:"quic_udp443_mode,omitempty"`
	LogLevel       string `json:"log_level,omitempty"`
}

type RPCRequest struct {
	ID       string              `json:"id"`
	Op       string              `json:"op"`
	Pkg      string              `json:"pkg,omitempty"`
	Activity string              `json:"activity,omitempty"`
	ApkPaths []string            `json:"apk_paths,omitempty"`
	Config   *RPCConfigOverrides `json:"config,omitempty"`
}

type RPCResponse struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	Data  any    `json:"data"`
}

func ValidPackageName(pkg string) bool {
	if len(pkg) < 3 || len(pkg) > 255 {
		return false
	}
	return PackageNameRegex.MatchString(pkg)
}

func ValidComponentClass(cls string) bool {
	if len(cls) == 0 || len(cls) > 255 || strings.Contains(cls, "..") {
		return false
	}
	return ComponentClassRegex.MatchString(cls)
}

func ValidLocaleTag(tag string) bool {
	if len(tag) < 2 || len(tag) > 32 {
		return false
	}
	return LocaleTagRegex.MatchString(tag)
}

func ValidClientUID(userID, uid int) bool {
	if oem.IsForbiddenUser(userID) {
		return false
	}
	start := userID * AndroidUserWidth
	return uid >= start+MinAppID && uid <= start+MaxAppID
}

func ValidUser0AppUID(uid int) bool {
	return uid >= MinAppID && uid < AndroidUserWidth
}
