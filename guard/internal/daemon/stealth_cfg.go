package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
	"sandbox_guard/internal/sysio"
)

// StealthConfig mirrors the JSON configuration shared with sandbox_stealth (Zygisk companion).
type StealthConfig struct {
	Enabled             bool   `json:"enabled"`
	SandboxUserID       int    `json:"sandbox_user_id"`
	ExemptWorkUID       int    `json:"exempt_work_uid"`
	ExemptUIDs          []int  `json:"exempt_uids,omitempty"`
	Timezone            string `json:"timezone"`
	Locale              string `json:"locale"`
	SimOperator         string `json:"sim_operator"`
	SimOperatorName     string `json:"sim_operator_name"`
	SimCountryISO       string `json:"sim_country_iso"`
	NetworkOperator     string `json:"network_operator"`
	NetworkOperatorName string `json:"network_operator_name"`
	NetworkCountryISO   string `json:"network_country_iso"`
	HideManagedProfile  bool   `json:"hide_managed_profile"`
	SpoofLocationMode   string `json:"spoof_location_mode"`
	BlockWifiScan       bool   `json:"block_wifi_scan"`
	SpoofCarrier        bool   `json:"spoof_carrier"`
	SpoofTimezone       bool   `json:"spoof_timezone"`
	SpoofLocale         bool   `json:"spoof_locale"`
	PreserveUserLocales bool   `json:"preserve_user_locales"`
	PropHookMode        string `json:"prop_hook_mode"`
	SanitizeNetwork     bool   `json:"sanitize_network"`
	SpoofBluetooth      bool   `json:"spoof_bluetooth"`
	SpoofDeviceRegion   bool   `json:"spoof_device_region"`
	SandboxLinkIPv4     string `json:"sandbox_link_ipv4"`
	DeviceName          string `json:"device_name"`
	DeviceRegion        string `json:"device_region,omitempty"`
	MiuiRegion          string `json:"miui_region"`
	BootHWC             string `json:"boot_hwc"`
	ActivePreset        string `json:"active_preset,omitempty"`
}

func DefaultStealthConfig(userID, exemptWorkUID int) StealthConfig {
	return StealthConfig{
		Enabled:             true,
		SandboxUserID:       userID,
		ExemptWorkUID:       exemptWorkUID,
		Timezone:            "UTC",
		Locale:              "en-US",
		HideManagedProfile:  true,
		SpoofLocationMode:   "block",
		BlockWifiScan:       true,
		SpoofCarrier:        false,
		SpoofTimezone:       true,
		SpoofLocale:         true,
		PreserveUserLocales: true,
		PropHookMode:        "plt",
		SanitizeNetwork:     true,
		SpoofBluetooth:      true,
		SpoofDeviceRegion:   false,
		SandboxLinkIPv4:     "10.172.10.2",
		DeviceName:          oem.Current().DefaultDeviceName,
	}
}

func (d *Daemon) resolvedStealthPaths() (cfgPath, runtimePath, disabledFlag string) {
	cfgPath = d.stealthConfigPath
	if cfgPath == "" {
		cfgPath = contracts.StealthConfigPath
	}
	runtimePath = d.stealthRuntimePath
	if runtimePath == "" {
		runtimePath = contracts.StealthRuntimePath
	}
	disabledFlag = d.zygiskDisabledFlag
	if disabledFlag == "" {
		disabledFlag = contracts.ZygiskDisabledFlag
	}
	return
}

func loadExistingOrDefaultStealth(cfgPath string, userID, exemptUID int) StealthConfig {
	cfg := DefaultStealthConfig(userID, exemptUID)
	if existingBytes, err := sysio.ReadRootOwnedSmallFile(cfgPath, contracts.MaxSmallFileBytes); err == nil {
		existing := DefaultStealthConfig(userID, exemptUID)
		if json.Unmarshal(existingBytes, &existing) == nil {
			cfg = existing
		}
	}
	if userID > 0 {
		cfg.SandboxUserID = userID
	}
	if exemptUID > 0 {
		cfg.ExemptWorkUID = exemptUID
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "UTC"
	}
	if cfg.Locale == "" {
		cfg.Locale = "en-US"
	}
	if cfg.NetworkOperator == "" {
		cfg.NetworkOperator = cfg.SimOperator
	}
	if cfg.NetworkOperatorName == "" {
		cfg.NetworkOperatorName = cfg.SimOperatorName
	}
	if cfg.NetworkCountryISO == "" {
		cfg.NetworkCountryISO = cfg.SimCountryISO
	}
	if cfg.SpoofLocationMode == "" {
		cfg.SpoofLocationMode = "block"
	}
	if cfg.PropHookMode == "" {
		cfg.PropHookMode = "plt"
	}
	if cfg.SandboxLinkIPv4 == "" {
		cfg.SandboxLinkIPv4 = "10.172.10.2"
	}
	if cfg.DeviceName == "" {
		cfg.DeviceName = oem.Current().DefaultDeviceName
	}
	if cfg.DeviceRegion == "" && cfg.MiuiRegion != "" {
		cfg.DeviceRegion = cfg.MiuiRegion
	} else if cfg.MiuiRegion == "" && cfg.DeviceRegion != "" {
		cfg.MiuiRegion = cfg.DeviceRegion
	}
	return cfg
}

func writeStealthFiles(cfgPath, runtimePath string, cfg StealthConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	payload := append(b, '\n')
	if err := sysio.WriteAtomic(cfgPath, payload, sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0}); err != nil {
		return err
	}
	// Purge any legacy world-readable mirror (/dev/sandbox_cfg/stealth.json);
	// Zygisk companion reads cfgPath (0600 root:root) directly without self-exposure.
	if runtimePath != "" {
		_ = removeIfExist(runtimePath)
	}
	return nil
}

// ResolveExemptUIDsForUser extracts sandbox app UIDs that must never be spoofed
// (controller package and com.android.managedprovisioning) from Android packages.list.
func ResolveExemptUIDsForUser(packagesListPath string, userID int, workUID int, callerPkgs ...string) []int {
	if oem.IsForbiddenUser(userID) {
		return nil
	}
	if packagesListPath == "" {
		packagesListPath = contracts.PackagesListPath
	}
	callerPkg := contracts.DefaultWorkPackage
	if len(callerPkgs) > 0 && contracts.ValidPackageName(callerPkgs[0]) {
		callerPkg = callerPkgs[0]
	}
	seen := make(map[int]struct{}, 4)
	addUID := func(uid int) {
		if uid < contracts.AndroidUserWidth {
			return
		}
		if uid/contracts.AndroidUserWidth != userID {
			return
		}
		appID := uid % contracts.AndroidUserWidth
		if appID >= contracts.MinAppID && appID < 90000 {
			seen[uid] = struct{}{}
		}
	}
	addUID(workUID)

	if f, err := os.Open(packagesListPath); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			pkg := fields[0]
			if pkg != contracts.ManagedProvisioningPkg && pkg != callerPkg {
				continue
			}
			rawID, perr := strconv.Atoi(fields[1])
			if perr != nil || rawID < 0 {
				continue
			}
			appID := rawID % contracts.AndroidUserWidth
			addUID(userID*contracts.AndroidUserWidth + appID)
		}
	}

	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for uid := range seen {
		out = append(out, uid)
	}
	sort.Ints(out)
	return out
}

func mergeExemptUIDs(existing []int, resolved []int, userID int) []int {
	seen := make(map[int]struct{}, len(existing)+len(resolved))
	add := func(uid int) {
		if uid >= contracts.AndroidUserWidth && uid/contracts.AndroidUserWidth == userID {
			appID := uid % contracts.AndroidUserWidth
			if appID >= contracts.MinAppID && appID < 90000 {
				seen[uid] = struct{}{}
			}
		}
	}
	for _, u := range existing {
		add(u)
	}
	for _, u := range resolved {
		add(u)
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	sort.Ints(out)
	return out
}

// ResolvePackageUIDForUser resolves the User-N UID for a given package name from packages.list.
// Returns 0 if not found or invalid.
func ResolvePackageUIDForUser(packagesListPath string, userID int, targetPkg string) int {
	if oem.IsForbiddenUser(userID) || !contracts.ValidPackageName(targetPkg) {
		return 0
	}
	if packagesListPath == "" {
		packagesListPath = contracts.PackagesListPath
	}
	f, err := os.Open(packagesListPath)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != targetPkg {
			continue
		}
		rawID, perr := strconv.Atoi(fields[1])
		if perr != nil || rawID < 0 {
			continue
		}
		appID := rawID % contracts.AndroidUserWidth
		if appID >= contracts.MinAppID && appID < 90000 {
			return userID*contracts.AndroidUserWidth + appID
		}
	}
	return 0
}

// SyncStealthConfig maintains stealth.json preserving existing overrides while updating
// sandbox_user_id, exempt_work_uid, and exempt_uids.
func (d *Daemon) SyncStealthConfig(policy contracts.Policy, clientUID int) (StealthConfig, error) {
	d.stealthMu.Lock()
	defer d.stealthMu.Unlock()
	cfgPath, runtimePath, _ := d.resolvedStealthPaths()
	pkgList := contracts.PackagesListPath
	if d.packagesListPath != "" {
		pkgList = d.packagesListPath
	}
	callerPkg := policy.EffectiveCallerPackage()
	if clientUID <= 0 {
		if resolvedWork := ResolvePackageUIDForUser(pkgList, policy.UserID, callerPkg); resolvedWork > 0 {
			clientUID = resolvedWork
		}
	}
	cfg := loadExistingOrDefaultStealth(cfgPath, policy.UserID, clientUID)
	resolved := ResolveExemptUIDsForUser(pkgList, policy.UserID, clientUID, callerPkg)
	cfg.ExemptUIDs = mergeExemptUIDs(cfg.ExemptUIDs, resolved, policy.UserID)
	if err := writeStealthFiles(cfgPath, runtimePath, cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (d *Daemon) resolvedStealthBootTriesPath() string {
	if d.stealthBootTriesPath != "" {
		return d.stealthBootTriesPath
	}
	if d.stealthConfigPath != "" && d.stealthConfigPath != contracts.StealthConfigPath {
		return filepath.Join(filepath.Dir(d.stealthConfigPath), "stealth_boot_tries")
	}
	return contracts.StealthBootTriesPath
}

func (d *Daemon) ReadStealthStatus() map[string]any {
	cfgPath, runtimePath, disabledFlag := d.resolvedStealthPaths()
	_, flagErr := os.Stat(disabledFlag)
	disabledByFlag := flagErr == nil

	tries := 0
	if raw, err := os.ReadFile(d.resolvedStealthBootTriesPath()); err == nil {
		if n, perr := strconv.Atoi(strings.TrimSpace(string(raw))); perr == nil && n >= 0 {
			tries = n
		}
	}

	cfg := StealthConfig{}
	loaded := false
	if b, err := sysio.ReadRootOwnedSmallFile(cfgPath, contracts.MaxSmallFileBytes); err == nil {
		if json.Unmarshal(b, &cfg) == nil {
			loaded = true
		}
	}
	return map[string]any{
		"config_loaded":       loaded,
		"config_path":         cfgPath,
		"runtime_path":        runtimePath,
		"zygisk_disabled":     disabledByFlag,
		"stealth_boot_tries":  tries,
		"active_on_boot":      loaded && cfg.Enabled && !disabledByFlag,
		"active_preset":       cfg.ActivePreset,
		"active_region":       cfg.DeviceRegion,
		"region_spoof_active": cfg.SpoofCarrier && cfg.SpoofDeviceRegion && strings.TrimSpace(cfg.DeviceRegion) != "",
		"config":              cfg,
	}
}

func (d *Daemon) ToggleStealth(enable bool) (StealthConfig, error) {
	d.stealthMu.Lock()
	defer d.stealthMu.Unlock()
	cfgPath, runtimePath, disabledFlag := d.resolvedStealthPaths()
	if enable {
		_ = removeIfExist(disabledFlag)
		if err := sysio.WriteAtomic(d.resolvedStealthBootTriesPath(), []byte("0\n"), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0}); err != nil {
			return StealthConfig{}, err
		}
	} else {
		if err := sysio.WriteAtomic(disabledFlag, []byte("disabled via ctl\n"), sysio.WriteAtomicOptions{Perm: 0644, UID: 0, GID: 0}); err != nil {
			return StealthConfig{}, err
		}
	}

	d.mu.Lock()
	policy := d.policy
	clientUID := 0
	if d.cachedID != nil {
		clientUID = d.cachedID.ClientUID
	}
	d.mu.Unlock()

	if policy.UserID <= 0 {
		policy.UserID = 10
	}
	pkgList := contracts.PackagesListPath
	if d.packagesListPath != "" {
		pkgList = d.packagesListPath
	}
	callerPkg := policy.EffectiveCallerPackage()
	if clientUID <= 0 {
		if resolvedWork := ResolvePackageUIDForUser(pkgList, policy.UserID, callerPkg); resolvedWork > 0 {
			clientUID = resolvedWork
		}
	}
	cfg := loadExistingOrDefaultStealth(cfgPath, policy.UserID, clientUID)
	resolved := ResolveExemptUIDsForUser(pkgList, policy.UserID, clientUID, callerPkg)
	cfg.ExemptUIDs = mergeExemptUIDs(cfg.ExemptUIDs, resolved, policy.UserID)
	cfg.Enabled = enable
	if err := writeStealthFiles(cfgPath, runtimePath, cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// RegionPreset models a region/carrier stealth preset JSON file loaded via `ctl preset-apply`.
type RegionPreset struct {
	Name                string  `json:"name,omitempty"`
	Timezone            *string `json:"timezone,omitempty"`
	Locale              *string `json:"locale,omitempty"`
	SimOperator         *string `json:"sim_operator,omitempty"`
	SimOperatorName     *string `json:"sim_operator_name,omitempty"`
	SimCountryISO       *string `json:"sim_country_iso,omitempty"`
	NetworkOperator     *string `json:"network_operator,omitempty"`
	NetworkOperatorName *string `json:"network_operator_name,omitempty"`
	NetworkCountryISO   *string `json:"network_country_iso,omitempty"`
	SpoofCarrier        *bool   `json:"spoof_carrier,omitempty"`
	SpoofTimezone       *bool   `json:"spoof_timezone,omitempty"`
	SpoofLocale         *bool   `json:"spoof_locale,omitempty"`
	SpoofDeviceRegion   *bool   `json:"spoof_device_region,omitempty"`
	SpoofBluetooth      *bool   `json:"spoof_bluetooth,omitempty"`
	DeviceName          *string `json:"device_name,omitempty"`
	DeviceRegion        *string `json:"device_region,omitempty"`
	MiuiRegion          *string `json:"miui_region,omitempty"`
	BootHWC             *string `json:"boot_hwc,omitempty"`
}

func normalizeRegionCode(cfg StealthConfig) string {
	if r := strings.ToUpper(strings.TrimSpace(cfg.DeviceRegion)); r != "" {
		return r
	}
	if r := strings.ToUpper(strings.TrimSpace(cfg.SimCountryISO)); r != "" {
		return r
	}
	return ""
}

// DetectRegionSwitch warns when a preset change alters an already-set country,
// which can fracture long-lived device and location trust consistency.
func DetectRegionSwitch(prev, next StealthConfig) string {
	p := normalizeRegionCode(prev)
	n := normalizeRegionCode(next)
	if p == "" || n == "" || p == n {
		return ""
	}
	return fmt.Sprintf("cross-region preset switch %s -> %s may destabilize device/geo consistency", p, n)
}

// ApplyPresetFile overlays a bounded preset JSON file onto stealth.json and syncs sandbox policies when pinned.
func (d *Daemon) ApplyPresetFile(ctx context.Context, presetPath string) (StealthConfig, error) {
	if strings.TrimSpace(presetPath) == "" || strings.ContainsAny(presetPath, "\x00\r\n") {
		return StealthConfig{}, errors.New("invalid preset path")
	}
	raw, err := sysio.ReadSmallFileNoFollow(presetPath, contracts.MaxSmallFileBytes)
	if err != nil {
		return StealthConfig{}, err
	}
	var p RegionPreset
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return StealthConfig{}, fmt.Errorf("parse preset JSON: %w", err)
	}
	if p.Locale != nil && *p.Locale != "" && !contracts.ValidLocaleTag(strings.TrimSpace(*p.Locale)) {
		return StealthConfig{}, fmt.Errorf("invalid preset locale %q", *p.Locale)
	}
	if p.Timezone != nil && strings.ContainsAny(*p.Timezone, "\x00\r\n;&|$`") {
		return StealthConfig{}, fmt.Errorf("invalid preset timezone %q", *p.Timezone)
	}

	d.stealthMu.Lock()
	defer d.stealthMu.Unlock()

	d.mu.Lock()
	loaded := d.policyLoaded
	policy := d.policy
	clientUID := 0
	if d.cachedID != nil {
		clientUID = d.cachedID.ClientUID
	}
	d.mu.Unlock()

	if policy.UserID <= 0 {
		policy.UserID = 10
	}
	pkgList := contracts.PackagesListPath
	if d.packagesListPath != "" {
		pkgList = d.packagesListPath
	}
	callerPkg := policy.EffectiveCallerPackage()
	if clientUID <= 0 {
		if resolvedWork := ResolvePackageUIDForUser(pkgList, policy.UserID, callerPkg); resolvedWork > 0 {
			clientUID = resolvedWork
		}
	}

	cfgPath, runtimePath, _ := d.resolvedStealthPaths()
	cfg := loadExistingOrDefaultStealth(cfgPath, policy.UserID, clientUID)
	prevCfg := cfg
	if p.Timezone != nil {
		cfg.Timezone = strings.TrimSpace(*p.Timezone)
	}
	if p.Locale != nil {
		cfg.Locale = strings.TrimSpace(*p.Locale)
	}
	if p.SimOperator != nil {
		cfg.SimOperator = strings.TrimSpace(*p.SimOperator)
	}
	if p.SimOperatorName != nil {
		cfg.SimOperatorName = strings.TrimSpace(*p.SimOperatorName)
	}
	if p.SimCountryISO != nil {
		cfg.SimCountryISO = strings.TrimSpace(*p.SimCountryISO)
	}
	if p.NetworkOperator != nil {
		cfg.NetworkOperator = strings.TrimSpace(*p.NetworkOperator)
	} else if p.SimOperator != nil {
		cfg.NetworkOperator = cfg.SimOperator
	}
	if p.NetworkOperatorName != nil {
		cfg.NetworkOperatorName = strings.TrimSpace(*p.NetworkOperatorName)
	} else if p.SimOperatorName != nil {
		cfg.NetworkOperatorName = cfg.SimOperatorName
	}
	if p.NetworkCountryISO != nil {
		cfg.NetworkCountryISO = strings.TrimSpace(*p.NetworkCountryISO)
	} else if p.SimCountryISO != nil {
		cfg.NetworkCountryISO = cfg.SimCountryISO
	}
	if p.SpoofCarrier != nil {
		cfg.SpoofCarrier = *p.SpoofCarrier
	}
	if p.SpoofTimezone != nil {
		cfg.SpoofTimezone = *p.SpoofTimezone
	}
	if p.SpoofLocale != nil {
		cfg.SpoofLocale = *p.SpoofLocale
	}
	if p.SpoofDeviceRegion != nil {
		cfg.SpoofDeviceRegion = *p.SpoofDeviceRegion
	}
	if p.SpoofBluetooth != nil {
		cfg.SpoofBluetooth = *p.SpoofBluetooth
	}
	if p.DeviceName != nil && strings.TrimSpace(*p.DeviceName) != "" {
		cfg.DeviceName = strings.TrimSpace(*p.DeviceName)
	}
	if p.DeviceRegion != nil {
		cfg.DeviceRegion = strings.TrimSpace(*p.DeviceRegion)
		cfg.MiuiRegion = cfg.DeviceRegion
	} else if p.MiuiRegion != nil {
		cfg.MiuiRegion = strings.TrimSpace(*p.MiuiRegion)
		cfg.DeviceRegion = cfg.MiuiRegion
	}
	if p.BootHWC != nil {
		cfg.BootHWC = strings.TrimSpace(*p.BootHWC)
	}
	if name := strings.TrimSpace(p.Name); name != "" {
		cfg.ActivePreset = name
	}
	if warn := DetectRegionSwitch(prevCfg, cfg); warn != "" && d.log != nil {
		d.log.Printf("preset-apply warning: %s", warn)
	}
	resolved := ResolveExemptUIDsForUser(pkgList, policy.UserID, clientUID, callerPkg)
	cfg.ExemptUIDs = mergeExemptUIDs(cfg.ExemptUIDs, resolved, policy.UserID)
	if err := writeStealthFiles(cfgPath, runtimePath, cfg); err != nil {
		return cfg, err
	}
	if loaded && d.runner != nil {
		_, _ = d.syncPolicies(ctx, policy)
	}
	return cfg, nil
}

func (d *Daemon) readActivePresetName() string {
	cfgPath, _, _ := d.resolvedStealthPaths()
	raw, err := sysio.ReadRootOwnedSmallFile(cfgPath, contracts.MaxSmallFileBytes)
	if err != nil {
		return "neutral"
	}
	var cfg StealthConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "neutral"
	}
	if name := strings.TrimSpace(cfg.ActivePreset); name != "" {
		return name
	}
	return "neutral"
}
