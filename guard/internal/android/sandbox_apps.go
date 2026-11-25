package android

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

var (
	installSessionIDRegex = regexp.MustCompile(`\[(\d+)\]`)
	coreSandboxApps       = []string{
		"com.android.vending",
		"com.google.android.googlequicksearchbox",
		"com.google.android.apps.bard",
		"com.google.android.apps.subscriptions.red",
		"com.google.android.gms",
	}
	locationOps = []string{
		"COARSE_LOCATION",
		"FINE_LOCATION",
		"MONITOR_LOCATION",
		"MONITOR_HIGH_POWER_LOCATION",
	}
)

type AppPolicySyncResult struct {
	UserID            int      `json:"user_id"`
	Locale            string   `json:"locale"`
	LocaleApps        int      `json:"locale_apps"`
	LocalePreserved   int      `json:"locale_preserved,omitempty"`
	LocaleUnsupported bool     `json:"locale_unsupported,omitempty"`
	LocationApps      int      `json:"location_apps"`
	PackagesHash      string   `json:"packages_hash,omitempty"`
	Errors            []string `json:"errors,omitempty"`
}

// PolicySyncOptions controls Per-App Locale, Bluetooth name, and appops enforcement inside the sandbox user.
type PolicySyncOptions struct {
	CallerPackage       string
	DefaultLocale       string
	PreserveUserLocales bool
	LocaleOverrides     map[string]string
	BluetoothDeviceName string
}

type InstallAPKResult struct {
	UserID    int      `json:"user_id"`
	SessionID string   `json:"session_id"`
	Files     []string `json:"files"`
	Output    string   `json:"output"`
}

func parsePackageList(output string) []string {
	seen := make(map[string]struct{})
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "package:") {
			continue
		}
		pkg := strings.TrimSpace(strings.TrimPrefix(line, "package:"))
		if idx := strings.IndexAny(pkg, " \t"); idx >= 0 {
			pkg = pkg[:idx]
		}
		if contracts.ValidPackageName(pkg) {
			seen[pkg] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for pkg := range seen {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out
}

// ListSandboxApps returns sorted third-party package names installed inside the sandbox user,
// excluding any specified internal packages.
func ListSandboxApps(ctx context.Context, r Runner, userID int, excludePkgs ...string) ([]string, error) {
	if oem.IsForbiddenUser(userID) {
		return nil, fmt.Errorf("invalid work user %d", userID)
	}
	exclude := make(map[string]struct{}, len(excludePkgs))
	for _, p := range excludePkgs {
		if p != "" {
			exclude[p] = struct{}{}
		}
	}
	out, err := r.Run(ctx, 3*time.Second, "", "cmd", "package", "list", "packages", "-3", "--user", strconv.Itoa(userID))
	if err != nil {
		return nil, err
	}
	raw := parsePackageList(out)
	res := make([]string, 0, len(raw))
	for _, pkg := range raw {
		if _, skip := exclude[pkg]; skip {
			continue
		}
		res = append(res, pkg)
	}
	return res, nil
}

func mergeSortedUnique(groups ...[]string) []string {
	seen := make(map[string]struct{})
	for _, g := range groups {
		for _, item := range g {
			if item != "" {
				seen[item] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for item := range seen {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func computePolicyFingerprint(userID int, pkgs []string, opts PolicySyncOptions) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "u=%d;loc=%s;pres=%v;", userID, opts.DefaultLocale, opts.PreserveUserLocales)
	for _, p := range pkgs {
		_, _ = fmt.Fprintf(h, "%s,", p)
	}
	if len(opts.LocaleOverrides) > 0 {
		keys := make([]string, 0, len(opts.LocaleOverrides))
		for k := range opts.LocaleOverrides {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, _ = fmt.Fprintf(h, ";ov:%s=%s", k, opts.LocaleOverrides[k])
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// HasNonEmptyAppLocale parses `cmd locale get-app-locales <pkg> --user <u>` output.
// Returns true ONLY when output explicitly contains a non-empty locale tag inside brackets like `[zh-CN]`.
func HasNonEmptyAppLocale(output string) bool {
	openIdx := strings.IndexByte(output, '[')
	closeIdx := strings.LastIndexByte(output, ']')
	if openIdx < 0 || closeIdx <= openIdx+1 {
		return false
	}
	inner := strings.TrimSpace(output[openIdx+1 : closeIdx])
	return inner != ""
}

func isExtraLocationUIDPkg(pkg string) bool {
	for _, p := range oem.Current().ExtraLocationDenyPackages {
		if pkg == p {
			return true
		}
	}
	return false
}

func isLocaleServiceUnsupported(out string, err error) bool {
	combined := strings.ToLower(out)
	if err != nil {
		combined += " " + strings.ToLower(err.Error())
	}
	return strings.Contains(combined, "unknown command") ||
		strings.Contains(combined, "can't find service: locale") ||
		strings.Contains(combined, "service locale not found")
}

// StopSandboxApps stops third-party and core Google background processes inside the sandbox user
// on pause while excluding the bridge package so zero idle battery/CPU drain occurs.
func StopSandboxApps(ctx context.Context, r Runner, userID int, excludePkg string) (int, error) {
	if oem.IsForbiddenUser(userID) {
		return 0, fmt.Errorf("invalid work user %d", userID)
	}
	u := strconv.Itoa(userID)
	out, listErr := r.Run(ctx, 5*time.Second, "", "cmd", "package", "list", "packages", "-3", "--user", u)
	pkgs := parsePackageList(out)
	targets := mergeSortedUnique(pkgs, coreSandboxApps)

	stopped := 0
	var errs []string
	for _, pkg := range targets {
		if pkg == excludePkg || !contracts.ValidPackageName(pkg) {
			continue
		}
		if _, err := r.Run(ctx, 3*time.Second, "", "am", "force-stop", "--user", u, pkg); err != nil {
			errs = append(errs, pkg+": "+err.Error())
		} else {
			stopped++
		}
	}
	if listErr != nil && stopped == 0 {
		return 0, listErr
	}
	if len(errs) > 0 && stopped == 0 {
		return 0, errors.New(strings.Join(errs, "; "))
	}
	return stopped, nil
}

// SyncSandboxAppPolicies enforces Per-App Locale (default ja-JP) and User-N appops isolation.
func SyncSandboxAppPolicies(ctx context.Context, r Runner, userID int, locale string) (AppPolicySyncResult, error) {
	return SyncSandboxAppPoliciesWithOpts(ctx, r, userID, PolicySyncOptions{
		DefaultLocale:       locale,
		PreserveUserLocales: false,
	})
}

// SyncSandboxAppPoliciesWithOpts enforces Per-App Locale and appops location isolation using
// direct argv invocations (zero shell invocation / zero sh -c), while preserving non-empty user locales.
func SyncSandboxAppPoliciesWithOpts(ctx context.Context, r Runner, userID int, opts PolicySyncOptions) (AppPolicySyncResult, error) {
	if oem.IsForbiddenUser(userID) {
		return AppPolicySyncResult{}, fmt.Errorf("invalid work user %d", userID)
	}
	callerPkg := strings.TrimSpace(opts.CallerPackage)
	if !contracts.ValidPackageName(callerPkg) {
		callerPkg = contracts.DefaultWorkPackage
	}
	defLoc := strings.TrimSpace(opts.DefaultLocale)
	if defLoc == "" {
		defLoc = "en-US"
	}
	if !contracts.ValidLocaleTag(defLoc) {
		return AppPolicySyncResult{}, fmt.Errorf("invalid locale tag %q", defLoc)
	}
	opts.DefaultLocale = defLoc

	u := strconv.Itoa(userID)
	res := AppPolicySyncResult{UserID: userID, Locale: defLoc}

	out, _ := r.Run(ctx, 5*time.Second, "", "cmd", "package", "list", "packages", "-3", "--user", u)
	userPkgs := parsePackageList(out)

	localeTargets := mergeSortedUnique(userPkgs, coreSandboxApps)
	locTargets := mergeSortedUnique(userPkgs, coreSandboxApps, oem.Current().ExtraLocationDenyPackages)
	res.PackagesHash = computePolicyFingerprint(userID, localeTargets, opts)

	localeSupported := true
	for _, pkg := range localeTargets {
		if !localeSupported {
			break
		}
		if pkg == callerPkg || !contracts.ValidPackageName(pkg) {
			continue
		}
		targetLoc := defLoc
		if opts.LocaleOverrides != nil {
			if ov, hasOv := opts.LocaleOverrides[pkg]; hasOv {
				ov = strings.TrimSpace(ov)
				if ov == "" {
					res.LocalePreserved++
					continue
				}
				if !contracts.ValidLocaleTag(ov) {
					res.Errors = append(res.Errors, fmt.Sprintf("invalid override locale %q for %s", ov, pkg))
					continue
				}
				targetLoc = ov
			}
		}
		if opts.PreserveUserLocales {
			curOut, gerr := r.Run(ctx, 3*time.Second, "", "cmd", "locale", "get-app-locales", pkg, "--user", u)
			if gerr != nil {
				if isLocaleServiceUnsupported(curOut, gerr) {
					localeSupported = false
					res.LocaleUnsupported = true
					continue
				}
				// Fail safe: never overwrite an existing user locale if current locale cannot be inspected.
				res.Errors = append(res.Errors, "get-locale "+pkg+": "+gerr.Error())
				continue
			}
			if HasNonEmptyAppLocale(curOut) {
				res.LocalePreserved++
				continue
			}
		}
		if setOut, err := r.Run(ctx, 4*time.Second, "", "cmd", "locale", "set-app-locales", pkg, "--user", u, "--locales", targetLoc); err != nil {
			if isLocaleServiceUnsupported(setOut, err) {
				localeSupported = false
				res.LocaleUnsupported = true
				continue
			}
			res.Errors = append(res.Errors, "locale "+pkg+": "+err.Error())
		} else {
			res.LocaleApps++
		}
	}

	for _, pkg := range locTargets {
		if pkg == callerPkg || !contracts.ValidPackageName(pkg) {
			continue
		}
		pkgOK := true
		for _, op := range locationOps {
			if _, err := r.Run(ctx, 3*time.Second, "", "appops", "set", "--user", u, pkg, op, "ignore"); err != nil {
				pkgOK = false
				res.Errors = append(res.Errors, "appops "+pkg+" "+op+": "+err.Error())
			}
			if pkg == "com.google.android.gms" || isExtraLocationUIDPkg(pkg) {
				if _, err := r.Run(ctx, 3*time.Second, "", "appops", "set", "--user", u, "--uid", pkg, op, "ignore"); err != nil {
					pkgOK = false
					res.Errors = append(res.Errors, "appops-uid "+pkg+" "+op+": "+err.Error())
				}
			}
		}
		if pkgOK {
			res.LocationApps++
		}
	}

	for _, pkg := range userPkgs {
		if pkg == "com.android.chrome" {
			_, _ = r.Run(ctx, 4*time.Second, "", "cmd", "role", "add-role-holder", "--user", u, "android.app.role.BROWSER", "com.android.chrome")
			break
		}
	}
	if btName := strings.TrimSpace(opts.BluetoothDeviceName); btName != "" && !strings.ContainsAny(btName, "\r\n\t\x00") {
		_, _ = r.Run(ctx, 3*time.Second, "", "settings", "put", "--user", u, "secure", "bluetooth_name", btName)
	}

	if len(res.Errors) > 0 && res.LocaleApps == 0 && res.LocalePreserved == 0 && res.LocationApps == 0 {
		return res, errors.New(strings.Join(res.Errors, "; "))
	}
	return res, nil
}

// SetSandboxAppLocale explicitly applies or clears an Android 13+ Per-App Locale inside the sandbox user.
func SetSandboxAppLocale(ctx context.Context, r Runner, userID int, pkg, locale string, callerPkg ...string) error {
	if oem.IsForbiddenUser(userID) {
		return fmt.Errorf("invalid work user %d", userID)
	}
	if !contracts.ValidPackageName(pkg) {
		return fmt.Errorf("invalid package name %q", pkg)
	}
	protectPkg := contracts.DefaultWorkPackage
	if len(callerPkg) > 0 && contracts.ValidPackageName(callerPkg[0]) {
		protectPkg = callerPkg[0]
	}
	if pkg == protectPkg || pkg == "com.google.android.gms" {
		return fmt.Errorf("refusing to alter Per-App Locale for protected package %s", pkg)
	}
	loc := strings.TrimSpace(locale)
	if strings.EqualFold(loc, "clear") || strings.EqualFold(loc, "none") {
		loc = ""
	}
	if loc != "" && !contracts.ValidLocaleTag(loc) {
		return fmt.Errorf("invalid locale tag %q", loc)
	}
	_, err := r.Run(ctx, 5*time.Second, "", "cmd", "locale", "set-app-locales", pkg, "--user", strconv.Itoa(userID), "--locales", loc)
	return err
}

func validateAPKPathForDirs(apk string, allowedDirs []string) (int64, error) {
	if apk == "" || !strings.HasSuffix(apk, ".apk") || strings.Contains(apk, "..") ||
		strings.ContainsAny(apk, "\x00\r\n\t;&|$`'\" ") {
		return 0, fmt.Errorf("unsafe apk path %q", apk)
	}
	bases := allowedDirs
	if len(bases) == 0 {
		if strings.ContainsRune(apk, '\\') {
			return 0, fmt.Errorf("unsafe apk path %q", apk)
		}
		bases = []string{"/data/local/tmp", contracts.StagingDir}
	}
	cleanAPK := filepath.Clean(apk)
	st, err := os.Lstat(cleanAPK)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", apk, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Size() <= 0 {
		return 0, fmt.Errorf("%s is not a non-empty regular file", apk)
	}
	realParent, err := filepath.EvalSymlinks(filepath.Dir(cleanAPK))
	if err != nil {
		return 0, fmt.Errorf("resolve parent %s: %w", apk, err)
	}
	matched := false
	for _, d := range bases {
		cleanBase := filepath.Clean(d)
		realBase, berr := filepath.EvalSymlinks(cleanBase)
		if berr != nil {
			realBase = cleanBase
		}
		if realParent == realBase || strings.HasPrefix(realParent, realBase+string(filepath.Separator)) {
			matched = true
			break
		}
	}
	if !matched {
		return 0, fmt.Errorf("apk path %q outside allowed staging dirs", apk)
	}
	return st.Size(), nil
}

// InstallSandboxAPKs stages and commits single or split APKs strictly inside User userID.
func InstallSandboxAPKs(ctx context.Context, r Runner, userID int, apkPaths []string, allowedDirs []string) (InstallAPKResult, error) {
	if oem.IsForbiddenUser(userID) {
		return InstallAPKResult{}, fmt.Errorf("invalid work user %d", userID)
	}
	if len(apkPaths) == 0 || len(apkPaths) > 32 {
		return InstallAPKResult{}, errors.New("expected 1..32 apk paths")
	}
	sizes := make([]int64, len(apkPaths))
	for i, p := range apkPaths {
		sz, err := validateAPKPathForDirs(p, allowedDirs)
		if err != nil {
			return InstallAPKResult{}, err
		}
		sizes[i] = sz
	}

	u := strconv.Itoa(userID)
	createOut, err := r.Run(ctx, 10*time.Second, "", "pm", "install-create", "--user", u, "-r")
	if err != nil {
		return InstallAPKResult{}, fmt.Errorf("pm install-create: %w (%s)", err, strings.TrimSpace(createOut))
	}
	m := installSessionIDRegex.FindStringSubmatch(createOut)
	if len(m) != 2 {
		return InstallAPKResult{}, fmt.Errorf("failed to parse install session id from %q", strings.TrimSpace(createOut))
	}
	sid := m[1]

	for i, p := range apkPaths {
		splitName := fmt.Sprintf("split_%d.apk", i)
		if out, werr := r.Run(ctx, 20*time.Second, "", "pm", "install-write",
			"-S", strconv.FormatInt(sizes[i], 10), sid, splitName, p); werr != nil {
			_, _ = r.Run(ctx, 4*time.Second, "", "pm", "install-abandon", sid)
			return InstallAPKResult{}, fmt.Errorf("pm install-write %s: %w (%s)", p, werr, strings.TrimSpace(out))
		}
	}

	commitOut, err := r.Run(ctx, 20*time.Second, "", "pm", "install-commit", sid)
	if err != nil {
		_, _ = r.Run(ctx, 4*time.Second, "", "pm", "install-abandon", sid)
		return InstallAPKResult{}, fmt.Errorf("pm install-commit: %w (%s)", err, strings.TrimSpace(commitOut))
	}
	return InstallAPKResult{
		UserID:    userID,
		SessionID: sid,
		Files:     append([]string(nil), apkPaths...),
		Output:    strings.TrimSpace(commitOut),
	}, nil
}
