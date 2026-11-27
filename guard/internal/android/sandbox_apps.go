package android

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

func parseInstallSessionID(out string) (string, bool) {
	for i := 0; i < len(out); i++ {
		if out[i] != '[' {
			continue
		}
		j := i + 1
		for j < len(out) && out[j] >= '0' && out[j] <= '9' {
			j++
		}
		if j > i+1 && j < len(out) && out[j] == ']' {
			return out[i+1 : j], true
		}
	}
	return "", false
}

var (
	coreSandboxApps = []string{
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
	UserID             int      `json:"user_id"`
	Locale             string   `json:"locale"`
	LocaleApps         int      `json:"locale_apps"`
	LocalePreserved    int      `json:"locale_preserved,omitempty"`
	LocaleUnsupported  bool     `json:"locale_unsupported,omitempty"`
	LocationApps       int      `json:"location_apps"`
	TrickyStoreTargets int      `json:"tricky_store_targets,omitempty"`
	PackagesHash       string   `json:"packages_hash,omitempty"`
	Errors             []string `json:"errors,omitempty"`
}

// PolicySyncOptions controls Per-App Locale, Bluetooth name, and appops enforcement inside the sandbox user.
type PolicySyncOptions struct {
	CallerPackage       string
	DefaultLocale       string
	PreserveUserLocales bool
	SkipLocale          bool
	LocaleOverrides     map[string]string
	BluetoothDeviceName string
	TrickyStoreDir      string
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

// StopSandboxApp force-stops a single package inside the sandbox user,
// refusing protected caller packages.
func StopSandboxApp(ctx context.Context, r Runner, userID int, pkg, callerPkg string) error {
	if oem.IsForbiddenUser(userID) {
		return fmt.Errorf("invalid work user %d", userID)
	}
	if !contracts.ValidPackageName(pkg) {
		return fmt.Errorf("invalid package name %q", pkg)
	}
	protectPkg := strings.TrimSpace(callerPkg)
	if protectPkg == "" {
		protectPkg = contracts.DefaultWorkPackage
	}
	if pkg == protectPkg || protectedRemovePackages[pkg] || pkg == contracts.ManagedProvisioningPkg {
		return fmt.Errorf("refusing to force-stop protected package %s", pkg)
	}
	out, err := r.Run(ctx, 5*time.Second, "", "am", "force-stop", "--user", strconv.Itoa(userID), pkg)
	if err != nil {
		return fmt.Errorf("am force-stop %s: %w (%s)", pkg, err, strings.TrimSpace(out))
	}
	return nil
}

var protectedRemovePackages = map[string]bool{
	"android":                 true,
	"com.android.settings":    true,
	"com.android.systemui":    true,
	"com.android.vending":     true,
	"com.google.android.gms":  true,
	"com.google.android.gsf":  true,
	"com.sandbox.controller":  true,
	"com.sandbox.verify":      true,
}

// RemoveSandboxApp uninstalls a user-installed (-3) package solely inside the sandbox user,
// blocking protected system, GMS, and controller packages.
func RemoveSandboxApp(ctx context.Context, r Runner, userID int, pkg, callerPkg string) (string, error) {
	if oem.IsForbiddenUser(userID) {
		return "", fmt.Errorf("invalid work user %d", userID)
	}
	if !contracts.ValidPackageName(pkg) {
		return "", fmt.Errorf("invalid package name %q", pkg)
	}
	protectPkg := strings.TrimSpace(callerPkg)
	if protectPkg == "" {
		protectPkg = contracts.DefaultWorkPackage
	}
	if pkg == protectPkg || protectedRemovePackages[pkg] {
		return "", fmt.Errorf("refusing to remove protected package %s", pkg)
	}
	installed, err := ListSandboxApps(ctx, r, userID, protectPkg, contracts.VerifyProbePackage)
	if err != nil {
		return "", fmt.Errorf("list sandbox apps: %w", err)
	}
	found := false
	for _, p := range installed {
		if p == pkg {
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("package %s is not a removable user app in work user %d", pkg, userID)
	}
	out, uerr := r.Run(ctx, 15*time.Second, "", "pm", "uninstall", "--user", strconv.Itoa(userID), pkg)
	trimmed := strings.TrimSpace(out)
	if uerr != nil {
		return trimmed, fmt.Errorf("pm uninstall %s: %w (%s)", pkg, uerr, trimmed)
	}
	return trimmed, nil
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
// on pause while excluding the specified packages (such as controller and admin) so zero idle battery/CPU drain occurs.
func StopSandboxApps(ctx context.Context, r Runner, userID int, excludePkgs ...string) (int, error) {
	if oem.IsForbiddenUser(userID) {
		return 0, fmt.Errorf("invalid work user %d", userID)
	}
	exclude := make(map[string]bool, len(excludePkgs))
	for _, ep := range excludePkgs {
		if ep != "" {
			exclude[ep] = true
		}
	}
	u := strconv.Itoa(userID)
	out, listErr := r.Run(ctx, 5*time.Second, "", "cmd", "package", "list", "packages", "-3", "--user", u)
	pkgs := parsePackageList(out)
	targets := mergeSortedUnique(pkgs, coreSandboxApps)

	stopped := 0
	var errs []string
	for _, pkg := range targets {
		if exclude[pkg] || !contracts.ValidPackageName(pkg) {
			continue
		}
		if err := stopPackagePreserveStopped(ctx, r, u, pkg); err != nil {
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

	out, err := r.Run(ctx, 5*time.Second, "", "cmd", "package", "list", "packages", "-3", "--user", u)
	if err != nil {
		return res, fmt.Errorf("list sandbox packages: %w (%s)", err, strings.TrimSpace(out))
	}
	userPkgs := parsePackageList(out)

	localeTargets := mergeSortedUnique(userPkgs, coreSandboxApps)
	locTargets := mergeSortedUnique(userPkgs, coreSandboxApps, oem.Current().ExtraLocationDenyPackages)
	res.PackagesHash = computePolicyFingerprint(userID, localeTargets, opts)

	if !opts.SkipLocale && len(localeTargets) > 0 {
		type localeItemResult struct {
			preserved   bool
			applied     bool
			unsupported bool
			errMsg      string
		}
		locRes := make([]localeItemResult, len(localeTargets))
		var idx atomic.Int32
		var unsupported atomic.Bool
		workers := sandboxWorkerPoolSize
		if len(localeTargets) < workers {
			workers = len(localeTargets)
		}
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for {
					i := int(idx.Add(1) - 1)
					if i >= len(localeTargets) || unsupported.Load() {
						return
					}
					pkg := localeTargets[i]
					if pkg == callerPkg || !contracts.ValidPackageName(pkg) {
						continue
					}
					targetLoc := defLoc
					if opts.LocaleOverrides != nil {
						if ov, hasOv := opts.LocaleOverrides[pkg]; hasOv {
							ov = strings.TrimSpace(ov)
							if ov == "" {
								locRes[i].preserved = true
								continue
							}
							if !contracts.ValidLocaleTag(ov) {
								locRes[i].errMsg = fmt.Sprintf("invalid override locale %q for %s", ov, pkg)
								continue
							}
							targetLoc = ov
						}
					}
					if opts.PreserveUserLocales {
						curOut, gerr := r.Run(ctx, 3*time.Second, "", "cmd", "locale", "get-app-locales", pkg, "--user", u)
						if gerr != nil {
							if isLocaleServiceUnsupported(curOut, gerr) {
								unsupported.Store(true)
								locRes[i].unsupported = true
								continue
							}
							// Fail safe: never overwrite an existing user locale if current locale cannot be inspected.
							locRes[i].errMsg = "get-locale " + pkg + ": " + gerr.Error()
							continue
						}
						if HasNonEmptyAppLocale(curOut) {
							locRes[i].preserved = true
							continue
						}
					}
					if setOut, err := r.Run(ctx, 4*time.Second, "", "cmd", "locale", "set-app-locales", pkg, "--user", u, "--locales", targetLoc); err != nil {
						if isLocaleServiceUnsupported(setOut, err) {
							unsupported.Store(true)
							locRes[i].unsupported = true
							continue
						}
						locRes[i].errMsg = "locale " + pkg + ": " + err.Error()
					} else {
						locRes[i].applied = true
					}
				}
			}()
		}
		wg.Wait()
		for _, item := range locRes {
			if item.unsupported {
				res.LocaleUnsupported = true
			}
			if item.preserved {
				res.LocalePreserved++
			}
			if item.applied {
				res.LocaleApps++
			}
			if item.errMsg != "" {
				res.Errors = append(res.Errors, item.errMsg)
			}
		}
	}

	if len(locTargets) > 0 {
		type locItemResult struct {
			ok     bool
			errMsg []string
		}
		appopsRes := make([]locItemResult, len(locTargets))
		var idx atomic.Int32
		workers := sandboxWorkerPoolSize
		if len(locTargets) < workers {
			workers = len(locTargets)
		}
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for {
					i := int(idx.Add(1) - 1)
					if i >= len(locTargets) {
						return
					}
					pkg := locTargets[i]
					if pkg == callerPkg || !contracts.ValidPackageName(pkg) {
						continue
					}
					pkgOK := true
					var errs []string
					for _, op := range locationOps {
						if _, err := r.Run(ctx, 3*time.Second, "", "appops", "set", "--user", u, pkg, op, "ignore"); err != nil {
							pkgOK = false
							errs = append(errs, "appops "+pkg+" "+op+": "+err.Error())
						}
						if pkg == "com.google.android.gms" || isExtraLocationUIDPkg(pkg) {
							if _, err := r.Run(ctx, 3*time.Second, "", "appops", "set", "--user", u, "--uid", pkg, op, "ignore"); err != nil {
								pkgOK = false
								errs = append(errs, "appops-uid "+pkg+" "+op+": "+err.Error())
							}
						}
					}
					appopsRes[i] = locItemResult{ok: pkgOK, errMsg: errs}
				}
			}()
		}
		wg.Wait()
		for _, item := range appopsRes {
			if item.ok {
				res.LocationApps++
			}
			if len(item.errMsg) > 0 {
				res.Errors = append(res.Errors, item.errMsg...)
			}
		}
	}

	for _, pkg := range userPkgs {
		if pkg == "com.android.chrome" {
			_, _ = r.Run(ctx, 4*time.Second, "", "cmd", "role", "add-role-holder", "--user", u, "android.app.role.BROWSER", "com.android.chrome")
			break
		}
	}
	if !opts.SkipLocale && defLoc != "" {
		_, _ = r.Run(ctx, 3*time.Second, "", "settings", "--user", u, "put", "system", "system_locales", defLoc)
	}
	if btName := strings.TrimSpace(opts.BluetoothDeviceName); btName != "" && !strings.ContainsAny(btName, "\r\n\t\x00") {
		if _, err := r.Run(ctx, 3*time.Second, "", "settings", "--user", u, "put", "secure", "bluetooth_name", btName); err != nil {
			res.Errors = append(res.Errors, "settings bluetooth_name: "+err.Error())
		}
	}
	if opts.TrickyStoreDir != "" {
		if tsRes, terr := SyncTrickyStoreTargets(ctx, r, opts.TrickyStoreDir, userPkgs, callerPkg); terr == nil && tsRes.Active {
			res.TrickyStoreTargets = tsRes.TargetsWritten
		}
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

func openValidatedAPKForDirs(apk string, allowedDirs []string) (*os.File, int64, error) {
	if apk == "" || !strings.HasSuffix(apk, ".apk") || strings.Contains(apk, "..") ||
		strings.ContainsAny(apk, "\x00\r\n\t;&|$`'\" ") {
		return nil, 0, fmt.Errorf("unsafe apk path %q", apk)
	}
	bases := allowedDirs
	if len(bases) == 0 {
		if strings.ContainsRune(apk, '\\') {
			return nil, 0, fmt.Errorf("unsafe apk path %q", apk)
		}
		bases = []string{"/data/local/tmp", contracts.StagingDir}
	}
	cleanAPK := filepath.Clean(apk)
	f, st, err := openRegularFileNoFollow(cleanAPK)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", apk, err)
	}
	if st.Size() <= 0 {
		_ = f.Close()
		return nil, 0, fmt.Errorf("%s is empty", apk)
	}
	realParent, err := filepath.EvalSymlinks(filepath.Dir(cleanAPK))
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("resolve parent %s: %w", apk, err)
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
		_ = f.Close()
		return nil, 0, fmt.Errorf("apk path %q outside allowed staging dirs", apk)
	}
	return f, st.Size(), nil
}

// InstallSandboxAPKs stages and commits single or split APKs strictly inside User userID.
func InstallSandboxAPKs(ctx context.Context, r Runner, userID int, apkPaths []string, allowedDirs []string) (InstallAPKResult, error) {
	if oem.IsForbiddenUser(userID) {
		return InstallAPKResult{}, fmt.Errorf("invalid work user %d", userID)
	}
	if len(apkPaths) == 0 || len(apkPaths) > 32 {
		return InstallAPKResult{}, errors.New("expected 1..32 apk paths")
	}
	files := make([]*os.File, 0, len(apkPaths))
	closeAll := func() {
		for _, f := range files {
			if f != nil {
				_ = f.Close()
			}
		}
	}
	defer closeAll()

	sizes := make([]int64, len(apkPaths))
	for i, p := range apkPaths {
		f, sz, err := openValidatedAPKForDirs(p, allowedDirs)
		if err != nil {
			return InstallAPKResult{}, err
		}
		files = append(files, f)
		sizes[i] = sz
	}

	u := strconv.Itoa(userID)
	createOut, err := r.Run(ctx, 10*time.Second, "", "pm", "install-create", "--user", u, "-r")
	if err != nil {
		return InstallAPKResult{}, fmt.Errorf("pm install-create: %w (%s)", err, strings.TrimSpace(createOut))
	}
	sid, ok := parseInstallSessionID(createOut)
	if !ok {
		return InstallAPKResult{}, fmt.Errorf("failed to parse install session id from %q", strings.TrimSpace(createOut))
	}

	abandonSession := func() {
		abCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_, _ = r.Run(abCtx, 4*time.Second, "", "pm", "install-abandon", sid)
	}

	rr, canStream := r.(ReaderRunner)
	for i, p := range apkPaths {
		splitName := fmt.Sprintf("split_%d.apk", i)
		sizeStr := strconv.FormatInt(sizes[i], 10)
		var out string
		var werr error
		if canStream {
			out, werr = rr.RunWithStdinReader(ctx, 60*time.Second, files[i], "pm", "install-write",
				"-S", sizeStr, sid, splitName, "-")
		} else {
			out, werr = r.Run(ctx, 60*time.Second, "", "pm", "install-write",
				"-S", sizeStr, sid, splitName, p)
		}
		if werr != nil {
			abandonSession()
			return InstallAPKResult{}, fmt.Errorf("pm install-write %s: %w (%s)", p, werr, strings.TrimSpace(out))
		}
	}

	commitOut, err := r.Run(ctx, 45*time.Second, "", "pm", "install-commit", sid)
	if err != nil {
		abandonSession()
		return InstallAPKResult{}, fmt.Errorf("pm install-commit: %w (%s)", err, strings.TrimSpace(commitOut))
	}
	return InstallAPKResult{
		UserID:    userID,
		SessionID: sid,
		Files:     append([]string(nil), apkPaths...),
		Output:    strings.TrimSpace(commitOut),
	}, nil
}
