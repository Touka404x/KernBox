package android

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
	"sandbox_guard/internal/sysio"
)

// baseProtectedSandboxPackages must NEVER be disabled inside sandbox profiles so keyboard input,
// Play/GMS, Gemini, file picking/uploads, web OAuth login, and DPM profile control keep working cleanly.
var baseProtectedSandboxPackages = map[string]bool{
	contracts.DefaultWorkPackage:                true,
	contracts.VerifyProbePackage:                true,
	contracts.ManagedProvisioningPkg:            true,
	"com.android.vending":                       true,
	"com.google.android.gms":                    true,
	"com.google.android.gsf":                    true,
	"com.google.android.googlequicksearchbox":   true,
	"com.google.android.apps.bard":              true,
	"com.google.android.apps.subscriptions.red": true,
	"com.android.chrome":                        true,
	"com.google.android.webview":                true,
	"com.android.webview":                       true,
	"com.android.permissioncontroller":          true,
	"com.google.android.permissioncontroller":   true,
	"com.android.packageinstaller":              true,
	"com.google.android.packageinstaller":       true,
	"com.android.providers.media.module":        true,
	"com.android.providers.media":               true,
	"com.android.documentsui":                   true,
	"com.google.android.documentsui":            true,
	"com.android.providers.downloads":           true,
	"com.android.externalstorage":               true,
	"com.android.keychain":                      true,
	"com.android.certinstaller":                 true,
	"com.android.settings":                      true,
	"com.android.systemui":                      true,
	"com.android.phone":                         true,
	"com.android.bluetooth":                     true,
	"com.google.android.inputmethod.latin":      true,
}

func protectedPackageSet(extraProtected ...string) map[string]bool {
	out := make(map[string]bool, len(baseProtectedSandboxPackages)+len(oem.Current().ExtraProtectedPackages)+len(extraProtected))
	for k, v := range baseProtectedSandboxPackages {
		out[k] = v
	}
	for _, pkg := range oem.Current().ExtraProtectedPackages {
		if contracts.ValidPackageName(pkg) {
			out[pkg] = true
		}
	}
	for _, pkg := range extraProtected {
		if contracts.ValidPackageName(pkg) {
			out[pkg] = true
		}
	}
	return out
}

type PrunedState struct {
	UserID    int      `json:"user_id"`
	Packages  []string `json:"packages"`
	UpdatedAt string   `json:"updated_at"`
}

type BloatActionResult struct {
	UserID   int      `json:"user_id"`
	Packages []string `json:"packages"`
	Skipped  []string `json:"skipped,omitempty"`
	Mode     string   `json:"mode"`
}

func parseIMEPkgs(output string) map[string]bool {
	out := make(map[string]bool)
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		pkg, _, _ := strings.Cut(line, "/")
		pkg = strings.TrimSpace(pkg)
		if contracts.ValidPackageName(pkg) {
			out[pkg] = true
		}
	}
	return out
}

func readPrunedState(path string) PrunedState {
	if b, err := sysio.ReadRootOwnedSmallFile(path, contracts.MaxSmallFileBytes); err == nil {
		var st PrunedState
		if json.Unmarshal(b, &st) == nil {
			return st
		}
	}
	return PrunedState{}
}

func writePrunedState(path string, st PrunedState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return sysio.WriteAtomic(path, append(b, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
}

// PruneSandboxBloat disables compile-time OEM bloat packages strictly inside sandbox User userID
// using direct argv calls (zero sh -c), while protecting critical Google/system/IME/controller packages.
func PruneSandboxBloat(ctx context.Context, r Runner, userID int, statePath string, extraProtected ...string) (BloatActionResult, error) {
	if oem.IsForbiddenUser(userID) {
		return BloatActionResult{}, fmt.Errorf("refusing to prune bloat on forbidden user %d", userID)
	}
	if statePath == "" {
		statePath = contracts.PrunedPkgsPath
	}
	candidatesList := oem.Current().BloatCandidates
	if len(candidatesList) == 0 {
		return BloatActionResult{
			UserID:   userID,
			Packages: nil,
			Skipped:  nil,
			Mode:     "prune",
		}, nil
	}

	u := strconv.Itoa(userID)
	enabledOut, err := r.Run(ctx, 5*time.Second, "", "pm", "list", "packages", "-e", "--user", u)
	if err != nil {
		return BloatActionResult{}, fmt.Errorf("pm list enabled packages: %w", err)
	}
	enabledSet := make(map[string]bool)
	for _, pkg := range parsePackageList(enabledOut) {
		enabledSet[pkg] = true
	}

	imeOut, _ := r.Run(ctx, 4*time.Second, "", "ime", "list", "-s", "--user", u)
	imeProtected := parseIMEPkgs(imeOut)
	protected := protectedPackageSet(extraProtected...)

	var candidates []string
	var skipped []string
	for _, pkg := range candidatesList {
		if !contracts.ValidPackageName(pkg) {
			continue
		}
		if protected[pkg] || imeProtected[pkg] {
			skipped = append(skipped, pkg)
			continue
		}
		if !enabledSet[pkg] {
			continue
		}
		candidates = append(candidates, pkg)
	}

	var mu sync.Mutex
	var disabledNow []string
	runPackagePool(ctx, candidates, sandboxWorkerPoolSize, func(pkg string) {
		if _, err := r.Run(ctx, 3*time.Second, "", "pm", "disable-user", "--user", u, pkg); err == nil {
			mu.Lock()
			disabledNow = append(disabledNow, pkg)
			mu.Unlock()
		}
		_, _ = r.Run(ctx, 2*time.Second, "", "am", "force-stop", "--user", u, pkg)
	})
	sort.Strings(disabledNow)

	prev := readPrunedState(statePath)
	merged := mergeSortedUnique(prev.Packages, disabledNow)
	sort.Strings(merged)
	_ = writePrunedState(statePath, PrunedState{
		UserID:    userID,
		Packages:  merged,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	})

	return BloatActionResult{
		UserID:   userID,
		Packages: disabledNow,
		Skipped:  skipped,
		Mode:     "prune",
	}, nil
}

// RestoreSandboxBloat re-enables every package previously disabled inside User userID in statePath.
func RestoreSandboxBloat(ctx context.Context, r Runner, userID int, statePath string) (BloatActionResult, error) {
	if oem.IsForbiddenUser(userID) {
		return BloatActionResult{}, fmt.Errorf("refusing to restore bloat on forbidden user %d", userID)
	}
	if statePath == "" {
		statePath = contracts.PrunedPkgsPath
	}
	st := readPrunedState(statePath)
	targets := st.Packages
	if len(targets) == 0 {
		targets = oem.Current().BloatCandidates
	}

	u := strconv.Itoa(userID)
	var reEnabled []string
	for _, pkg := range targets {
		if !contracts.ValidPackageName(pkg) {
			continue
		}
		if _, err := r.Run(ctx, 3*time.Second, "", "pm", "enable", "--user", u, pkg); err == nil {
			reEnabled = append(reEnabled, pkg)
		}
	}
	_ = writePrunedState(statePath, PrunedState{
		UserID:    userID,
		Packages:  nil,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	return BloatActionResult{
		UserID:   userID,
		Packages: reEnabled,
		Mode:     "restore",
	}, nil
}
