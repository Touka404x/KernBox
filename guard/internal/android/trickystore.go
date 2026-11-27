package android

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/sysio"
)

const (
	DefaultTrickyStoreDir       = "/data/adb/tricky_store"
	DefaultTrickyStoreModuleDir = "/data/adb/modules/tricky_store"

	trickyBeginMarker = "# kernbox-managed-begin"
	trickyEndMarker   = "# kernbox-managed-end"
)

var trickyStoreCoreApps = []string{
	"com.google.android.gms",
	"com.android.vending",
}

// TrickyStoreStatus captures lightweight stat-only availability of TrickyStore & custom keybox.
type TrickyStoreStatus struct {
	Installed     bool `json:"installed"`
	Active        bool `json:"active"`
	KeyboxPresent bool `json:"keybox_present"`
}

// TrickyStoreSyncResult describes one idempotent TrickyStore target/patch sync pass.
type TrickyStoreSyncResult struct {
	Active         bool `json:"active"`
	TargetsWritten int  `json:"targets_written"`
	Updated        bool `json:"updated"`
	PatchSeeded    bool `json:"patch_seeded"`
}

// ProbeTrickyStoreStatus checks TrickyStore presence with pure stat calls (zero forks).
func ProbeTrickyStoreStatus(tsDir, modDir string) TrickyStoreStatus {
	var st TrickyStoreStatus
	if tsDir == "" {
		return st
	}
	info, err := os.Stat(tsDir)
	if err != nil || !info.IsDir() {
		return st
	}
	st.Installed = true
	st.Active = true
	if modDir != "" {
		if _, err := os.Stat(filepath.Join(modDir, "disable")); err == nil {
			st.Active = false
		}
		if _, err := os.Stat(filepath.Join(modDir, "remove")); err == nil {
			st.Active = false
		}
	}
	if kb, err := os.Stat(filepath.Join(tsDir, "keybox.xml")); err == nil && kb.Mode().IsRegular() && kb.Size() > 0 {
		st.KeyboxPresent = true
	}
	return st
}

// SyncTrickyStoreTargets keeps TrickyStore target.txt scoped strictly to sandbox User-N apps + GMS/Play
// while preserving any user-written entries/suffixes and only rewriting on diff.
func SyncTrickyStoreTargets(ctx context.Context, r Runner, tsDir string, pkgs []string, callerPkg string) (TrickyStoreSyncResult, error) {
	var res TrickyStoreSyncResult
	if tsDir == "" {
		return res, nil
	}
	info, err := os.Stat(tsDir)
	if err != nil || !info.IsDir() {
		return res, nil
	}
	res.Active = true

	targetPath := filepath.Join(tsDir, "target.txt")
	existingRaw, readErr := os.ReadFile(targetPath)
	var userLines []string
	if readErr == nil {
		userLines = extractTrickyUserLines(string(existingRaw))
	}

	userPkgSet := make(map[string]struct{}, len(userLines))
	for _, rawLine := range userLines {
		t := strings.TrimSpace(rawLine)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		base := strings.TrimRight(t, "!?")
		if contracts.ValidPackageName(base) {
			userPkgSet[base] = struct{}{}
		}
	}

	protectPkg := strings.TrimSpace(callerPkg)
	if !contracts.ValidPackageName(protectPkg) {
		protectPkg = contracts.DefaultWorkPackage
	}

	candSet := make(map[string]struct{}, len(pkgs)+len(trickyStoreCoreApps))
	for _, p := range trickyStoreCoreApps {
		if _, exists := userPkgSet[p]; !exists {
			candSet[p] = struct{}{}
		}
	}
	for _, rawPkg := range pkgs {
		p := strings.TrimSpace(rawPkg)
		if p == "" || p == protectPkg || !contracts.ValidPackageName(p) {
			continue
		}
		if _, exists := userPkgSet[p]; exists {
			continue
		}
		candSet[p] = struct{}{}
	}

	managed := make([]string, 0, len(candSet))
	for p := range candSet {
		managed = append(managed, p)
	}
	sort.Strings(managed)
	res.TargetsWritten = len(managed)

	rendered := renderTrickyTargetFile(userLines, managed)
	if readErr != nil || string(existingRaw) != rendered {
		if err := sysio.WriteAtomic(targetPath, []byte(rendered), sysio.WriteAtomicOptions{Perm: 0644, UID: 0, GID: 0}); err != nil {
			return res, err
		}
		res.Updated = true
	}

	patchPath := filepath.Join(tsDir, "security_patch.txt")
	if _, perr := os.Stat(patchPath); perr != nil && os.IsNotExist(perr) && r != nil {
		if rawPatch, gerr := r.Run(ctx, 2*time.Second, "", "getprop", "ro.build.version.security_patch"); gerr == nil {
			if norm := normalizeSecurityPatchYYYYMMDD(rawPatch); norm != "" {
				if werr := sysio.WriteAtomic(patchPath, []byte(norm+"\n"), sysio.WriteAtomicOptions{Perm: 0644, UID: 0, GID: 0}); werr == nil {
					res.PatchSeeded = true
				}
			}
		}
	}

	return res, nil
}

func extractTrickyUserLines(raw string) []string {
	norm := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(norm, "\n")
	// Drop single trailing empty element from terminating LF.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var out []string
	inManaged := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == trickyBeginMarker {
			inManaged = true
			continue
		}
		if trimmed == trickyEndMarker {
			inManaged = false
			continue
		}
		if !inManaged {
			out = append(out, line)
		}
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}

func renderTrickyTargetFile(userLines, managed []string) string {
	var b strings.Builder
	for _, line := range userLines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString(trickyBeginMarker)
	b.WriteByte('\n')
	for _, pkg := range managed {
		b.WriteString(pkg)
		b.WriteByte('\n')
	}
	b.WriteString(trickyEndMarker)
	b.WriteByte('\n')
	return b.String()
}

func normalizeSecurityPatchYYYYMMDD(raw string) string {
	s := strings.TrimSpace(raw)
	// Expect YYYY-MM-DD (10 chars)
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return ""
	}
	var b strings.Builder
	b.Grow(8)
	for i := 0; i < len(s); i++ {
		if i == 4 || i == 7 {
			continue
		}
		c := s[i]
		if c < '0' || c > '9' {
			return ""
		}
		b.WriteByte(c)
	}
	return b.String()
}
