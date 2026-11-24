package android

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

func TestPruneAndRestoreSandboxBloatSafetyAndIMEGuard(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "pruned_pkgs.json")

	if _, err := PruneSandboxBloat(context.Background(), &sandboxRecRunner{}, 0, statePath); err == nil {
		t.Fatal("must reject User 0")
	}
	for _, ex := range oem.Current().ExcludedCloneUsers {
		if _, err := PruneSandboxBloat(context.Background(), &sandboxRecRunner{}, ex, statePath); err == nil {
			t.Fatalf("must reject excluded clone user %d", ex)
		}
	}

	candidates := oem.Current().BloatCandidates
	if len(candidates) == 0 {
		r := &sandboxRecRunner{}
		res, err := PruneSandboxBloat(context.Background(), r, 10, statePath, "com.custom.controller")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Packages) != 0 || len(r.calls) != 0 {
			t.Fatalf("expected no bloat pruning calls on OEM %s, got res=%+v calls=%v", oem.Current().Name, res, r.calls)
		}
		return
	}

	var sample []string
	for _, c := range candidates {
		sample = append(sample, c)
		if len(sample) == 3 {
			break
		}
	}
	var pkgLines []string
	for _, p := range sample {
		pkgLines = append(pkgLines, "package:"+p)
	}
	pkgLines = append(pkgLines,
		"package:com.google.android.apps.bard",
		"package:com.android.vending",
		"package:com.android.chrome",
		"package:com.custom.ime",
		"package:"+contracts.DefaultWorkPackage,
		"package:com.custom.controller",
	)

	r := &sandboxRecRunner{
		out: map[string]string{
			"pm list packages -e --user 10": strings.Join(pkgLines, "\n") + "\n",
			"ime list -s --user 10":         "com.custom.ime/com.custom.IME\n",
		},
	}

	res, err := PruneSandboxBloat(context.Background(), r, 10, statePath, "com.custom.controller")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != len(sample) {
		t.Fatalf("expected %d enabled bloat packages pruned on OEM %s, got %v", len(sample), oem.Current().Name, res.Packages)
	}
	joined := strings.Join(r.calls, "\n")
	if strings.Contains(joined, "sh -c") {
		t.Fatalf("must not invoke sh -c:\n%s", joined)
	}
	for _, forbidden := range []string{
		"pm disable-user --user 10 com.google.android.apps.bard",
		"pm disable-user --user 10 com.android.vending",
		"pm disable-user --user 10 com.android.chrome",
		"pm disable-user --user 10 " + contracts.DefaultWorkPackage,
		"pm disable-user --user 10 com.custom.controller",
		"pm disable-user --user 10 com.custom.ime",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("protected package %s leaked into calls:\n%s", forbidden, joined)
		}
	}
	for _, wantPkg := range sample {
		if !strings.Contains(joined, "pm disable-user --user 10 "+wantPkg) {
			t.Fatalf("missing expected bloat disable call for %s:\n%s", wantPkg, joined)
		}
	}

	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var saved PrunedState
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.UserID != 10 || len(saved.Packages) != len(sample) {
		t.Fatalf("unexpected persisted pruned state: %+v", saved)
	}

	r.calls = nil
	restored, err := RestoreSandboxBloat(context.Background(), r, 10, statePath)
	if err != nil {
		t.Fatal(err)
	}
	restJoined := strings.Join(r.calls, "\n")
	if len(restored.Packages) != len(sample) || !strings.Contains(restJoined, "pm enable --user 10 "+sample[0]) {
		t.Fatalf("unexpected restore calls: %+v\n%s", restored, restJoined)
	}
	rawAfter, _ := os.ReadFile(statePath)
	var after PrunedState
	_ = json.Unmarshal(rawAfter, &after)
	if len(after.Packages) != 0 {
		t.Fatalf("expected pruned list cleared after restore, got %+v", after.Packages)
	}
}
