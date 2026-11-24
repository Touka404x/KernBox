package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/buildinfo"
	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

type variantTestRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *variantTestRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.mu.Lock()
	r.calls = append(r.calls, cmd)
	r.mu.Unlock()

	switch {
	case strings.Contains(cmd, "get secure miui_home_hide_app_list"):
		return "[]", nil
	case strings.HasPrefix(cmd, "pm list packages"):
		return "package:" + contracts.DefaultWorkPackage + "\n", nil
	case strings.HasPrefix(cmd, "ime list"):
		return "", nil
	case strings.HasPrefix(cmd, "settings get secure default_input_method"):
		return "", nil
	case strings.HasPrefix(cmd, "cmd device_config list"):
		return "", nil
	default:
		return "", nil
	}
}

func (r *variantTestRunner) hasCallPrefix(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestBuildInfoVariantConsistency(t *testing.T) {
	v := buildinfo.Current()
	prof := oem.Current()
	if v.OEM != prof.Name {
		t.Fatalf("buildinfo.Current().OEM = %q, want %q", v.OEM, prof.Name)
	}
	if v.SupportsHideApps != prof.SupportsHideApps {
		t.Fatalf("SupportsHideApps mismatch: buildinfo=%v oem=%v", v.SupportsHideApps, prof.SupportsHideApps)
	}
	if v.Kernel == "" || v.Transport == "" || v.FreezerEngine == "" || v.OpenatMode == "" || v.ProcessReclaim == "" {
		t.Fatalf("variant metadata incomplete: %+v", v)
	}
	if len(v.SupportedModes) == 0 {
		t.Fatalf("expected non-empty SupportedModes in %+v", v)
	}
	s := buildinfo.BuildString()
	if !strings.Contains(s, v.OEM) || !strings.Contains(s, v.Kernel) || !strings.Contains(s, v.Transport) {
		t.Fatalf("BuildString() = %q missing variant fields", s)
	}
}

func TestHandleCtlVariantInfo(t *testing.T) {
	d := &Daemon{}
	out, err := d.HandleCtl(context.Background(), "variant-info", nil)
	if err != nil {
		t.Fatalf("HandleCtl variant-info error: %v", err)
	}
	var decoded buildinfo.VariantInfo
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("unmarshal variant-info: %v (raw=%s)", err, out)
	}
	cur := buildinfo.Current()
	if decoded.OEM != cur.OEM || decoded.Kernel != cur.Kernel || decoded.Transport != cur.Transport || decoded.SupportsHideApps != cur.SupportsHideApps {
		t.Fatalf("variant-info mismatch: got %+v, want %+v", decoded, cur)
	}
}

func TestHandleCtlPresetApplyAndValidation(t *testing.T) {
	dir := t.TempDir()
	pkgList := filepath.Join(dir, "packages.list")
	if err := os.WriteFile(pkgList, []byte(contracts.DefaultWorkPackage+" 10376 0 /data/user/0/"+contracts.DefaultWorkPackage+" default:targetSdkVersion=35\n"), 0600); err != nil {
		t.Fatal(err)
	}

	runner := &variantTestRunner{}
	d := &Daemon{
		runner:             runner,
		packagesListPath:   pkgList,
		stealthConfigPath:  filepath.Join(dir, "stealth.json"),
		stealthRuntimePath: filepath.Join(dir, "runtime_stealth.json"),
		zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
		policyLoaded:       true,
		policy: contracts.Policy{
			UserID:        10,
			CallerPackage: contracts.DefaultWorkPackage,
		},
	}

	presetPath := filepath.Join(dir, "jp_preset.json")
	presetBody := `{
  "timezone": "Asia/Tokyo",
  "locale": "ja-JP",
  "sim_operator": "44010",
  "sim_operator_name": "NTT DOCOMO",
  "sim_country_iso": "jp",
  "spoof_carrier": true,
  "spoof_timezone": true,
  "spoof_locale": true,
  "spoof_device_region": true,
  "device_name": "Pixel 9",
  "device_region": "JP"
}`
	if err := os.WriteFile(presetPath, []byte(presetBody), 0600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	out, err := d.HandleCtl(ctx, "preset-apply", []string{presetPath})
	if err != nil {
		t.Fatalf("HandleCtl preset-apply error: %v", err)
	}
	var applied StealthConfig
	if err := json.Unmarshal([]byte(out), &applied); err != nil {
		t.Fatalf("unmarshal preset-apply output: %v", err)
	}
	if applied.Timezone != "Asia/Tokyo" || applied.Locale != "ja-JP" {
		t.Fatalf("unexpected timezone/locale after preset-apply: %+v", applied)
	}
	if applied.NetworkOperator != "44010" || applied.NetworkOperatorName != "NTT DOCOMO" || applied.NetworkCountryISO != "jp" {
		t.Fatalf("expected network operator fields inherited from SIM fields, got %+v", applied)
	}
	if applied.DeviceRegion != "JP" || applied.MiuiRegion != "JP" || !applied.SpoofCarrier {
		t.Fatalf("expected region/carrier overlay applied, got %+v", applied)
	}
	if len(applied.ExemptUIDs) == 0 || applied.ExemptUIDs[0] != 1010376 {
		t.Fatalf("expected work client UID 1010376 in ExemptUIDs, got %v", applied.ExemptUIDs)
	}

	cfgRaw, err := os.ReadFile(d.stealthConfigPath)
	if err != nil {
		t.Fatalf("stealth.json not written: %v", err)
	}
	var saved StealthConfig
	if err := json.Unmarshal(cfgRaw, &saved); err != nil || saved.Timezone != "Asia/Tokyo" || saved.Locale != "ja-JP" {
		t.Fatalf("stealth.json mismatch: %+v (err=%v)", saved, err)
	}
	if _, err := os.Stat(d.stealthRuntimePath); !os.IsNotExist(err) {
		t.Fatalf("expected runtime_stealth.json purged, got err=%v", err)
	}
	if !runner.hasCallPrefix("cmd locale set-app-locales ") || !runner.hasCallPrefix("settings put --user 10 secure bluetooth_name Pixel 9") {
		t.Fatalf("expected policy sync locale & settings calls after preset-apply while policyLoaded=true, calls=%v", runner.calls)
	}

	// Negative validation cases.
	if _, err := d.HandleCtl(ctx, "preset-apply", nil); err == nil {
		t.Fatal("expected error for missing preset path")
	}
	badLocale := filepath.Join(dir, "bad_locale.json")
	if err := os.WriteFile(badLocale, []byte(`{"locale":"bad_loc!!"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ApplyPresetFile(ctx, badLocale); err == nil {
		t.Fatal("expected error for invalid locale in preset")
	}
	badTZ := filepath.Join(dir, "bad_tz.json")
	if err := os.WriteFile(badTZ, []byte(`{"timezone":"Asia/Tokyo;rm -rf /"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ApplyPresetFile(ctx, badTZ); err == nil {
		t.Fatal("expected error for shell metacharacter timezone in preset")
	}
}

func TestRepoPresetsValid(t *testing.T) {
	presetDir := filepath.Join("..", "..", "..", "presets")
	files, err := filepath.Glob(filepath.Join(presetDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 6 {
		t.Fatalf("expected at least 6 preset JSON files under %s, got %d", presetDir, len(files))
	}
	ctx := context.Background()
	for _, p := range files {
		dir := t.TempDir()
		d := &Daemon{
			stealthConfigPath:  filepath.Join(dir, "stealth.json"),
			stealthRuntimePath: filepath.Join(dir, "runtime_stealth.json"),
			zygiskDisabledFlag: filepath.Join(dir, "zygisk_disabled"),
		}
		if _, err := d.ApplyPresetFile(ctx, p); err != nil {
			t.Fatalf("ApplyPresetFile(%s) failed: %v", p, err)
		}
	}
}

func TestOEMConditionalHideAppsAndBloatBehavior(t *testing.T) {
	prof := oem.Current()
	for _, u := range prof.ExcludedCloneUsers {
		if !oem.IsForbiddenUser(u) {
			t.Fatalf("expected oem.IsForbiddenUser(%d)=true", u)
		}
	}

	ctx := context.Background()
	runner := &variantTestRunner{}
	hideRes, err := android.SyncHideApps(ctx, runner, 10, 1000)
	if err != nil {
		t.Fatalf("SyncHideApps failed: %v", err)
	}
	if prof.SupportsHideApps {
		if hideRes.Skipped {
			t.Fatalf("expected HideSyncResult.Skipped=false on %s, got true", prof.Name)
		}
	} else {
		if !hideRes.Skipped {
			t.Fatalf("expected HideSyncResult.Skipped=true on %s, got false", prof.Name)
		}
	}

	if _, err := android.PruneSandboxBloat(ctx, runner, 10, filepath.Join(t.TempDir(), "pruned.json"), contracts.DefaultWorkPackage); err != nil {
		t.Fatalf("PruneSandboxBloat failed: %v", err)
	}
}

func TestToggleStealthResetsBootTriesAndHybridFallbackWithoutCgroup(t *testing.T) {
	dir := t.TempDir()
	triesPath := filepath.Join(dir, "stealth_boot_tries")
	disFlag := filepath.Join(dir, "zygisk_disabled")
	if err := os.WriteFile(triesPath, []byte("2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disFlag, []byte("tripped\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cgRoot := filepath.Join(dir, "empty_cgroup")
	if err := os.MkdirAll(cgRoot, 0755); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		stealthConfigPath:    filepath.Join(dir, "stealth.json"),
		stealthRuntimePath:   filepath.Join(dir, "runtime_stealth.json"),
		zygiskDisabledFlag:   disFlag,
		stealthBootTriesPath: triesPath,
		cgroupRoot:           cgRoot,
		policyLoaded:         true,
		policy:               contracts.Policy{UserID: 10},
	}

	stBefore := d.ReadStealthStatus()
	if stBefore["stealth_boot_tries"] != 2 || stBefore["zygisk_disabled"] != true {
		t.Fatalf("unexpected pre-toggle stealth status: %+v", stBefore)
	}

	cfg, err := d.ToggleStealth(true)
	if err != nil {
		t.Fatalf("ToggleStealth(true) error: %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("expected cfg.Enabled=true after ToggleStealth(true)")
	}
	if _, err := os.Stat(disFlag); !os.IsNotExist(err) {
		t.Fatalf("expected zygisk_disabled removed, got err=%v", err)
	}
	rawTries, err := os.ReadFile(triesPath)
	if err != nil || strings.TrimSpace(string(rawTries)) != "0" {
		t.Fatalf("expected stealth_boot_tries reset to 0, got %q (err=%v)", string(rawTries), err)
	}
	if eff := d.resolveEffectivePauseMode(PauseModeHybrid, ""); eff != PauseModeDeep {
		t.Fatalf("expected hybrid pause mode without cgroup freeze nodes to resolve to deep, got %q", eff)
	}
}
