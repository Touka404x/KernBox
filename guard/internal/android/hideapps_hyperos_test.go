//go:build oem_hyperos

package android

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHideAppBeanJSONAndQueryParser(t *testing.T) {
	const queryOut = `Activity #0:
  priority=0x0 preferredOrder=0x0 match=0x108000 specificIndex=-1 isDefault=false
  ActivityInfo:
    name=com.google.android.apps.chrome.Main
    packageName=com.android.chrome
    enabled=true exported=true
    ApplicationInfo:
      name=com.google.android.apps.chrome.ChromeApplication
      packageName=com.android.chrome
Activity #1:
  ActivityInfo:
    name=.AssetBrowserActivity
    packageName=com.android.vending
    ApplicationInfo:
      name=com.google.android.finsky.application.FinskyApplicationImpl
      packageName=com.android.vending
`

	acts := ParseQueryActivities(queryOut)
	if len(acts) != 2 {
		t.Fatalf("expected 2 launcher activities, got %+v", acts)
	}
	if acts[0].PackageName != "com.android.chrome" || acts[1].ActivityName != "com.android.vending.AssetBrowserActivity" {
		t.Fatalf("unexpected parsed activities: %+v", acts)
	}

	existing := []HideAppBean{
		BuildHideAppBean("com.user0.secret", "com.user0.secret.Main", "0"),
		BuildHideAppBean("com.old.removed", "com.old.removed.Main", "1000"),
	}
	merged, missing, stale := MergeHideAppList(existing, acts, "1000")
	if len(missing) != 2 || stale != 1 || len(merged) != 3 {
		t.Fatalf("unexpected merge result: merged=%d missing=%d stale=%d", len(merged), len(missing), stale)
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `"serialNumber":"0"`) || !strings.Contains(s, `"serialNumber":"1000"`) || strings.Contains(s, "com.old.removed") {
		t.Fatalf("unexpected HideAppBean JSON: %s", s)
	}
}
