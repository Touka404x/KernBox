//go:build oem_hyperos

package android

import (
	"context"
	"strings"
	"testing"

	"sandbox_guard/internal/oem"
)

func TestHideAppsHyperOSRegression(t *testing.T) {
	ctx := context.Background()

	// 1. ParseQueryActivities skips ApplicationInfo blocks.
	acts := ParseQueryActivities(`Activity #0:
  ActivityInfo:
    name=com.example.MainActivity
    packageName=com.example.app
  ApplicationInfo:
    name=com.example.BogusAppClass
    packageName=com.example.app
`)
	if len(acts) != 1 || acts[0].ActivityName != "com.example.MainActivity" {
		t.Fatalf("expected only MainActivity, got %+v", acts)
	}

	// 2. SyncHideApps refuses to overwrite User 0 settings when get returns malformed/non-JSON output.
	badHideRunner := &v250LifecycleMockRunner{
		out: map[string]string{
			"cmd package query-activities --user 10 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER": "Activity #0:\n  ActivityInfo:\n    name=com.example.A\n    packageName=com.example.a\n",
			"settings --user 0 get secure " + oem.Current().HideSecureListKey:                                           "Failure calling service settings",
		},
	}
	if _, err := SyncHideApps(ctx, badHideRunner, 10, 1000); err == nil {
		t.Fatal("expected SyncHideApps to fail instead of overwriting on non-JSON settings get output")
	}
	for _, call := range badHideRunner.callsSnapshot() {
		if strings.Contains(call, "settings --user 0 put") {
			t.Fatalf("SyncHideApps must NOT call settings put on malformed get, got calls=%v", badHideRunner.callsSnapshot())
		}
	}
}
