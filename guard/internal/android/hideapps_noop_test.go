//go:build !oem_hyperos

package android

import (
	"context"
	"testing"
)

func TestSyncHideAppsNoopOnNonHyperOS(t *testing.T) {
	r := &sandboxRecRunner{}
	res, err := SyncHideApps(context.Background(), r, 10, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || len(r.calls) != 0 {
		t.Fatalf("expected Skipped=true and 0 shell calls, got res=%+v calls=%v", res, r.calls)
	}
}
