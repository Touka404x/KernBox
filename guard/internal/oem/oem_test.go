package oem

import "testing"

func TestOEMProfileInvariants(t *testing.T) {
	p := Current()
	if p.Name == "" || p.FreezerName == "" || p.DefaultDeviceName == "" {
		t.Fatalf("incomplete OEM profile: %+v", p)
	}
	if !IsForbiddenUser(0) || !IsForbiddenUser(-1) {
		t.Fatal("user <= 0 must always be forbidden")
	}
	if IsForbiddenUser(10) {
		t.Fatal("standard managed profile user 10 must be allowed")
	}
	if p.Name == "hyperos" {
		if !p.SupportsHideApps || !IsForbiddenUser(999) {
			t.Fatalf("hyperos profile invariants failed: %+v", p)
		}
		protected := make(map[string]bool, len(p.ExtraProtectedPackages))
		for _, pkg := range p.ExtraProtectedPackages {
			protected[pkg] = true
		}
		for _, bloat := range p.BloatCandidates {
			if protected[bloat] || bloat == "com.android.vending" || bloat == "com.google.android.gms" {
				t.Fatalf("bloat candidate %q conflicts with protected package", bloat)
			}
		}
	} else if p.SupportsHideApps {
		t.Fatalf("non-hyperos OEM %q must not enable MIUI hideapps", p.Name)
	}
	if p.Name == "oneui" {
		for _, u := range []int{95, 150, 999} {
			if !IsForbiddenUser(u) {
				t.Fatalf("oneui must exclude reserved user %d", u)
			}
		}
	}
	if p.Name == "oplus" || p.Name == "generic" {
		if !IsForbiddenUser(999) {
			t.Fatalf("%s must exclude clone user 999", p.Name)
		}
	}
}
