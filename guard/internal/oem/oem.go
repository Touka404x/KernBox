package oem

// Profile captures compile-time OEM characteristics stripped to zero dead branches per variant.
type Profile struct {
	Name                      string
	ExcludedCloneUsers        []int
	BloatCandidates           []string
	ExtraProtectedPackages    []string
	ExtraLocationDenyPackages []string
	SupportsHideApps          bool
	FreezerName               string
	DefaultDeviceName         string
	HideProviderURI           string
	HideSecureListKey         string
}

// Current returns the compile-time selected OEM profile.
func Current() Profile {
	return currentProfile
}

// IsExcludedUser reports whether userID is an OEM dual-app / secure-folder / reserved clone user
// that the sandbox guard must never modify, freeze, prune, or signal.
func (p Profile) IsExcludedUser(userID int) bool {
	for _, u := range p.ExcludedCloneUsers {
		if userID == u {
			return true
		}
	}
	return false
}

// IsForbiddenUser returns true for user <= 0 or any OEM clone/secure-folder user.
func IsForbiddenUser(userID int) bool {
	if userID <= 0 {
		return true
	}
	return currentProfile.IsExcludedUser(userID)
}
