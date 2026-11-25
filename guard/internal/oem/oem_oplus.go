//go:build oem_oplus

package oem

var currentProfile = Profile{
	Name:               "oplus",
	ExcludedCloneUsers: []int{999},
	SupportsHideApps:   false,
	FreezerName:        "hans",
	DefaultDeviceName:  "OnePlus",
	ExtraProtectedPackages: []string{
		"com.oplus.securitypermission",
		"com.coloros.securitypermission",
		"com.oplus.appdetail",
		"com.oplus.bluetooth",
	},
	ExtraLocationDenyPackages: []string{
		"com.oplus.location",
		"com.heytap.location",
	},
	BloatCandidates: []string{
		"com.heytap.market",
		"com.heytap.cloud",
		"com.heytap.mcs",
		"com.oplus.statistics.rom",
		"com.oplus.athena",
		"com.oplus.location",
		"com.heytap.location",
		"com.coloros.oshare",
		"com.oplus.games",
		"com.heytap.browser",
		"com.coloros.weather2",
		"com.coloros.note",
	},
}
