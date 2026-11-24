//go:build oem_oneui

package oem

var currentProfile = Profile{
	Name:               "oneui",
	ExcludedCloneUsers: []int{95, 150, 999},
	SupportsHideApps:   false,
	FreezerName:        "freecess",
	DefaultDeviceName:  "Galaxy",
	ExtraProtectedPackages: []string{
		"com.samsung.android.packageinstaller",
		"com.samsung.android.permissioncontroller",
		"com.samsung.android.bluetooth",
		"com.samsung.android.honeyboard",
		"com.samsung.android.knox.containercore",
	},
	ExtraLocationDenyPackages: []string{
		"com.sec.location.nsflp2",
		"com.samsung.android.location",
	},
	BloatCandidates: []string{
		"com.samsung.android.game.gos",
		"com.samsung.android.rubin.app",
		"com.samsung.android.scloud",
		"com.sec.android.app.samsungapps",
		"com.samsung.android.bixby.agent",
		"com.samsung.android.beaconmanager",
		"com.sec.location.nsflp2",
		"com.samsung.android.mateagent",
	},
}
