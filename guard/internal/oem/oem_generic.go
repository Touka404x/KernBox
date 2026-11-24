//go:build !oem_hyperos && !oem_aosp && !oem_oplus && !oem_oneui

package oem

var currentProfile = Profile{
	Name:               "generic",
	ExcludedCloneUsers: []int{999},
	SupportsHideApps:   false,
	FreezerName:        "generic",
	DefaultDeviceName:  "Android",
}
