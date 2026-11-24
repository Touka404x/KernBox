//go:build oem_aosp

package oem

var currentProfile = Profile{
	Name:               "aosp",
	ExcludedCloneUsers: []int{999},
	SupportsHideApps:   false,
	FreezerName:        "aosp",
	DefaultDeviceName:  "Pixel",
}
