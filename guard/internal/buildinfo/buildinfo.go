package buildinfo

import (
	"fmt"

	"sandbox_guard/internal/oem"
)

// Injected or overridden via -ldflags "-X sandbox_guard/internal/buildinfo.<Field>=..." at compile time.
var (
	Version   = "1.1.0"
	OEM       = oem.Current().Name
	Kernel    = kernelTier
	Transport = transportTier
)

type VariantInfo struct {
	Version          string   `json:"version"`
	OEM              string   `json:"oem"`
	Kernel           string   `json:"kernel"`
	Transport        string   `json:"transport"`
	SupportsHideApps bool     `json:"supports_hide_apps"`
	FreezerEngine    string   `json:"freezer_engine"`
	ExcludedUsers    []int    `json:"excluded_clone_users,omitempty"`
	OpenatMode       string   `json:"openat_mode"`
	ProcessReclaim   string   `json:"process_reclaim"`
	SupportedModes   []string `json:"supported_modes"`
}

func Current() VariantInfo {
	p := oem.Current()
	modes := make([]string, len(supportedModes))
	copy(modes, supportedModes)
	var excluded []int
	if len(p.ExcludedCloneUsers) > 0 {
		excluded = make([]int, len(p.ExcludedCloneUsers))
		copy(excluded, p.ExcludedCloneUsers)
	}
	return VariantInfo{
		Version:          Version,
		OEM:              OEM,
		Kernel:           Kernel,
		Transport:        Transport,
		SupportsHideApps: p.SupportsHideApps,
		FreezerEngine:    p.FreezerName,
		ExcludedUsers:    excluded,
		OpenatMode:       openatMode,
		ProcessReclaim:   processReclaim,
		SupportedModes:   modes,
	}
}

func BuildString() string {
	v := Current()
	return fmt.Sprintf("%s (%s/%s/%s)", v.Version, v.OEM, v.Kernel, v.Transport)
}
