package daemon

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/sysio"
)

const (
	PauseModeDeep   = "deep"
	PauseModeLight  = "light"
	PauseModeHot    = "hot"
	PauseModeHybrid = "hybrid"
)

// PerfConfig controls v2.5.0 performance, idle lifecycle, bloat pruning, and locale-preservation behavior.
type PerfConfig struct {
	PauseMode                   string            `json:"pause_mode"`
	AutoPauseIdleMinutes        int               `json:"auto_pause_idle_minutes"`
	HotFreezeMinutes            int               `json:"hot_freeze_minutes"`
	AutoPruneBloatOnStart       bool              `json:"auto_prune_bloat_on_start"`
	KernelRejectQuicUDP443      bool              `json:"kernel_reject_quic_udp443"`
	FlushSandboxConnsOnRouteChg bool              `json:"flush_sandbox_conns_on_route_change"`
	PreserveUserLocales         bool              `json:"preserve_user_locales"`
	SkipAppOpsForFrozen         bool              `json:"skip_appops_for_frozen"`
	SyncTargetOnly              bool              `json:"sync_target_only"`
	LaunchBoostMs               int               `json:"launch_boost_ms"`
	OOMScoreAdj                 int               `json:"oom_score_adj"`
	SandboxInboundName          string            `json:"sandbox_inbound_name,omitempty"`
	LocaleOverrides             map[string]string `json:"locale_overrides,omitempty"`
}

func DefaultPerfConfig() PerfConfig {
	return PerfConfig{
		PauseMode:                   PauseModeDeep,
		AutoPauseIdleMinutes:        15,
		HotFreezeMinutes:            30,
		AutoPruneBloatOnStart:       true,
		KernelRejectQuicUDP443:      true,
		FlushSandboxConnsOnRouteChg: true,
		PreserveUserLocales:         true,
		SkipAppOpsForFrozen:         false,
		SyncTargetOnly:              false,
		LaunchBoostMs:               1500,
		OOMScoreAdj:                 -900,
		SandboxInboundName:          contracts.DefaultSandboxInName,
	}
}

func (c *PerfConfig) Normalize() {
	if c == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(c.PauseMode)) {
	case PauseModeLight:
		c.PauseMode = PauseModeLight
	case PauseModeHot:
		c.PauseMode = PauseModeHot
	case PauseModeHybrid:
		c.PauseMode = PauseModeHybrid
	default:
		c.PauseMode = PauseModeDeep
	}
	if c.AutoPauseIdleMinutes < 0 {
		c.AutoPauseIdleMinutes = 0
	} else if c.AutoPauseIdleMinutes > 1440 {
		c.AutoPauseIdleMinutes = 1440
	}
	if c.HotFreezeMinutes < 0 {
		c.HotFreezeMinutes = 0
	} else if c.HotFreezeMinutes > 1440 {
		c.HotFreezeMinutes = 1440
	}
	if c.LaunchBoostMs < 0 {
		c.LaunchBoostMs = 0
	} else if c.LaunchBoostMs > 5000 {
		c.LaunchBoostMs = 5000
	}
	if c.OOMScoreAdj < -1000 {
		c.OOMScoreAdj = -1000
	} else if c.OOMScoreAdj > 0 {
		c.OOMScoreAdj = 0
	}
	if strings.TrimSpace(c.SandboxInboundName) == "" {
		c.SandboxInboundName = contracts.DefaultSandboxInName
	}
	if len(c.LocaleOverrides) > 0 {
		clean := make(map[string]string, len(c.LocaleOverrides))
		for pkg, loc := range c.LocaleOverrides {
			if !contracts.ValidPackageName(pkg) {
				continue
			}
			loc = strings.TrimSpace(loc)
			if loc == "" || contracts.ValidLocaleTag(loc) {
				clean[pkg] = loc
			}
		}
		if len(clean) == 0 {
			c.LocaleOverrides = nil
		} else {
			c.LocaleOverrides = clean
		}
	}
}

// LoadPerfConfig reads path safely with defaults fallback; omitted JSON fields retain defaults.
func LoadPerfConfig(path string) PerfConfig {
	if path == "" {
		path = contracts.PerfConfigPath
	}
	cfg := DefaultPerfConfig()
	if b, err := sysio.ReadRootOwnedSmallFile(path, contracts.MaxSmallFileBytes); err == nil {
		var tmp = DefaultPerfConfig()
		if json.Unmarshal(b, &tmp) == nil {
			cfg = tmp
		}
	}
	cfg.Normalize()
	return cfg
}

// WritePerfConfig atomically persists perf.json with 0600 root ownership.
func WritePerfConfig(path string, cfg PerfConfig) error {
	if path == "" {
		path = contracts.PerfConfigPath
	}
	cfg.Normalize()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return sysio.WriteAtomic(path, append(b, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
}

// SyncPerfConfig loads existing perf.json (or seeds defaults if missing) and ensures normalized disk state.
func SyncPerfConfig(path string) PerfConfig {
	if path == "" {
		path = contracts.PerfConfigPath
	}
	cfg := DefaultPerfConfig()
	needWrite := true
	if b, err := sysio.ReadRootOwnedSmallFile(path, contracts.MaxSmallFileBytes); err == nil {
		tmp := DefaultPerfConfig()
		if json.Unmarshal(b, &tmp) == nil {
			cfg = tmp
			needWrite = false
		}
	}
	cfg.Normalize()
	if needWrite {
		_ = WritePerfConfig(path, cfg)
	}
	return cfg
}

// ApplyOOMScoreAdj protects the current process from system LMK termination.
func ApplyOOMScoreAdj(adj int) error {
	if adj < -1000 {
		adj = -1000
	} else if adj > 0 {
		adj = 0
	}
	return os.WriteFile("/proc/self/oom_score_adj", []byte(strconv.Itoa(adj)), 0644)
}
