# Changelog

All notable changes to **KernBox** are documented in this file.

## [1.2.0] - 2026-11-25

### Added
- **Brand Identity & Dual-Theme Showcases (`assets/`, `README*.md`)**: Designed crisp transparent superellipse squircle icon (`assets/kernbox-icon.png`) and Retina light/dark bilingual product showcases (`assets/kernbox-showcase-{zh,en}-{dark,light}.png`) rendered via `<picture>` theme switching.
- **Packaging Lifecycle Hooks (`packaging/`)**: Added POSIX-compliant `action.sh` (in-manager one-tap pause/resume toggle) and `uninstall.sh` (restores hibernated apps/bloat, flushes `SBW_*` netfilter chains & policy routing rules, cleans runtime sockets); upgraded `versionCode` generation to monotonic `major*10000 + minor*100 + patch`.
- **Verification & Governance (`.github/`, `docs/`, `agent-prompts/`)**: Added GitHub Actions `shellcheck` + full `KernBox.apk` / `KernBoxVerify.apk` CI gates, `testing`-package leak assertion on Linux/arm64 binaries, structured issue templates (`config.yml`, `feature-request.yml`), FAQ troubleshooting Mermaid decision tree, and complete English documentation (`docs/FAQ_EN.md`, `docs/TPROXY_INTEGRATION_EN.md`, `agent-prompts/DIAGNOSE_EN.md`, `agent-prompts/UPGRADE_AND_ROLLBACK_EN.md`).

### Changed & Fixed
- **Controller APK (`controller/`)**: Implemented true Android 15+ Edge-to-Edge (`WindowInsets`) across all activities/sheets, light/dark navigation bar styling (`values-v27`/`values-night-v27`), dual background executors (`rpcExecutor` + `iconExecutor`) with Work Profile `LauncherApps` icon fallback, scrollable `DiagnosticsSheet` with full 12-item scorecard & redacted JSON report export, multi-line split APK installation (`buildInstallApks`), contextual offline remediation helper, and strict `JsonParser` depth/EOF bounds.
- **Stealth & Verification Probe (`stealth/`, `verify/`)**: Added Android 15/16 `IServiceManager.getService2`/`checkService2` `ServiceWithMetadata` unwrapping, NDK `--min-sdk 31` target, expanded native property hook slots (`kMaxPropHookSlots=24`) with `gsm.sim.state` & legacy `__system_property_read`, broadened `getifaddrs` tunnel/MAC sanitization, additional Binder privacy/location/device-policy hooks, compact `am instrument` JSON output, private/loopback reject checks, and `exit_geo_match` reporting.
- **Guard Daemon, Netfilter, Android Lifecycle & SELinux (`guard/`, `tools/`)**:
  - Fixed `ksu.rule` dual `ksu`/`su` domain transitions (KernelSU >= 0.9 / KSU-Next / SukiSU), `resolveIPTablesCompanionBin` nft/legacy suffix resolution, `SBW_TPROXY_PRE` loopback target (`127.0.0.1`), `TProxyReadyProbe` UID/IP checks, and stale `pref 2025` rule cleanup.
  - Fixed empty `sandboxAckPath`/`mainConfigPath`/`proxyCtlScript` resolution for custom `policy.json` proxy layouts, added `EnsureProxyBaseWatch` + `reload-policy` error propagation, removed `"testing"` import from Linux `sysio`, and switched `InstallSandboxAPKs` to `O_NOFOLLOW` FD streaming (`pm install-write ... -`).
  - Hardened `HotFreezeSandboxUserWithOpts`, `InspectSandboxActivityFast`, `UnfreezeCgroupV1` (never thaws global `frozen/freezer.state`), `ApplyPresetFile` (`DisallowUnknownFields` + `O_NOFOLLOW`), `ReadMihomoControllerConfig` (4 MiB cap + `Proxy: nil`), `UplinkIfRegex` / `vpn_management` `(lockdown)` matching, and `probe_device` / `select_variant.py` checks.
  - Updated `golang.org/x/sys` to `v0.50.0`.

## [1.1.0] - 2026-11-25

### Added
- **Least-Privilege Workspace App Control (`guard/`)**: Added `STOP_APP` (`StopSandboxApp`) and `REMOVE_APP` (`RemoveSandboxApp`) whitelisted RPCs with strict package validation, protected package guards (`com.sandbox.controller`, `com.sandbox.verify`, GMS, Play Store, system packages), and `-race` unit test coverage, plus `active_preset` reporting in `GET_STATUS`.
- **Full `KernBox.apk` Experience Closure (`controller/`)**:
  - **Offline Cert Helper (`CertUtil`)**: Displays the controller APK's live SHA-256 signing digest with one-tap clipboard copy when the broker socket is offline or unpinned.
  - **Long-Press App Management (`AppActionSheet`)**: Long-press any workspace tile to launch, force stop (`STOP_APP`), copy package name, or safely uninstall from the sandbox (`REMOVE_APP` with second-tap confirmation).
  - **Live Diagnostics Sheet (`DiagnosticsSheet`)**: One-tap `RUN_PROBE` inspection from the header showing Isolation Gate, TProxy readiness, active preset, Zygisk stealth state, Private DNS warning, stuck sockets, and `KernBoxVerify.apk` probe posture.
  - **Adaptive Light & Dark Quiet-Luxury Theme (`ThemePalette` + `values-night/styles.xml`)**: Automatically switches between Warm Archival Ivory and Warm Obsidian Charcoal with brushed-copper accents, alongside Android 13+ `OnBackInvokedCallback` predictive back navigation.
- **Documentation & Governance**: Reorganized bilingual homepages (`README.md` Chinese default + `README_EN.md`) around the core isolation problem, upgraded `ARCHITECTURE.md` with Mermaid diagrams, and added `docs/TPROXY_INTEGRATION.md`, `docs/FAQ.md`, `.github/PULL_REQUEST_TEMPLATE.md`, and `.github/dependabot.yml`.

### Changed
- **Deterministic Packaging & Zero-Warning CI**: Fixed ZIP entry timestamps/ordering across `pack_variant.py`, `build-controller.py`, and `build-probe.py`; injected `-X sandbox_guard/internal/buildinfo.Version` into release binaries; upgraded GitHub Actions to Node 24 native major versions (`checkout@v7`, `setup-python@v7`, `setup-go@v7`, `setup-java@v6`, `upload-artifact@v7`, `action-gh-release@v3`).

## [1.0.0] - 2026-11-25

### Added
- **30 Lean Device-Specialized ARM64 Builds**: Compile-time specialized module matrix across `5 OEMs` (`hyperos`, `aosp`, `oplus`, `oneui`, `generic`), `2 Kernel Tiers` (`k510` with `openat2`/`pidfd`/`process_madvise`/cgroup v2 freeze; `k419` with `-tags kernel_compat` and cgroup v1 fallback), and `4 Root Manager integrations` (`ksu`, `ksu_legacy`, `magisk`, `apatch`).
- **Fail-Closed Netfilter & Upgrade Fence (`guard/`)**: Atomic `iptables-restore --noflush` enforcement across `SBW_RAW_OUTPUT`, `SBW_OUTPUT`, `SBW_EGRESS`, and `SBW_TPROXY_*`, privilege-separated `sandbox_broker` UDS verification (`SO_PEERCRED` + APK cert SHA-256 + shared token), `ListSandboxApps` exposure in `GET_STATUS`, and 6 hot-switchable region presets (`presets/*.json`).
- **Two-Layer Zygisk + Binder Stealth (`stealth/`)**: Zero-allocation Native PLT property/interface sanitization paired with `InMemoryDexClassLoader` dynamic `IServiceManager` proxy in `system_server` & `com.android.phone`, plus automatic two-strike bootloop kill-switch.
- **Minimalist Companion Controller (`controller/` -> `KernBox.apk`)**: Zero-bloat pure Android SDK GUI with Dieter Rams warm-ivory palette, custom adaptive launcher icon, animated breathing dial, one-tap Start/Pause sandbox toggle, workspace app grid (`LAUNCH_APP`), and animated `+` bottom sheet for User 0 app import (`IMPORT_EXISTING`) and staged APK installation (`INSTALL_APK`).
- **Standalone Verification Probe (`verify/` -> `KernBoxVerify.apk`)**: Unprivileged 12-item isolation & real-device scorecard instrumentation probe with synced KernBox adaptive icon.
- **AI-Agent Co-Installation & Hygiene Gate (`tools/`, `agent-prompts/`)**: Anonymized device probers (`.ps1`/`.sh`), deterministic variant selector, privacy/CRLF gatekeeper (`verify_privacy_leak.py`), and bilingual AI deployment playbooks.
