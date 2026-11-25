# Changelog

All notable changes to **KernBox** are documented in this file.

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
