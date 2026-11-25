# Changelog

All notable changes to **KernBox** are documented in this file.

## [1.0.0] - 2026-11-25

### Added
- **30 Lean Device-Specialized ARM64 Builds**: Compile-time specialized module matrix across `5 OEMs` (`hyperos`, `aosp`, `oplus`, `oneui`, `generic`), `2 Kernel Tiers` (`k510` with `openat2`/`pidfd`/`process_madvise`/cgroup v2 freeze; `k419` with `-tags kernel_compat` and cgroup v1 fallback), and `4 Root Manager integrations` (`ksu`, `ksu_legacy`, `magisk`, `apatch`).
- **Fail-Closed Netfilter & Upgrade Fence (`guard/`)**: Atomic `iptables-restore --noflush` enforcement across `SBW_RAW_OUTPUT`, `SBW_OUTPUT`, `SBW_EGRESS`, and `SBW_TPROXY_*`, privilege-separated `sandbox_broker` UDS verification (`SO_PEERCRED` + APK cert SHA-256 + shared token), `ListSandboxApps` exposure in `GET_STATUS`, and 6 hot-switchable region presets (`presets/*.json`).
- **Two-Layer Zygisk + Binder Stealth (`stealth/`)**: Zero-allocation Native PLT property/interface sanitization paired with `InMemoryDexClassLoader` dynamic `IServiceManager` proxy in `system_server` & `com.android.phone`, plus automatic two-strike bootloop kill-switch.
- **Minimalist Companion Controller (`controller/` -> `KernBox.apk`)**: Zero-bloat pure Android SDK GUI with Dieter Rams warm-ivory palette, custom adaptive launcher icon, animated breathing dial, one-tap Start/Pause sandbox toggle, workspace app grid (`LAUNCH_APP`), and animated `+` bottom sheet for User 0 app import (`IMPORT_EXISTING`) and staged APK installation (`INSTALL_APK`).
- **Standalone Verification Probe (`verify/` -> `KernBoxVerify.apk`)**: Unprivileged 12-item isolation & real-device scorecard instrumentation probe with synced KernBox adaptive icon.
- **AI-Agent Co-Installation & Hygiene Gate (`tools/`, `agent-prompts/`)**: Anonymized device probers (`.ps1`/`.sh`), deterministic variant selector, privacy/CRLF gatekeeper (`verify_privacy_leak.py`), and bilingual AI deployment playbooks.
