# Android Sandbox Guard — Multi-Variant Root + Full-Kernel Work-Profile Sandbox

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

English documentation | [中文说明 (README.md)](README.md)

**Android Sandbox Guard** builds lean, compile-time-specialized Android Work Profile sandboxing and anti-fingerprinting modules across OEMs, Linux kernel tiers, and Root managers, paired with an **AI-Agent-first Phone + PC installation workflow**.

Instead of shipping a single bloated universal package full of runtime branches, unused OEM hooks, and legacy fallbacks, the project builds **30 targeted ARM64 release ZIPs** (`SandboxGuard-<oem>-<kernel>-<root>-arm64.zip`) plus an unprivileged runtime verification APK (`SandboxVerifyProbe.apk`).

---

## Specialization Axes

- **5 OEM Profiles** (`-tags oem_<oem>` in Go, `-DOEM_<OEM>` in C++):
  - `hyperos` — Xiaomi HyperOS / MIUI (MIUI hide-app sync, Millet cgroup/binder handling, XSpace 999 exclusion, Xiaomi location/push bloat rules)
  - `oplus` — OPPO ColorOS / OnePlus OxygenOS / Realme UI (`oplus`/`oppo` region property slots, dual-clone protections, Hans freezer awareness)
  - `oneui` — Samsung One UI (`ro.csc.*` region properties, Dual Messenger / Secure Folder clone exclusions)
  - `aosp` — Google Pixel, LineageOS, GrapheneOS, CalyxOS, crDroid (minimal overhead)
  - `generic` — Safe conservative baseline for other AOSP derivatives
- **2 Kernel Tiers**:
  - `k510` (Linux 5.10+ with cgroup v2 freezer): `openat2(RESOLVE_BENEATH)`, `pidfd_open`/`pidfd_send_signal`, `process_madvise(MADV_PAGEOUT)`, cgroup v2 freeze
  - `k419` (Linux 4.14–5.9 or kernels without cgroup v2 freeze): `-tags kernel_compat` using `openat(O_NOFOLLOW)` component traversal, verified `/proc/<pid>/stat` starttime + UID kill, and cgroup v1 freezer fallback
  - *(Optional source build flag `-tags transport_vpn` for legacy VPN+TProxy builds; default OSS releases specialize strictly on lean TProxy mode.)*
- **4 Root Managers** (`packaging/` SELinux policy & boot script templates):
  - `ksu` (KernelSU >= 0.9 on `k510`)
  - `ksu_legacy` (KernelSU < 0.9 or `k419` compatibility)
  - `magisk`
  - `apatch`

---

## Quick Start: Phone + PC Agent Co-Installation

1. Connect your rooted Android 12+ (`arm64-v8a`) device via USB with **ADB Debugging** authorized.
2. Open this repository in your PC coding agent (Antigravity, Claude Code, Codex, Cursor, Gemini CLI, etc.).
3. Copy the full prompt from [`agent-prompts/INSTALL_EN.md`](agent-prompts/INSTALL_EN.md) (or [`agent-prompts/INSTALL_CN.md`](agent-prompts/INSTALL_CN.md)) into your agent.

Your PC agent will automatically:
1. Run read-only anonymized probing (`./tools/probe_device.sh` or `./tools/probe_device.ps1`) -> `device_profile.json`
2. Deterministically match your exact variant (`python ./tools/select_variant.py --profile ./dist/device_profile.json --json`)
3. Verify `SHA256SUMS.txt` integrity
4. Flash via `ksud` / `magisk` / `apd`
5. Confirm `ctl variant-info`, `ctl status`, optional `presets/*.json`, and `SandboxVerifyProbe.apk` probe output.

---

## Build the Full 30-Variant Matrix from Source

Set standard toolchain environment variables (`GOROOT` or `go` in PATH, `JAVA_HOME`, `ANDROID_SDK_ROOT`, `ANDROID_NDK_HOME`) and run:

```bash
python ./tools/build_matrix.py --version 3.0.0-oss
```

All 30 ZIPs, `SandboxVerifyProbe.apk`, `SHA256SUMS.txt`, and `variants-manifest.json` are generated into `./dist/`.

## License

[Apache License 2.0](LICENSE)
