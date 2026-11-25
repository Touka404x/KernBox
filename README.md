# KernBox

**Kernel-level isolated Android Work Profile sandbox with 30 lean device-specialized builds and AI-Agent co-installation.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-12%2B%20ARM64-3DDC84.svg)](VARIANT_MATRIX.md)
[![Variants](https://img.shields.io/badge/Builds-30%20Lean%20Variants-0A66C2.svg)](VARIANT_MATRIX.md)
[![Root](https://img.shields.io/badge/Root-KernelSU%20%7C%20Magisk%20%7C%20APatch-black.svg)](VARIANT_MATRIX.md)

**English** · [简体中文](README_CN.md) · [30-Variant Matrix](VARIANT_MATRIX.md) · [Architecture](ARCHITECTURE.md) · [AI Install Playbook](agent-prompts/INSTALL_EN.md) · [Security](SECURITY.md)

---

## Why KernBox?

Most Android sandbox and multi-profile tools ship one bloated universal binary stuffed with unused OEM workarounds, legacy kernel fallbacks, and runtime branch checks — hurting battery, responsiveness, and stealth footprint.

**KernBox takes the opposite approach:**
- **30 lean compile-time-specialized builds**: Every release ships 30 targeted ARM64 modules (`5 OEMs × 2 Kernel Tiers × 3 Root Managers`, ~4.1 MB each). Your device only compiles and runs the exact kernel, OEM, SELinux, and Root paths it actually uses.
- **AI-Agent-first Phone + PC co-installation**: You don't have to guess kernel tiers, cgroup versions, or SELinux rules by hand. Plug your phone into your PC, hand a built-in playbook to your AI coding agent, and let it probe, match, verify SHA-256 checksums, flash, and audit post-boot isolation step-by-step.

---

## 30-Second Quick Start with an AI Agent (Recommended)

### Prerequisites
1. A rooted **ARM64 (`arm64-v8a`) Android 12+ (API 31+)** phone (`KernelSU`, `Magisk`, or `APatch`) with **USB Debugging (ADB)** authorized on your PC.
2. Any terminal-capable AI coding agent on your PC (Antigravity, Claude Code, Codex, Cursor, Gemini CLI, etc.).

### Send This Prompt to Your PC Agent
Clone or open this repository on your PC and send:

```text
Read agent-prompts/INSTALL_EN.md and follow its workflow strictly in order for my connected Android phone: run the read-only anonymized device prober, match the exact KernBox variant via tools/select_variant.py, verify the artifact SHA-256 against SHA256SUMS.txt, and pause for my confirmation before flashing, rebooting, or running post-boot checks. Never print my hardware serial, IMEI, MAC, or IP.
```

What happens automatically under your supervision:
```text
probe_device (.ps1/.sh)  ──▶  select_variant.py  ──▶  SHA-256 Strict Verify
         │                             │                         │
         ▼                             ▼                         ▼
 Anonymized device facts     Exact 1-of-30 ZIP match     ksud / magisk / apd flash
                                                                 │
         KernBoxVerify.apk ◀── ctl variant-info/status ◀─────────┘ Reboot confirm
```

---

## 30-Variant Device Coverage

KernBox ships `5 OEMs × 2 Kernel Tiers × 3 Root Managers per tier = 30 ARM64 ZIPs` (`KernBox-<oem>-<kernel>-<root>-arm64.zip`) plus the standalone unprivileged probe APK (`KernBoxVerify.apk`):

| Axis | Coverage | Specialization Notes |
| :--- | :--- | :--- |
| **OEM Profiles (5)** | `hyperos`, `aosp`, `oplus`, `oneui`, `generic` | Go `-tags oem_<oem>` & C++ `-DOEM_<OEM>` trim OEM bloat rules, clone exclusions, freezer handling, and property slots at compile time. |
| **Kernel Tiers (2)** | `k510`, `k419` | `k510` (Linux 5.10+ w/ cgroup v2 freeze): `openat2`, `pidfd`, `process_madvise`, `cgroup.freeze`. `k419` (`-tags kernel_compat`): `openat(O_NOFOLLOW)` traversal, verified `/proc` kill, cgroup v1 fallback. |
| **Root Managers** | `ksu`, `ksu_legacy`, `magisk`, `apatch` | Manager-specific `sepolicy.rule` (`ksu_legacy` targets KSU `< 0.9` / `k419`), `resetprop`/`busybox` lookup, and official CLI install integration. |

> See every artifact filename and build flag in [`VARIANT_MATRIX.md`](VARIANT_MATRIX.md). Custom AOSP ROMs on OEM hardware (e.g., LineageOS on Xiaomi) are automatically classified as `aosp`.

---

## Core Capabilities

- **Fail-Closed Netfilter Isolation & Upgrade Fence**: Atomic `iptables-restore --noflush` management across `SBW_RAW_OUTPUT`, `SBW_OUTPUT`, `SBW_EGRESS`, and `SBW_TPROXY_*`. Blocks boot/locked/upgrade-window leaks deterministically with zero `TRANSPORT_VPN` footprint on the default TProxy path.
- **Microsecond Hot-Freeze & Memory Reclaim**: Freezes sandbox Work Profile UIDs via cgroup v2 (`k510`) and triggers `process_madvise(MADV_PAGEOUT)` under memory pressure for near-zero idle drain and instant resume; falls back cleanly to cgroup v1 / hibernation on `k419`.
- **Privilege-Separated Broker & Root IPC**: Splits unprivileged controller UDS (`/dev/socket/sandbox_ctrl/ctrl.sock`) from root daemon UDS (`/dev/socket/sandbox_priv/guard.sock`) via SELinux `sandbox_broker`, enforcing APK signing cert SHA-256, `SO_PEERCRED`, and shared token auth.
- **Two-Layer Zygisk + Binder Stealth with Two-Strike Kill-Switch**: Zero-allocation Native PLT property/interface sanitization paired with an `InMemoryDexClassLoader` dynamic `IServiceManager` proxy in `system_server` & `com.android.phone`. Ships 6 switchable region/carrier presets under [`presets/`](presets/) (`neutral` default + `jp-docomo`, `us-tmobile`, `uk-ee`, `sg-singtel`, `de-telekom`), plus an automatic 2-failed-boot kill-switch (`zygisk_disabled`).
- **Independent Verification APK**: Unprivileged pure-Java probe [`KernBoxVerify.apk`](verify/) verifies network isolation, IPv6 blocking, proc hygiene, and KeyMint attestation posture inside the sandboxed user.

---

## AI Operations Playbooks

- **Install & First Audit**: [`agent-prompts/INSTALL_EN.md`](agent-prompts/INSTALL_EN.md) · [中文版](agent-prompts/INSTALL_CN.md)
- **Read-Only Anonymized Diagnostics**: [`agent-prompts/DIAGNOSE.md`](agent-prompts/DIAGNOSE.md)
- **Zero-Leak Upgrade & Emergency Rollback**: [`agent-prompts/UPGRADE_AND_ROLLBACK.md`](agent-prompts/UPGRADE_AND_ROLLBACK.md)

---

## Build All 30 Variants from Source

With `go` (matching [`guard/go.mod`](guard/go.mod)), `JAVA_HOME` (JDK 21), `ANDROID_SDK_ROOT` (`platforms;android-35`, `build-tools;35.0.0`), `ANDROID_NDK_HOME`, and Python 3.10+ configured:

```bash
# Cross-platform Python builder
python ./tools/build_matrix.py --version 1.0.0
```

```powershell
# Windows PowerShell wrapper
.\tools\build_matrix.ps1 -Version 1.0.0
```

Outputs are written to `./dist/` (gitignored): all 30 `KernBox-<oem>-<kernel>-<root>-arm64.zip` modules, `KernBoxVerify.apk`, `SHA256SUMS.txt`, and `variants-manifest.json`. Optional source build flag `-tags transport_vpn` enables legacy VPN fallback builds outside the default 30 TProxy-only releases.

---

## Privacy, Security & License

- **Zero Telemetry / Zero Sensitive Data in Repo**: Device probes strip hardware serials, IMEIs, MACs, and IPs locally and never transmit telemetry. All commits are gated by [`tools/verify_privacy_leak.py`](tools/verify_privacy_leak.py).
- **Security & Contributions**: See [`SECURITY.md`](SECURITY.md) for vulnerability reporting and [`CONTRIBUTING.md`](CONTRIBUTING.md) for pre-PR hygiene & test checks.
- **Intended Use**: Provided strictly for personal privacy isolation, managed work-profile research, and defensive Android security testing. Users are responsible for complying with local laws and platform terms.
- **License**: [Apache License 2.0](LICENSE)
