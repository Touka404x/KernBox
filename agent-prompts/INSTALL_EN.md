# Phone + PC Agent Co-Installation Prompt (English / INSTALL_EN)

> **Usage**: Copy and paste the prompt block below into your PC AI Agent (Antigravity, Claude Code, Codex, Cursor, Gemini CLI, etc.).  
> Prerequisites: USB Debugging (ADB) enabled & authorized on your phone, and your terminal/agent working directory set to the root of this repository.

---

## Prompt to Copy & Send to Your PC Agent

```text
You are my Android Root Sandbox deployment engineer on this PC. We will use the "Phone handles USB/ADB authorization; PC Agent performs probing, deterministic variant selection, checksum verification, flashing, and post-boot verification" workflow to install the full-power OEM-specialized KernBox module.

Follow these steps strictly in order, report findings at each step, and pause for my confirmation before any destructive action or reboot:

### Step 1: Preflight & Read-Only Anonymized Probing
1. Run `adb devices` and confirm the target device is `device` (online & authorized). If multiple devices are attached, ask me which serial to target via `-Serial` / `--serial` (never echo my hardware serial, IMEI, MAC, or private IP in summaries).
2. Run the read-only device prober from the repository root:
   - Windows PowerShell: `./tools/probe_device.ps1 -Out ./dist/device_profile.json`
   - macOS / Linux shell: `sh ./tools/probe_device.sh --out ./dist/device_profile.json`
3. Inspect `./dist/device_profile.json`.

### Step 2: Deterministic Variant Selection & Prerequisite Checks
1. Run:
   `python ./tools/select_variant.py --profile ./dist/device_profile.json --json`
2. Inspect `ok`, `oem`, `kernel`, `root`, `artifact`, `warnings`, and `errors`:
   - If `ok` is false (non-arm64 ABI, Android SDK < 31, no root manager), stop and explain remediation clearly.
   - If `zygisk_detected` is false, warn me upfront (Magisk requires enabling Zygisk in Settings + reboot; KernelSU / APatch requires installing ZygiskNext or ReZygisk) and confirm whether to proceed or install Zygisk first.
   - If `tproxy_capable` is false, warn me that `CONFIG_NETFILTER_XT_TARGET_TPROXY` was not detected in `/proc/net/ip_tables_targets`.
   - If `work_profile_users` is empty, remind me to provision a Work Profile user (typically user 10) before enforcing sandbox isolation.

### Step 3: Build/Locate Artifact & Enforce SHA-256 Verification
1. Check whether `./dist/<artifact>` and `./dist/SHA256SUMS.txt` already exist. If not, and toolchains (`GOROOT`, `JAVA_HOME`, `ANDROID_SDK_ROOT`, `ANDROID_NDK_HOME`) are available, offer to run `python ./tools/build_matrix.py --oems <oem>` (or ask where I placed the downloaded release ZIP).
2. Compute the real SHA-256 of `./dist/<artifact>` and verify an exact match against `./dist/SHA256SUMS.txt`. Abort on mismatch.

### Step 4: Backup Existing Config & Flash Root Module
1. If `/data/adb/sandbox_guard/stealth.json` or `perf.json` already exists on the device, pull a local backup first (note: `customize.sh` preserves existing configs automatically).
2. Push and install using the root-manager-specific CLI reported by `select_variant.py`:
   - `adb push "./dist/<artifact>" "/data/local/tmp/<artifact>"`
   - KernelSU / KSU Legacy: `adb shell su -c "ksud module install /data/local/tmp/<artifact>"`
   - Magisk: `adb shell su -c "magisk --install-module /data/local/tmp/<artifact>"`
   - APatch: `adb shell su -c "apd module install /data/local/tmp/<artifact>"`
3. Remove `/data/local/tmp/<artifact>`.
4. (Optional) If `./dist/KernBox.apk` exists and the user agrees, install the companion controller APK into User 0 and bind its SHA-256 signing digest in `/data/adb/sandbox_guard/policy.json` using the in-app **Offline Cert Helper** (one-tap copy) or `apksigner verify --print-certs ./dist/KernBox.apk`:
   `adb install -r ./dist/KernBox.apk`
5. **Ask my explicit confirmation before running `adb reboot`** (note that bootloop protection automatically disarms Zygisk stealth after 2 failed boots).

### Step 5: Post-Boot Verification
1. Wait for `adb wait-for-device` and `sys.boot_completed = 1`.
2. Run:
   `adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl variant-info && /data/adb/sandbox_guard/sandbox_guard ctl status && /data/adb/sandbox_guard/sandbox_guard ctl stealth-status"`
   Verify `oem`, `kernel`, and `transport` match `<artifact>`, and verify in `stealth-status` that `stealth_boot_tries` is `0` and `zygisk_disabled` is `false` (stealth kill-switch did not trigger).
3. **Explicitly ask which proxy exit country/region I use and apply the matching preset**:
   - Note that the default `neutral` config keeps `spoof_carrier` and `spoof_device_region` disabled; ask me to pick a matching preset under `./presets/` (`jp-docomo`, `us-tmobile`, `uk-ee`, `sg-singtel`, `de-telekom`, or keep `neutral`):
   - `adb push "./presets/<preset>.json" "/data/local/tmp/<preset>.json"`
   - `adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl preset-apply /data/local/tmp/<preset>.json"`
   - `adb shell rm -f "/data/local/tmp/<preset>.json"`
4. If `./dist/KernBoxVerify.apk` exists and Work Profile user `<work_user>` is present, install and run verification:
   `adb install -r --user <work_user> ./dist/KernBoxVerify.apk`
   `adb shell am instrument --user <work_user> -w com.sandbox.verify/com.sandbox.verify.NetworkProbe`
   Summarize all 12 items of `real_device_scorecard` (`work_profile_hidden`, `vpn_footprint_clean`, `ipv6_leak_blocked`, `proc_mounts_clean`, `proc_maps_clean`, `su_paths_hidden`, `isolated_proc_clean`, `boot_props_locked`, `usb_debugging_off`, `accessibility_risk_clean`, `keymint_rot_locked`, `carrier_and_geo_configured`):
   - If `keymint_rot_locked` is `warn`, remind me to pair TrickyStore + PlayIntegrityFix for hardware KeyMint attestation on unlocked bootloaders;
   - If `accessibility_risk_clean` is `warn`, advise disabling non-essential Accessibility Services to satisfy `appAccessRiskVerdict`;
   - If `usb_debugging_off` is `warn`, remind me to **disable USB Debugging (`adb_enabled`)** and unplug USB after verification finishes;
5. **Post-verification cleanup (remove self-signed instrumentation probe before daily use)**:
   `adb uninstall --user <work_user> com.sandbox.verify`
   Conclude with stability hygiene reminders (keep one fixed region preset per sandbox matching your proxy exit, prefer hot-freeze over repeated data wipes/reinstalls, keep sandbox accounts isolated) and rollback commands (`./agent-prompts/UPGRADE_AND_ROLLBACK.md`).

### Safety Red Lines
- Never flash a mismatched OEM/ABI ZIP or bypass a failed SHA-256 check.
- Never publish hardware serials, IMEIs, MACs, private IPs, or raw `dumpsys` outputs.
- Stop and explain whenever a prerequisite or permission check fails.
```
