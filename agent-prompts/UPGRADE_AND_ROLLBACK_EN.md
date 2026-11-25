# Zero-Leak Upgrade & Emergency Rollback Prompt (UPGRADE_AND_ROLLBACK_EN)

Covers two common workflows:
1. **Upgrade / Cross-Variant Migration** (with `upgrade_fence` leak protection)
2. **Emergency Disable & Full Rollback** (including bootloop recovery and clean `uninstall.sh` cleanup)

---

## Scenario A: Upgrade or Switch Variant (Send to PC Agent)

```text
Upgrade or migrate KernBox on my connected phone to the target version/variant ZIP while keeping my Work Profile user intact and preserving `stealth.json` / `perf.json`.

1. Re-run `./tools/probe_device.ps1` (or `.sh`) and `./tools/select_variant.py` to confirm the target ZIP `<artifact>` matches my device, and verify its SHA-256 against `SHA256SUMS.txt`.
2. Pull a local temporary backup of `/data/adb/sandbox_guard/stealth.json`, `perf.json`, and `policy.json` (never echo sensitive values).
3. If also upgrading the external proxy core, use the upgrade fence:
   `adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl upgrade-begin 90"` -> upgrade proxy -> `ctl upgrade-end`.
4. Flash the KernBox module ZIP via the device's Root Manager CLI:
   - KernelSU: `ksud module install /data/local/tmp/<artifact>`
   - Magisk: `magisk --install-module /data/local/tmp/<artifact>`
   - APatch: `apd module install /data/local/tmp/<artifact>`
   Clean up `/data/local/tmp/<artifact>`.
5. Ask for my explicit confirmation before running `adb reboot`.
6. After reboot, run `ctl variant-info` and `ctl status` to confirm the new version/variant is online.
```

---

## Scenario B: Boot Anomaly / Emergency Disable & Clean Uninstall

Note that KernBox already ships a **Two-Strike Bootloop Kill-Switch** (`zygisk_disabled`), an in-manager **Action toggle** (`action.sh` pauses/resumes cleanly), and **`uninstall.sh`** (restores hibernated apps/bloat and tears down `SBW_*` netfilter rules).

```text
Emergency-disable or roll back KernBox on my phone:

### Option 1: Disable Zygisk Stealth Only (Keep Daemon & Netfilter Isolation)
adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl stealth-toggle off"
# Or disable Zygisk component permanently across reboots:
adb shell su -c "touch /data/adb/modules/sandbox_guard/zygisk_disabled && chmod 0644 /data/adb/modules/sandbox_guard/zygisk_disabled"

### Option 2: Disable Entire Module (Preserves Work Profile App Data)
adb shell su -c "sh /data/adb/modules/sandbox_guard/service.sh stop || true"
adb shell su -c "touch /data/adb/modules/sandbox_guard/disable"
# Ask confirmation before: adb reboot

### Option 3: Safe-Mode / Clean Uninstall
1. Use your Root Manager's hardware-key Safe Mode (volume-down on boot) or Uninstall button (runs `uninstall.sh` on next boot to restore hibernated apps and flush `SBW_*` rules).
2. Under TWRP / ADB Root manual cleanup:
   `sh /data/adb/modules/sandbox_guard/uninstall.sh || true`
   `rm -rf /data/adb/modules/sandbox_guard /data/adb/modules_update/sandbox_guard`
```
