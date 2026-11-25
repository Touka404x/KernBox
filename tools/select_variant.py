#!/usr/bin/env python3
"""Deterministic variant selector mapping an anonymized device_profile.json to the optimal build."""

import argparse
import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


SUPPORTED_OEMS = ("hyperos", "oplus", "oneui", "aosp", "generic")
SUPPORTED_KERNELS = ("k510", "k419")
SUPPORTED_ROOTS = ("ksu", "ksu_legacy", "magisk", "apatch")
MATRIX_KERNEL_ROOTS = {
    "k510": ("ksu", "magisk", "apatch"),
    "k419": ("ksu_legacy", "magisk", "apatch"),
}
CUSTOM_AOSP_FLAVOR_TOKENS = (
    "lineage",
    "graphene",
    "calyx",
    "crdroid",
    "aosp",
    "evolution",
    "pixelexperience",
    "pixelos",
    "paranoid",
)
PIXEL_FLAVOR_TOKENS = ("pixel", "panther", "cheetah", "husky", "shiba", "oriole", "raven", "komodo", "tokay")


def parse_kernel_tuple(profile: Dict[str, Any]) -> Tuple[int, int]:
    maj = profile.get("kernel_major")
    min_v = profile.get("kernel_minor")
    if isinstance(maj, int) and isinstance(min_v, int) and maj > 0:
        return maj, min_v
    krel = str(profile.get("kernel_release") or "")
    m = re.match(r"^(\d+)\.(\d+)", krel.strip())
    if m:
        return int(m.group(1)), int(m.group(2))
    return 0, 0


def parse_semver_tuple(ver_str: str) -> Optional[Tuple[int, int, int]]:
    m = re.search(r"v?(\d+)\.(\d+)(?:\.(\d+))?", str(ver_str or ""))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def determine_oem(profile: Dict[str, Any]) -> Tuple[str, str]:
    brand = str(profile.get("brand") or "").strip().lower()
    mfg = str(profile.get("manufacturer") or "").strip().lower()
    sigs = profile.get("oem_signals") or {}
    miui = str(sigs.get("miui_ui_version") or "").strip()
    hyperos = str(sigs.get("hyperos_version") or "").strip()
    oplusrom = str(sigs.get("oplusrom") or "").strip()
    oneui = str(sigs.get("oneui") or "").strip()
    flavor = str(sigs.get("build_flavor") or "").strip().lower()

    has_oem_ui = bool(miui or hyperos or oplusrom or oneui)
    if not has_oem_ui and any(tok in flavor for tok in CUSTOM_AOSP_FLAVOR_TOKENS):
        return "aosp", "Detected custom AOSP-based ROM without proprietary OEM skin; using oem_aosp."

    if miui or hyperos or brand in ("xiaomi", "redmi", "poco") or mfg in ("xiaomi",):
        return "hyperos", "Detected Xiaomi/HyperOS/MIUI ROM signals; using oem_hyperos (MIUI hide-app + Millet + clone exclusions)."
    if oplusrom or brand in ("oneplus", "oppo", "realme") or mfg in ("oneplus", "oppo", "realme"):
        return "oplus", "Detected ColorOS/OxygenOS/RealmeUI signals; using oem_oplus (Hans freezer + multi-app clone 999)."
    if oneui or brand in ("samsung",) or mfg in ("samsung",):
        return "oneui", "Detected Samsung One UI signals; using oem_oneui (Dual Messenger/Secure Folder clone protections)."
    if brand in ("google",) or mfg in ("google",) or any(tok in flavor for tok in PIXEL_FLAVOR_TOKENS):
        return "aosp", "Detected Pixel / pure AOSP-based ROM; using oem_aosp (minimal lean profile)."
    return "generic", "No specialized OEM skin detected; falling back to oem_generic (safe conservative compatibility)."


def determine_kernel(profile: Dict[str, Any]) -> Tuple[str, str]:
    maj, min_v = parse_kernel_tuple(profile)
    cg2 = bool(profile.get("cgroup_v2_freeze"))
    if (maj, min_v) >= (5, 10) and cg2:
        return "k510", f"Kernel {maj}.{min_v} >= 5.10 with cgroup v2 freezer active -> fast k510 tier (openat2 + pidfd + cgroup v2 freeze + process_madvise)."
    if (maj, min_v) >= (5, 10) and not cg2:
        return "k419", f"Kernel {maj}.{min_v} >= 5.10 lacks active cgroup v2 freezer -> falling back safely to k419 compat tier."
    if maj > 0:
        return "k419", f"Kernel {maj}.{min_v} < 5.10 -> using k419 compat tier (openat O_NOFOLLOW walk + cgroup v1 freezer fallback)."
    return "k419", "Kernel version undetermined; conservatively selecting k419 compat tier."


def determine_root_and_tier(profile: Dict[str, Any], kernel: str) -> Tuple[str, Optional[str], str, Optional[str]]:
    raw_root = str(profile.get("root_manager") or "").strip().lower()
    raw_ver = str(profile.get("root_version") or "").strip()

    if raw_root in ("", "none", "unknown"):
        return kernel, None, "No supported root manager (KernelSU / Magisk / APatch) detected via ADB.", None
    if raw_root == "ksu_legacy":
        warn = None
        if kernel != "k419":
            warn = f"Explicit ksu_legacy root requires the k419 compat matrix tier (downgrading {kernel} -> k419)."
            kernel = "k419"
        return kernel, "ksu_legacy", "Explicit ksu_legacy root profile mapped to k419/ksu_legacy.", warn
    if raw_root in ("ksu", "kernelsu"):
        ver = parse_semver_tuple(raw_ver)
        if ver is not None and (ver[0], ver[1]) < (0, 9):
            warn = None
            if kernel != "k419":
                warn = f"Legacy KernelSU {raw_ver} (< 0.9) maps to k419/ksu_legacy release artifact."
                kernel = "k419"
            return kernel, "ksu_legacy", f"KernelSU ({raw_ver}) mapped to k419/ksu_legacy.", warn
        if kernel == "k419":
            return kernel, "ksu_legacy", f"KernelSU ({raw_ver or 'compat'}) on k419 mapped to ksu_legacy.", None
        return kernel, "ksu", f"KernelSU ({raw_ver or 'modern'}) on {kernel} mapped to ksu.", None
    if raw_root == "magisk":
        return kernel, "magisk", f"Magisk ({raw_ver or 'detected'}) mapped to {kernel}/magisk.", None
    if raw_root == "apatch":
        return kernel, "apatch", f"APatch ({raw_ver or 'detected'}) mapped to {kernel}/apatch.", None
    return kernel, None, f"Unsupported root manager {raw_root!r}; expected one of ksu, ksu_legacy, magisk, apatch.", None


def install_command_for_root(root: str, artifact: str) -> str:
    remote = f"/data/local/tmp/{artifact}"
    if root in ("ksu", "ksu_legacy"):
        return f'adb push "{artifact}" {remote} && adb shell su -c "ksud module install {remote}"'
    if root == "magisk":
        return f'adb push "{artifact}" {remote} && adb shell su -c "magisk --install-module {remote}"'
    if root == "apatch":
        return f'adb push "{artifact}" {remote} && adb shell su -c "apd module install {remote}"'
    return f"adb push {artifact} {remote}"


def select_variant(profile: Dict[str, Any], version: str = "1.0.0", preset: Optional[str] = None) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []
    reasons: List[str] = []

    abi = str(profile.get("cpu_abi") or "").strip().lower()
    if abi != "arm64-v8a":
        errors.append(f"Unsupported CPU ABI {abi!r}: KernBox only supports arm64-v8a devices.")

    sdk = int(profile.get("android_sdk") or 0)
    if sdk <= 0:
        errors.append("Missing android_sdk in device profile (Android 12 / API 31+ required).")
    elif sdk < 31:
        errors.append(f"Unsupported Android SDK {sdk} (Android {profile.get('android_release') or '?'}): API 31+ (Android 12+) is required.")

    oem, oem_reason = determine_oem(profile)
    reasons.append(oem_reason)

    kernel, kernel_reason = determine_kernel(profile)
    reasons.append(kernel_reason)

    kernel, root, root_reason, tier_warn = determine_root_and_tier(profile, kernel)
    if tier_warn:
        warnings.append(tier_warn)
    if root is None:
        errors.append(root_reason)
    else:
        reasons.append(root_reason)
        allowed_roots = MATRIX_KERNEL_ROOTS.get(kernel, ())
        if root not in allowed_roots:
            errors.append(f"Unsupported combination ({kernel}, {root}); expected root in {allowed_roots}.")

    if not profile.get("zygisk_detected", False):
        if root == "magisk":
            warnings.append("Zygisk is NOT active in Magisk: enable 'Zygisk' in Magisk Settings and reboot so SystemServer/Phone stealth works.")
        else:
            warnings.append(f"Zygisk module (ZygiskNext / ReZygisk) NOT detected alongside {root or 'root'}: install ZygiskNext or ReZygisk before expecting SystemServer/Phone stealth.")

    if "tproxy_capable" in profile and not profile.get("tproxy_capable"):
        warnings.append("TProxy netfilter target not confirmed in /proc/net/ip_tables_targets; verify kernel CONFIG_NETFILTER_XT_TARGET_TPROXY or use a TProxy-capable kernel.")

    work_users = profile.get("work_profile_users") or []
    work_user = int(work_users[0]) if work_users else 10
    if not work_users:
        warnings.append("No active Work Profile user detected yet; provision User 10 via Shelter / TestDPC / your profile controller before activating guard rules.")

    readiness = profile.get("real_device_readiness")
    if not isinstance(readiness, dict):
        readiness = {}
    if not preset:
        warnings.append(
            "Default 'neutral' config leaves spoof_carrier=false and spoof_device_region=false; "
            "pass --preset <name> (e.g. jp-docomo, us-tmobile, uk-ee, sg-singtel, de-telekom) "
            "or run `ctl preset-apply` to align carrier/locale/timezone with your proxy exit country."
        )
    vb_state = str(readiness.get("bootloader_verified_state") or "").strip().lower()
    flash_locked = str(readiness.get("bootloader_flash_locked") or "").strip()
    if ((vb_state and vb_state != "green") or flash_locked == "0") and not readiness.get("trickystore_detected"):
        warnings.append(
            "Unlocked bootloader detected without TrickyStore: hardware KeyMint RootOfTrust attestation "
            "will still reveal unlocked state unless paired with TrickyStore (+ PlayIntegrityFix)."
        )
    if root == "magisk" and readiness.get("root_hider_detected") is False:
        warnings.append(
            "Magisk detected without Shamiko / Zygisk Assistant / SuSFS: enable Enforce DenyList "
            "(or install Shamiko) so /proc/self/mountinfo and su paths stay hidden."
        )
    if readiness.get("adb_enabled") is True:
        warnings.append(
            "USB Debugging (adb_enabled=1) is active: turn off USB Debugging after installation and "
            "verification so apps inspecting Settings.Global.ADB_ENABLED see a retail device."
        )
    if readiness.get("accessibility_services_active") is True:
        warnings.append(
            "Active Android Accessibility Service(s) detected: non-essential accessibility services "
            "can trigger Play Integrity appAccessRiskVerdict; disable them before sensitive use."
        )

    artifact = f"KernBox-{oem}-{kernel}-{root}-arm64.zip" if (not errors and root) else None

    result: Dict[str, Any] = {
        "ok": len(errors) == 0,
        "oem": oem,
        "kernel": kernel,
        "root": root,
        "version": version,
        "artifact": artifact,
        "target_work_user": work_user,
        "reasons": reasons,
        "warnings": warnings,
        "errors": errors,
        "commands": {},
    }
    if artifact:
        cmds = {
            "install": install_command_for_root(root, artifact),
            "reboot": "adb reboot",
            "status_check": 'adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl variant-info && /data/adb/sandbox_guard/sandbox_guard ctl status && /data/adb/sandbox_guard/sandbox_guard ctl stealth-status"',
            "verify_install": f'adb install -r --user {work_user} KernBoxVerify.apk && adb shell am instrument --user {work_user} -w com.sandbox.verify/com.sandbox.verify.NetworkProbe',
            "verify_cleanup": f"adb uninstall --user {work_user} com.sandbox.verify",
        }
        if preset:
            preset_name = preset if preset.endswith(".json") else f"{preset}.json"
            cmds["preset_apply"] = (
                f'adb push "presets/{preset_name}" "/data/local/tmp/{preset_name}" && '
                f'adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl preset-apply /data/local/tmp/{preset_name}"'
            )
        result["commands"] = cmds
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Select optimal KernBox variant from device_profile.json")
    p.add_argument("--profile", required=True, help="Path to device_profile.json (or '-' for stdin)")
    p.add_argument("--version", default="1.0.0", help="Release version tag")
    p.add_argument("--preset", help="Optional preset name under presets/ (e.g. jp-docomo, us-tmobile)")
    p.add_argument("--json", action="store_true", help="Emit structured JSON output")
    args = p.parse_args(argv)

    raw = sys.stdin.read() if args.profile == "-" else pathlib.Path(args.profile).read_text(encoding="utf-8")
    profile = json.loads(raw)
    res = select_variant(profile, version=args.version, preset=args.preset)

    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        if not res["ok"]:
            print("SELECTION FAILED:", file=sys.stderr)
            for err in res["errors"]:
                print(f"  [ERROR] {err}", file=sys.stderr)
            for warn in res["warnings"]:
                print(f"  [WARN]  {warn}", file=sys.stderr)
            return 2
        print(f"SELECTED VARIANT : {res['artifact']}")
        print(f"PROFILE TUPLE    : oem={res['oem']} kernel={res['kernel']} root={res['root']} work_user={res['target_work_user']}")
        for r in res["reasons"]:
            print(f"  - {r}")
        for w in res["warnings"]:
            print(f"  [WARN] {w}")
        print("\nNEXT COMMANDS:")
        for label, cmd in res["commands"].items():
            print(f"  {label}: {cmd}")

    return 0 if res["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
