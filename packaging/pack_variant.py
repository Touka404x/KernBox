#!/usr/bin/env python3
"""Packages a single KernBox (OEM, KernelTier, RootManager) root module ZIP."""

import argparse
import hashlib
import json
import pathlib
import sys
import zipfile

PKG_DIR = pathlib.Path(__file__).resolve().parent
COMMON_DIR = PKG_DIR / "common"
SEPOLICY_DIR = PKG_DIR / "sepolicy"

OEMS = ("hyperos", "aosp", "oplus", "oneui", "generic")
KERNELS = ("k510", "k419")
ROOTS = ("ksu", "ksu_legacy", "magisk", "apatch")

ROOT_PROFILE = {
    "ksu": {
        "sepolicy": "ksu.rule",
        "path_prefix": "/data/adb/ksu/bin",
        "resetprop": "/data/adb/ksu/bin/resetprop",
        "busybox": "/data/adb/ksu/bin/busybox /data/adb/magisk/busybox /data/adb/ap/bin/busybox",
    },
    "ksu_legacy": {
        "sepolicy": "ksu_legacy.rule",
        "path_prefix": "/data/adb/ksu/bin",
        "resetprop": "/data/adb/ksu/bin/resetprop",
        "busybox": "/data/adb/ksu/bin/busybox /data/adb/magisk/busybox /data/adb/ap/bin/busybox",
    },
    "magisk": {
        "sepolicy": "magisk.rule",
        "path_prefix": "/data/adb/magisk",
        "resetprop": "/data/adb/magisk/resetprop /sbin/resetprop /debug_ramdisk/resetprop",
        "busybox": "/data/adb/magisk/busybox /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox",
    },
    "apatch": {
        "sepolicy": "apatch.rule",
        "path_prefix": "/data/adb/ap/bin",
        "resetprop": "/data/adb/ap/bin/resetprop /data/adb/ksu/bin/resetprop",
        "busybox": "/data/adb/ap/bin/busybox /data/adb/ksu/bin/busybox /data/adb/magisk/busybox",
    },
}

FIXED_DATE = (2026, 11, 25, 0, 0, 0)


def version_to_code(ver: str) -> str:
    """Convert semver 'major.minor.patch' to a monotonic integer code (e.g. 1.2.0 -> '10200')."""
    parts = [int(p) for p in ver.strip().lstrip("vV").split(".") if p.isdigit()]
    if len(parts) >= 3:
        return str(parts[0] * 10000 + parts[1] * 100 + parts[2])
    if len(parts) == 2:
        return str(parts[0] * 10000 + parts[1] * 100)
    if len(parts) == 1:
        return str(parts[0] * 10000)
    return "10000"


def render_template(raw_text: str, mapping: dict) -> bytes:
    rendered = raw_text
    for key, val in mapping.items():
        rendered = rendered.replace("{{" + key + "}}", val)
    if "{{" in rendered or "}}" in rendered:
        raise AssertionError(f"Unexpanded template placeholder in rendered output")
    out = rendered.replace("\r\n", "\n").encode("utf-8")
    if b"\r" in out:
        raise AssertionError("CR byte present after LF normalization")
    return out


def make_zipinfo(arcname: str, mode: int) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(filename=arcname, date_time=FIXED_DATE)
    zi.create_system = 3  # Unix
    zi.external_attr = ((0o100000 | mode) & 0xFFFF) << 16
    zi.compress_type = zipfile.ZIP_DEFLATED
    return zi


def pack_variant(
    oem: str,
    kernel: str,
    root: str,
    version: str,
    guard_bin: pathlib.Path,
    broker_bin: pathlib.Path,
    zygisk_so: pathlib.Path,
    out_zip: pathlib.Path,
    quiet: bool = False,
) -> dict:
    for p in (guard_bin, broker_bin, zygisk_so):
        if not p.is_file():
            raise FileNotFoundError(f"Missing binary artifact: {p}")

    rp = ROOT_PROFILE[root]
    mapping = {
        "OEM": oem,
        "KERNEL": kernel,
        "ROOT": root,
        "VERSION": version,
        "VERSION_CODE": version_to_code(version),
        "ROOT_PATH_PREFIX": rp["path_prefix"],
        "RESETPROP_CANDIDATES": rp["resetprop"],
        "BUSYBOX_CANDIDATES": rp["busybox"],
    }

    variant_meta = json.dumps(
        {
            "version": version,
            "oem": oem,
            "kernel": kernel,
            "root": root,
            "arch": "arm64-v8a",
            "transport": "tproxy",
            "artifact": out_zip.name,
        },
        indent=2,
        sort_keys=True,
    ) + "\n"

    text_entries = [
        ("module.prop", render_template((COMMON_DIR / "module.prop.tmpl").read_text(encoding="utf-8"), mapping), 0o644),
        ("customize.sh", render_template((COMMON_DIR / "customize.sh.tmpl").read_text(encoding="utf-8"), mapping), 0o755),
        ("post-fs-data.sh", render_template((COMMON_DIR / "post-fs-data.sh.tmpl").read_text(encoding="utf-8"), mapping), 0o755),
        ("service.sh", render_template((COMMON_DIR / "service.sh.tmpl").read_text(encoding="utf-8"), mapping), 0o755),
        ("action.sh", render_template((COMMON_DIR / "action.sh.tmpl").read_text(encoding="utf-8"), mapping), 0o755),
        ("uninstall.sh", render_template((COMMON_DIR / "uninstall.sh.tmpl").read_text(encoding="utf-8"), mapping), 0o755),
        ("sepolicy.rule", (SEPOLICY_DIR / rp["sepolicy"]).read_bytes().replace(b"\r\n", b"\n"), 0o644),
        ("defaults/stealth.json", (COMMON_DIR / "defaults" / "stealth.json").read_bytes().replace(b"\r\n", b"\n"), 0o600),
        ("defaults/perf.json", (COMMON_DIR / "defaults" / "perf.json").read_bytes().replace(b"\r\n", b"\n"), 0o600),
        ("variant.json", variant_meta.encode("utf-8"), 0o644),
    ]

    bin_entries = [
        ("bin/sandbox_guard", guard_bin, 0o755),
        ("bin/sandbox_broker", broker_bin, 0o755),
        ("zygisk/arm64-v8a.so", zygisk_so, 0o644),
    ]

    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for arcname, data, mode in text_entries:
            if b"\r" in data:
                raise AssertionError(f"CR byte found in {arcname}")
            zf.writestr(make_zipinfo(arcname, mode), data)
        for arcname, src, mode in bin_entries:
            zf.writestr(make_zipinfo(arcname, mode), src.read_bytes())

    with zipfile.ZipFile(out_zip, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise AssertionError(f"Corrupted ZIP entry {bad} in {out_zip}")
        for arcname, _, _ in text_entries:
            if b"\r" in zf.read(arcname):
                raise AssertionError(f"CR byte in zip entry {arcname}")

    zip_bytes = out_zip.read_bytes()
    sha256 = hashlib.sha256(zip_bytes).hexdigest().lower()
    if not quiet:
        print(f"PACKAGED {out_zip.name} size={len(zip_bytes)} sha256={sha256}")
    return {
        "artifact": out_zip.name,
        "oem": oem,
        "kernel": kernel,
        "root": root,
        "version": version,
        "size": len(zip_bytes),
        "sha256": sha256,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Package a single KernBox root module ZIP")
    p.add_argument("--oem", required=True, choices=OEMS)
    p.add_argument("--kernel", required=True, choices=KERNELS)
    p.add_argument("--root", required=True, choices=ROOTS)
    p.add_argument("--version", default="1.0.0")
    p.add_argument("--guard-bin", required=True, type=pathlib.Path)
    p.add_argument("--broker-bin", required=True, type=pathlib.Path)
    p.add_argument("--zygisk-so", required=True, type=pathlib.Path)
    p.add_argument("--out", type=pathlib.Path)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    out_zip = args.out or pathlib.Path(f"KernBox-{args.oem}-{args.kernel}-{args.root}-arm64.zip")
    pack_variant(
        oem=args.oem,
        kernel=args.kernel,
        root=args.root,
        version=args.version,
        guard_bin=args.guard_bin,
        broker_bin=args.broker_bin,
        zygisk_so=args.zygisk_so,
        out_zip=out_zip,
        quiet=args.quiet,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
