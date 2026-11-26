#!/usr/bin/env python3
"""Builds the pure-C11 static zero-GC ARM64 sandbox_broker binary + ELF hygiene check."""

import argparse
import hashlib
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
IS_WIN = os.name == "nt"


def exe_name(base: str, win_ext: str = ".exe") -> str:
    return f"{base}{win_ext}" if IS_WIN else base


def resolve_toolchain(args: argparse.Namespace) -> dict:
    sdk_str = args.sdk or os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") or ""
    ndk_str = (
        args.ndk
        or os.environ.get("ANDROID_NDK_HOME")
        or os.environ.get("ANDROID_NDK_ROOT")
        or os.environ.get("ANDROID_NDK")
        or ""
    )
    if not ndk_str and sdk_str:
        ndk_root = pathlib.Path(sdk_str) / "ndk"
        if ndk_root.is_dir():
            hits = sorted(ndk_root.iterdir(), reverse=True)
            if hits:
                ndk_str = str(hits[0])
    if not ndk_str:
        raise RuntimeError("Missing Android NDK: pass --ndk, --sdk, or set ANDROID_NDK_HOME")
    ndk = pathlib.Path(ndk_str)

    prebuilt_bins = sorted((ndk / "toolchains" / "llvm" / "prebuilt").glob("*/bin"))
    if not prebuilt_bins:
        raise FileNotFoundError(f"LLVM toolchain bin dir not found under {ndk}")
    ndk_bin = prebuilt_bins[0]

    clang = ndk_bin / exe_name("clang")
    if not clang.is_file():
        raise FileNotFoundError(f"clang not found at {clang}")
    llvm_readelf = ndk_bin / exe_name("llvm-readelf")
    if not llvm_readelf.is_file():
        raise FileNotFoundError(f"llvm-readelf not found at {llvm_readelf}")

    return {
        "clang": clang,
        "llvm_readelf": llvm_readelf,
        "target": f"aarch64-linux-android{int(args.min_sdk)}",
    }


def verify_static_elf(tc: dict, out_bin: pathlib.Path) -> None:
    ph = subprocess.run(
        [str(tc["llvm_readelf"]), "-l", str(out_bin)],
        capture_output=True,
        text=True,
        check=True,
    )
    if re.search(r"^\s*INTERP\b", ph.stdout, re.MULTILINE):
        raise AssertionError(f"{out_bin} must be 100% static (unexpected PT_INTERP)")

    dyn = subprocess.run(
        [str(tc["llvm_readelf"]), "-d", str(out_bin)],
        capture_output=True,
        text=True,
        check=True,
    )
    if "TEXTREL" in dyn.stdout:
        raise AssertionError(f"{out_bin} contains forbidden TEXTREL")
    needed = re.findall(r"Shared library:\s*\[([^\]]+)\]", dyn.stdout)
    if needed:
        raise AssertionError(f"{out_bin} has unexpected DT_NEEDED entries: {needed}")


def build_broker(args: argparse.Namespace) -> pathlib.Path:
    tc = resolve_toolchain(args)
    out_bin = pathlib.Path(args.out) if args.out else (REPO_ROOT / "dist" / "sandbox_broker")
    out_bin.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(tc["clang"]),
        f"--target={tc['target']}",
        "-static",
        "-std=c11",
        "-Oz",
        "-flto",
        "-fmerge-all-constants",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-ffunction-sections",
        "-fdata-sections",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        "-I",
        str(ROOT),
        str(ROOT / "broker_core.c"),
        str(ROOT / "main.c"),
        "-o",
        str(out_bin),
        "-Wl,--gc-sections,-s,--icf=all,-z,max-page-size=16384",
    ]
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True)
    verify_static_elf(tc, out_bin)

    raw = out_bin.read_bytes()
    sha = hashlib.sha256(raw).hexdigest().lower()
    print(f"BUILT_STATIC_BROKER={out_bin} size={len(raw)} sha256={sha}")
    return out_bin


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Build static C11 ARM64 sandbox_broker")
    p.add_argument("--out", help="Output binary path")
    p.add_argument("--min-sdk", type=int, default=31, help="NDK API level (default: 31)")
    p.add_argument("--sdk", default="", help="Android SDK path")
    p.add_argument("--ndk", default="", help="Android NDK path")
    args = p.parse_args(argv)
    build_broker(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
