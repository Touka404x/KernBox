#!/usr/bin/env python3
"""Builds OEM-specialized Zygisk stealth libraries (DEX -> header -> arm64 .so) + ELF hygiene check."""

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
OEMS = ("hyperos", "aosp", "oplus", "oneui", "generic")
IS_WIN = os.name == "nt"


def exe_name(base: str, win_ext: str = ".exe") -> str:
    return f"{base}{win_ext}" if IS_WIN else base


def resolve_toolchain(args: argparse.Namespace) -> dict:
    jdk_home_str = args.jdk or os.environ.get("JAVA_HOME") or ""
    if not jdk_home_str:
        javac_on_path = shutil.which("javac")
        if javac_on_path:
            jdk_home_str = str(pathlib.Path(javac_on_path).resolve().parent.parent)
    if not jdk_home_str:
        raise RuntimeError("Missing JDK: pass --jdk or set JAVA_HOME")
    jdk_home = pathlib.Path(jdk_home_str)
    jdk_bin = jdk_home / "bin"
    javac = jdk_bin / exe_name("javac")
    if not javac.is_file():
        raise FileNotFoundError(f"javac not found at {javac}")

    sdk_str = args.sdk or os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") or ""
    if not sdk_str:
        raise RuntimeError("Missing Android SDK: pass --sdk or set ANDROID_SDK_ROOT / ANDROID_HOME")
    sdk = pathlib.Path(sdk_str)
    android_jar = sdk / "platforms" / "android-35" / "android.jar"
    if not android_jar.is_file():
        platforms = sorted((sdk / "platforms").glob("android-*/android.jar"), reverse=True)
        if not platforms:
            raise FileNotFoundError(f"No android.jar found under {sdk / 'platforms'}")
        android_jar = platforms[0]

    d8_name = "d8.bat" if IS_WIN else "d8"
    d8 = sdk / "build-tools" / "35.0.0" / d8_name
    if not d8.is_file():
        d8_hits = sorted((sdk / "build-tools").glob(f"*/{d8_name}"), reverse=True)
        if not d8_hits:
            raise FileNotFoundError(f"No {d8_name} found under {sdk / 'build-tools'}")
        d8 = d8_hits[0]

    ndk_str = (
        args.ndk
        or os.environ.get("ANDROID_NDK_HOME")
        or os.environ.get("ANDROID_NDK_ROOT")
        or os.environ.get("ANDROID_NDK")
        or ""
    )
    if not ndk_str and (sdk / "ndk").is_dir():
        ndk_dirs = sorted((sdk / "ndk").iterdir(), reverse=True)
        if ndk_dirs:
            ndk_str = str(ndk_dirs[0])
    if not ndk_str:
        raise RuntimeError("Missing Android NDK: pass --ndk or set ANDROID_NDK_HOME / ANDROID_NDK_ROOT")
    ndk = pathlib.Path(ndk_str)

    prebuilt_candidates = sorted((ndk / "toolchains" / "llvm" / "prebuilt").glob("*/bin"))
    if not prebuilt_candidates:
        raise FileNotFoundError(f"LLVM toolchain bin dir not found under {ndk}")
    ndk_bin = prebuilt_candidates[0]
    clang_name = "aarch64-linux-android33-clang++.cmd" if IS_WIN else "aarch64-linux-android33-clang++"
    clangxx = ndk_bin / clang_name
    if not clangxx.is_file():
        clang_hits = sorted(ndk_bin.glob("aarch64-linux-android*-clang++" + (".cmd" if IS_WIN else "")), reverse=True)
        if not clang_hits:
            raise FileNotFoundError(f"aarch64 clang++ not found under {ndk_bin}")
        clangxx = clang_hits[0]

    llvm_nm = ndk_bin / exe_name("llvm-nm")
    llvm_readelf = ndk_bin / exe_name("llvm-readelf")
    env = dict(os.environ)
    env["JAVA_HOME"] = str(jdk_home)
    env["PATH"] = str(jdk_bin) + os.pathsep + env.get("PATH", "")

    return {
        "javac": javac,
        "android_jar": android_jar,
        "d8": d8,
        "clangxx": clangxx,
        "llvm_nm": llvm_nm,
        "llvm_readelf": llvm_readelf,
        "env": env,
    }


def run(cmd, env=None):
    str_cmd = [str(x) for x in cmd]
    print("+", " ".join(str_cmd))
    subprocess.run(str_cmd, env=env, check=True)


def build_dex(tc: dict, build_dir: pathlib.Path) -> bytes:
    classes_dir = build_dir / "classes"
    dex_dir = build_dir / "dex"
    if classes_dir.exists():
        shutil.rmtree(classes_dir)
    if dex_dir.exists():
        shutil.rmtree(dex_dir)
    classes_dir.mkdir(parents=True, exist_ok=True)
    dex_dir.mkdir(parents=True, exist_ok=True)

    java_files = sorted((ROOT / "java").rglob("*.java"))
    assert java_files, f"No Java source files under {ROOT / 'java'}"

    run(
        [
            tc["javac"],
            "--release",
            "11",
            "-encoding",
            "UTF-8",
            "-Xlint:all",
            "-Werror",
            "-cp",
            tc["android_jar"],
            "-d",
            classes_dir,
            *java_files,
        ],
        env=tc["env"],
    )

    class_files = sorted(classes_dir.rglob("*.class"))
    assert class_files, "javac produced no .class files"

    d8_cmd = ["cmd", "/c", str(tc["d8"])] if IS_WIN and str(tc["d8"]).lower().endswith(".bat") else [str(tc["d8"])]
    d8_cmd.extend(["--min-api", "26", "--release", "--output", str(dex_dir), *[str(p) for p in class_files]])
    run(d8_cmd, env=tc["env"])

    dex_path = dex_dir / "classes.dex"
    assert dex_path.exists(), f"Missing {dex_path}"
    data = dex_path.read_bytes()
    assert data[:4] == b"dex\n", "Invalid DEX magic"
    print(f"Built classes.dex: {len(data)} bytes")
    return data


def write_dex_header(data: bytes, build_dir: pathlib.Path) -> pathlib.Path:
    build_dir.mkdir(parents=True, exist_ok=True)
    hdr = build_dir / "stealth_agent_dex.h"
    lines = [
        "#pragma once",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "inline constexpr uint8_t kStealthAgentDex[] = {",
    ]
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.extend([
        "};",
        "inline constexpr size_t kStealthAgentDexLen = sizeof(kStealthAgentDex);",
        "",
    ])
    hdr.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(f"Wrote {hdr} ({len(data)} bytes)")
    return hdr


def build_so(tc: dict, build_dir: pathlib.Path, oem: str, out_so: pathlib.Path) -> pathlib.Path:
    out_so.parent.mkdir(parents=True, exist_ok=True)
    src_cpp = ROOT / "jni" / "stealth_module.cpp"
    macro = f"-DOEM_{oem.upper()}"

    cmd = ["cmd", "/c", str(tc["clangxx"])] if IS_WIN and str(tc["clangxx"]).lower().endswith(".cmd") else [str(tc["clangxx"])]
    cmd.extend([
        "-std=c++17",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        macro,
        f"-I{build_dir}",
        f"-I{ROOT / 'jni'}",
        "-fvisibility=hidden",
        "-ffunction-sections",
        "-fdata-sections",
        "-static-libstdc++",
        "-fno-exceptions",
        "-fno-rtti",
        "-shared",
        str(src_cpp),
        "-o",
        str(out_so),
        "-llog",
        "-Wl,--gc-sections,-s,--exclude-libs,ALL,--hash-style=both,-z,max-page-size=16384",
    ])
    run(cmd, env=tc["env"])
    print(f"Built {out_so} (oem={oem}): {out_so.stat().st_size} bytes")
    return out_so


def verify_elf(tc: dict, so_path: pathlib.Path):
    nm_res = subprocess.run(
        [str(tc["llvm_nm"]), "--dynamic", "--defined-only", str(so_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    exported = []
    for line in nm_res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("T", "D", "R", "W"):
            exported.append(parts[2])
    expected = {"zygisk_companion_entry", "zygisk_module_entry"}
    if set(exported) != expected:
        raise AssertionError(f"Unexpected exported ELF symbols: {exported} (want {sorted(expected)})")
    print(f"ELF dynamic exports verified: {sorted(exported)}")

    re_res = subprocess.run(
        [str(tc["llvm_readelf"]), "-d", str(so_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    if "TEXTREL" in re_res.stdout:
        raise AssertionError("ELF contains forbidden TEXTREL")
    needed = re.findall(r"Shared library:\s*\[([^\]]+)\]", re_res.stdout)
    allowed_needed = {"liblog.so", "libm.so", "libdl.so", "libc.so"}
    disallowed = [lib for lib in needed if lib not in allowed_needed]
    if disallowed:
        raise AssertionError(f"ELF contains non-system DT_NEEDED entries: {disallowed} (all={needed})")
    print(f"ELF dynamic section verified: zero TEXTREL, DT_NEEDED={needed}")


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build OEM-specialized Zygisk stealth module library")
    p.add_argument("--oem", choices=OEMS, default="generic", help="OEM property specialization profile")
    p.add_argument("--out", help="Output path for compiled arm64-v8a .so")
    p.add_argument("--build-dir", help="Intermediate build directory (defaults to stealth/build)")
    p.add_argument("--skip-dex-if-exists", action="store_true", help="Reuse existing stealth_agent_dex.h in build-dir")
    p.add_argument("--jdk", help="JDK home path (overrides JAVA_HOME)")
    p.add_argument("--sdk", help="Android SDK path (overrides ANDROID_SDK_ROOT / ANDROID_HOME)")
    p.add_argument("--ndk", help="Android NDK path (overrides ANDROID_NDK_HOME / ANDROID_NDK_ROOT)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    tc = resolve_toolchain(args)
    build_dir = pathlib.Path(args.build_dir) if args.build_dir else (ROOT / "build")
    hdr = build_dir / "stealth_agent_dex.h"
    if not (args.skip_dex_if_exists and hdr.is_file()):
        dex = build_dex(tc, build_dir)
        write_dex_header(dex, build_dir)
    out_so = pathlib.Path(args.out) if args.out else (build_dir / f"zygisk-{args.oem}-arm64-v8a.so")
    so_path = build_so(tc, build_dir, args.oem, out_so)
    verify_elf(tc, so_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
