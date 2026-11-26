#!/usr/bin/env python3
"""Builds the full 30-variant KernBox release matrix into dist/."""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "packaging"))
import pack_variant  # noqa: E402

OEMS = ("hyperos", "aosp", "oplus", "oneui", "generic")
KERNEL_ROOT_PAIRS = [
    ("k510", ("ksu", "magisk", "apatch")),
    ("k419", ("ksu_legacy", "magisk", "apatch")),
]


def resolve_go(explicit: str = "") -> str:
    if explicit:
        return explicit
    goroot = os.environ.get("GOROOT", "").strip()
    if goroot:
        cand = pathlib.Path(goroot) / "bin" / ("go.exe" if os.name == "nt" else "go")
        if cand.is_file():
            return str(cand)
    found = shutil.which("go")
    if not found:
        raise RuntimeError("Go compiler not found: pass --go or set GOROOT / PATH")
    return found


def build_go_guard(go_exe: str, oem: str, kernel: str, version: str, stage_dir: pathlib.Path) -> pathlib.Path:
    tags = f"oem_{oem}" if kernel == "k510" else f"oem_{oem},kernel_compat"
    out_dir = stage_dir / "go" / f"{oem}-{kernel}"
    out_dir.mkdir(parents=True, exist_ok=True)
    guard_bin = out_dir / "sandbox_guard"

    env = dict(os.environ)
    env["CGO_ENABLED"] = "0"
    env["GOOS"] = "linux"
    env["GOARCH"] = "arm64"
    env.setdefault("GOTOOLCHAIN", "local")
    ldflags = f"-s -w -X sandbox_guard/internal/buildinfo.Version={version}"

    print(f"[go build] oem={oem} kernel={kernel} version={version} tags={tags}")
    subprocess.run(
        [go_exe, "build", "-trimpath", f"-ldflags={ldflags}", "-tags", tags, "-o", str(guard_bin), "./cmd/guard"],
        cwd=REPO_ROOT / "guard",
        env=env,
        check=True,
    )
    return guard_bin


def build_native_broker(stage_dir: pathlib.Path, args: argparse.Namespace) -> pathlib.Path:
    out_bin = stage_dir / "native" / "sandbox_broker"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "broker" / "build.py"),
        "--out",
        str(out_bin),
    ]
    if args.sdk:
        cmd.extend(["--sdk", args.sdk])
    if args.ndk:
        cmd.extend(["--ndk", args.ndk])
    print("[broker build] static C11 arm64 sandbox_broker")
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    return out_bin


def build_zygisk_oem(oem: str, stage_dir: pathlib.Path, args: argparse.Namespace, skip_dex: bool) -> pathlib.Path:
    out_so = stage_dir / "zygisk" / f"zygisk-{oem}-arm64-v8a.so"
    dex_build_dir = stage_dir / "stealth-build"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "stealth" / "build.py"),
        "--oem",
        oem,
        "--build-dir",
        str(dex_build_dir),
        "--out",
        str(out_so),
    ]
    if skip_dex:
        cmd.append("--skip-dex-if-exists")
    if args.jdk:
        cmd.extend(["--jdk", args.jdk])
    if args.sdk:
        cmd.extend(["--sdk", args.sdk])
    if args.ndk:
        cmd.extend(["--ndk", args.ndk])
    print(f"[stealth build] oem={oem}")
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    return out_so


def build_verify_apk(out_dir: pathlib.Path, args: argparse.Namespace) -> dict:
    apk_path = out_dir / "KernBoxVerify.apk"
    cmd = [sys.executable, str(REPO_ROOT / "verify" / "build-probe.py"), "--out", str(apk_path)]
    if args.jdk:
        cmd.extend(["--jdk", args.jdk])
    if args.sdk:
        cmd.extend(["--sdk", args.sdk])
    print("[verify apk build] building KernBoxVerify.apk")
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    raw = apk_path.read_bytes()
    return {
        "artifact": apk_path.name,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest().lower(),
    }


def build_controller_apk(out_dir: pathlib.Path, args: argparse.Namespace) -> dict:
    apk_path = out_dir / "KernBox.apk"
    cmd = [sys.executable, str(REPO_ROOT / "controller" / "build-controller.py"), "--out", str(apk_path)]
    if args.controller_keystore:
        cmd.extend(["--keystore", args.controller_keystore])
    if args.controller_alias:
        cmd.extend(["--alias", args.controller_alias])
    if args.controller_storepass_env:
        cmd.extend(["--storepass-env", args.controller_storepass_env])
    if args.jdk:
        cmd.extend(["--jdk", args.jdk])
    if args.sdk:
        cmd.extend(["--sdk", args.sdk])
    print("[controller apk build] building KernBox.apk")
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    raw = apk_path.read_bytes()
    return {
        "artifact": apk_path.name,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest().lower(),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Build 30-variant KernBox release matrix")
    p.add_argument("--out", type=pathlib.Path, default=REPO_ROOT / "dist", help="Output distribution directory")
    p.add_argument("--version", default="1.2.0", help="Release version string")
    p.add_argument("--oems", nargs="+", choices=OEMS, default=list(OEMS), help="Subset of OEMs to build")
    p.add_argument("--controller-keystore", default="", help="Optional release keystore for KernBox.apk")
    p.add_argument("--controller-alias", default="kernbox-controller", help="Optional keystore alias for KernBox.apk")
    p.add_argument("--controller-storepass-env", default="", help="Optional env var holding keystore password")
    p.add_argument("--go", default="", help="Path to go executable")
    p.add_argument("--jdk", default="", help="Optional JDK home")
    p.add_argument("--sdk", default="", help="Optional Android SDK root")
    p.add_argument("--ndk", default="", help="Optional Android NDK home")
    args = p.parse_args(argv)

    go_exe = resolve_go(args.go)
    out_dir = args.out.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    stage_dir = out_dir / ".stage"
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    try:
        ctrl_meta = build_controller_apk(out_dir, args)
        apk_meta = build_verify_apk(out_dir, args)
        broker_bin = build_native_broker(stage_dir, args)

        zygisk_map: dict[str, pathlib.Path] = {}
        for idx, oem in enumerate(args.oems):
            zygisk_map[oem] = build_zygisk_oem(oem, stage_dir, args, skip_dex=(idx > 0))

        variants = []
        for oem in args.oems:
            for kernel, roots in KERNEL_ROOT_PAIRS:
                guard_bin = build_go_guard(go_exe, oem, kernel, args.version, stage_dir)
                for root in roots:
                    zip_name = f"KernBox-{oem}-{kernel}-{root}-arm64.zip"
                    meta = pack_variant.pack_variant(
                        oem=oem,
                        kernel=kernel,
                        root=root,
                        version=args.version,
                        guard_bin=guard_bin,
                        broker_bin=broker_bin,
                        zygisk_so=zygisk_map[oem],
                        out_zip=out_dir / zip_name,
                        quiet=False,
                    )
                    variants.append(meta)

        checksum_lines = [f"{m['sha256']}  {m['artifact']}" for m in variants]
        checksum_lines.append(f"{ctrl_meta['sha256']}  {ctrl_meta['artifact']}")
        checksum_lines.append(f"{apk_meta['sha256']}  {apk_meta['artifact']}")
        (out_dir / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8", newline="\n")

        manifest = {
            "schema_version": 1,
            "version": args.version,
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_variants": len(variants),
            "controller_apk": ctrl_meta,
            "verify_apk": apk_meta,
            "variants": variants,
        }
        (out_dir / "variants-manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        print(f"MATRIX_BUILD_COMPLETE total_variants={len(variants)} out={out_dir}")
        return 0
    finally:
        if stage_dir.exists():
            shutil.rmtree(stage_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
