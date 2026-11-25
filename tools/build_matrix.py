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


def build_go_pair(go_exe: str, oem: str, kernel: str, stage_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    tags = f"oem_{oem}" if kernel == "k510" else f"oem_{oem},kernel_compat"
    out_dir = stage_dir / "go" / f"{oem}-{kernel}"
    out_dir.mkdir(parents=True, exist_ok=True)
    guard_bin = out_dir / "sandbox_guard"
    broker_bin = out_dir / "sandbox_broker"

    env = dict(os.environ)
    env["CGO_ENABLED"] = "0"
    env["GOOS"] = "linux"
    env["GOARCH"] = "arm64"
    env.setdefault("GOTOOLCHAIN", "local")

    print(f"[go build] oem={oem} kernel={kernel} tags={tags}")
    subprocess.run(
        [go_exe, "build", "-trimpath", "-ldflags=-s -w", "-tags", tags, "-o", str(guard_bin), "./cmd/guard"],
        cwd=REPO_ROOT / "guard",
        env=env,
        check=True,
    )
    subprocess.run(
        [go_exe, "build", "-trimpath", "-ldflags=-s -w", "-tags", tags, "-o", str(broker_bin), "./cmd/broker"],
        cwd=REPO_ROOT / "guard",
        env=env,
        check=True,
    )
    return guard_bin, broker_bin


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


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Build 30-variant KernBox release matrix")
    p.add_argument("--out", type=pathlib.Path, default=REPO_ROOT / "dist", help="Output distribution directory")
    p.add_argument("--version", default="1.0.0", help="Release version string")
    p.add_argument("--oems", nargs="+", choices=OEMS, default=list(OEMS), help="Subset of OEMs to build")
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
        apk_meta = build_verify_apk(out_dir, args)

        zygisk_map: dict[str, pathlib.Path] = {}
        for idx, oem in enumerate(args.oems):
            zygisk_map[oem] = build_zygisk_oem(oem, stage_dir, args, skip_dex=(idx > 0))

        variants = []
        for oem in args.oems:
            for kernel, roots in KERNEL_ROOT_PAIRS:
                guard_bin, broker_bin = build_go_pair(go_exe, oem, kernel, stage_dir)
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
        checksum_lines.append(f"{apk_meta['sha256']}  {apk_meta['artifact']}")
        (out_dir / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8", newline="\n")

        manifest = {
            "schema_version": 1,
            "version": args.version,
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_variants": len(variants),
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
