#!/usr/bin/env python3
"""Builds the standalone pure-Java KernBoxVerify.apk (zero tracked keystores)."""

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from zipfile import ZipFile

SOURCE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = SOURCE.parent
IS_WIN = os.name == "nt"


def exe_name(base: str, win_ext: str = ".exe") -> str:
    return f"{base}{win_ext}" if IS_WIN else base


def resolve_toolchain(args: argparse.Namespace) -> dict:
    jdk_str = args.jdk or os.environ.get("JAVA_HOME") or ""
    if not jdk_str:
        javac_on_path = shutil.which("javac")
        if javac_on_path:
            jdk_str = str(pathlib.Path(javac_on_path).resolve().parent.parent)
    if not jdk_str:
        raise RuntimeError("Missing JDK: pass --jdk or set JAVA_HOME")
    jdk = pathlib.Path(jdk_str)
    jdk_bin = jdk / "bin"

    sdk_str = args.sdk or os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") or ""
    if not sdk_str:
        raise RuntimeError("Missing Android SDK: pass --sdk or set ANDROID_SDK_ROOT / ANDROID_HOME")
    sdk = pathlib.Path(sdk_str)

    platform = sdk / "platforms" / "android-35" / "android.jar"
    if not platform.is_file():
        hits = sorted((sdk / "platforms").glob("android-*/android.jar"), reverse=True)
        if not hits:
            raise FileNotFoundError(f"No android.jar found under {sdk / 'platforms'}")
        platform = hits[0]

    tools_dir = sdk / "build-tools" / "35.0.0"
    if not tools_dir.is_dir():
        bt_dirs = sorted((sdk / "build-tools").iterdir(), reverse=True)
        if not bt_dirs:
            raise FileNotFoundError(f"No build-tools found under {sdk / 'build-tools'}")
        tools_dir = bt_dirs[0]

    env = dict(os.environ)
    env["JAVA_HOME"] = str(jdk)
    env["PATH"] = str(jdk_bin) + os.pathsep + env.get("PATH", "")

    return {
        "javac": jdk_bin / exe_name("javac"),
        "keytool": jdk_bin / exe_name("keytool"),
        "platform": platform,
        "d8": tools_dir / exe_name("d8", ".bat"),
        "aapt": tools_dir / exe_name("aapt"),
        "zipalign": tools_dir / exe_name("zipalign"),
        "apksigner": tools_dir / exe_name("apksigner", ".bat"),
        "env": env,
    }


def run_cmd(tc: dict, *arguments):
    str_args = [str(v) for v in arguments]
    if IS_WIN and str_args[0].lower().endswith(".bat"):
        str_args = ["cmd", "/c", *str_args]
    subprocess.run(str_args, env=tc["env"], check=True)


def build_apk(args: argparse.Namespace) -> pathlib.Path:
    tc = resolve_toolchain(args)
    output = pathlib.Path(args.out) if args.out else (REPO_ROOT / "dist" / "KernBoxVerify.apk")
    output.parent.mkdir(parents=True, exist_ok=True)

    java_sources = sorted(SOURCE.glob("*.java"))
    if not java_sources:
        raise RuntimeError(f"No .java sources found in {SOURCE}")

    with TemporaryDirectory(prefix="sandbox-verify-probe-") as tmp:
        staging = pathlib.Path(tmp)
        key = pathlib.Path(args.keystore) if args.keystore else (staging / "ephemeral-debug.p12")
        alias = args.alias
        storepass = args.storepass
        if not args.keystore:
            run_cmd(
                tc,
                tc["keytool"],
                "-genkeypair",
                "-alias",
                alias,
                "-keystore",
                key,
                "-storetype",
                "PKCS12",
                "-storepass",
                storepass,
                "-dname",
                "CN=Sandbox Verify Probe",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "365",
            )

        classes = staging / "classes"
        classes.mkdir()
        run_cmd(
            tc,
            tc["javac"],
            "--release",
            "8",
            "-encoding",
            "UTF-8",
            "-classpath",
            tc["platform"],
            "-d",
            classes,
            *java_sources,
        )

        jar = staging / "classes.jar"
        with ZipFile(jar, "w") as archive:
            for compiled in classes.rglob("*.class"):
                archive.write(compiled, compiled.relative_to(classes).as_posix())

        run_cmd(tc, tc["d8"], "--min-api", "26", "--lib", tc["platform"], "--output", staging, jar)
        unsigned = staging / "unsigned.apk"
        run_cmd(tc, tc["aapt"], "package", "-f", "-M", SOURCE / "AndroidManifest.xml", "-I", tc["platform"], "-F", unsigned)
        with ZipFile(unsigned, "a") as archive:
            archive.write(staging / "classes.dex", "classes.dex")

        aligned = staging / "aligned.apk"
        run_cmd(tc, tc["zipalign"], "-f", "4", unsigned, aligned)
        run_cmd(
            tc,
            tc["apksigner"],
            "sign",
            "--ks",
            key,
            "--ks-key-alias",
            alias,
            "--ks-pass",
            f"pass:{storepass}",
            "--out",
            output,
            aligned,
        )

    run_cmd(tc, tc["apksigner"], "verify", "--print-certs", output)
    run_cmd(tc, tc["aapt"], "dump", "badging", output)
    print(f"BUILT_APK={output} SIZE={output.stat().st_size}")
    return output


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Build KernBoxVerify.apk")
    p.add_argument("--out", help="Output APK path (default: dist/KernBoxVerify.apk)")
    p.add_argument("--keystore", help="Optional PKCS12/JKS release keystore path (ephemeral debug key if omitted)")
    p.add_argument("--alias", default="sandbox-verify-probe", help="Keystore key alias")
    p.add_argument("--storepass", default="android", help="Keystore password")
    p.add_argument("--jdk", help="JDK home path (overrides JAVA_HOME)")
    p.add_argument("--sdk", help="Android SDK path (overrides ANDROID_SDK_ROOT)")
    args = p.parse_args(argv)
    build_apk(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
