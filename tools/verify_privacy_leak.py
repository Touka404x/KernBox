#!/usr/bin/env python3
"""Open-source privacy, personal-data, legacy-branding, and LF line-ending gatekeeper."""

import argparse
import pathlib
import re
import subprocess
import sys
from typing import List, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Build literal tokens via concatenation so no raw sensitive string exists anywhere in source.
FORBIDDEN_LITERALS: List[Tuple[str, str]] = [
    ("personal_serial", "RWUG" + "XKHUZLHELZGM"),
    ("personal_model", "23054" + "RA19C"),
    ("private_ip_1", "216.23." + "100.6"),
    ("private_ip_2", "217.116." + "174.172"),
    ("local_path_vendor_ws", "Legend" + "SG"),
    ("local_path_user", "Users\\" + "king"),
    ("local_path_user_fwd", "Users/" + "king"),
    ("local_path_cloud", "Android-Cloud-" + "Pixel9Pro"),
    ("legacy_pkg_prefix", "com." + "legend"),
    ("legacy_guard_name", "legend_" + "jp_guard"),
    ("legacy_broker_name", "legend_" + "work_broker"),
    ("legacy_proxy_dir", "legend_" + "proxy"),
    ("legacy_cfg_dir", "legend_" + "work_cfg"),
    ("legacy_sock_dir", "legend_" + "work"),
    ("legacy_chain_lgw", "LGW" + "_"),
    ("legacy_chain_lgp", "LGP" + "_"),
    ("legacy_chain_lgc", "LGC" + "_"),
    ("legacy_stealth_tag", "Legend" + "Stealth"),
    ("legacy_work_tag", "Legend" + "Work"),
    ("legacy_brand_title", "Legend" + " Japan"),
    ("legacy_cn_name", "work-jp-" + "tproxy"),
    ("legacy_pid_field", "legend_" + "pid"),
]

FORBIDDEN_REGEXES: List[Tuple[str, re.Pattern]] = [
    ("private_key_pem", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("win_user_home_path", re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+")),
    ("unix_home_path", re.compile(r"/home/[a-zA-Z0-9._-]+/")),
    ("xiaomi_personal_model", re.compile(r"\b2\d{4}[A-Z]{2}\d{2}[A-Z]\b")),
]

FORBIDDEN_EXTS = {
    ".apk", ".idsig", ".p12", ".jks", ".keystore",
    ".pem", ".crt", ".key", ".der", ".pk8", ".bks",
    ".zip", ".so",
}
LF_REQUIRED_SUFFIXES = (".sh", ".sh.tmpl", ".rule", ".prop.tmpl")


def collect_candidate_files(repo_root: pathlib.Path, mode: str) -> List[pathlib.Path]:
    if mode == "git":
        cmd = ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
        res = subprocess.run(cmd, cwd=repo_root, capture_output=True, check=True)
        rels = [p.decode("utf-8", errors="replace") for p in res.stdout.split(b"\x00") if p]
        return [repo_root / r for r in rels if (repo_root / r).is_file()]
    return [p for p in repo_root.rglob("*") if p.is_file() and ".git" not in p.parts]


def scan_files(repo_root: pathlib.Path, files: List[pathlib.Path]) -> List[str]:
    findings: List[str] = []
    lower_literals = [(label, tok.lower()) for label, tok in FORBIDDEN_LITERALS]
    for fpath in sorted(files):
        rel = fpath.relative_to(repo_root).as_posix()
        low_ext = fpath.suffix.lower()
        if low_ext in FORBIDDEN_EXTS:
            findings.append(f"{rel}: forbidden tracked/non-ignored binary or keystore extension {low_ext}")
            continue
        raw = fpath.read_bytes()
        if any(rel.endswith(suf) for suf in LF_REQUIRED_SUFFIXES):
            if b"\r" in raw:
                findings.append(f"{rel}: contains CR (\\r) byte; UNIX LF line endings required")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            line_low = line.lower()
            for label, tok_low in lower_literals:
                if tok_low in line_low:
                    findings.append(f"{rel}:{lineno}: forbidden literal ({label})")
            for label, rx in FORBIDDEN_REGEXES:
                if rx.search(line):
                    findings.append(f"{rel}:{lineno}: forbidden secret/PII pattern ({label})")
    return findings


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Verify oss-main contains zero private data, legacy branding, or CRLF script errors")
    p.add_argument("--root", type=pathlib.Path, default=REPO_ROOT, help="Repository root to scan")
    p.add_argument("--mode", choices=("git", "walk"), default="git", help="File discovery mode")
    args = p.parse_args(argv)

    root = args.root.resolve()
    files = collect_candidate_files(root, args.mode)
    findings = scan_files(root, files)
    if findings:
        for item in findings:
            print(f"[FAIL] {item}", file=sys.stderr)
        print(f"PRIVACY_CHECK_FAILED findings={len(findings)} scanned={len(files)}", file=sys.stderr)
        return 1
    print(f"PRIVACY_CHECK_PASSED scanned={len(files)} findings=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
