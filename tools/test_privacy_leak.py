import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import verify_privacy_leak as vpl


class PrivacyLeakScannerTests(unittest.TestCase):
    def test_clean_repo_passes(self):
        files = vpl.collect_candidate_files(vpl.REPO_ROOT, "git")
        findings = vpl.scan_files(vpl.REPO_ROOT, files)
        self.assertEqual(findings, [], f"Unexpected findings in repo: {findings}")

    def test_detects_sensitive_literals_paths_keys_and_crlf(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "a.txt").write_text("device=" + "23054" + "RA19C" + "\n", encoding="utf-8")
            (root / "b.go").write_text('const p = "COM.' + 'LEGEND.work"\n', encoding="utf-8")
            (root / "c.md").write_text("path=" + "C:\\Use" + "rs\\alice\\work\\file\n", encoding="utf-8")
            (root / "d.md").write_text("unix=/ho" + "me/developer/src\n", encoding="utf-8")
            (root / "k.pem").write_text("-----BEGIN RSA " + "PRIVATE KEY-----\nabc\n", encoding="utf-8")
            (root / "cert.crt").write_text("cert\n", encoding="utf-8")
            (root / "module.prop.tmpl").write_bytes(b"id=sandbox_guard\r\n")
            (root / "s.sh").write_bytes(b"#!/bin/sh\r\necho hi\r\n")
            (root / "app.apk").write_bytes(b"PK\x03\x04")
            files = vpl.collect_candidate_files(root, "walk")
            findings = vpl.scan_files(root, files)
            joined = "\n".join(findings)
            self.assertIn("personal_model", joined)
            self.assertIn("legacy_pkg_prefix", joined)
            self.assertIn("win_user_home_path", joined)
            self.assertIn("unix_home_path", joined)
            self.assertIn(".pem", joined)
            self.assertIn(".crt", joined)
            self.assertIn("module.prop.tmpl", joined)
            self.assertIn("s.sh", joined)
            self.assertIn(".apk", joined)


if __name__ == "__main__":
    unittest.main()
