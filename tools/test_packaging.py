import pathlib
import tempfile
import unittest
import zipfile

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGING = REPO_ROOT / "packaging"

import sys
sys.path.insert(0, str(PACKAGING))
import pack_variant  # noqa: E402


class TestPackagingVariants(unittest.TestCase):
    def test_ksu_and_legacy_sepolicy_cover_both_ksu_and_su_domains(self):
        for rule_name in ("ksu.rule", "ksu_legacy.rule"):
            text = (PACKAGING / "sepolicy" / rule_name).read_text(encoding="utf-8")
            for required in (
                "allow ksu sandbox_broker process transition",
                "allow su sandbox_broker process transition",
                "type_transition ksu sandbox_broker_exec process sandbox_broker",
                "type_transition su sandbox_broker_exec process sandbox_broker",
                "allow sandbox_broker su fd use",
                "allow sandbox_broker ksu fd use",
            ):
                self.assertIn(required, text, f"{rule_name} missing: {required}")

    def test_version_to_code_monotonic(self):
        c1 = int(pack_variant.version_to_code("1.1.0"))
        c2 = int(pack_variant.version_to_code("1.1.10"))
        c3 = int(pack_variant.version_to_code("1.2.0"))
        self.assertLess(c1, c2)
        self.assertLess(c2, c3)
        self.assertEqual(c3, 10200)

    def test_pack_variant_emits_unix_lf_and_valid_zip(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            dummy = tmp / "bin"
            dummy.write_bytes(b"\x7fELFdummy")
            out_zip = tmp / "KernBox-test.zip"
            pack_variant.pack_variant(
                oem="hyperos",
                kernel="k510",
                root="ksu",
                version="1.2.0",
                guard_bin=dummy,
                broker_bin=dummy,
                zygisk_so=dummy,
                out_zip=out_zip,
            )
            with zipfile.ZipFile(out_zip) as zf:
                self.assertIsNone(zf.testzip())
                for name in ("service.sh", "post-fs-data.sh", "customize.sh", "action.sh", "uninstall.sh", "sepolicy.rule", "module.prop"):
                    self.assertIn(name, zf.namelist())
                    raw = zf.read(name)
                    self.assertNotIn(b"\r\n", raw, f"CRLF detected in {name}")
                for exec_sh in ("service.sh", "post-fs-data.sh", "customize.sh", "action.sh", "uninstall.sh"):
                    mode = (zf.getinfo(exec_sh).external_attr >> 16) & 0o777
                    self.assertEqual(mode, 0o755, f"{exec_sh} mode={oct(mode)}")
                self.assertIn(b"versionCode=10200\n", zf.read("module.prop"))

                uninstall_sh = zf.read("uninstall.sh").decode("utf-8")
                self.assertIn("ctl start-sandbox", uninstall_sh)
                self.assertNotIn("ctl resume", uninstall_sh)
                self.assertIn("mangle -D POSTROUTING -j SBW_EGRESS", uninstall_sh)
                self.assertIn("mangle:SBW_EGRESS", uninstall_sh)

                action_sh = zf.read("action.sh").decode("utf-8")
                self.assertIn("ctl start-sandbox", action_sh)
                self.assertIn("ctl pause-sandbox", action_sh)
                self.assertNotIn("ctl resume", action_sh)
                self.assertNotIn("ctl pause\n", action_sh)

                customize_sh = zf.read("customize.sh").decode("utf-8")
                for must_exec in ("action.sh", "uninstall.sh", "bin/sandbox_guard", "bin/sandbox_broker"):
                    self.assertIn(must_exec, customize_sh)

                service_sh = zf.read("service.sh").decode("utf-8")
                self.assertIn("9>&- &", service_sh)


if __name__ == "__main__":
    unittest.main()
