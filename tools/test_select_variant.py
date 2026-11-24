import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build_matrix as bm
import select_variant as sv


def base_profile(**overrides):
    p = {
        "schema_version": 1,
        "manufacturer": "Google",
        "brand": "google",
        "android_sdk": 35,
        "android_release": "15",
        "cpu_abi": "arm64-v8a",
        "kernel_release": "6.1.75-android14-11",
        "kernel_major": 6,
        "kernel_minor": 1,
        "oem_signals": {
            "miui_ui_version": "",
            "hyperos_version": "",
            "oplusrom": "",
            "oneui": "",
            "build_flavor": "husky-user",
        },
        "root_manager": "ksu",
        "root_version": "0.9.5",
        "zygisk_detected": True,
        "cgroup_v2_freeze": True,
        "tproxy_capable": True,
        "work_profile_users": [10],
        "existing_guard_installed": False,
    }
    for k, v in overrides.items():
        if k == "oem_signals":
            p["oem_signals"].update(v)
        else:
            p[k] = v
    return p


class SelectVariantTests(unittest.TestCase):
    def test_hyperos_k510_ksu(self):
        p = base_profile(
            manufacturer="Xiaomi", brand="Redmi",
            oem_signals={"hyperos_version": "OS1.0", "build_flavor": "corot-user"},
        )
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["artifact"], "SandboxGuard-hyperos-k510-ksu-arm64.zip")

    def test_miui_poco_k419_ksu_legacy(self):
        p = base_profile(
            manufacturer="Xiaomi", brand="POCO",
            android_sdk=31, android_release="12",
            kernel_release="4.19.157-perf", kernel_major=4, kernel_minor=19,
            cgroup_v2_freeze=False,
            oem_signals={"miui_ui_version": "V130", "build_flavor": "alioth-user"},
            root_manager="ksu", root_version="0.8.1",
        )
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["artifact"], "SandboxGuard-hyperos-k419-ksu_legacy-arm64.zip")

    def test_custom_aosp_rom_on_xiaomi_hardware_selects_aosp(self):
        p = base_profile(
            manufacturer="Xiaomi", brand="Xiaomi",
            oem_signals={"miui_ui_version": "", "hyperos_version": "", "build_flavor": "lineage_munch-userdebug"},
        )
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["oem"], "aosp")
        self.assertEqual(r["artifact"], "SandboxGuard-aosp-k510-ksu-arm64.zip")

    def test_oplus_oneplus_k510_apatch(self):
        p = base_profile(
            manufacturer="OnePlus", brand="OnePlus",
            oem_signals={"oplusrom": "V14.1.0", "build_flavor": "waffle-user"},
            root_manager="apatch", root_version="10763",
        )
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["artifact"], "SandboxGuard-oplus-k510-apatch-arm64.zip")
        self.assertIn("apd module install", r["commands"]["install"])

    def test_oplus_oppo_k419_magisk(self):
        p = base_profile(
            manufacturer="OPPO", brand="OPPO",
            kernel_release="5.4.210", kernel_major=5, kernel_minor=4,
            cgroup_v2_freeze=False,
            oem_signals={"oplusrom": "V13.1"},
            root_manager="magisk", root_version="27.0:MAGISK",
        )
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["artifact"], "SandboxGuard-oplus-k419-magisk-arm64.zip")
        self.assertIn("magisk --install-module", r["commands"]["install"])

    def test_oneui_samsung_k510_magisk(self):
        p = base_profile(
            manufacturer="samsung", brand="samsung",
            oem_signals={"oneui": "60101", "build_flavor": "dm3q-user"},
            root_manager="magisk",
        )
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["artifact"], "SandboxGuard-oneui-k510-magisk-arm64.zip")

    def test_aosp_pixel_k510_ksu(self):
        p = base_profile()
        r = sv.select_variant(p, preset="jp-docomo")
        self.assertTrue(r["ok"])
        self.assertEqual(r["artifact"], "SandboxGuard-aosp-k510-ksu-arm64.zip")
        self.assertIn("preset-apply", r["commands"]["preset_apply"])

    def test_aosp_lineage_flavor_detection(self):
        p = base_profile(
            manufacturer="Motorola", brand="motorola",
            oem_signals={"build_flavor": "lineage_devon-userdebug"},
        )
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["oem"], "aosp")

    def test_unknown_oem_falls_back_to_generic(self):
        p = base_profile(
            manufacturer="Nothing", brand="Nothing",
            oem_signals={"build_flavor": "Tetris-user"},
        )
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["oem"], "generic")
        self.assertEqual(r["artifact"], "SandboxGuard-generic-k510-ksu-arm64.zip")

    def test_510_without_cgroupv2_uses_k419_compat(self):
        p = base_profile(
            kernel_release="5.10.168", kernel_major=5, kernel_minor=10,
            cgroup_v2_freeze=False,
        )
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["kernel"], "k419")
        self.assertEqual(r["root"], "ksu_legacy")

    def test_ksu_sub_09_on_k510_maps_to_valid_k419_ksu_legacy_matrix_artifact(self):
        p = base_profile(root_manager="ksu", root_version="0.7.6")
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["kernel"], "k419")
        self.assertEqual(r["root"], "ksu_legacy")
        self.assertEqual(r["artifact"], "SandboxGuard-aosp-k419-ksu_legacy-arm64.zip")

    def test_all_valid_selections_match_build_matrix(self):
        matrix_set = {
            f"SandboxGuard-{oem}-{kernel}-{root}-arm64.zip"
            for oem in bm.OEMS
            for kernel, roots in bm.KERNEL_ROOT_PAIRS
            for root in roots
        }
        self.assertEqual(len(matrix_set), 30)
        for brand, sigs in [
            ("Xiaomi", {"hyperos_version": "OS2"}),
            ("Google", {}),
            ("OnePlus", {"oplusrom": "V14"}),
            ("samsung", {"oneui": "60101"}),
            ("Nothing", {}),
        ]:
            for cg2 in (True, False):
                for rmgr, rver in (("ksu", "1.0.2"), ("ksu", "0.7.6"), ("magisk", "27.0"), ("apatch", "10763")):
                    p = base_profile(
                        brand=brand, manufacturer=brand,
                        oem_signals=sigs, cgroup_v2_freeze=cg2,
                        root_manager=rmgr, root_version=rver,
                    )
                    r = sv.select_variant(p)
                    self.assertTrue(r["ok"], r)
                    self.assertIn(r["artifact"], matrix_set)

    def test_reject_non_arm64(self):
        p = base_profile(cpu_abi="armeabi-v7a")
        r = sv.select_variant(p)
        self.assertFalse(r["ok"])
        self.assertIsNone(r["artifact"])
        self.assertTrue(any("arm64-v8a" in e for e in r["errors"]))

    def test_reject_sdk_below_31(self):
        p = base_profile(android_sdk=30, android_release="11")
        r = sv.select_variant(p)
        self.assertFalse(r["ok"])
        self.assertTrue(any("API 31+" in e for e in r["errors"]))

    def test_reject_missing_root(self):
        p = base_profile(root_manager="none")
        r = sv.select_variant(p)
        self.assertFalse(r["ok"])
        self.assertTrue(any("root manager" in e.lower() for e in r["errors"]))

    def test_missing_zygisk_emits_warning_not_error(self):
        p = base_profile(zygisk_detected=False)
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertTrue(any("ZygiskNext" in w for w in r["warnings"]))

    def test_missing_tproxy_emits_warning(self):
        p = base_profile(tproxy_capable=False)
        r = sv.select_variant(p)
        self.assertTrue(r["ok"])
        self.assertTrue(any("TProxy" in w for w in r["warnings"]))


if __name__ == "__main__":
    unittest.main()
