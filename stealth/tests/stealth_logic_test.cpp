#include "../jni/stealth_logic.hpp"

#include <cassert>
#include <iostream>
#include <string>

int main() {
    // 1. Neutral defaults / empty / disabled configs
    {
        auto empty = stealth::parseStealthConfig("");
        assert(!empty.enabled);
        assert(empty.timezone == "UTC");
        assert(empty.locale == "en-US");
        assert(empty.sim_operator.empty());
        assert(empty.sim_operator_name.empty());
        assert(empty.sim_country_iso.empty());
        assert(!empty.spoof_carrier);
        assert(!empty.spoof_device_region);
        assert(empty.device_region.empty());
        assert(empty.boot_hwc.empty());
        assert(!stealth::shouldSpoofAppUid(empty, 1010377));

        char out[192];
        assert(!stealth::lookupSpoofedProperty(empty, "gsm.sim.operator.numeric", "46002", out, sizeof(out)));
    }

    // 2. Active sandbox config parsing + UID filter
    {
        const char* json = R"({
            "enabled": true,
            "sandbox_user_id": 10,
            "exempt_work_uid": 1010376,
            "exempt_uids": [1010076, 1010376],
            "timezone": "Asia/Tokyo",
            "locale": "ja-JP",
            "sim_operator": "44010",
            "sim_operator_name": "NTT DOCOMO",
            "sim_country_iso": "jp",
            "prop_hook_mode": "plt",
            "spoof_carrier": true,
            "spoof_timezone": true,
            "spoof_locale": true
        })";
        auto cfg = stealth::parseStealthConfig(json);
        assert(cfg.enabled);
        assert(cfg.sandbox_user_id == 10);
        assert(cfg.exempt_work_uid == 1010376);
        assert(cfg.exempt_uids.size() == 2 && cfg.exempt_uids[0] == 1010076);
        assert(cfg.timezone == "Asia/Tokyo");
        assert(cfg.locale == "ja-JP");
        assert(cfg.sim_operator == "44010");
        assert(cfg.network_operator == "44010");
        assert(cfg.network_country_iso == "jp");

        assert(!stealth::shouldSpoofAppUid(cfg, 10377));     // User 0
        assert(!stealth::shouldSpoofAppUid(cfg, 1001));      // Phone
        assert(!stealth::shouldSpoofAppUid(cfg, 1001000));   // User 10 system uid
        assert(!stealth::shouldSpoofAppUid(cfg, 1010376));   // Exempt work bridge UID
        assert(!stealth::shouldSpoofAppUid(cfg, 1010076));   // Exempt managedprovisioning UID
        assert(stealth::shouldSpoofAppUid(cfg, 1099211));    // User 10 isolated renderer must also spoof
        assert(!stealth::shouldSpoofAppUid(cfg, 99910123));  // Dual clone user 999
        assert(stealth::shouldSpoofAppUid(cfg, 1010377));    // Verify probe / regular app
        assert(stealth::shouldSpoofAppUid(cfg, 1010122));    // GMS in User 10
    }

    // 3. Multi-SIM formatting
    {
        char mbuf[64];
        assert(stealth::formatMultiSimIntoBuf("", "44010", mbuf, sizeof(mbuf)) && std::string(mbuf) == "44010");
        assert(stealth::formatMultiSimIntoBuf("46002", "44010", mbuf, sizeof(mbuf)) && std::string(mbuf) == "44010");
        assert(stealth::formatMultiSimIntoBuf("46002,46000", "44010", mbuf, sizeof(mbuf)) && std::string(mbuf) == "44010,44010");
        assert(stealth::formatMultiSimIntoBuf(",46002", "44010", mbuf, sizeof(mbuf)) && std::string(mbuf) == ",44010");
        assert(stealth::formatMultiSimIntoBuf("46002,", "44010", mbuf, sizeof(mbuf)) && std::string(mbuf) == "44010,");
        assert(stealth::formatMultiSimIntoBuf(",", "jp", mbuf, sizeof(mbuf)) && std::string(mbuf) == ",");
    }

    // 4. Property lookup whitelist + passthrough
    {
        auto cfg = stealth::parseStealthConfig(
            R"({"enabled":true,"timezone":"Asia/Tokyo","locale":"ja-JP","spoof_carrier":true,"sim_operator":"44010","sim_country_iso":"jp","sim_operator_name":"NTT DOCOMO"})");
        char out[192];
        assert(stealth::lookupSpoofedProperty(cfg, "persist.sys.timezone", "Asia/Shanghai", out, sizeof(out)) && std::string(out) == "Asia/Tokyo");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.sim.operator.numeric", "46002,", out, sizeof(out)) && std::string(out) == "44010,");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.sim.operator.iso-country", "cn,cn", out, sizeof(out)) && std::string(out) == "jp,jp");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.sim.operator.alpha", "CarrierA", out, sizeof(out)) && std::string(out) == "NTT DOCOMO");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.operator.numeric", "46002", out, sizeof(out)) && std::string(out) == "44010");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.operator.iso-country", ",cn", out, sizeof(out)) && std::string(out) == ",jp");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.operator.alpha", "CarrierB", out, sizeof(out)) && std::string(out) == "NTT DOCOMO");
        assert(!stealth::lookupSpoofedProperty(cfg, "ro.product.model", "GenericPhone", out, sizeof(out)));
        assert(stealth::lookupSpoofedProperty(cfg, "persist.sys.locale", "zh-CN", out, sizeof(out)) && std::string(out) == "ja-JP");
        assert(stealth::lookupSpoofedProperty(cfg, "ro.product.locale", "zh-CN", out, sizeof(out)) && std::string(out) == "ja-JP");

        auto no_loc = stealth::parseStealthConfig(
            R"({"enabled":true,"locale":"ja-JP","spoof_locale":false})");
        assert(!stealth::lookupSpoofedProperty(no_loc, "persist.sys.locale", "zh-CN", out, sizeof(out)));
        assert(!stealth::lookupSpoofedProperty(no_loc, "ro.product.locale", "zh-CN", out, sizeof(out)));
    }

    // 5. Zero-allocation pre-baked property buffer fast path
    {
        auto cfg = stealth::parseStealthConfig(
            R"({"enabled":true,"timezone":"Asia/Tokyo","locale":"ja-JP","spoof_carrier":true,"sim_operator":"44010","sim_country_iso":"jp","sim_operator_name":"NTT DOCOMO"})");
        auto baked = stealth::bakeSpoofedProps(cfg);
        char stack_buf[192];
        const char* res = nullptr;

        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "persist.sys.timezone", "Asia/Shanghai", stack_buf, sizeof(stack_buf), &res));
        assert(std::string(res) == "Asia/Tokyo");
        assert(res == baked.values[0]); // exact zero-copy pointer reuse

        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "gsm.sim.operator.numeric", "46002,46000", stack_buf, sizeof(stack_buf), &res));
        assert(std::string(res) == "44010,44010");
        assert(res == stack_buf);

        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "gsm.sim.state", "ABSENT", stack_buf, sizeof(stack_buf), &res));
        assert(std::string(res) == "READY");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "gsm.sim.state", "ABSENT,NOT_READY", stack_buf, sizeof(stack_buf), &res));
        assert(std::string(res) == "READY,READY");

        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.build.fingerprint", "foo", stack_buf, sizeof(stack_buf), &res));
    }

    // 6. Anti-linkage network config & strict zero-alloc IPv4 octet parser
    {
        auto def_cfg = stealth::parseStealthConfig(R"({"enabled":true})");
        assert(def_cfg.sanitize_network);
        assert(def_cfg.sandbox_link_ipv4 == "10.172.10.2");

        auto custom_cfg = stealth::parseStealthConfig(
            R"({"enabled":true,"sanitize_network":false,"sandbox_link_ipv4":"10.172.88.5"})");
        assert(!custom_cfg.sanitize_network);
        assert(custom_cfg.sandbox_link_ipv4 == "10.172.88.5");

        uint8_t oct[4] = {};
        assert(stealth::parseIPv4Octets("10.172.10.2", oct));
        assert(oct[0] == 10 && oct[1] == 172 && oct[2] == 10 && oct[3] == 2);
        assert(stealth::parseIPv4Octets(" 192.168.0.1 ", oct));
        assert(oct[0] == 192 && oct[1] == 168 && oct[2] == 0 && oct[3] == 1);

        assert(!stealth::parseIPv4Octets("", oct));
        assert(!stealth::parseIPv4Octets("256.0.0.1", oct));
        assert(!stealth::parseIPv4Octets("010.1.1.1", oct));
        assert(!stealth::parseIPv4Octets("1.2.3", oct));
        assert(!stealth::parseIPv4Octets("1.2.3.4.5", oct));
    }

    // 7. Compile-time OEM specialized device region & locale properties
    {
        assert(stealth::kMaxBakedValueBytes == 92);

        auto legacy_alias = stealth::parseStealthConfig(
            R"({"enabled":true,"spoof_device_region":true,"miui_region":"US","boot_hwc":"Global"})");
        assert(legacy_alias.spoof_device_region);
        assert(legacy_alias.device_region == "US");
        assert(legacy_alias.boot_hwc == "Global");

        auto override_cfg = stealth::parseStealthConfig(
            R"({"enabled":true,"spoof_device_region":true,"miui_region":"US","device_region":"DE","locale":"de-DE"})");
        assert(override_cfg.device_region == "DE");

        auto cfg_clean = stealth::parseStealthConfig(
            R"({"enabled":true,"spoof_device_region":true,"locale":"ja-JP","device_region":"JP","boot_hwc":"JP"})");
        auto baked = stealth::bakeSpoofedProps(cfg_clean);
        char stack_buf[92];
        const char* res = nullptr;

        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "persist.sys.country", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "persist.sys.language", "zh", stack_buf, sizeof(stack_buf), &res));
        assert(std::string(res) == "ja");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.boot.hwcountry", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(std::string(res) == "JP");

#if defined(OEM_HYPEROS)
        assert(std::string(stealth::kOemProfileName) == "hyperos");
        assert(stealth::kBakedPropCount == 22);
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.boot.hwc", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.region", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.cust_variant", "cn", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "jp");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.build.region", "cn", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "jp");
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.oplus.region", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.country_code", "CN", stack_buf, sizeof(stack_buf), &res));
#elif defined(OEM_OPLUS)
        assert(std::string(stealth::kOemProfileName) == "oplus");
        assert(stealth::kBakedPropCount == 22);
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "persist.sys.oplus.region", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.oplus.region", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.vendor.oplus.regionmark", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "persist.sys.oppo.region", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.region", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.country_code", "CN", stack_buf, sizeof(stack_buf), &res));
#elif defined(OEM_ONEUI)
        assert(std::string(stealth::kOemProfileName) == "oneui");
        assert(stealth::kBakedPropCount == 23);
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.country_code", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.countryiso_code", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.sales_code", "CHN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.omcnw_code", "CHN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "persist.omc.sales_code", "CHN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.region", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.oplus.region", "CN", stack_buf, sizeof(stack_buf), &res));
#else
        assert(stealth::kBakedPropCount == 18);
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.region", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.oplus.region", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.country_code", "CN", stack_buf, sizeof(stack_buf), &res));
#endif

        auto disabled_region = stealth::parseStealthConfig(
            R"({"enabled":true,"spoof_device_region":false,"device_region":"US","boot_hwc":"Global"})");
        auto baked_off = stealth::bakeSpoofedProps(disabled_region);
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked_off, "ro.boot.hwcountry", "CN", stack_buf, sizeof(stack_buf), &res));
    }

    // 8. Isolated UIDs, string-embedded JSON safety, overflow fallback, and last-wins escape decoding
    {
        const char* sneaky_json =
            R"({"sandbox_user_id":10,"sim_operator_name":"Carrier\",\"enabled\":false,\"locale\":\"zh-CN\"",)"
            R"("enabled":true,"locale":"ja-JP","device_region":"JP","boot_hwc":"JP","spoof_carrier":true,"sim_operator":"44010"})";
        auto cfg = stealth::parseStealthConfig(sneaky_json);
        assert(cfg.enabled);
        assert(cfg.locale == "ja-JP");
        assert(cfg.sim_operator_name == R"(Carrier","enabled":false,"locale":"zh-CN")");
        assert(stealth::shouldSpoofAppUid(cfg, 1099001));
        assert(!stealth::shouldSpoofAppUid(cfg, 99001));

        auto baked = stealth::bakeSpoofedProps(cfg);
        char tiny_buf[6];
        const char* ov_res = nullptr;
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "gsm.sim.operator.numeric", "46000,46001", tiny_buf, sizeof(tiny_buf), &ov_res));
        assert(ov_res == baked.values[1]);
        assert(std::string(ov_res) == "44010");

        auto dup_cfg = stealth::parseStealthConfig(
            R"({"enabled":false,"sim_operator_name":"NTT\u0020DOCOMO\u0026Co","enabled":true,"nested":{"enabled":false}})");
        assert(dup_cfg.enabled);
        assert(dup_cfg.sim_operator_name == "NTT DOCOMO&Co");
    }

    // 9. ADB/USB stealth properties, gsm.network.type multi-SIM, and full OEM slot round-trip
    {
        for (int i = 0; i < static_cast<int>(stealth::kBakedPropCount); i++) {
            const char* pname = stealth::spoofablePropNameByIndex(i);
            assert(pname != nullptr);
            assert(stealth::spoofablePropIndex(pname) == i);
        }

        auto cfg = stealth::parseStealthConfig(
            R"({"enabled":true,"spoof_carrier":true,"sim_operator":"44010","locale":"ja-JP","device_region":"JP","boot_hwc":"JP"})");
        assert(cfg.hide_adb);
        auto baked = stealth::bakeSpoofedProps(cfg);
        char stack_buf[92];
        const char* res = nullptr;

        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "init.svc.adbd", "running", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "stopped");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "sys.usb.state", "adb", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "none");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "sys.usb.config", "adb", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "none");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "persist.sys.usb.config", "adb", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "none");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "gsm.network.type", "NR_NSA,LTE", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "LTE,LTE");

        auto no_adb = stealth::parseStealthConfig(R"({"enabled":true,"hide_adb":false})");
        assert(!no_adb.hide_adb);
        auto baked_no_adb = stealth::bakeSpoofedProps(no_adb);
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked_no_adb, "init.svc.adbd", "running", stack_buf, sizeof(stack_buf), &res));
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked_no_adb, "sys.usb.state", "adb", stack_buf, sizeof(stack_buf), &res));
    }

    // 10. /proc/*/maps & smaps sanitization helpers
    {
        bool is_smaps = true;
        assert(stealth::isSanitizedProcMapsPath("/proc/self/maps", &is_smaps) && !is_smaps);
        assert(stealth::isSanitizedProcMapsPath("/proc/thread-self/maps", &is_smaps) && !is_smaps);
        assert(stealth::isSanitizedProcMapsPath("/proc/15423/maps", &is_smaps) && !is_smaps);
        assert(stealth::isSanitizedProcMapsPath("/proc/self/smaps", &is_smaps) && is_smaps);
        assert(stealth::isSanitizedProcMapsPath("/proc/thread-self/smaps", &is_smaps) && is_smaps);
        assert(stealth::isSanitizedProcMapsPath("/proc/99/smaps", &is_smaps) && is_smaps);

        assert(!stealth::isSanitizedProcMapsPath(nullptr, &is_smaps));
        assert(!stealth::isSanitizedProcMapsPath("/proc/self/mountinfo", &is_smaps));
        assert(!stealth::isSanitizedProcMapsPath("/proc/self/status", &is_smaps));
        assert(!stealth::isSanitizedProcMapsPath("/proc/maps", &is_smaps));
        assert(!stealth::isSanitizedProcMapsPath("/proc/abc/maps", &is_smaps));
        assert(!stealth::isSanitizedProcMapsPath("/data/self/maps", &is_smaps));
        assert(!stealth::isSanitizedProcMapsPath("/proc/self/maps/extra", &is_smaps));

        const char* hdr1 = "311f744000-311f768000 r--p 00000000 fe:2f 1998962  /data/adb/modules/sandbox_guard/zygisk/arm64-v8a.so (deleted)\n";
        const char* hdr2 = "311fd86000-311fec1000 r-xp 00000000 fe:2f 2301169  /data/adb/modules/zygisksu/lib64/libzygisk.so\n";
        const char* attr1 = "Size:                144 kB\n";
        const char* attr2 = "VmFlags: rd ex mr mw me dw\n";
        assert(stealth::isSmapsHeaderLine(hdr1, std::strlen(hdr1)));
        assert(stealth::isSmapsHeaderLine(hdr2, std::strlen(hdr2)));
        assert(!stealth::isSmapsHeaderLine(attr1, std::strlen(attr1)));
        assert(!stealth::isSmapsHeaderLine(attr2, std::strlen(attr2)));

        assert(stealth::shouldHideProcMapsLine(hdr1, std::strlen(hdr1)));
        assert(stealth::shouldHideProcMapsLine(hdr2, std::strlen(hdr2)));
        const char* mixed = "7000-8000 r-xp 0000 00:00 0 /memfd:LSPosed-dex\n";
        assert(stealth::shouldHideProcMapsLine(mixed, std::strlen(mixed)));

        const char* safe1 = "7f80000000-7f80100000 r-xp 00000000 fd:00 123 /system/lib64/libc.so\n";
        const char* safe2 = "7f90000000-7f90100000 r-xp 00000000 00:00 0 /memfd:jit-cache (deleted)\n";
        const char* safe3 = "7fa0000000-7fa0100000 r--p 00000000 fd:01 456 /apex/com.android.art/lib64/libart.so\n";
        assert(!stealth::shouldHideProcMapsLine(safe1, std::strlen(safe1)));
        assert(!stealth::shouldHideProcMapsLine(safe2, std::strlen(safe2)));
        assert(!stealth::shouldHideProcMapsLine(safe3, std::strlen(safe3)));
    }

    // 11. parseMccMnc 5-digit & 6-digit validation
    {
        int mcc = 0, mnc = 0;
        assert(stealth::parseMccMnc("44010", mcc, mnc) && mcc == 440 && mnc == 10);
        assert(stealth::parseMccMnc("310260", mcc, mnc) && mcc == 310 && mnc == 260);
        assert(stealth::parseMccMnc("23430", mcc, mnc) && mcc == 234 && mnc == 30);
        assert(!stealth::parseMccMnc(nullptr, mcc, mnc));
        assert(!stealth::parseMccMnc("", mcc, mnc));
        assert(!stealth::parseMccMnc("4401", mcc, mnc));
        assert(!stealth::parseMccMnc("4401000", mcc, mnc));
        assert(!stealth::parseMccMnc("4401a", mcc, mnc));
        assert(!stealth::parseMccMnc("00010", mcc, mnc));
    }

    std::cout << "ALL stealth_logic_test C++ ASSERTIONS PASSED (oem=" << stealth::kOemProfileName << ")\n";
    return 0;
}
