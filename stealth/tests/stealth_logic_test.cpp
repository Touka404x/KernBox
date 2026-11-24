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

        std::string out;
        assert(!stealth::lookupSpoofedProperty(empty, "gsm.sim.operator.numeric", "46002", out));
    }

    // 2. Active sandbox config parsing + UID filter
    {
        std::string json = R"({
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
        assert(stealth::formatMultiSimValue("", "44010") == "44010");
        assert(stealth::formatMultiSimValue("46002", "44010") == "44010");
        assert(stealth::formatMultiSimValue("46002,46000", "44010") == "44010,44010");
        assert(stealth::formatMultiSimValue(",46002", "44010") == ",44010");
        assert(stealth::formatMultiSimValue("46002,", "44010") == "44010,");
        assert(stealth::formatMultiSimValue(",", "jp") == ",");
    }

    // 4. Property lookup whitelist + passthrough
    {
        auto cfg = stealth::parseStealthConfig(
            R"({"enabled":true,"timezone":"Asia/Tokyo","locale":"ja-JP","spoof_carrier":true,"sim_operator":"44010","sim_country_iso":"jp","sim_operator_name":"NTT DOCOMO"})");
        std::string out;
        assert(stealth::lookupSpoofedProperty(cfg, "persist.sys.timezone", "Asia/Shanghai", out) && out == "Asia/Tokyo");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.sim.operator.numeric", "46002,", out) && out == "44010,");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.sim.operator.iso-country", "cn,cn", out) && out == "jp,jp");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.sim.operator.alpha", "CarrierA", out) && out == "NTT DOCOMO");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.operator.numeric", "46002", out) && out == "44010");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.operator.iso-country", ",cn", out) && out == ",jp");
        assert(stealth::lookupSpoofedProperty(cfg, "gsm.operator.alpha", "CarrierB", out) && out == "NTT DOCOMO");
        assert(!stealth::lookupSpoofedProperty(cfg, "ro.product.model", "GenericPhone", out));
        assert(stealth::lookupSpoofedProperty(cfg, "persist.sys.locale", "zh-CN", out) && out == "ja-JP");
        assert(stealth::lookupSpoofedProperty(cfg, "ro.product.locale", "zh-CN", out) && out == "ja-JP");

        auto no_loc = stealth::parseStealthConfig(
            R"({"enabled":true,"locale":"ja-JP","spoof_locale":false})");
        assert(!stealth::lookupSpoofedProperty(no_loc, "persist.sys.locale", "zh-CN", out));
        assert(!stealth::lookupSpoofedProperty(no_loc, "ro.product.locale", "zh-CN", out));
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
        assert(stealth::kBakedPropCount == 16);
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.boot.hwc", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.region", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.cust_variant", "cn", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "jp");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.build.region", "cn", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "jp");
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.oplus.region", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.country_code", "CN", stack_buf, sizeof(stack_buf), &res));
#elif defined(OEM_OPLUS)
        assert(std::string(stealth::kOemProfileName) == "oplus");
        assert(stealth::kBakedPropCount == 16);
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "persist.sys.oplus.region", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.oplus.region", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.vendor.oplus.regionmark", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "persist.sys.oppo.region", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.region", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.country_code", "CN", stack_buf, sizeof(stack_buf), &res));
#elif defined(OEM_ONEUI)
        assert(std::string(stealth::kOemProfileName) == "oneui");
        assert(stealth::kBakedPropCount == 15);
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.country_code", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.countryiso_code", "CN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.csc.sales_code", "CHN", stack_buf, sizeof(stack_buf), &res) && std::string(res) == "JP");
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.miui.region", "CN", stack_buf, sizeof(stack_buf), &res));
        assert(!stealth::lookupSpoofedPropertyIntoBuf(baked, "ro.oplus.region", "CN", stack_buf, sizeof(stack_buf), &res));
#else
        assert(stealth::kBakedPropCount == 12);
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
        const std::string sneaky_json =
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

    std::cout << "ALL stealth_logic_test C++ ASSERTIONS PASSED (oem=" << stealth::kOemProfileName << ")\n";
    return 0;
}
