#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if !defined(OEM_HYPEROS) && !defined(OEM_OPLUS) && !defined(OEM_ONEUI) && !defined(OEM_AOSP) && !defined(OEM_GENERIC)
#define OEM_GENERIC 1
#endif

namespace stealth {

inline constexpr int kAndroidUserStride = 100000;
inline constexpr int kFirstAppId = 10000;
inline constexpr int kFirstIsolatedId = 90000;
inline constexpr int kXSpaceUserId = 999;
inline constexpr size_t kMaxBakedValueBytes = 92;

#if defined(OEM_HYPEROS)
inline constexpr const char* kOemProfileName = "hyperos";
inline constexpr size_t kBakedPropCount = 22;
#elif defined(OEM_OPLUS)
inline constexpr const char* kOemProfileName = "oplus";
inline constexpr size_t kBakedPropCount = 22;
#elif defined(OEM_ONEUI)
inline constexpr const char* kOemProfileName = "oneui";
inline constexpr size_t kBakedPropCount = 23;
#elif defined(OEM_AOSP)
inline constexpr const char* kOemProfileName = "aosp";
inline constexpr size_t kBakedPropCount = 18;
#else
inline constexpr const char* kOemProfileName = "generic";
inline constexpr size_t kBakedPropCount = 18;
#endif

struct StealthConfig {
    bool enabled = false;
    int sandbox_user_id = 10;
    int exempt_work_uid = -1;
    std::vector<int> exempt_uids;
    std::string timezone = "UTC";
    std::string locale = "en-US";
    std::string sim_operator = "";
    std::string sim_operator_name = "";
    std::string sim_country_iso = "";
    std::string network_operator = "";
    std::string network_operator_name = "";
    std::string network_country_iso = "";
    std::string prop_hook_mode = "plt";
    bool spoof_carrier = false;
    bool spoof_timezone = true;
    bool spoof_locale = true;
    bool sanitize_network = true;
    bool spoof_device_region = false;
    bool hide_adb = true;
    std::string sandbox_link_ipv4 = "10.172.10.2";
    std::string device_region = "";
    std::string boot_hwc = "";
};

struct BakedProps {
    bool active[kBakedPropCount] = {};
    char values[kBakedPropCount][kMaxBakedValueBytes] = {};
};

namespace detail {

inline void skipJsonWs(const std::string& json, size_t& p) {
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t' || json[p] == '\r' || json[p] == '\n')) {
        p++;
    }
}

inline bool readJsonStringToken(const std::string& json, size_t& p, std::string* out_val) {
    if (p >= json.size() || json[p] != '"') {
        return false;
    }
    if (out_val) {
        out_val->clear();
    }
    p++;
    while (p < json.size()) {
        char c = json[p++];
        if (c == '"') {
            return true;
        }
        if (c == '\\') {
            if (p >= json.size()) {
                return false;
            }
            char e = json[p++];
            if (out_val) {
                switch (e) {
                    case '"': out_val->push_back('"'); break;
                    case '\\': out_val->push_back('\\'); break;
                    case '/': out_val->push_back('/'); break;
                    case 'b': out_val->push_back('\b'); break;
                    case 'f': out_val->push_back('\f'); break;
                    case 'n': out_val->push_back('\n'); break;
                    case 'r': out_val->push_back('\r'); break;
                    case 't': out_val->push_back('\t'); break;
                    case 'u': {
                        if (p + 4 <= json.size()) {
                            uint32_t cp = 0;
                            bool hex_ok = true;
                            for (int k = 0; k < 4; k++) {
                                char h = json[p + k];
                                cp <<= 4;
                                if (h >= '0' && h <= '9') cp |= static_cast<uint32_t>(h - '0');
                                else if (h >= 'a' && h <= 'f') cp |= static_cast<uint32_t>(h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') cp |= static_cast<uint32_t>(h - 'A' + 10);
                                else { hex_ok = false; break; }
                            }
                            if (hex_ok) {
                                p += 4;
                                if (cp <= 0x7Fu) {
                                    out_val->push_back(static_cast<char>(cp));
                                } else if (cp <= 0x7FFu) {
                                    out_val->push_back(static_cast<char>(0xC0u | (cp >> 6)));
                                    out_val->push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
                                } else {
                                    out_val->push_back(static_cast<char>(0xE0u | (cp >> 12)));
                                    out_val->push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
                                    out_val->push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
                                }
                                break;
                            }
                        }
                        out_val->push_back('u');
                        break;
                    }
                    default: out_val->push_back(e); break;
                }
            }
        } else if (out_val) {
            out_val->push_back(c);
        }
    }
    return false;
}

inline bool readJsonCompoundToken(
    const std::string& json,
    size_t& p,
    char open_ch,
    char close_ch,
    std::string* out_raw) {
    if (p >= json.size() || json[p] != open_ch) {
        return false;
    }
    size_t start = p;
    int depth = 0;
    while (p < json.size()) {
        char c = json[p];
        if (c == '"') {
            if (!readJsonStringToken(json, p, nullptr)) {
                return false;
            }
            continue;
        }
        if (c == open_ch) {
            depth++;
        } else if (c == close_ch) {
            depth--;
            if (depth == 0) {
                p++;
                if (out_raw) {
                    out_raw->assign(json.data() + start, p - start);
                }
                return true;
            }
        }
        p++;
    }
    return false;
}

inline bool skipJsonValueToken(const std::string& json, size_t& p) {
    skipJsonWs(json, p);
    if (p >= json.size()) {
        return false;
    }
    char c = json[p];
    if (c == '"') {
        return readJsonStringToken(json, p, nullptr);
    }
    if (c == '[') {
        return readJsonCompoundToken(json, p, '[', ']', nullptr);
    }
    if (c == '{') {
        return readJsonCompoundToken(json, p, '{', '}', nullptr);
    }
    size_t start = p;
    while (p < json.size() && json[p] != ',' && json[p] != '}' && json[p] != ']' &&
           json[p] != ' ' && json[p] != '\t' && json[p] != '\r' && json[p] != '\n') {
        p++;
    }
    return p > start;
}

inline bool parseFlatJsonValue(const std::string& json, const char* key, std::string& out_val, bool& is_string) {
    out_val.clear();
    is_string = false;
    if (!key || key[0] == '\0') {
        return false;
    }
    size_t p = 0;
    skipJsonWs(json, p);
    if (p >= json.size() || json[p] != '{') {
        return false;
    }
    p++;
    std::string cur_key;
    std::string tmp_val;
    bool found = false;
    while (p < json.size()) {
        skipJsonWs(json, p);
        if (p < json.size() && json[p] == ',') {
            p++;
            skipJsonWs(json, p);
        }
        if (p >= json.size()) {
            return found;
        }
        if (json[p] == '}') {
            return found;
        }
        if (!readJsonStringToken(json, p, &cur_key)) {
            return found;
        }
        skipJsonWs(json, p);
        if (p >= json.size() || json[p] != ':') {
            return found;
        }
        p++;
        skipJsonWs(json, p);
        if (p >= json.size()) {
            return found;
        }
        const bool match = (cur_key == key);
        char c = json[p];
        if (!match) {
            if (!skipJsonValueToken(json, p)) {
                return found;
            }
            continue;
        }
        tmp_val.clear();
        bool tmp_is_string = false;
        bool val_ok = false;
        if (c == '"') {
            tmp_is_string = true;
            val_ok = readJsonStringToken(json, p, &tmp_val);
        } else if (c == '[') {
            val_ok = readJsonCompoundToken(json, p, '[', ']', &tmp_val);
        } else if (c == '{') {
            val_ok = readJsonCompoundToken(json, p, '{', '}', &tmp_val);
        } else {
            size_t start = p;
            while (p < json.size() && json[p] != ',' && json[p] != '}' &&
                   json[p] != ' ' && json[p] != '\t' && json[p] != '\r' && json[p] != '\n') {
                p++;
            }
            tmp_val.assign(json.data() + start, p - start);
            val_ok = !tmp_val.empty();
        }
        if (!val_ok) {
            return found;
        }
        out_val = tmp_val;
        is_string = tmp_is_string;
        found = true;
    }
    return found;
}

inline bool readBoolField(const std::string& json, const char* key, bool def) {
    std::string v;
    bool is_str = false;
    if (!parseFlatJsonValue(json, key, v, is_str)) return def;
    if (v == "true") return true;
    if (v == "false") return false;
    return def;
}

inline int readIntField(const std::string& json, const char* key, int def) {
    std::string v;
    bool is_str = false;
    if (!parseFlatJsonValue(json, key, v, is_str) || v.empty()) return def;
    char* end = nullptr;
    long parsed = std::strtol(v.c_str(), &end, 10);
    if (end == v.c_str() || *end != '\0') return def;
    return static_cast<int>(parsed);
}

inline std::vector<int> readIntArrayField(const std::string& json, const char* key) {
    std::vector<int> out;
    std::string raw;
    bool is_str = false;
    if (!parseFlatJsonValue(json, key, raw, is_str) || is_str || raw.empty()) {
        return out;
    }
    size_t i = 0;
    while (i < raw.size()) {
        char c = raw[i];
        if ((c >= '0' && c <= '9') || c == '-') {
            char* end = nullptr;
            long val = std::strtol(raw.c_str() + i, &end, 10);
            if (end > raw.c_str() + i) {
                if (val > 0) {
                    out.push_back(static_cast<int>(val));
                }
                i = static_cast<size_t>(end - raw.c_str());
                continue;
            }
        }
        i++;
    }
    return out;
}

inline std::string readStringField(const std::string& json, const char* key, const std::string& def) {
    std::string v;
    bool is_str = false;
    if (!parseFlatJsonValue(json, key, v, is_str) || !is_str || v.empty()) return def;
    return v;
}

} // namespace detail

inline StealthConfig parseStealthConfig(const std::string& json) {
    StealthConfig cfg;
    if (json.empty()) {
        return cfg;
    }
    cfg.enabled = detail::readBoolField(json, "enabled", false);
    cfg.sandbox_user_id = detail::readIntField(json, "sandbox_user_id", 10);
    cfg.exempt_work_uid = detail::readIntField(json, "exempt_work_uid", -1);
    cfg.exempt_uids = detail::readIntArrayField(json, "exempt_uids");
    cfg.timezone = detail::readStringField(json, "timezone", cfg.timezone);
    cfg.locale = detail::readStringField(json, "locale", cfg.locale);
    cfg.sim_operator = detail::readStringField(json, "sim_operator", cfg.sim_operator);
    cfg.sim_operator_name = detail::readStringField(json, "sim_operator_name", cfg.sim_operator_name);
    cfg.sim_country_iso = detail::readStringField(json, "sim_country_iso", cfg.sim_country_iso);
    cfg.network_operator = detail::readStringField(json, "network_operator", cfg.sim_operator);
    cfg.network_operator_name = detail::readStringField(json, "network_operator_name", cfg.sim_operator_name);
    cfg.network_country_iso = detail::readStringField(json, "network_country_iso", cfg.sim_country_iso);
    cfg.prop_hook_mode = detail::readStringField(json, "prop_hook_mode", "plt");
    cfg.spoof_carrier = detail::readBoolField(json, "spoof_carrier", false);
    cfg.spoof_timezone = detail::readBoolField(json, "spoof_timezone", true);
    cfg.spoof_locale = detail::readBoolField(json, "spoof_locale", true);
    cfg.sanitize_network = detail::readBoolField(json, "sanitize_network", true);
    cfg.spoof_device_region = detail::readBoolField(json, "spoof_device_region", false);
    cfg.hide_adb = detail::readBoolField(json, "hide_adb", true);
    cfg.sandbox_link_ipv4 = detail::readStringField(json, "sandbox_link_ipv4", cfg.sandbox_link_ipv4);

    std::string legacy_region = detail::readStringField(json, "miui_region", "");
    std::string primary_region = detail::readStringField(json, "device_region", "");
    if (!primary_region.empty()) {
        cfg.device_region = primary_region;
    } else if (!legacy_region.empty()) {
        cfg.device_region = legacy_region;
    }
    cfg.boot_hwc = detail::readStringField(json, "boot_hwc", "");
    return cfg;
}

// Strict 4-octet decimal IPv4 parser (zero heap allocation).
inline bool parseIPv4Octets(const std::string& ip, uint8_t out[4]) {
    if (!out || ip.empty()) {
        return false;
    }
    int octet = 0;
    size_t idx = 0;
    const size_t n = ip.size();
    while (idx < n && (ip[idx] == ' ' || ip[idx] == '\t')) {
        idx++;
    }
    for (; octet < 4; octet++) {
        if (idx >= n || ip[idx] < '0' || ip[idx] > '9') {
            return false;
        }
        if (ip[idx] == '0' && idx + 1 < n && ip[idx + 1] >= '0' && ip[idx + 1] <= '9') {
            return false; // reject leading zeros
        }
        unsigned int val = 0;
        while (idx < n && ip[idx] >= '0' && ip[idx] <= '9') {
            val = val * 10U + static_cast<unsigned int>(ip[idx] - '0');
            if (val > 255U) {
                return false;
            }
            idx++;
        }
        out[octet] = static_cast<uint8_t>(val);
        if (octet < 3) {
            if (idx >= n || ip[idx] != '.') {
                return false;
            }
            idx++;
        }
    }
    while (idx < n && (ip[idx] == ' ' || ip[idx] == '\t')) {
        idx++;
    }
    return idx == n;
}

inline bool shouldSpoofAppUid(const StealthConfig& cfg, int uid) {
    if (!cfg.enabled || cfg.sandbox_user_id <= 0 || cfg.sandbox_user_id == kXSpaceUserId) {
        return false;
    }
    if (uid < kAndroidUserStride) {
        return false;
    }
    if ((uid / kAndroidUserStride) != cfg.sandbox_user_id) {
        return false;
    }
    int app_id = uid % kAndroidUserStride;
    if (app_id < kFirstAppId || app_id >= kAndroidUserStride) {
        return false;
    }
    if (cfg.exempt_work_uid > 0 && uid == cfg.exempt_work_uid) {
        return false;
    }
    for (size_t i = 0; i < cfg.exempt_uids.size(); i++) {
        if (uid == cfg.exempt_uids[i]) {
            return false;
        }
    }
    return true;
}

/**
 * Formats dual-SIM comma-separated TelephonyProperties while preserving empty slots.
 */
inline std::string formatMultiSimValue(const std::string& orig, const std::string& spoof) {
    if (orig.empty() || orig.find(',') == std::string::npos) {
        return spoof;
    }
    std::string out;
    out.reserve(orig.size() + spoof.size() * 2);
    size_t start = 0;
    while (start <= orig.size()) {
        size_t comma = orig.find(',', start);
        size_t end = (comma == std::string::npos) ? orig.size() : comma;
        if (end > start) {
            out.append(spoof);
        }
        if (comma == std::string::npos) {
            break;
        }
        out.push_back(',');
        start = comma + 1;
    }
    return out;
}

// Allocation-free dual-SIM formatter into caller stack buffer. Returns false on overflow.
inline bool formatMultiSimIntoBuf(const char* orig, const char* spoof, char* out, size_t cap) {
    if (!out || cap == 0 || !spoof) return false;
    size_t spoof_len = std::strlen(spoof);
    if (!orig || orig[0] == '\0' || std::strchr(orig, ',') == nullptr) {
        if (spoof_len + 1 > cap) return false;
        std::memcpy(out, spoof, spoof_len + 1);
        return true;
    }
    size_t out_pos = 0;
    const char* p = orig;
    for (;;) {
        const char* comma = std::strchr(p, ',');
        size_t seg_len = comma ? static_cast<size_t>(comma - p) : std::strlen(p);
        if (seg_len > 0) {
            if (out_pos + spoof_len >= cap) return false;
            std::memcpy(out + out_pos, spoof, spoof_len);
            out_pos += spoof_len;
        }
        if (!comma) break;
        if (out_pos + 1 >= cap) return false;
        out[out_pos++] = ',';
        p = comma + 1;
    }
    out[out_pos] = '\0';
    return true;
}

// O(1) first-byte dispatch rejects non-target system property keys in 1 comparison.
// Slots 0..17 are universal across all OEMs; slots 18+ are compiled per OEM profile.
inline bool isMultiSimCarrierSlot(int idx) {
    return (idx >= 1 && idx <= 6) || idx == 11 || idx == 13;
}

inline int spoofablePropIndex(const char* name) {
    if (!name) return -1;
    switch (name[0]) {
        case 'p':
            if (std::strcmp(name, "persist.sys.timezone") == 0) return 0;
            if (std::strcmp(name, "persist.sys.locale") == 0) return 7;
            if (std::strcmp(name, "persist.sys.country") == 0) return 9;
            if (std::strcmp(name, "persist.sys.language") == 0) return 10;
            if (std::strcmp(name, "persist.sys.usb.config") == 0) return 17;
#if defined(OEM_OPLUS)
            if (std::strcmp(name, "persist.sys.oplus.region") == 0) return 18;
            if (std::strcmp(name, "persist.sys.oppo.region") == 0) return 21;
#elif defined(OEM_ONEUI)
            if (std::strcmp(name, "persist.omc.sales_code") == 0) return 22;
#endif
            return -1;
        case 'g':
            if (name[1] != 's' || name[2] != 'm' || name[3] != '.') return -1;
            if (std::strcmp(name, "gsm.sim.operator.numeric") == 0) return 1;
            if (std::strcmp(name, "gsm.sim.operator.iso-country") == 0) return 2;
            if (std::strcmp(name, "gsm.sim.operator.alpha") == 0) return 3;
            if (std::strcmp(name, "gsm.operator.numeric") == 0) return 4;
            if (std::strcmp(name, "gsm.operator.iso-country") == 0) return 5;
            if (std::strcmp(name, "gsm.operator.alpha") == 0) return 6;
            if (std::strcmp(name, "gsm.sim.state") == 0) return 11;
            if (std::strcmp(name, "gsm.network.type") == 0) return 13;
            return -1;
        case 'i':
            if (std::strcmp(name, "init.svc.adbd") == 0) return 14;
            return -1;
        case 's':
            if (std::strcmp(name, "sys.usb.state") == 0) return 15;
            if (std::strcmp(name, "sys.usb.config") == 0) return 16;
            return -1;
        case 'r':
            if (std::strcmp(name, "ro.product.locale") == 0) return 8;
            if (std::strcmp(name, "ro.boot.hwcountry") == 0) return 12;
#if defined(OEM_HYPEROS)
            if (std::strcmp(name, "ro.boot.hwc") == 0) return 18;
            if (std::strcmp(name, "ro.miui.region") == 0) return 19;
            if (std::strcmp(name, "ro.miui.cust_variant") == 0) return 20;
            if (std::strcmp(name, "ro.miui.build.region") == 0) return 21;
#elif defined(OEM_OPLUS)
            if (std::strcmp(name, "ro.oplus.region") == 0) return 19;
            if (std::strcmp(name, "ro.vendor.oplus.regionmark") == 0) return 20;
#elif defined(OEM_ONEUI)
            if (std::strcmp(name, "ro.csc.country_code") == 0) return 18;
            if (std::strcmp(name, "ro.csc.countryiso_code") == 0) return 19;
            if (std::strcmp(name, "ro.csc.sales_code") == 0) return 20;
            if (std::strcmp(name, "ro.csc.omcnw_code") == 0) return 21;
#endif
            return -1;
        default:
            return -1;
    }
}

inline const char* spoofablePropNameByIndex(int idx) {
    switch (idx) {
        case 0: return "persist.sys.timezone";
        case 1: return "gsm.sim.operator.numeric";
        case 2: return "gsm.sim.operator.iso-country";
        case 3: return "gsm.sim.operator.alpha";
        case 4: return "gsm.operator.numeric";
        case 5: return "gsm.operator.iso-country";
        case 6: return "gsm.operator.alpha";
        case 7: return "persist.sys.locale";
        case 8: return "ro.product.locale";
        case 9: return "persist.sys.country";
        case 10: return "persist.sys.language";
        case 11: return "gsm.sim.state";
        case 12: return "ro.boot.hwcountry";
        case 13: return "gsm.network.type";
        case 14: return "init.svc.adbd";
        case 15: return "sys.usb.state";
        case 16: return "sys.usb.config";
        case 17: return "persist.sys.usb.config";
#if defined(OEM_HYPEROS)
        case 18: return "ro.boot.hwc";
        case 19: return "ro.miui.region";
        case 20: return "ro.miui.cust_variant";
        case 21: return "ro.miui.build.region";
#elif defined(OEM_OPLUS)
        case 18: return "persist.sys.oplus.region";
        case 19: return "ro.oplus.region";
        case 20: return "ro.vendor.oplus.regionmark";
        case 21: return "persist.sys.oppo.region";
#elif defined(OEM_ONEUI)
        case 18: return "ro.csc.country_code";
        case 19: return "ro.csc.countryiso_code";
        case 20: return "ro.csc.sales_code";
        case 21: return "ro.csc.omcnw_code";
        case 22: return "persist.omc.sales_code";
#endif
        default: return nullptr;
    }
}

namespace detail {

inline std::string asciiLower(const std::string& in) {
    std::string out = in;
    for (size_t i = 0; i < out.size(); i++) {
        if (out[i] >= 'A' && out[i] <= 'Z') {
            out[i] = static_cast<char>(out[i] - 'A' + 'a');
        }
    }
    return out;
}

inline std::string asciiUpper(const std::string& in) {
    std::string out = in;
    for (size_t i = 0; i < out.size(); i++) {
        if (out[i] >= 'a' && out[i] <= 'z') {
            out[i] = static_cast<char>(out[i] - 'a' + 'A');
        }
    }
    return out;
}

inline void splitLocaleTag(const std::string& locale, const std::string& fallback_region, std::string& out_lang, std::string& out_country) {
    out_lang.clear();
    out_country.clear();
    size_t sep = locale.find_first_of("-_");
    if (sep == std::string::npos) {
        out_lang = asciiLower(locale);
        out_country = asciiUpper(fallback_region);
        return;
    }
    out_lang = asciiLower(locale.substr(0, sep));
    size_t rest = sep + 1;
    while (rest < locale.size() && (locale[rest] == '-' || locale[rest] == '_')) {
        rest++;
    }
    size_t next_sep = locale.find_first_of("-_", rest);
    std::string seg = (next_sep == std::string::npos) ? locale.substr(rest) : locale.substr(rest, next_sep - rest);
    if (seg.size() == 4) {
        // Skip BCP-47 4-letter script subtag (e.g. zh-Hans-CN -> CN)
        if (next_sep != std::string::npos) {
            size_t r2 = next_sep + 1;
            size_t s2 = locale.find_first_of("-_", r2);
            seg = (s2 == std::string::npos) ? locale.substr(r2) : locale.substr(r2, s2 - r2);
        } else {
            seg.clear();
        }
    }
    out_country = seg.empty() ? asciiUpper(fallback_region) : asciiUpper(seg);
}

} // namespace detail

inline BakedProps bakeSpoofedProps(const StealthConfig& cfg) {
    BakedProps baked;
    if (!cfg.enabled) {
        return baked;
    }
    auto setSlot = [&](size_t idx, bool cond, const std::string& val) {
        if (idx >= kBakedPropCount || !cond || val.empty() || val.size() >= kMaxBakedValueBytes) return;
        baked.active[idx] = true;
        std::memcpy(baked.values[idx], val.c_str(), val.size() + 1);
    };
    std::string lang;
    std::string country;
    detail::splitLocaleTag(cfg.locale, cfg.device_region, lang, country);
    const std::string effective_region = !cfg.device_region.empty() ? cfg.device_region : country;
    const std::string region_lower = detail::asciiLower(effective_region);
    const std::string region_upper = detail::asciiUpper(effective_region);
    const std::string effective_hwc = !cfg.boot_hwc.empty() ? cfg.boot_hwc : region_upper;

    setSlot(0, cfg.spoof_timezone, cfg.timezone);
    setSlot(1, cfg.spoof_carrier, cfg.sim_operator);
    setSlot(2, cfg.spoof_carrier, cfg.sim_country_iso);
    setSlot(3, cfg.spoof_carrier, cfg.sim_operator_name);
    setSlot(4, cfg.spoof_carrier, cfg.network_operator);
    setSlot(5, cfg.spoof_carrier, cfg.network_country_iso);
    setSlot(6, cfg.spoof_carrier, cfg.network_operator_name);
    setSlot(7, cfg.spoof_locale, cfg.locale);
    setSlot(8, cfg.spoof_locale, cfg.locale);
    setSlot(9, cfg.spoof_locale, country);
    setSlot(10, cfg.spoof_locale, lang);
    setSlot(11, cfg.spoof_carrier, std::string("READY"));
    setSlot(12, cfg.spoof_device_region, effective_hwc);
    setSlot(13, cfg.spoof_carrier, std::string("LTE"));
    setSlot(14, cfg.hide_adb, std::string("stopped"));
    setSlot(15, cfg.hide_adb, std::string("none"));
    setSlot(16, cfg.hide_adb, std::string("none"));
    setSlot(17, cfg.hide_adb, std::string("none"));
#if defined(OEM_HYPEROS)
    setSlot(18, cfg.spoof_device_region, effective_hwc);
    setSlot(19, cfg.spoof_device_region, region_upper);
    setSlot(20, cfg.spoof_device_region, region_lower);
    setSlot(21, cfg.spoof_device_region, region_lower);
#elif defined(OEM_OPLUS)
    setSlot(18, cfg.spoof_device_region, region_upper);
    setSlot(19, cfg.spoof_device_region, region_upper);
    setSlot(20, cfg.spoof_device_region, region_upper);
    setSlot(21, cfg.spoof_device_region, region_upper);
#elif defined(OEM_ONEUI)
    setSlot(18, cfg.spoof_device_region, region_upper);
    setSlot(19, cfg.spoof_device_region, region_upper);
    setSlot(20, cfg.spoof_device_region, region_upper);
    setSlot(21, cfg.spoof_device_region, region_upper);
    setSlot(22, cfg.spoof_device_region, region_upper);
#endif
    return baked;
}

// Zero-allocation property lookup for PLT hook hot path.
inline bool lookupSpoofedPropertyIntoBuf(
    const BakedProps& baked,
    const char* name,
    const char* orig_val,
    char* stack_buf,
    size_t stack_cap,
    const char** out_ptr) {
    if (!out_ptr) return false;
    int idx = spoofablePropIndex(name);
    if (idx < 0 || static_cast<size_t>(idx) >= kBakedPropCount || !baked.active[idx]) {
        return false;
    }
    if (!isMultiSimCarrierSlot(idx)) {
        *out_ptr = baked.values[idx];
        return true;
    }
    if (!orig_val || orig_val[0] == '\0' || std::strchr(orig_val, ',') == nullptr) {
        *out_ptr = baked.values[idx];
        return true;
    }
    if (formatMultiSimIntoBuf(orig_val, baked.values[idx], stack_buf, stack_cap)) {
        *out_ptr = stack_buf;
        return true;
    }
    // Never leak raw multi-SIM property on formatting overflow; fall back to primary spoof value.
    *out_ptr = baked.values[idx];
    return true;
}

inline bool lookupSpoofedProperty(
    const StealthConfig& cfg,
    const char* name,
    const char* orig_val,
    std::string& out) {
    BakedProps baked = bakeSpoofedProps(cfg);
    char buf[192];
    const char* res = nullptr;
    if (!lookupSpoofedPropertyIntoBuf(baked, name, orig_val, buf, sizeof(buf), &res) || !res) {
        return false;
    }
    out.assign(res);
    return true;
}

} // namespace stealth
