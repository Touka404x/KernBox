#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

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

template <size_t Cap>
struct FixedStr {
    static_assert(Cap > 1, "FixedStr capacity must exceed 1");
    char buf[Cap] = {};
    size_t len = 0;

    FixedStr() = default;
    FixedStr(const char* s) { assign(s); }

    const char* c_str() const { return buf; }
    const char* data() const { return buf; }
    size_t size() const { return len; }
    bool empty() const { return len == 0; }
    void clear() {
        len = 0;
        buf[0] = '\0';
    }
    void push_back(char c) {
        if (len + 1 < Cap) {
            buf[len++] = c;
            buf[len] = '\0';
        }
    }
    void assign(const char* s, size_t n) {
        if (!s || n == 0) {
            clear();
            return;
        }
        size_t copy_n = n < (Cap - 1) ? n : (Cap - 1);
        std::memcpy(buf, s, copy_n);
        len = copy_n;
        buf[len] = '\0';
    }
    void assign(const char* s) {
        if (!s) {
            clear();
            return;
        }
        assign(s, strnlen(s, Cap - 1));
    }
    char operator[](size_t i) const { return buf[i]; }
    char& operator[](size_t i) { return buf[i]; }
    bool operator==(const char* rhs) const {
        if (!rhs) return len == 0;
        return std::strcmp(buf, rhs) == 0;
    }
    bool operator!=(const char* rhs) const { return !(*this == rhs); }
    template <size_t OtherCap>
    bool operator==(const FixedStr<OtherCap>& rhs) const {
        return len == rhs.len && std::memcmp(buf, rhs.buf, len) == 0;
    }
};

template <size_t Cap>
struct FixedIntVec {
    int items[Cap] = {};
    size_t len = 0;

    size_t size() const { return len; }
    bool empty() const { return len == 0; }
    void clear() { len = 0; }
    void push_back(int v) {
        if (len < Cap) {
            items[len++] = v;
        }
    }
    int operator[](size_t i) const { return items[i]; }
    const int* begin() const { return items; }
    const int* end() const { return items + len; }
};

struct StealthConfig {
    bool enabled = false;
    int sandbox_user_id = 10;
    int exempt_work_uid = -1;
    FixedIntVec<32> exempt_uids;
    FixedStr<96> timezone = "UTC";
    FixedStr<96> locale = "en-US";
    FixedStr<96> sim_operator = "";
    FixedStr<96> sim_operator_name = "";
    FixedStr<96> sim_country_iso = "";
    FixedStr<96> network_operator = "";
    FixedStr<96> network_operator_name = "";
    FixedStr<96> network_country_iso = "";
    FixedStr<32> prop_hook_mode = "plt";
    bool spoof_carrier = false;
    bool spoof_timezone = true;
    bool spoof_locale = true;
    bool sanitize_network = true;
    bool spoof_device_region = false;
    bool hide_adb = true;
    FixedStr<64> sandbox_link_ipv4 = "10.172.10.2";
    FixedStr<64> device_region = "";
    FixedStr<64> boot_hwc = "";
};

struct BakedProps {
    bool active[kBakedPropCount] = {};
    char values[kBakedPropCount][kMaxBakedValueBytes] = {};
};

namespace detail {

inline void skipJsonWs(const char* json, size_t json_len, size_t& p) {
    while (p < json_len && (json[p] == ' ' || json[p] == '\t' || json[p] == '\r' || json[p] == '\n')) {
        p++;
    }
}

template <size_t Cap>
inline bool readJsonStringToken(const char* json, size_t json_len, size_t& p, FixedStr<Cap>* out_val) {
    if (p >= json_len || json[p] != '"') {
        return false;
    }
    if (out_val) {
        out_val->clear();
    }
    p++;
    while (p < json_len) {
        char c = json[p++];
        if (c == '"') {
            return true;
        }
        if (c == '\\') {
            if (p >= json_len) {
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
                        if (p + 4 <= json_len) {
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

template <size_t Cap>
inline bool readJsonCompoundToken(
    const char* json,
    size_t json_len,
    size_t& p,
    char open_ch,
    char close_ch,
    FixedStr<Cap>* out_raw) {
    if (p >= json_len || json[p] != open_ch) {
        return false;
    }
    size_t start = p;
    int depth = 0;
    while (p < json_len) {
        char c = json[p];
        if (c == '"') {
            if (!readJsonStringToken<2>(json, json_len, p, nullptr)) {
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
                    out_raw->assign(json + start, p - start);
                }
                return true;
            }
        }
        p++;
    }
    return false;
}

inline bool skipJsonValueToken(const char* json, size_t json_len, size_t& p) {
    skipJsonWs(json, json_len, p);
    if (p >= json_len) {
        return false;
    }
    char c = json[p];
    if (c == '"') {
        return readJsonStringToken<2>(json, json_len, p, nullptr);
    }
    if (c == '[') {
        return readJsonCompoundToken<2>(json, json_len, p, '[', ']', nullptr);
    }
    if (c == '{') {
        return readJsonCompoundToken<2>(json, json_len, p, '{', '}', nullptr);
    }
    size_t start = p;
    while (p < json_len && json[p] != ',' && json[p] != '}' && json[p] != ']' &&
           json[p] != ' ' && json[p] != '\t' && json[p] != '\r' && json[p] != '\n') {
        p++;
    }
    return p > start;
}

template <size_t Cap>
inline bool parseFlatJsonValue(const char* json, size_t json_len, const char* key, FixedStr<Cap>& out_val, bool& is_string) {
    out_val.clear();
    is_string = false;
    if (!json || json_len == 0 || !key || key[0] == '\0') {
        return false;
    }
    size_t p = 0;
    skipJsonWs(json, json_len, p);
    if (p >= json_len || json[p] != '{') {
        return false;
    }
    p++;
    FixedStr<64> cur_key;
    FixedStr<Cap> tmp_val;
    bool found = false;
    while (p < json_len) {
        skipJsonWs(json, json_len, p);
        if (p < json_len && json[p] == ',') {
            p++;
            skipJsonWs(json, json_len, p);
        }
        if (p >= json_len || json[p] == '}') {
            return found;
        }
        if (!readJsonStringToken(json, json_len, p, &cur_key)) {
            return found;
        }
        skipJsonWs(json, json_len, p);
        if (p >= json_len || json[p] != ':') {
            return found;
        }
        p++;
        skipJsonWs(json, json_len, p);
        if (p >= json_len) {
            return found;
        }
        const bool match = (cur_key == key);
        char c = json[p];
        if (!match) {
            if (!skipJsonValueToken(json, json_len, p)) {
                return found;
            }
            continue;
        }
        tmp_val.clear();
        bool tmp_is_string = false;
        bool val_ok = false;
        if (c == '"') {
            tmp_is_string = true;
            val_ok = readJsonStringToken(json, json_len, p, &tmp_val);
        } else if (c == '[') {
            val_ok = readJsonCompoundToken(json, json_len, p, '[', ']', &tmp_val);
        } else if (c == '{') {
            val_ok = readJsonCompoundToken(json, json_len, p, '{', '}', &tmp_val);
        } else {
            size_t start = p;
            while (p < json_len && json[p] != ',' && json[p] != '}' &&
                   json[p] != ' ' && json[p] != '\t' && json[p] != '\r' && json[p] != '\n') {
                p++;
            }
            tmp_val.assign(json + start, p - start);
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

inline bool readBoolField(const char* json, size_t json_len, const char* key, bool def) {
    FixedStr<16> v;
    bool is_str = false;
    if (!parseFlatJsonValue(json, json_len, key, v, is_str)) return def;
    if (v == "true") return true;
    if (v == "false") return false;
    return def;
}

inline int readIntField(const char* json, size_t json_len, const char* key, int def) {
    FixedStr<32> v;
    bool is_str = false;
    if (!parseFlatJsonValue(json, json_len, key, v, is_str) || v.empty()) return def;
    char* end = nullptr;
    long parsed = std::strtol(v.c_str(), &end, 10);
    if (end == v.c_str() || *end != '\0') return def;
    return static_cast<int>(parsed);
}

inline FixedIntVec<32> readIntArrayField(const char* json, size_t json_len, const char* key) {
    FixedIntVec<32> out;
    FixedStr<384> raw;
    bool is_str = false;
    if (!parseFlatJsonValue(json, json_len, key, raw, is_str) || is_str || raw.empty()) {
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

template <size_t Cap>
inline FixedStr<Cap> readStringField(const char* json, size_t json_len, const char* key, const FixedStr<Cap>& def) {
    FixedStr<Cap> v;
    bool is_str = false;
    if (!parseFlatJsonValue(json, json_len, key, v, is_str) || !is_str || v.empty()) return def;
    return v;
}

template <size_t Cap>
inline FixedStr<Cap> readStringFieldLit(const char* json, size_t json_len, const char* key, const char* def_lit) {
    FixedStr<Cap> def(def_lit);
    return readStringField(json, json_len, key, def);
}

} // namespace detail

inline StealthConfig parseStealthConfig(const char* json, size_t json_len) {
    StealthConfig cfg;
    if (!json || json_len == 0) {
        return cfg;
    }
    cfg.enabled = detail::readBoolField(json, json_len, "enabled", false);
    cfg.sandbox_user_id = detail::readIntField(json, json_len, "sandbox_user_id", 10);
    cfg.exempt_work_uid = detail::readIntField(json, json_len, "exempt_work_uid", -1);
    cfg.exempt_uids = detail::readIntArrayField(json, json_len, "exempt_uids");
    cfg.timezone = detail::readStringField(json, json_len, "timezone", cfg.timezone);
    cfg.locale = detail::readStringField(json, json_len, "locale", cfg.locale);
    cfg.sim_operator = detail::readStringField(json, json_len, "sim_operator", cfg.sim_operator);
    cfg.sim_operator_name = detail::readStringField(json, json_len, "sim_operator_name", cfg.sim_operator_name);
    cfg.sim_country_iso = detail::readStringField(json, json_len, "sim_country_iso", cfg.sim_country_iso);
    cfg.network_operator = detail::readStringField(json, json_len, "network_operator", cfg.sim_operator);
    cfg.network_operator_name = detail::readStringField(json, json_len, "network_operator_name", cfg.sim_operator_name);
    cfg.network_country_iso = detail::readStringField(json, json_len, "network_country_iso", cfg.sim_country_iso);
    cfg.prop_hook_mode = detail::readStringFieldLit<32>(json, json_len, "prop_hook_mode", "plt");
    cfg.spoof_carrier = detail::readBoolField(json, json_len, "spoof_carrier", false);
    cfg.spoof_timezone = detail::readBoolField(json, json_len, "spoof_timezone", true);
    cfg.spoof_locale = detail::readBoolField(json, json_len, "spoof_locale", true);
    cfg.sanitize_network = detail::readBoolField(json, json_len, "sanitize_network", true);
    cfg.spoof_device_region = detail::readBoolField(json, json_len, "spoof_device_region", false);
    cfg.hide_adb = detail::readBoolField(json, json_len, "hide_adb", true);
    cfg.sandbox_link_ipv4 = detail::readStringField(json, json_len, "sandbox_link_ipv4", cfg.sandbox_link_ipv4);

    FixedStr<64> legacy_region = detail::readStringFieldLit<64>(json, json_len, "miui_region", "");
    FixedStr<64> primary_region = detail::readStringFieldLit<64>(json, json_len, "device_region", "");
    if (!primary_region.empty()) {
        cfg.device_region = primary_region;
    } else if (!legacy_region.empty()) {
        cfg.device_region = legacy_region;
    }
    cfg.boot_hwc = detail::readStringFieldLit<64>(json, json_len, "boot_hwc", "");
    return cfg;
}

inline StealthConfig parseStealthConfig(const char* json) {
    return parseStealthConfig(json, json ? std::strlen(json) : 0);
}

// Strict 4-octet decimal IPv4 parser (zero heap allocation).
template <size_t Cap>
inline bool parseIPv4Octets(const FixedStr<Cap>& ip, uint8_t out[4]) {
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

inline bool parseIPv4Octets(const char* ip_str, uint8_t out[4]) {
    FixedStr<64> fs(ip_str);
    return parseIPv4Octets(fs, out);
}

inline bool parseMccMnc(const char* op, int& out_mcc, int& out_mnc) {
    if (!op) return false;
    int d[6]{};
    size_t n = 0;
    while (op[n] != '\0') {
        if (op[n] < '0' || op[n] > '9' || n >= 6) {
            return false;
        }
        d[n] = op[n] - '0';
        n++;
    }
    if (n != 5 && n != 6) {
        return false;
    }
    int mcc = d[0] * 100 + d[1] * 10 + d[2];
    int mnc = d[3] * 10 + d[4];
    if (n == 6) {
        mnc = mnc * 10 + d[5];
    }
    if (mcc <= 0) {
        return false;
    }
    out_mcc = mcc;
    out_mnc = mnc;
    return true;
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

template <size_t Cap>
inline FixedStr<Cap> asciiLower(const char* in, size_t n) {
    FixedStr<Cap> out;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
        out.push_back(c);
    }
    return out;
}

template <size_t Cap>
inline FixedStr<Cap> asciiUpper(const char* in, size_t n) {
    FixedStr<Cap> out;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 'a' + 'A');
        }
        out.push_back(c);
    }
    return out;
}

template <size_t Cap1, size_t Cap2, size_t OutCap>
inline void splitLocaleTag(
    const FixedStr<Cap1>& locale,
    const FixedStr<Cap2>& fallback_region,
    FixedStr<OutCap>& out_lang,
    FixedStr<OutCap>& out_country) {
    out_lang.clear();
    out_country.clear();
    const char* s = locale.c_str();
    const size_t n = locale.size();
    size_t sep = 0;
    while (sep < n && s[sep] != '-' && s[sep] != '_') {
        sep++;
    }
    if (sep >= n) {
        out_lang = asciiLower<OutCap>(s, n);
        out_country = asciiUpper<OutCap>(fallback_region.c_str(), fallback_region.size());
        return;
    }
    out_lang = asciiLower<OutCap>(s, sep);
    size_t rest = sep + 1;
    while (rest < n && (s[rest] == '-' || s[rest] == '_')) {
        rest++;
    }
    size_t next_sep = rest;
    while (next_sep < n && s[next_sep] != '-' && s[next_sep] != '_') {
        next_sep++;
    }
    const char* seg_ptr = s + rest;
    size_t seg_len = next_sep - rest;
    if (seg_len == 4) {
        // Skip BCP-47 4-letter script subtag (e.g. zh-Hans-CN -> CN)
        if (next_sep < n) {
            size_t r2 = next_sep + 1;
            size_t s2 = r2;
            while (s2 < n && s[s2] != '-' && s[s2] != '_') {
                s2++;
            }
            seg_ptr = s + r2;
            seg_len = s2 - r2;
        } else {
            seg_len = 0;
        }
    }
    out_country = seg_len == 0
        ? asciiUpper<OutCap>(fallback_region.c_str(), fallback_region.size())
        : asciiUpper<OutCap>(seg_ptr, seg_len);
}

} // namespace detail

inline BakedProps bakeSpoofedProps(const StealthConfig& cfg) {
    BakedProps baked;
    if (!cfg.enabled) {
        return baked;
    }
    auto setSlot = [&](size_t idx, bool cond, const char* val, size_t val_len) {
        if (idx >= kBakedPropCount || !cond || !val || val_len == 0 || val_len >= kMaxBakedValueBytes) return;
        baked.active[idx] = true;
        std::memcpy(baked.values[idx], val, val_len);
        baked.values[idx][val_len] = '\0';
    };
    FixedStr<32> lang;
    FixedStr<32> country;
    detail::splitLocaleTag(cfg.locale, cfg.device_region, lang, country);
    const char* eff_reg_ptr = !cfg.device_region.empty() ? cfg.device_region.c_str() : country.c_str();
    const size_t eff_reg_len = !cfg.device_region.empty() ? cfg.device_region.size() : country.size();
    FixedStr<64> region_lower = detail::asciiLower<64>(eff_reg_ptr, eff_reg_len);
    (void)region_lower;
    FixedStr<64> region_upper = detail::asciiUpper<64>(eff_reg_ptr, eff_reg_len);
    const char* eff_hwc_ptr = !cfg.boot_hwc.empty() ? cfg.boot_hwc.c_str() : region_upper.c_str();
    const size_t eff_hwc_len = !cfg.boot_hwc.empty() ? cfg.boot_hwc.size() : region_upper.size();

    setSlot(0, cfg.spoof_timezone, cfg.timezone.c_str(), cfg.timezone.size());
    setSlot(1, cfg.spoof_carrier, cfg.sim_operator.c_str(), cfg.sim_operator.size());
    setSlot(2, cfg.spoof_carrier, cfg.sim_country_iso.c_str(), cfg.sim_country_iso.size());
    setSlot(3, cfg.spoof_carrier, cfg.sim_operator_name.c_str(), cfg.sim_operator_name.size());
    setSlot(4, cfg.spoof_carrier, cfg.network_operator.c_str(), cfg.network_operator.size());
    setSlot(5, cfg.spoof_carrier, cfg.network_country_iso.c_str(), cfg.network_country_iso.size());
    setSlot(6, cfg.spoof_carrier, cfg.network_operator_name.c_str(), cfg.network_operator_name.size());
    setSlot(7, cfg.spoof_locale, cfg.locale.c_str(), cfg.locale.size());
    setSlot(8, cfg.spoof_locale, cfg.locale.c_str(), cfg.locale.size());
    setSlot(9, cfg.spoof_locale, country.c_str(), country.size());
    setSlot(10, cfg.spoof_locale, lang.c_str(), lang.size());
    setSlot(11, cfg.spoof_carrier, "READY", 5);
    setSlot(12, cfg.spoof_device_region, eff_hwc_ptr, eff_hwc_len);
    setSlot(13, cfg.spoof_carrier, "LTE", 3);
    setSlot(14, cfg.hide_adb, "stopped", 7);
    setSlot(15, cfg.hide_adb, "none", 4);
    setSlot(16, cfg.hide_adb, "none", 4);
    setSlot(17, cfg.hide_adb, "none", 4);
#if defined(OEM_HYPEROS)
    setSlot(18, cfg.spoof_device_region, eff_hwc_ptr, eff_hwc_len);
    setSlot(19, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
    setSlot(20, cfg.spoof_device_region, region_lower.c_str(), region_lower.size());
    setSlot(21, cfg.spoof_device_region, region_lower.c_str(), region_lower.size());
#elif defined(OEM_OPLUS)
    setSlot(18, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
    setSlot(19, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
    setSlot(20, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
    setSlot(21, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
#elif defined(OEM_ONEUI)
    setSlot(18, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
    setSlot(19, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
    setSlot(20, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
    setSlot(21, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
    setSlot(22, cfg.spoof_device_region, region_upper.c_str(), region_upper.size());
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
    char* out_buf,
    size_t out_cap) {
    if (!out_buf || out_cap == 0) return false;
    BakedProps baked = bakeSpoofedProps(cfg);
    char buf[192];
    const char* res = nullptr;
    if (!lookupSpoofedPropertyIntoBuf(baked, name, orig_val, buf, sizeof(buf), &res) || !res) {
        return false;
    }
    const size_t n = std::strlen(res);
    if (n >= out_cap) return false;
    std::memcpy(out_buf, res, n + 1);
    return true;
}

inline bool isSanitizedProcMapsPath(const char* path, bool* out_is_smaps = nullptr) {
    if (!path || std::strncmp(path, "/proc/", 6) != 0) {
        return false;
    }
    const char* p = path + 6;
    if (std::strncmp(p, "self/", 5) == 0) {
        p += 5;
    } else if (std::strncmp(p, "thread-self/", 12) == 0) {
        p += 12;
    } else if (*p >= '0' && *p <= '9') {
        while (*p >= '0' && *p <= '9') {
            p++;
        }
        if (*p != '/') {
            return false;
        }
        p++;
    } else {
        return false;
    }
    if (std::strcmp(p, "maps") == 0) {
        if (out_is_smaps) *out_is_smaps = false;
        return true;
    }
    if (std::strcmp(p, "smaps") == 0) {
        if (out_is_smaps) *out_is_smaps = true;
        return true;
    }
    return false;
}

inline bool isSmapsHeaderLine(const char* line, size_t len) {
    if (!line || len == 0) {
        return false;
    }
    auto isHex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };
    size_t i = 0;
    size_t left_hex = 0;
    while (i < len && isHex(line[i])) {
        left_hex++;
        i++;
    }
    if (left_hex == 0 || i >= len || line[i] != '-') {
        return false;
    }
    i++; // consume '-'
    size_t right_hex = 0;
    while (i < len && isHex(line[i])) {
        right_hex++;
        i++;
    }
    if (right_hex == 0 || i >= len) {
        return false;
    }
    return line[i] == ' ' || line[i] == '\t';
}

namespace detail {

inline bool containsAsciiCaseInsensitive(const char* hay, size_t hay_len, const char* needle, size_t needle_len) {
    if (!hay || !needle || needle_len == 0 || hay_len < needle_len) {
        return false;
    }
    auto lowerChar = [](unsigned char c) -> unsigned char {
        return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c - 'A' + 'a') : c;
    };
    const size_t limit = hay_len - needle_len;
    for (size_t i = 0; i <= limit; i++) {
        size_t j = 0;
        while (j < needle_len &&
               lowerChar(static_cast<unsigned char>(hay[i + j])) ==
               lowerChar(static_cast<unsigned char>(needle[j]))) {
            j++;
        }
        if (j == needle_len) {
            return true;
        }
    }
    return false;
}

} // namespace detail

inline bool shouldHideProcMapsLine(const char* line, size_t len) {
    if (!line || len == 0) {
        return false;
    }
    static constexpr const char* kTokens[] = {
        "/data/adb/",
        "zygisk",
        "sandbox_guard",
        "libzygisk",
        "magisk",
        "kernelsu",
        "apatch",
        "lsposed",
        "lspd",
        "riru",
        "shamiko",
        "susfs",
        "debug_ramdisk",
    };
    for (const char* tok : kTokens) {
        if (detail::containsAsciiCaseInsensitive(line, len, tok, std::strlen(tok))) {
            return true;
        }
    }
    return false;
}

} // namespace stealth
