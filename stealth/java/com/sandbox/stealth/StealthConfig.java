package com.sandbox.stealth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure-Java configuration model and UID filter for the SystemServer/Phone stealth proxy.
 * Uses a zero-dependency JSON object parser so it runs identically inside Android
 * system_server/phone and host JDK 21 unit tests without android.jar stub conflicts.
 */
public final class StealthConfig {
    private static final int USER_UID_STRIDE = 100000;
    private static final int FIRST_APP_ID = 10000;

    public final boolean enabled;
    public final int sandboxUserId;
    public final int exemptWorkUid;
    public final int[] exemptUids;
    public final String timezone;
    public final String locale;
    public final String simOperator;
    public final String simOperatorName;
    public final String simCountryIso;
    public final String networkOperator;
    public final String networkOperatorName;
    public final String networkCountryIso;
    public final boolean hideManagedProfile;
    public final String spoofLocationMode;
    public final boolean blockWifiScan;
    public final boolean spoofCarrier;
    public final boolean sanitizeNetwork;
    public final boolean spoofBluetooth;
    public final boolean spoofDeviceRegion;
    public final String sandboxLinkIpv4;
    public final String deviceName;
    public final String deviceRegion;
    public final String bootHwc;

    public StealthConfig(
            boolean enabled,
            int sandboxUserId,
            int exemptWorkUid,
            String timezone,
            String locale,
            String simOperator,
            String simOperatorName,
            String simCountryIso,
            String networkOperator,
            String networkOperatorName,
            String networkCountryIso,
            boolean hideManagedProfile,
            String spoofLocationMode,
            boolean blockWifiScan,
            boolean spoofCarrier) {
        this(
                enabled,
                sandboxUserId,
                exemptWorkUid,
                null,
                timezone,
                locale,
                simOperator,
                simOperatorName,
                simCountryIso,
                networkOperator,
                networkOperatorName,
                networkCountryIso,
                hideManagedProfile,
                spoofLocationMode,
                blockWifiScan,
                spoofCarrier,
                true,
                true,
                "10.172.10.2",
                "Android");
    }

    public StealthConfig(
            boolean enabled,
            int sandboxUserId,
            int exemptWorkUid,
            int[] exemptUids,
            String timezone,
            String locale,
            String simOperator,
            String simOperatorName,
            String simCountryIso,
            String networkOperator,
            String networkOperatorName,
            String networkCountryIso,
            boolean hideManagedProfile,
            String spoofLocationMode,
            boolean blockWifiScan,
            boolean spoofCarrier) {
        this(
                enabled,
                sandboxUserId,
                exemptWorkUid,
                exemptUids,
                timezone,
                locale,
                simOperator,
                simOperatorName,
                simCountryIso,
                networkOperator,
                networkOperatorName,
                networkCountryIso,
                hideManagedProfile,
                spoofLocationMode,
                blockWifiScan,
                spoofCarrier,
                true,
                true,
                "10.172.10.2",
                "Android");
    }

    public StealthConfig(
            boolean enabled,
            int sandboxUserId,
            int exemptWorkUid,
            int[] exemptUids,
            String timezone,
            String locale,
            String simOperator,
            String simOperatorName,
            String simCountryIso,
            String networkOperator,
            String networkOperatorName,
            String networkCountryIso,
            boolean hideManagedProfile,
            String spoofLocationMode,
            boolean blockWifiScan,
            boolean spoofCarrier,
            boolean sanitizeNetwork,
            boolean spoofBluetooth,
            String sandboxLinkIpv4,
            String deviceName) {
        this(
                enabled,
                sandboxUserId,
                exemptWorkUid,
                exemptUids,
                timezone,
                locale,
                simOperator,
                simOperatorName,
                simCountryIso,
                networkOperator,
                networkOperatorName,
                networkCountryIso,
                hideManagedProfile,
                spoofLocationMode,
                blockWifiScan,
                spoofCarrier,
                sanitizeNetwork,
                spoofBluetooth,
                false,
                sandboxLinkIpv4,
                deviceName,
                "",
                "");
    }

    public StealthConfig(
            boolean enabled,
            int sandboxUserId,
            int exemptWorkUid,
            int[] exemptUids,
            String timezone,
            String locale,
            String simOperator,
            String simOperatorName,
            String simCountryIso,
            String networkOperator,
            String networkOperatorName,
            String networkCountryIso,
            boolean hideManagedProfile,
            String spoofLocationMode,
            boolean blockWifiScan,
            boolean spoofCarrier,
            boolean sanitizeNetwork,
            boolean spoofBluetooth,
            boolean spoofDeviceRegion,
            String sandboxLinkIpv4,
            String deviceName,
            String deviceRegion,
            String bootHwc) {
        this.enabled = enabled;
        this.sandboxUserId = sandboxUserId;
        this.exemptWorkUid = exemptWorkUid;
        this.exemptUids = normalizeExemptUids(exemptWorkUid, exemptUids);
        this.timezone = timezone;
        this.locale = locale;
        this.simOperator = simOperator != null ? simOperator : "";
        this.simOperatorName = simOperatorName != null ? simOperatorName : "";
        this.simCountryIso = simCountryIso != null ? simCountryIso : "";
        this.networkOperator = networkOperator != null ? networkOperator : "";
        this.networkOperatorName = networkOperatorName != null ? networkOperatorName : "";
        this.networkCountryIso = networkCountryIso != null ? networkCountryIso : "";
        this.hideManagedProfile = hideManagedProfile;
        this.spoofLocationMode = spoofLocationMode;
        this.blockWifiScan = blockWifiScan;
        this.spoofCarrier = spoofCarrier;
        this.sanitizeNetwork = sanitizeNetwork;
        this.spoofBluetooth = spoofBluetooth;
        this.spoofDeviceRegion = spoofDeviceRegion;
        this.sandboxLinkIpv4 = nonEmptyOrDefault(sandboxLinkIpv4, "10.172.10.2");
        this.deviceName = nonEmptyOrDefault(deviceName, "Android");
        this.deviceRegion = deviceRegion != null ? deviceRegion : "";
        this.bootHwc = bootHwc != null ? bootHwc : "";
    }

    private static int[] normalizeExemptUids(int workUid, int[] extra) {
        int extraLen = extra == null ? 0 : extra.length;
        int[] buf = new int[extraLen + (workUid > 0 ? 1 : 0)];
        int count = 0;
        if (workUid > 0) {
            buf[count++] = workUid;
        }
        if (extra != null) {
            for (int uid : extra) {
                if (uid <= 0) continue;
                boolean dup = false;
                for (int i = 0; i < count; i++) {
                    if (buf[i] == uid) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    buf[count++] = uid;
                }
            }
        }
        return count == buf.length ? buf : Arrays.copyOf(buf, count);
    }

    public static StealthConfig defaults() {
        return new StealthConfig(
                true,
                10,
                -1,
                null,
                "UTC",
                "en-US",
                "",
                "",
                "",
                "",
                "",
                "",
                true,
                "block",
                true,
                false);
    }

    public static StealthConfig fromJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return new StealthConfig(
                    false, 10, -1, null, "UTC", "en-US",
                    "", "", "", "", "", "",
                    true, "block", true, false);
        }
        Map<String, String> kv = parseFlatJson(json);
        if (kv.isEmpty()) {
            return new StealthConfig(
                    false, 10, -1, null, "UTC", "en-US",
                    "", "", "", "", "", "",
                    true, "block", true, false);
        }
        boolean enabled = parseBool(kv.get("enabled"), false);
        int userId = parseInt(kv.get("sandbox_user_id"), 10);
        int exemptUid = parseInt(kv.get("exempt_work_uid"), -1);
        int[] exemptUids = parseIntArray(kv.get("exempt_uids"));
        String tz = nonEmptyOrDefault(kv.get("timezone"), "UTC");
        String loc = nonEmptyOrDefault(kv.get("locale"), "en-US");
        String simOp = nonEmptyOrDefault(kv.get("sim_operator"), "");
        String simAlpha = nonEmptyOrDefault(kv.get("sim_operator_name"), "");
        String simIso = nonEmptyOrDefault(kv.get("sim_country_iso"), "");
        String netOp = nonEmptyOrDefault(kv.get("network_operator"), simOp);
        String netAlpha = nonEmptyOrDefault(kv.get("network_operator_name"), simAlpha);
        String netIso = nonEmptyOrDefault(kv.get("network_country_iso"), simIso);
        boolean hideManaged = parseBool(kv.get("hide_managed_profile"), true);
        String locMode = nonEmptyOrDefault(kv.get("spoof_location_mode"), "block");
        boolean blockWifi = parseBool(kv.get("block_wifi_scan"), true);
        boolean carrier = parseBool(kv.get("spoof_carrier"), false);
        boolean sanitizeNet = parseBool(kv.get("sanitize_network"), true);
        boolean spoofBt = parseBool(kv.get("spoof_bluetooth"), true);
        boolean spoofRegion = parseBool(kv.get("spoof_device_region"), false);
        String linkIpv4 = nonEmptyOrDefault(kv.get("sandbox_link_ipv4"), "10.172.10.2");
        String devName = nonEmptyOrDefault(kv.get("device_name"), "Android");
        String primaryRegion = kv.get("device_region");
        String legacyRegion = kv.get("miui_region");
        String region = (primaryRegion != null && !primaryRegion.isEmpty())
                ? primaryRegion
                : nonEmptyOrDefault(legacyRegion, "");
        String hwc = nonEmptyOrDefault(kv.get("boot_hwc"), "");

        return new StealthConfig(
                enabled, userId, exemptUid, exemptUids, tz, loc,
                simOp, simAlpha, simIso, netOp, netAlpha, netIso,
                hideManaged, locMode, blockWifi, carrier,
                sanitizeNet, spoofBt, spoofRegion, linkIpv4, devName, region, hwc);
    }

    /**
     * Only intercept non-exempt ordinary app UIDs inside the designated sandbox profile.
     * User 0 (< 100000), clone user 999, system UIDs (< 10000 appId),
     * and exempt controller/provisioning UIDs pass straight through unmodified.
     */
    public boolean shouldIntercept(int callingUid) {
        if (!enabled || sandboxUserId <= 0 || sandboxUserId == 999) {
            return false;
        }
        if (callingUid < USER_UID_STRIDE) {
            return false;
        }
        if ((callingUid / USER_UID_STRIDE) != sandboxUserId) {
            return false;
        }
        int appId = callingUid % USER_UID_STRIDE;
        if (appId < FIRST_APP_ID || appId >= USER_UID_STRIDE) {
            return false;
        }
        for (int i = 0; i < exemptUids.length; i++) {
            if (callingUid == exemptUids[i]) {
                return false;
            }
        }
        return true;
    }

    private static String nonEmptyOrDefault(String v, String def) {
        return (v == null || v.isEmpty()) ? def : v;
    }

    private static boolean parseBool(String v, boolean def) {
        if (v == null) return def;
        if ("true".equalsIgnoreCase(v)) return true;
        if ("false".equalsIgnoreCase(v)) return false;
        return def;
    }

    private static int parseInt(String v, int def) {
        if (v == null) return def;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException ignored) {
            return def;
        }
    }

    private static int[] parseIntArray(String raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        List<Integer> vals = new ArrayList<>();
        int n = raw.length();
        int i = 0;
        while (i < n) {
            char c = raw.charAt(i);
            if ((c >= '0' && c <= '9') || c == '-') {
                int start = i++;
                while (i < n && raw.charAt(i) >= '0' && raw.charAt(i) <= '9') {
                    i++;
                }
                try {
                    vals.add(Integer.parseInt(raw.substring(start, i)));
                } catch (NumberFormatException ignored) {
                }
            } else {
                i++;
            }
        }
        if (vals.isEmpty()) {
            return null;
        }
        int[] out = new int[vals.size()];
        for (int k = 0; k < vals.size(); k++) {
            out[k] = vals.get(k);
        }
        return out;
    }

    static Map<String, String> parseFlatJson(String json) {
        Map<String, String> map = new HashMap<>();
        if (json == null) {
            return map;
        }
        int n = json.length();
        int i = skipWs(json, 0);
        if (i >= n || json.charAt(i) != '{') {
            return map;
        }
        i++;
        while (i < n) {
            i = skipWs(json, i);
            if (i < n && json.charAt(i) == ',') {
                i = skipWs(json, i + 1);
            }
            if (i >= n || json.charAt(i) == '}') {
                break;
            }
            if (json.charAt(i) != '"') {
                break;
            }
            StringBuilder key = new StringBuilder();
            i = readJsonString(json, i + 1, key);
            if (i < 0) {
                break;
            }
            i = skipWs(json, i);
            if (i >= n || json.charAt(i) != ':') {
                break;
            }
            i = skipWs(json, i + 1);
            if (i >= n) {
                break;
            }
            char c = json.charAt(i);
            if (c == '"') {
                StringBuilder val = new StringBuilder();
                i = readJsonString(json, i + 1, val);
                if (i < 0) {
                    break;
                }
                map.put(key.toString(), val.toString());
            } else if (c == '[') {
                int vStart = i;
                i = skipJsonCompound(json, i, '[', ']');
                if (i < 0) {
                    break;
                }
                map.put(key.toString(), json.substring(vStart, i));
            } else if (c == '{') {
                // Skip nested objects completely so nested fields never overwrite top-level keys.
                i = skipJsonCompound(json, i, '{', '}');
                if (i < 0) {
                    break;
                }
            } else {
                int vStart = i;
                while (i < n && json.charAt(i) != ',' && json.charAt(i) != '}' && !Character.isWhitespace(json.charAt(i))) {
                    i++;
                }
                map.put(key.toString(), json.substring(vStart, i));
            }
        }
        return map;
    }

    private static int skipWs(String s, int i) {
        int n = s.length();
        while (i < n && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        return i;
    }

    private static int skipJsonCompound(String s, int start, char openCh, char closeCh) {
        int n = s.length();
        int depth = 0;
        int i = start;
        StringBuilder discard = new StringBuilder();
        while (i < n) {
            char c = s.charAt(i);
            if (c == '"') {
                discard.setLength(0);
                i = readJsonString(s, i + 1, discard);
                if (i < 0) {
                    return -1;
                }
                continue;
            }
            if (c == openCh) {
                depth++;
            } else if (c == closeCh) {
                depth--;
                if (depth == 0) {
                    return i + 1;
                }
            }
            i++;
        }
        return -1;
    }

    private static int readJsonString(String s, int from, StringBuilder out) {
        int n = s.length();
        int i = from;
        while (i < n) {
            char c = s.charAt(i++);
            if (c == '"') return i;
            if (c == '\\' && i < n) {
                char esc = s.charAt(i++);
                switch (esc) {
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u':
                        if (i + 4 <= n) {
                            try {
                                out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            } catch (NumberFormatException ignored) {}
                            i += 4;
                        }
                        break;
                    default: out.append(esc); break;
                }
            } else {
                out.append(c);
            }
        }
        return -1;
    }
}
