package com.sandbox.controller;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure-Java wire protocol matching guard/internal/contracts RPCRequest and RPCResponse.
 * Intentionally free of android.* imports so host JDK unit tests run cleanly.
 */
public final class BrokerProtocol {

    public static final String SOCKET_PATH = "/dev/socket/sandbox_ctrl/ctrl.sock";

    public static final String OP_GET_STATUS = "GET_STATUS";
    public static final String OP_IMPORT_EXISTING = "IMPORT_EXISTING";
    public static final String OP_INSTALL_APK = "INSTALL_APK";
    public static final String OP_START_VPN = "START_VPN";
    public static final String OP_PAUSE_VPN = "PAUSE_VPN";
    public static final String OP_RUN_PROBE = "RUN_PROBE";
    public static final String OP_LAUNCH_APP = "LAUNCH_APP";
    public static final String OP_STOP_APP = "STOP_APP";
    public static final String OP_REMOVE_APP = "REMOVE_APP";
    public static final String OP_RELOAD_CONFIG = "RELOAD_CONFIG";
    public static final String OP_SYNC_HIDE_APPS = "SYNC_HIDE_APPS";

    private static final int MAX_APK_PATH_LEN = 512;
    private static final int MAX_SPLIT_APKS = 32;

    public enum OfflineReason {
        NONE,
        DAEMON_DOWN,
        CERT_UNPINNED,
        SELINUX_DENIED
    }

    private BrokerProtocol() {}

    public static String buildGetStatus(String id) {
        return buildSimpleRequest(id, OP_GET_STATUS);
    }

    public static String buildStartVpn(String id) {
        return buildSimpleRequest(id, OP_START_VPN);
    }

    public static String buildPauseVpn(String id) {
        return buildSimpleRequest(id, OP_PAUSE_VPN);
    }

    public static String buildRunProbe(String id) {
        return buildSimpleRequest(id, OP_RUN_PROBE);
    }

    public static String buildSyncHideApps(String id) {
        return buildSimpleRequest(id, OP_SYNC_HIDE_APPS);
    }

    public static String buildReloadConfig(String id, String quicUdp443Mode, String logLevel) {
        StringBuilder cfg = new StringBuilder();
        if (quicUdp443Mode != null && !quicUdp443Mode.trim().isEmpty()) {
            cfg.append("\"quic_udp443_mode\":").append(quote(quicUdp443Mode.trim()));
        }
        if (logLevel != null && !logLevel.trim().isEmpty()) {
            if (cfg.length() > 0) {
                cfg.append(',');
            }
            cfg.append("\"log_level\":").append(quote(logLevel.trim()));
        }
        return "{\"id\":" + quote(nonEmpty(id, "req"))
                + ",\"op\":" + quote(OP_RELOAD_CONFIG)
                + ",\"config\":{" + cfg.toString() + "}}";
    }

    public static String buildImportExisting(String id, String pkg) {
        return buildPkgRequest(id, OP_IMPORT_EXISTING, pkg);
    }

    public static String buildLaunchApp(String id, String pkg) {
        return buildPkgRequest(id, OP_LAUNCH_APP, pkg);
    }

    public static String buildStopApp(String id, String pkg) {
        return buildPkgRequest(id, OP_STOP_APP, pkg);
    }

    public static String buildRemoveApp(String id, String pkg) {
        return buildPkgRequest(id, OP_REMOVE_APP, pkg);
    }

    public static String buildInstallApk(String id, String apkPath) {
        return buildInstallApks(id, Collections.singletonList(nonNull(apkPath)));
    }

    public static String buildInstallApks(String id, List<String> apkPaths) {
        StringBuilder arr = new StringBuilder("[");
        if (apkPaths != null) {
            for (int i = 0; i < apkPaths.size(); i++) {
                if (i > 0) {
                    arr.append(',');
                }
                arr.append(quote(nonNull(apkPaths.get(i))));
            }
        }
        arr.append(']');
        return "{\"id\":" + quote(nonEmpty(id, "req"))
                + ",\"op\":" + quote(OP_INSTALL_APK)
                + ",\"apk_paths\":" + arr.toString() + "}";
    }

    public static List<String> parseApkPathList(String rawText) {
        if (rawText == null) {
            return Collections.emptyList();
        }
        String[] parts = rawText.split("[\\r\\n,]+");
        List<String> out = new ArrayList<String>();
        for (String part : parts) {
            String p = part.trim();
            if (p.isEmpty()) {
                continue;
            }
            if (!isAllowedApkPath(p) || out.size() >= MAX_SPLIT_APKS) {
                return Collections.emptyList();
            }
            out.add(p);
        }
        return out;
    }

    private static String buildSimpleRequest(String id, String op) {
        return "{\"id\":" + quote(nonEmpty(id, "req")) + ",\"op\":" + quote(op) + "}";
    }

    private static String buildPkgRequest(String id, String op, String pkg) {
        return "{\"id\":" + quote(nonEmpty(id, "req"))
                + ",\"op\":" + quote(op)
                + ",\"pkg\":" + quote(nonNull(pkg)) + "}";
    }

    public static boolean isAllowedApkPath(String rawPath) {
        if (rawPath == null) {
            return false;
        }
        String p = rawPath.trim();
        if (p.isEmpty() || p.length() > MAX_APK_PATH_LEN || !p.endsWith(".apk") || p.contains("..")) {
            return false;
        }
        boolean inTmp = p.startsWith("/data/local/tmp/");
        boolean inStaging = p.startsWith("/data/adb/sandbox_guard/staging/");
        if (!inTmp && !inStaging) {
            return false;
        }
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            if (c <= 0x20 || c == ';' || c == '&' || c == '|' || c == '$'
                    || c == '`' || c == '\'' || c == '"' || c == '\\') {
                return false;
            }
        }
        return true;
    }

    public static RpcResponse parseResponse(String rawJson) {
        if (rawJson == null || rawJson.trim().isEmpty()) {
            return RpcResponse.error("", "empty response", true);
        }
        try {
            Object parsed = new JsonParser(rawJson).parseRoot();
            if (!(parsed instanceof Map)) {
                return RpcResponse.error("", "response is not a JSON object", false);
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> root = (Map<String, Object>) parsed;
            String id = asString(root.get("id"), "");
            boolean ok = asBoolean(root.get("ok"), false);
            String err = asString(root.get("error"), "");
            @SuppressWarnings("unchecked")
            Map<String, Object> data = root.get("data") instanceof Map
                    ? (Map<String, Object>) root.get("data")
                    : Collections.<String, Object>emptyMap();
            StatusSnapshot snapshot = parseSnapshot(data);
            return new RpcResponse(id, ok, false, OfflineReason.NONE, err, snapshot);
        } catch (IllegalArgumentException ex) {
            return RpcResponse.error("", "malformed JSON: " + ex.getMessage(), false);
        }
    }

    @SuppressWarnings("unchecked")
    public static StatusSnapshot parseSnapshot(Map<String, Object> data) {
        if (data == null || data.isEmpty()) {
            return StatusSnapshot.empty();
        }
        String version = asString(data.get("version"), "");
        String variant = extractVariant(data.get("variant"));
        String state = asString(data.get("state"), "UNKNOWN");
        String mode = asString(data.get("mode"), "");
        String activePreset = asString(data.get("active_preset"), "neutral");
        boolean paused = asBoolean(data.get("paused"), true);
        boolean policyLoaded = asBoolean(data.get("policy_loaded"), false);
        boolean openGate = asBoolean(data.get("sbw_open"), false);
        boolean sbwRawArmed = asBoolean(data.get("sbw_raw_armed"), false);
        boolean frozen = asBoolean(data.get("frozen"), false);
        boolean hotFrozen = asBoolean(data.get("hot_frozen"), false);
        boolean tproxyReady = asBoolean(data.get("tproxy_ready"), false);
        boolean zygiskDisabled = asBoolean(data.get("zygisk_disabled"), false);
        boolean privateDnsWarning = asBoolean(data.get("private_dns_warning"), false);
        boolean probeApkInstalled = asBoolean(data.get("probe_apk_installed"), false);
        boolean instrumentOk = asBoolean(data.get("instrument_ok"), false);
        boolean hasProbeData = data.containsKey("probe_apk_installed") || data.containsKey("instrument_ok");
        int userId = asInt(data.get("user_id"), 10);
        int runningProcs = asInt(data.get("u10_running_procs"), 0);
        int hibernatedCount = asInt(data.get("hibernated_count"), 0);
        int stuckWorkSockets = asInt(data.get("stuck_work_sockets"), 0);
        int tproxyPort = asInt(data.get("tproxy_port"), 1537);
        int stealthBootTries = asInt(data.get("stealth_boot_tries"), 0);
        String privateDnsMode = asString(data.get("private_dns_mode"), "");
        int scorecardPassed = 0;
        int scorecardFailed = 0;
        int scorecardWarn = 0;
        int scorecardTotal = 0;
        if (data.get("probe_result") instanceof Map) {
            Map<String, Object> pr = (Map<String, Object>) data.get("probe_result");
            if (pr.get("real_device_scorecard") instanceof Map) {
                Map<String, Object> sc = (Map<String, Object>) pr.get("real_device_scorecard");
                scorecardPassed = asInt(sc.get("passed"), 0);
                scorecardFailed = asInt(sc.get("failed"), 0);
                scorecardWarn = sc.containsKey("warnings") ? asInt(sc.get("warnings"), 0) : asInt(sc.get("warn"), 0);
                scorecardTotal = asInt(sc.get("total"), scorecardPassed + scorecardFailed + scorecardWarn);
            }
        }
        String lastError = asString(data.get("last_error"), "");
        String exitIp = "";
        boolean vpnRunning = openGate;
        if (data.get("vpn_status") instanceof Map) {
            Map<String, Object> vpn = (Map<String, Object>) data.get("vpn_status");
            exitIp = asString(vpn.get("exit_ip"), "");
            vpnRunning = asBoolean(vpn.get("running"), openGate);
        }
        List<String> apps = new ArrayList<String>();
        if (data.get("sandbox_apps") instanceof List) {
            for (Object item : (List<Object>) data.get("sandbox_apps")) {
                if (item instanceof String) {
                    String s = ((String) item).trim();
                    if (!s.isEmpty()) {
                        apps.add(s);
                    }
                }
            }
        }
        return new StatusSnapshot(
                version,
                variant,
                state,
                mode,
                activePreset,
                paused,
                policyLoaded,
                openGate,
                sbwRawArmed,
                frozen,
                hotFrozen,
                tproxyReady,
                zygiskDisabled,
                privateDnsWarning,
                probeApkInstalled,
                instrumentOk,
                hasProbeData,
                vpnRunning,
                userId,
                runningProcs,
                hibernatedCount,
                stuckWorkSockets,
                tproxyPort,
                stealthBootTries,
                privateDnsMode,
                scorecardPassed,
                scorecardFailed,
                scorecardWarn,
                scorecardTotal,
                exitIp,
                lastError,
                Collections.unmodifiableList(apps)
        );
    }

    private static String nonNull(String s) {
        return s == null ? "" : s;
    }

    private static String nonEmpty(String s, String fallback) {
        return (s == null || s.trim().isEmpty()) ? fallback : s;
    }

    private static String asString(Object v, String fallback) {
        return v instanceof String ? (String) v : fallback;
    }

    @SuppressWarnings("unchecked")
    private static String extractVariant(Object raw) {
        if (raw instanceof String) {
            return (String) raw;
        }
        if (raw instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) raw;
            String oem = asString(m.get("oem"), "").trim();
            String kernel = asString(m.get("kernel"), "").trim();
            if (!oem.isEmpty() && !kernel.isEmpty()) {
                return oem + "-" + kernel;
            }
            if (!oem.isEmpty()) {
                return oem;
            }
        }
        return "";
    }

    private static boolean asBoolean(Object v, boolean fallback) {
        return v instanceof Boolean ? ((Boolean) v).booleanValue() : fallback;
    }

    private static int asInt(Object v, int fallback) {
        return v instanceof Number ? ((Number) v).intValue() : fallback;
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        sb.append('"');
        return sb.toString();
    }

    public static final class RpcResponse {
        public final String id;
        public final boolean ok;
        public final boolean offline;
        public final OfflineReason offlineReason;
        public final String error;
        public final StatusSnapshot snapshot;

        public RpcResponse(String id, boolean ok, boolean offline, String error, StatusSnapshot snapshot) {
            this(id, ok, offline, offline ? OfflineReason.DAEMON_DOWN : OfflineReason.NONE, error, snapshot);
        }

        public RpcResponse(String id, boolean ok, boolean offline, OfflineReason offlineReason, String error, StatusSnapshot snapshot) {
            this.id = id;
            this.ok = ok;
            this.offline = offline;
            this.offlineReason = offlineReason == null ? OfflineReason.NONE : offlineReason;
            this.error = error == null ? "" : error;
            this.snapshot = snapshot == null ? StatusSnapshot.empty() : snapshot;
        }

        public static RpcResponse error(String id, String error, boolean offline) {
            return new RpcResponse(id, false, offline, offline ? OfflineReason.DAEMON_DOWN : OfflineReason.NONE, error, StatusSnapshot.empty());
        }

        public static RpcResponse error(String id, String error, OfflineReason reason) {
            boolean off = reason != null && reason != OfflineReason.NONE;
            return new RpcResponse(id, false, off, reason, error, StatusSnapshot.empty());
        }
    }

    public static final class StatusSnapshot {
        public final String version;
        public final String variant;
        public final String state;
        public final String mode;
        public final String activePreset;
        public final boolean paused;
        public final boolean policyLoaded;
        public final boolean sbwOpen;
        public final boolean sbwRawArmed;
        public final boolean frozen;
        public final boolean hotFrozen;
        public final boolean tproxyReady;
        public final boolean zygiskDisabled;
        public final boolean privateDnsWarning;
        public final boolean probeApkInstalled;
        public final boolean instrumentOk;
        public final boolean hasProbeData;
        public final boolean vpnRunning;
        public final int userId;
        public final int runningProcs;
        public final int hibernatedCount;
        public final int stuckWorkSockets;
        public final int tproxyPort;
        public final int stealthBootTries;
        public final String privateDnsMode;
        public final int scorecardPassed;
        public final int scorecardFailed;
        public final int scorecardWarn;
        public final int scorecardTotal;
        public final String exitIp;
        public final String lastError;
        public final List<String> sandboxApps;

        public StatusSnapshot(
                String version,
                String variant,
                String state,
                String mode,
                String activePreset,
                boolean paused,
                boolean policyLoaded,
                boolean sbwOpen,
                boolean sbwRawArmed,
                boolean frozen,
                boolean hotFrozen,
                boolean tproxyReady,
                boolean zygiskDisabled,
                boolean privateDnsWarning,
                boolean probeApkInstalled,
                boolean instrumentOk,
                boolean hasProbeData,
                boolean vpnRunning,
                int userId,
                int runningProcs,
                int hibernatedCount,
                int stuckWorkSockets,
                int tproxyPort,
                int stealthBootTries,
                String privateDnsMode,
                int scorecardPassed,
                int scorecardFailed,
                int scorecardWarn,
                int scorecardTotal,
                String exitIp,
                String lastError,
                List<String> sandboxApps) {
            this.version = version;
            this.variant = variant;
            this.state = state;
            this.mode = mode;
            this.activePreset = activePreset;
            this.paused = paused;
            this.policyLoaded = policyLoaded;
            this.sbwOpen = sbwOpen;
            this.sbwRawArmed = sbwRawArmed;
            this.frozen = frozen;
            this.hotFrozen = hotFrozen;
            this.tproxyReady = tproxyReady;
            this.zygiskDisabled = zygiskDisabled;
            this.privateDnsWarning = privateDnsWarning;
            this.probeApkInstalled = probeApkInstalled;
            this.instrumentOk = instrumentOk;
            this.hasProbeData = hasProbeData;
            this.vpnRunning = vpnRunning;
            this.userId = userId;
            this.runningProcs = runningProcs;
            this.hibernatedCount = hibernatedCount;
            this.stuckWorkSockets = stuckWorkSockets;
            this.tproxyPort = tproxyPort;
            this.stealthBootTries = stealthBootTries;
            this.privateDnsMode = privateDnsMode;
            this.scorecardPassed = scorecardPassed;
            this.scorecardFailed = scorecardFailed;
            this.scorecardWarn = scorecardWarn;
            this.scorecardTotal = scorecardTotal;
            this.exitIp = exitIp;
            this.lastError = lastError;
            this.sandboxApps = sandboxApps;
        }

        public StatusSnapshot withPreservedProbeFrom(StatusSnapshot prev) {
            if (this.hasProbeData || prev == null || !prev.hasProbeData) {
                return this;
            }
            return new StatusSnapshot(
                    version, variant, state, mode, activePreset, paused, policyLoaded, sbwOpen, sbwRawArmed,
                    frozen, hotFrozen, tproxyReady, zygiskDisabled, privateDnsWarning,
                    prev.probeApkInstalled, prev.instrumentOk, true, vpnRunning,
                    userId, runningProcs, hibernatedCount, stuckWorkSockets,
                    tproxyPort, stealthBootTries, privateDnsMode,
                    prev.scorecardPassed, prev.scorecardFailed, prev.scorecardWarn, prev.scorecardTotal,
                    exitIp, lastError, sandboxApps
            );
        }

        public String toRedactedDiagnosticJson() {
            return "{\n"
                    + "  \"version\": " + quote(nonNull(version)) + ",\n"
                    + "  \"variant\": " + quote(nonNull(variant)) + ",\n"
                    + "  \"state\": " + quote(nonNull(state)) + ",\n"
                    + "  \"mode\": " + quote(nonNull(mode)) + ",\n"
                    + "  \"active_preset\": " + quote(nonNull(activePreset)) + ",\n"
                    + "  \"paused\": " + paused + ",\n"
                    + "  \"policy_loaded\": " + policyLoaded + ",\n"
                    + "  \"sbw_open\": " + sbwOpen + ",\n"
                    + "  \"sbw_raw_armed\": " + sbwRawArmed + ",\n"
                    + "  \"tproxy_ready\": " + tproxyReady + ",\n"
                    + "  \"tproxy_port\": " + tproxyPort + ",\n"
                    + "  \"zygisk_disabled\": " + zygiskDisabled + ",\n"
                    + "  \"stealth_boot_tries\": " + stealthBootTries + ",\n"
                    + "  \"private_dns_mode\": " + quote(nonNull(privateDnsMode)) + ",\n"
                    + "  \"private_dns_warning\": " + privateDnsWarning + ",\n"
                    + "  \"stuck_work_sockets\": " + stuckWorkSockets + ",\n"
                    + "  \"sandbox_apps_count\": " + sandboxApps.size() + ",\n"
                    + "  \"has_probe_data\": " + hasProbeData + ",\n"
                    + "  \"probe_apk_installed\": " + probeApkInstalled + ",\n"
                    + "  \"instrument_ok\": " + instrumentOk + ",\n"
                    + "  \"scorecard\": {\"passed\": " + scorecardPassed + ", \"warn\": " + scorecardWarn + ", \"failed\": " + scorecardFailed + ", \"total\": " + scorecardTotal + "},\n"
                    + "  \"last_error\": " + quote(nonNull(lastError)) + "\n"
                    + "}";
        }

        public static StatusSnapshot empty() {
            return new StatusSnapshot(
                    "", "", "OFFLINE", "", "neutral",
                    true, false, false, false, false, false, false, false, false, false, false, false, false,
                    10, 0, 0, 0, 1537, 0, "", 0, 0, 0, 0, "", "", Collections.<String>emptyList()
            );
        }
    }

    private static final class JsonParser {
        private static final int MAX_DEPTH = 32;
        private final String src;
        private int pos;
        private int depth;

        JsonParser(String src) {
            this.src = src;
        }

        Object parseRoot() {
            Object val = parseValue();
            skipWs();
            if (pos != src.length()) {
                throw new IllegalArgumentException("trailing content at " + pos);
            }
            return val;
        }

        Object parseValue() {
            skipWs();
            if (pos >= src.length()) {
                throw new IllegalArgumentException("unexpected end of input");
            }
            char c = src.charAt(pos);
            switch (c) {
                case '{':
                    return parseObject();
                case '[':
                    return parseArray();
                case '"':
                    return parseString();
                case 't':
                    expectLiteral("true");
                    return Boolean.TRUE;
                case 'f':
                    expectLiteral("false");
                    return Boolean.FALSE;
                case 'n':
                    expectLiteral("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return parseNumber();
                    }
                    throw new IllegalArgumentException("unexpected token '" + c + "' at " + pos);
            }
        }

        private Map<String, Object> parseObject() {
            if (++depth > MAX_DEPTH) {
                throw new IllegalArgumentException("nesting too deep");
            }
            try {
                Map<String, Object> map = new LinkedHashMap<String, Object>();
                pos++;
                skipWs();
                if (peek('}')) {
                    pos++;
                    return map;
                }
                while (true) {
                    skipWs();
                    if (!peek('"')) {
                        throw new IllegalArgumentException("expected object key at " + pos);
                    }
                    String key = parseString();
                    skipWs();
                    expectChar(':');
                    Object val = parseValue();
                    map.put(key, val);
                    skipWs();
                    if (peek(',')) {
                        pos++;
                    } else if (peek('}')) {
                        pos++;
                        return map;
                    } else {
                        throw new IllegalArgumentException("expected ',' or '}' at " + pos);
                    }
                }
            } finally {
                depth--;
            }
        }

        private List<Object> parseArray() {
            if (++depth > MAX_DEPTH) {
                throw new IllegalArgumentException("nesting too deep");
            }
            try {
                List<Object> list = new ArrayList<Object>();
                pos++;
                skipWs();
                if (peek(']')) {
                    pos++;
                    return list;
                }
                while (true) {
                    list.add(parseValue());
                    skipWs();
                    if (peek(',')) {
                        pos++;
                    } else if (peek(']')) {
                        pos++;
                        return list;
                    } else {
                        throw new IllegalArgumentException("expected ',' or ']' at " + pos);
                    }
                }
            } finally {
                depth--;
            }
        }

        private String parseString() {
            expectChar('"');
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (pos >= src.length()) {
                        throw new IllegalArgumentException("unterminated escape");
                    }
                    char esc = src.charAt(pos++);
                    switch (esc) {
                        case '"':
                        case '\\':
                        case '/':
                            sb.append(esc);
                            break;
                        case 'b':
                            sb.append('\b');
                            break;
                        case 'f':
                            sb.append('\f');
                            break;
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'u':
                            if (pos + 4 > src.length()) {
                                throw new IllegalArgumentException("bad unicode escape");
                            }
                            int code = Integer.parseInt(src.substring(pos, pos + 4), 16);
                            sb.append((char) code);
                            pos += 4;
                            break;
                        default:
                            throw new IllegalArgumentException("invalid escape \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("unterminated string");
        }

        private Number parseNumber() {
            int start = pos;
            if (peek('-')) {
                pos++;
            }
            while (pos < src.length() && src.charAt(pos) >= '0' && src.charAt(pos) <= '9') {
                pos++;
            }
            boolean isFloat = false;
            if (pos < src.length() && src.charAt(pos) == '.') {
                isFloat = true;
                pos++;
                while (pos < src.length() && src.charAt(pos) >= '0' && src.charAt(pos) <= '9') {
                    pos++;
                }
            }
            if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
                isFloat = true;
                pos++;
                if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) {
                    pos++;
                }
                while (pos < src.length() && src.charAt(pos) >= '0' && src.charAt(pos) <= '9') {
                    pos++;
                }
            }
            String token = src.substring(start, pos);
            try {
                return isFloat ? (Number) Double.valueOf(token) : (Number) Long.valueOf(token);
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("bad number " + token);
            }
        }

        private void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private boolean peek(char expected) {
            return pos < src.length() && src.charAt(pos) == expected;
        }

        private void expectChar(char expected) {
            if (pos >= src.length() || src.charAt(pos) != expected) {
                throw new IllegalArgumentException("expected '" + expected + "' at " + pos);
            }
            pos++;
        }

        private void expectLiteral(String lit) {
            if (!src.startsWith(lit, pos)) {
                throw new IllegalArgumentException("expected " + lit + " at " + pos);
            }
            pos += lit.length();
        }
    }
}
