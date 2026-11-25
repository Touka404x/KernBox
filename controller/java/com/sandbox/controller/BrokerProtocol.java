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
    public static final String OP_LAUNCH_APP = "LAUNCH_APP";

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

    public static String buildImportExisting(String id, String pkg) {
        return "{\"id\":" + quote(nonEmpty(id, "req"))
                + ",\"op\":" + quote(OP_IMPORT_EXISTING)
                + ",\"pkg\":" + quote(nonNull(pkg)) + "}";
    }

    public static String buildLaunchApp(String id, String pkg) {
        return "{\"id\":" + quote(nonEmpty(id, "req"))
                + ",\"op\":" + quote(OP_LAUNCH_APP)
                + ",\"pkg\":" + quote(nonNull(pkg)) + "}";
    }

    public static String buildInstallApk(String id, String apkPath) {
        return "{\"id\":" + quote(nonEmpty(id, "req"))
                + ",\"op\":" + quote(OP_INSTALL_APK)
                + ",\"apk_paths\":[" + quote(nonNull(apkPath)) + "]}";
    }

    private static String buildSimpleRequest(String id, String op) {
        return "{\"id\":" + quote(nonEmpty(id, "req")) + ",\"op\":" + quote(op) + "}";
    }

    public static boolean isAllowedApkPath(String rawPath) {
        if (rawPath == null) {
            return false;
        }
        String p = rawPath.trim();
        if (p.isEmpty() || !p.endsWith(".apk") || p.contains("..")) {
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
            Object parsed = new JsonParser(rawJson).parseValue();
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
            return new RpcResponse(id, ok, false, err, snapshot);
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
        String variant = asString(data.get("variant"), "");
        String state = asString(data.get("state"), "UNKNOWN");
        String mode = asString(data.get("mode"), "");
        boolean paused = asBoolean(data.get("paused"), true);
        boolean policyLoaded = asBoolean(data.get("policy_loaded"), false);
        boolean openGate = asBoolean(data.get("sbw_open"), false);
        boolean frozen = asBoolean(data.get("frozen"), false);
        boolean hotFrozen = asBoolean(data.get("hot_frozen"), false);
        int userId = asInt(data.get("user_id"), 10);
        int runningProcs = asInt(data.get("u10_running_procs"), 0);
        int hibernatedCount = asInt(data.get("hibernated_count"), 0);
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
                paused,
                policyLoaded,
                openGate,
                frozen,
                hotFrozen,
                vpnRunning,
                userId,
                runningProcs,
                hibernatedCount,
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
        public final String error;
        public final StatusSnapshot snapshot;

        public RpcResponse(String id, boolean ok, boolean offline, String error, StatusSnapshot snapshot) {
            this.id = id;
            this.ok = ok;
            this.offline = offline;
            this.error = error == null ? "" : error;
            this.snapshot = snapshot == null ? StatusSnapshot.empty() : snapshot;
        }

        public static RpcResponse error(String id, String error, boolean offline) {
            return new RpcResponse(id, false, offline, error, StatusSnapshot.empty());
        }
    }

    public static final class StatusSnapshot {
        public final String version;
        public final String variant;
        public final String state;
        public final String mode;
        public final boolean paused;
        public final boolean policyLoaded;
        public final boolean sbwOpen;
        public final boolean frozen;
        public final boolean hotFrozen;
        public final boolean vpnRunning;
        public final int userId;
        public final int runningProcs;
        public final int hibernatedCount;
        public final String exitIp;
        public final String lastError;
        public final List<String> sandboxApps;

        public StatusSnapshot(
                String version,
                String variant,
                String state,
                String mode,
                boolean paused,
                boolean policyLoaded,
                boolean sbwOpen,
                boolean frozen,
                boolean hotFrozen,
                boolean vpnRunning,
                int userId,
                int runningProcs,
                int hibernatedCount,
                String exitIp,
                String lastError,
                List<String> sandboxApps) {
            this.version = version;
            this.variant = variant;
            this.state = state;
            this.mode = mode;
            this.paused = paused;
            this.policyLoaded = policyLoaded;
            this.sbwOpen = sbwOpen;
            this.frozen = frozen;
            this.hotFrozen = hotFrozen;
            this.vpnRunning = vpnRunning;
            this.userId = userId;
            this.runningProcs = runningProcs;
            this.hibernatedCount = hibernatedCount;
            this.exitIp = exitIp;
            this.lastError = lastError;
            this.sandboxApps = sandboxApps;
        }

        public static StatusSnapshot empty() {
            return new StatusSnapshot(
                    "", "", "OFFLINE", "", true, false, false, false, false, false,
                    10, 0, 0, "", "", Collections.<String>emptyList()
            );
        }
    }

    private static final class JsonParser {
        private final String src;
        private int pos;

        JsonParser(String src) {
            this.src = src;
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
            Map<String, Object> map = new LinkedHashMap<String, Object>();
            pos++; // {
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
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<Object>();
            pos++; // [
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
