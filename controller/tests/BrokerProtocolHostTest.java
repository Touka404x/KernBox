package com.sandbox.controller;

import java.util.Arrays;
import java.util.Collections;

public final class BrokerProtocolHostTest {

    private static void assertTrue(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError(msg);
        }
    }

    private static void assertEquals(Object expected, Object actual, String msg) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(msg + ": expected=" + expected + " actual=" + actual);
        }
    }

    public static void main(String[] args) {
        testBuilders();
        testApkPathValidation();
        testParseStatusSnapshot();
        testParseErrorOfflineAndMalformed();
        System.out.println("BROKER_PROTOCOL_HOST_TESTS_PASSED");
    }

    private static void testBuilders() {
        assertEquals("{\"id\":\"r1\",\"op\":\"GET_STATUS\"}",
                BrokerProtocol.buildGetStatus("r1"), "GET_STATUS");
        assertEquals("{\"id\":\"r2\",\"op\":\"START_VPN\"}",
                BrokerProtocol.buildStartVpn("r2"), "START_VPN");
        assertEquals("{\"id\":\"r3\",\"op\":\"PAUSE_VPN\"}",
                BrokerProtocol.buildPauseVpn("r3"), "PAUSE_VPN");
        assertEquals("{\"id\":\"r3b\",\"op\":\"RUN_PROBE\"}",
                BrokerProtocol.buildRunProbe("r3b"), "RUN_PROBE");
        assertEquals("{\"id\":\"r4\",\"op\":\"IMPORT_EXISTING\",\"pkg\":\"org.mozilla.firefox\"}",
                BrokerProtocol.buildImportExisting("r4", "org.mozilla.firefox"), "IMPORT_EXISTING");
        assertEquals("{\"id\":\"r5\",\"op\":\"LAUNCH_APP\",\"pkg\":\"com.android.vending\"}",
                BrokerProtocol.buildLaunchApp("r5", "com.android.vending"), "LAUNCH_APP");
        assertEquals("{\"id\":\"r5b\",\"op\":\"STOP_APP\",\"pkg\":\"com.discord\"}",
                BrokerProtocol.buildStopApp("r5b", "com.discord"), "STOP_APP");
        assertEquals("{\"id\":\"r5c\",\"op\":\"REMOVE_APP\",\"pkg\":\"com.discord\"}",
                BrokerProtocol.buildRemoveApp("r5c", "com.discord"), "REMOVE_APP");
        assertEquals("{\"id\":\"r6\",\"op\":\"INSTALL_APK\",\"apk_paths\":[\"/data/local/tmp/a\\\"b.apk\"]}",
                BrokerProtocol.buildInstallApk("r6", "/data/local/tmp/a\"b.apk"), "INSTALL_APK escaping");
    }

    private static void testApkPathValidation() {
        assertTrue(BrokerProtocol.isAllowedApkPath("/data/local/tmp/app.apk"), "tmp apk");
        assertTrue(BrokerProtocol.isAllowedApkPath("  /data/adb/sandbox_guard/staging/base.apk  "), "staging apk");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/sdcard/Download/app.apk"), "reject sdcard");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/data/local/tmp/../etc.apk"), "reject dotdot");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/data/local/tmp/app.zip"), "reject non-apk");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/data/local/tmp/app;rm.apk"), "reject shell metachar");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/data/local/tmp/with space.apk"), "reject space");
        assertTrue(!BrokerProtocol.isAllowedApkPath(null), "reject null");
    }

    private static void testParseStatusSnapshot() {
        String sample = "{\"id\":\"kb-1\",\"ok\":true,\"error\":\"\",\"data\":{"
                + "\"version\":\"1.1.0\","
                + "\"variant\":\"hyperos-k510-ksu\","
                + "\"state\":\"OPEN\","
                + "\"mode\":\"tproxy\","
                + "\"active_preset\":\"jp-docomo\","
                + "\"paused\":false,"
                + "\"policy_loaded\":true,"
                + "\"sbw_open\":true,"
                + "\"sbw_raw_armed\":false,"
                + "\"frozen\":false,"
                + "\"hot_frozen\":true,"
                + "\"tproxy_ready\":true,"
                + "\"zygisk_disabled\":false,"
                + "\"private_dns_warning\":true,"
                + "\"probe_apk_installed\":true,"
                + "\"instrument_ok\":true,"
                + "\"user_id\":10,"
                + "\"u10_running_procs\":3,"
                + "\"hibernated_count\":2,"
                + "\"stuck_work_sockets\":1,"
                + "\"last_error\":\"\","
                + "\"vpn_status\":{\"running\":true,\"exit_ip\":\"198.51.100.2\"},"
                + "\"sandbox_apps\":[\"com.android.chrome\",\"com.example.\\u0061pp\"]"
                + "}}";

        BrokerProtocol.RpcResponse resp = BrokerProtocol.parseResponse(sample);
        assertTrue(resp.ok, "ok=true");
        assertTrue(!resp.offline, "offline=false");
        assertEquals("kb-1", resp.id, "id");
        assertEquals("hyperos-k510-ksu", resp.snapshot.variant, "variant");
        assertEquals("tproxy", resp.snapshot.mode, "mode");
        assertEquals("jp-docomo", resp.snapshot.activePreset, "active_preset");
        assertTrue(!resp.snapshot.paused, "paused=false");
        assertTrue(resp.snapshot.sbwOpen, "sbw_open=true");
        assertTrue(!resp.snapshot.sbwRawArmed, "sbw_raw_armed=false");
        assertTrue(resp.snapshot.hotFrozen, "hot_frozen=true");
        assertTrue(resp.snapshot.tproxyReady, "tproxy_ready=true");
        assertTrue(!resp.snapshot.zygiskDisabled, "zygisk_disabled=false");
        assertTrue(resp.snapshot.privateDnsWarning, "private_dns_warning=true");
        assertTrue(resp.snapshot.probeApkInstalled, "probe_apk_installed=true");
        assertTrue(resp.snapshot.instrumentOk, "instrument_ok=true");
        assertEquals(10, resp.snapshot.userId, "user_id");
        assertEquals(3, resp.snapshot.runningProcs, "running procs");
        assertEquals(1, resp.snapshot.stuckWorkSockets, "stuck sockets");
        assertEquals("198.51.100.2", resp.snapshot.exitIp, "exit_ip");
        assertEquals(Arrays.asList("com.android.chrome", "com.example.app"),
                resp.snapshot.sandboxApps, "sandbox_apps");
    }

    private static void testParseErrorOfflineAndMalformed() {
        BrokerProtocol.RpcResponse err = BrokerProtocol.parseResponse(
                "{\"id\":\"kb-2\",\"ok\":false,\"error\":\"policy not pinned\",\"data\":{\"sandbox_apps\":[]}}");
        assertTrue(!err.ok, "ok=false");
        assertTrue(!err.offline, "offline=false");
        assertEquals("policy not pinned", err.error, "error string");
        assertEquals(Collections.<String>emptyList(), err.snapshot.sandboxApps, "empty sandbox_apps");

        BrokerProtocol.RpcResponse empty = BrokerProtocol.parseResponse("   ");
        assertTrue(!empty.ok && empty.offline, "blank input is offline");

        BrokerProtocol.RpcResponse badJson = BrokerProtocol.parseResponse("{not json");
        assertTrue(!badJson.ok && !badJson.offline, "malformed JSON flagged cleanly");
        assertTrue(badJson.error.startsWith("malformed JSON"), "malformed JSON message");
    }
}
