package com.sandbox.controller;

import java.util.Arrays;

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
        testParseErrorAndOffline();
        System.out.println("BROKER_PROTOCOL_HOST_TESTS_PASSED");
    }

    private static void testBuilders() {
        assertEquals("{\"id\":\"r1\",\"op\":\"GET_STATUS\"}",
                BrokerProtocol.buildGetStatus("r1"), "GET_STATUS");
        assertEquals("{\"id\":\"r2\",\"op\":\"START_VPN\"}",
                BrokerProtocol.buildStartVpn("r2"), "START_VPN");
        assertEquals("{\"id\":\"r3\",\"op\":\"PAUSE_VPN\"}",
                BrokerProtocol.buildPauseVpn("r3"), "PAUSE_VPN");
        assertEquals("{\"id\":\"r4\",\"op\":\"IMPORT_EXISTING\",\"pkg\":\"org.mozilla.firefox\"}",
                BrokerProtocol.buildImportExisting("r4", "org.mozilla.firefox"), "IMPORT_EXISTING");
        assertEquals("{\"id\":\"r5\",\"op\":\"LAUNCH_APP\",\"pkg\":\"com.android.vending\"}",
                BrokerProtocol.buildLaunchApp("r5", "com.android.vending"), "LAUNCH_APP");
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
    }

    private static void testParseStatusSnapshot() {
        String sample = "{\"id\":\"kb-1\",\"ok\":true,\"error\":\"\",\"data\":{"
                + "\"version\":\"1.0.0\","
                + "\"variant\":\"hyperos-k510-ksu\","
                + "\"state\":\"OPEN\","
                + "\"mode\":\"tproxy\","
                + "\"paused\":false,"
                + "\"policy_loaded\":true,"
                + "\"sbw_open\":true,"
                + "\"frozen\":false,"
                + "\"hot_frozen\":true,"
                + "\"user_id\":10,"
                + "\"u10_running_procs\":3,"
                + "\"hibernated_count\":2,"
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
        assertTrue(!resp.snapshot.paused, "paused=false");
        assertTrue(resp.snapshot.sbwOpen, "sbw_open=true");
        assertTrue(resp.snapshot.hotFrozen, "hot_frozen=true");
        assertEquals(10, resp.snapshot.userId, "user_id");
        assertEquals(3, resp.snapshot.runningProcs, "running procs");
        assertEquals("198.51.100.2", resp.snapshot.exitIp, "exit_ip");
        assertEquals(Arrays.asList("com.android.chrome", "com.example.app"),
                resp.snapshot.sandboxApps, "sandbox_apps");
    }

    private static void testParseErrorAndOffline() {
        BrokerProtocol.RpcResponse err = BrokerProtocol.parseResponse(
                "{\"id\":\"kb-2\",\"ok\":false,\"error\":\"policy not pinned\",\"data\":{}}");
        assertTrue(!err.ok, "ok=false");
        assertTrue(!err.offline, "offline=false");
        assertEquals("policy not pinned", err.error, "error string");

        BrokerProtocol.RpcResponse empty = BrokerProtocol.parseResponse("   ");
        assertTrue(!empty.ok && empty.offline, "blank input is offline");
    }
}
