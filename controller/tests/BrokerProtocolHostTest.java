package com.sandbox.controller;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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
        testApkPathValidationAndSplitList();
        testParseStatusSnapshotAndPreservation();
        testParseErrorOfflineAndJsonHardening();
        testBilingualStrings();
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
        assertEquals("{\"id\":\"r3c\",\"op\":\"SYNC_HIDE_APPS\"}",
                BrokerProtocol.buildSyncHideApps("r3c"), "SYNC_HIDE_APPS");
        assertEquals("{\"id\":\"r3d\",\"op\":\"RELOAD_CONFIG\",\"config\":{\"quic_udp443_mode\":\"reject\",\"log_level\":\"warn\"}}",
                BrokerProtocol.buildReloadConfig("r3d", "reject", "warn"), "RELOAD_CONFIG");
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
        assertEquals("{\"id\":\"r6b\",\"op\":\"INSTALL_APK\",\"apk_paths\":[\"/data/local/tmp/base.apk\",\"/data/local/tmp/arm64.apk\"]}",
                BrokerProtocol.buildInstallApks("r6b", Arrays.asList("/data/local/tmp/base.apk", "/data/local/tmp/arm64.apk")),
                "INSTALL_APK split bundle");
    }

    private static void testApkPathValidationAndSplitList() {
        assertTrue(BrokerProtocol.isAllowedApkPath("/data/local/tmp/app.apk"), "tmp apk");
        assertTrue(BrokerProtocol.isAllowedApkPath("  /data/adb/sandbox_guard/staging/base.apk  "), "staging apk");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/sdcard/Download/app.apk"), "reject sdcard");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/data/local/tmp/../etc.apk"), "reject dotdot");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/data/local/tmp/app.zip"), "reject non-apk");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/data/local/tmp/app;rm.apk"), "reject shell metachar");
        assertTrue(!BrokerProtocol.isAllowedApkPath("/data/local/tmp/with space.apk"), "reject space");
        assertTrue(!BrokerProtocol.isAllowedApkPath(null), "reject null");

        StringBuilder longPath = new StringBuilder("/data/local/tmp/");
        for (int i = 0; i < 510; i++) {
            longPath.append('a');
        }
        longPath.append(".apk");
        assertTrue(!BrokerProtocol.isAllowedApkPath(longPath.toString()), "reject >512 chars path");

        List<String> splits = BrokerProtocol.parseApkPathList(
                "/data/local/tmp/base.apk\n/data/adb/sandbox_guard/staging/config.arm64_v8a.apk, ");
        assertEquals(Arrays.asList("/data/local/tmp/base.apk", "/data/adb/sandbox_guard/staging/config.arm64_v8a.apk"),
                splits, "split apk list parsing");
        assertTrue(BrokerProtocol.parseApkPathList("/data/local/tmp/base.apk\n/sdcard/bad.apk").isEmpty(),
                "invalid item rejects whole split list");

        StringBuilder thirtyThree = new StringBuilder();
        for (int i = 0; i < 33; i++) {
            thirtyThree.append("/data/local/tmp/s").append(i).append(".apk\n");
        }
        assertTrue(BrokerProtocol.parseApkPathList(thirtyThree.toString()).isEmpty(),
                "must reject >32 split apk entries");
    }

    private static void testParseStatusSnapshotAndPreservation() {
        String sample = "{\"id\":\"kb-1\",\"ok\":true,\"error\":\"\",\"data\":{"
                + "\"version\":\"1.2.0\","
                + "\"variant\":\"hyperos-k510-ksu\","
                + "\"state\":\"OPEN\","
                + "\"mode\":\"tproxy\","
                + "\"tproxy_port\":1537,"
                + "\"active_preset\":\"jp-docomo\","
                + "\"paused\":false,"
                + "\"policy_loaded\":true,"
                + "\"sbw_open\":true,"
                + "\"sbw_raw_armed\":false,"
                + "\"frozen\":false,"
                + "\"hot_frozen\":true,"
                + "\"tproxy_ready\":true,"
                + "\"zygisk_disabled\":false,"
                + "\"stealth_boot_tries\":1,"
                + "\"private_dns_mode\":\"off\","
                + "\"private_dns_warning\":true,"
                + "\"probe_apk_installed\":true,"
                + "\"instrument_ok\":true,"
                + "\"probe_result\":{\"real_device_scorecard\":{\"passed\":11,\"warn\":1,\"failed\":0,\"total\":12}},"
                + "\"user_id\":10,"
                + "\"u10_running_procs\":3,"
                + "\"hibernated_count\":2,"
                + "\"stuck_work_sockets\":1,"
                + "\"cross_pool_12c6_hits\":2,"
                + "\"exemption\":{\"generation\":226},"
                + "\"sandbox_ack\":{\"applied_generation\":226},"
                + "\"boot_alert\":\"Zygisk disabled test\","
                + "\"last_error\":\"\","
                + "\"vpn_status\":{\"running\":true,\"exit_ip\":\"198.51.100.2\",\"quic_udp443_mode\":\"allow\"},"
                + "\"sandbox_apps\":[\"com.android.chrome\",\"com.example.\\u0061pp\"]"
                + "}}";

        BrokerProtocol.RpcResponse resp = BrokerProtocol.parseResponse(sample);
        assertTrue(resp.ok, "ok=true");
        assertTrue(!resp.offline, "offline=false");
        assertEquals(BrokerProtocol.OfflineReason.NONE, resp.offlineReason, "offlineReason=NONE");
        assertEquals("kb-1", resp.id, "id");
        assertEquals("hyperos-k510-ksu", resp.snapshot.variant, "variant");
        assertEquals("tproxy", resp.snapshot.mode, "mode");
        assertEquals(1537, resp.snapshot.tproxyPort, "tproxy_port");
        assertEquals("jp-docomo", resp.snapshot.activePreset, "active_preset");
        assertEquals("off", resp.snapshot.privateDnsMode, "private_dns_mode");
        assertTrue(resp.snapshot.hasProbeData, "hasProbeData=true");
        assertTrue(resp.snapshot.probeApkInstalled, "probe_apk_installed=true");
        assertTrue(resp.snapshot.instrumentOk, "instrument_ok=true");
        assertEquals(11, resp.snapshot.scorecardPassed, "scorecardPassed");
        assertEquals(1, resp.snapshot.scorecardWarn, "scorecardWarn");
        assertEquals(12, resp.snapshot.scorecardTotal, "scorecardTotal");
        assertEquals("198.51.100.2", resp.snapshot.exitIp, "exit_ip");
        assertEquals(2, resp.snapshot.crossPool12c6Hits, "crossPool12c6Hits");
        assertEquals("Zygisk disabled test", resp.snapshot.bootAlert, "bootAlert");
        assertEquals("allow", resp.snapshot.quicUdp443Mode, "quicUdp443Mode");
        assertEquals(226L, resp.snapshot.exemptionGen, "exemptionGen");
        assertEquals(226L, resp.snapshot.ackAppliedGen, "ackAppliedGen");
        assertTrue(resp.snapshot.isGateHealthyOpen(), "isGateHealthyOpen=true");
        assertTrue(resp.snapshot.hasStartupOrHealthAlert(), "hasStartupOrHealthAlert checks stuck sockets / cross pool / bootAlert");
        String summary = resp.snapshot.buildAlertSummary(new Strings(true));
        assertTrue(summary.contains("Zygisk disabled test") && summary.contains("198.18"), "alert summary includes bootAlert and crossPool");
        assertEquals(Arrays.asList("com.android.chrome", "com.example.app"),
                resp.snapshot.sandboxApps, "sandbox_apps");

        // Regular GET_STATUS omits probe fields; withPreservedProbeFrom must preserve prior RUN_PROBE scorecard
        BrokerProtocol.RpcResponse statusNoProbe = BrokerProtocol.parseResponse(
                "{\"id\":\"kb-1b\",\"ok\":true,\"data\":{\"policy_loaded\":true,\"state\":\"OPEN\",\"sandbox_apps\":[\"com.android.chrome\"]}}");
        assertTrue(!statusNoProbe.snapshot.hasProbeData, "regular GET_STATUS lacks probe data");
        BrokerProtocol.StatusSnapshot merged = statusNoProbe.snapshot.withPreservedProbeFrom(resp.snapshot);
        assertTrue(merged.hasProbeData && merged.probeApkInstalled && merged.instrumentOk,
                "withPreservedProbeFrom retains live probe results");
        assertEquals(12, merged.scorecardTotal, "withPreservedProbeFrom retains scorecardTotal");

        BrokerProtocol.RpcResponse scWarnings = BrokerProtocol.parseResponse(
                "{\"id\":\"kb-1c\",\"ok\":true,\"data\":{\"probe_apk_installed\":true,\"instrument_ok\":true,"
                + "\"variant\":{\"oem\":\"hyperos\",\"kernel\":\"k510\",\"transport\":\"tproxy\"},"
                + "\"probe_result\":{\"real_device_scorecard\":{\"passed\":10,\"warnings\":2,\"failed\":0}}}}");
        assertEquals("hyperos-k510", scWarnings.snapshot.variant, "variant object parsed");
        assertEquals(2, scWarnings.snapshot.scorecardWarn, "scorecard 'warnings' alias parsed");
        assertEquals(12, scWarnings.snapshot.scorecardTotal, "scorecard computed total=12");

        String redacted = merged.toRedactedDiagnosticJson();
        assertTrue(!redacted.contains("198.51.100.2"), "redacted report omits exit_ip");
        assertTrue(!redacted.contains("com.android.chrome"), "redacted report omits app package names");
        assertTrue(redacted.contains("\"sandbox_apps_count\": 1"), "redacted report keeps app count");

        String safeCache = resp.snapshot.toSafeCacheJson();
        assertTrue(!safeCache.contains("198.51.100.2"), "safe cache must omit exit_ip");
        BrokerProtocol.StatusSnapshot restored = BrokerProtocol.StatusSnapshot.fromSafeCacheJson(safeCache);
        assertTrue(restored != null, "safe cache restores valid snapshot");
        assertEquals("OPEN", restored.state, "restored state");
        assertEquals(resp.snapshot.variant, restored.variant, "restored variant");
        assertEquals("", restored.exitIp, "restored snapshot omits exitIp");
        assertEquals(Arrays.asList("com.android.chrome", "com.example.app"),
                restored.sandboxApps, "restored sandbox_apps");
        assertTrue(BrokerProtocol.StatusSnapshot.fromSafeCacheJson("{bad") == null, "malformed cache rejected safely");
    }

    private static void testParseErrorOfflineAndJsonHardening() {
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

        BrokerProtocol.RpcResponse trailing = BrokerProtocol.parseResponse("{\"ok\":true} garbage");
        assertTrue(!trailing.ok && trailing.error.contains("trailing"), "trailing tokens rejected");

        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            deep.append('[');
        }
        deep.append('1');
        for (int i = 0; i < 40; i++) {
            deep.append(']');
        }
        BrokerProtocol.RpcResponse deepResp = BrokerProtocol.parseResponse(deep.toString());
        assertTrue(!deepResp.ok && deepResp.error.contains("nesting"), "excessive nesting depth rejected");

        BrokerProtocol.RpcResponse timeoutResp = BrokerProtocol.RpcResponse.error(
                "kb-t1", "RPC timeout: SocketTimeoutException", BrokerProtocol.OfflineReason.RPC_TIMEOUT);
        assertTrue(!timeoutResp.ok && !timeoutResp.offline, "RPC_TIMEOUT must NOT wipe UI as offline");
        assertEquals(BrokerProtocol.OfflineReason.RPC_TIMEOUT, timeoutResp.offlineReason, "offlineReason=RPC_TIMEOUT");

        BrokerProtocol.RpcResponse guardDown = BrokerProtocol.parseResponse(
                "{\"id\":\"kb-g1\",\"ok\":false,\"error\":\"guard unavailable\",\"data\":{}}");
        assertTrue(!guardDown.ok && guardDown.offline, "guard unavailable with empty data must mark offline=true");
        assertEquals(BrokerProtocol.OfflineReason.DAEMON_DOWN, guardDown.offlineReason, "offlineReason=DAEMON_DOWN");
    }

    private static void testBilingualStrings() {
        Strings zh = new Strings(true);
        Strings en = new Strings(false);
        assertTrue(!zh.offlineCertUnpinnedHint().isEmpty() && !en.offlineCertUnpinnedHint().isEmpty(), "cert hint");
        assertTrue(!zh.offlineSelinuxHint().isEmpty() && !en.offlineSelinuxHint().isEmpty(), "selinux hint");
        assertTrue(!zh.diagCopyReport().isEmpty() && !en.diagCopyReport().isEmpty(), "diag copy report");
        assertTrue(!zh.diagScorecardFmt(11, 12, 1, 0).isEmpty() && !en.diagScorecardFmt(11, 12, 1, 0).isEmpty(), "scorecard fmt");
        assertTrue(!zh.freezeDeep().isEmpty() && !en.freezeDeep().isEmpty(), "freezeDeep");
        assertTrue(!zh.a11yRefresh().isEmpty() && !en.a11yClose().isEmpty(), "a11y descriptions");
        assertTrue(!zh.alertBannerTitle().isEmpty() && !en.alertBannerTitle().isEmpty(), "alertBannerTitle");
        assertTrue(!zh.alertRpcTimeout().isEmpty() && !en.alertRpcTimeout().isEmpty(), "alertRpcTimeout");
        assertTrue(!zh.qsTimeout().isEmpty() && !en.qsTimeout().isEmpty(), "qsTimeout");
        assertTrue(!zh.diagLabelBootAlert().isEmpty() && !en.diagLabelCrossPool().isEmpty(), "diag alert labels");
    }
}
