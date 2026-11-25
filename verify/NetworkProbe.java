package com.sandbox.verify;

import android.app.Activity;
import android.app.Instrumentation;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.media.MediaDrm;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.SystemClock;
import android.os.UserManager;
import android.provider.Settings;
import android.telephony.TelephonyManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.Socket;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

/**
 * Pure-Java dual-space (plus isolatedProcess) environment & network probe.
 * Runs as an unprivileged app inside User 0 or Work Profile User u.
 */
public final class NetworkProbe extends Instrumentation {
    private static final int SOCKET_TIMEOUT_MS = 4500;
    private static final int FAST_REJECT_TIMEOUT_MS = 1500;
    private static final int IPV6_TIMEOUT_MS = 2500;
    private static final String DEFAULT_TARGET_WORK_PKG = "com.sandbox.controller";
    private static final UUID WIDEVINE_UUID =
        new UUID(-0x121074568629b532L, -0x5c37d8232ae2de13L);

    private volatile Bundle launchArgs;

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        this.launchArgs = arguments;
        start();
    }

    @Override
    public void onStart() {
        Bundle result = new Bundle();
        long monoStartNs = SystemClock.elapsedRealtimeNanos();
        String mode = "full";
        String targetWorkPkg = DEFAULT_TARGET_WORK_PKG;
        if (launchArgs != null) {
            String argMode = launchArgs.getString("mode");
            if (argMode != null && !argMode.trim().isEmpty()) {
                mode = argMode.trim();
            }
            String argTarget = launchArgs.getString("target_pkg");
            if (argTarget != null && !argTarget.trim().isEmpty()) {
                targetWorkPkg = argTarget.trim();
            }
        }
        boolean networkFast = "network_fast".equalsIgnoreCase(mode);
        ExecutorService workers = Executors.newFixedThreadPool(networkFast ? 3 : 8, task -> {
            Thread thread = new Thread(task, "NetworkProbe");
            thread.setDaemon(true);
            return thread;
        });

        try {
            Context context = getTargetContext();
            JSONObject report = new JSONObject();
            report.put("schema_version", 2);
            report.put("mode", mode);
            report.put("probe_mono_start_ns", monoStartNs);

            int uid = Process.myUid();
            report.put("uid", uid);

            JSONObject env = collectEnvironment(context);
            boolean isVpn = env.optJSONObject("connectivity") != null
                && env.getJSONObject("connectivity").optBoolean("transport_vpn", false);
            report.put("vpn", isVpn);
            report.put("environment", env);

            Map<String, Future<JSONObject>> probes = new LinkedHashMap<>();
            probes.put("https_ipv4", workers.submit(timed(() -> httpsTrace("1.1.1.1", SOCKET_TIMEOUT_MS))));
            probes.put("https_name", workers.submit(timed(() -> httpsStatus("https://www.gstatic.com/generate_204?probe=" + SystemClock.elapsedRealtimeNanos()))));

            if (!networkFast) {
                report.put("identity", collectIdentity(context, targetWorkPkg));
                report.put("proc_hygiene", ProcHygieneScanner.scan());

                Future<JSONObject> isolatedFuture = workers.submit(() -> collectIsolated(context));
                Future<JSONObject> attestFuture = workers.submit(() ->
                    KeyMintAttestationProbe.probe(String.valueOf(uid)));

                probes.put("https_cf_name", workers.submit(timed(() -> httpsTrace("www.cloudflare.com", SOCKET_TIMEOUT_MS))));
                probes.put("https_ip_echo", workers.submit(timed(NetworkProbe::httpsIpEcho)));
                probes.put("dot_853_portal", workers.submit(timed(NetworkProbe::probeDot853Portal)));
                probes.put("private_ip_reject", workers.submit(timed(NetworkProbe::probePrivateIpReject)));
                probes.put("ipv6_blocked", workers.submit(timed(NetworkProbe::probeIpv6Blocked)));
                probes.put("udp_ipv4", workers.submit(timed(NetworkProbe::udpQuery)));
                probes.put("stun_ipv4", workers.submit(timed(NetworkProbe::stun)));

                try {
                    report.put("isolated_process", isolatedFuture.get(5500, TimeUnit.MILLISECONDS));
                } catch (Throwable t) {
                    report.put("isolated_process", new JSONObject().put("error", t.getClass().getSimpleName()));
                }
                try {
                    report.put("integrity", attestFuture.get(5500, TimeUnit.MILLISECONDS));
                } catch (Throwable t) {
                    report.put("integrity", new JSONObject().put("status", "error")
                        .put("exception", t.getClass().getName()));
                }
            }

            long deadline = SystemClock.elapsedRealtime() + 12_000;
            JSONObject networkProbes = new JSONObject();
            for (Map.Entry<String, Future<JSONObject>> entry : probes.entrySet()) {
                JSONObject probeRes;
                try {
                    long remaining = Math.max(50, deadline - SystemClock.elapsedRealtime());
                    probeRes = entry.getValue().get(remaining, TimeUnit.MILLISECONDS);
                } catch (Exception error) {
                    probeRes = new JSONObject().put("error", error.getClass().getSimpleName());
                }
                networkProbes.put(entry.getKey(), probeRes);
                report.put(entry.getKey(), probeRes);
            }
            if (networkProbes.has("ipv6_blocked")) {
                report.put("https_ipv6", networkProbes.getJSONObject("ipv6_blocked"));
            }
            report.put("network_probes", networkProbes);
            if (!networkFast) {
                report.put("real_device_scorecard", buildRealDeviceScorecard(report, env, networkProbes));
            }
            report.put("probe_mono_end_ns", SystemClock.elapsedRealtimeNanos());

            result.putString("network", report.toString());
            finish(Activity.RESULT_OK, result);
        } catch (Exception error) {
            try {
                result.putString("error", error.getClass().getSimpleName() + ":" + error.getMessage());
            } catch (Exception ignored) {}
            finish(Activity.RESULT_CANCELED, result);
        } finally {
            workers.shutdownNow();
        }
    }

    private static JSONObject collectIdentity(Context context, String targetWorkPkg) {
        JSONObject id = new JSONObject();
        try {
            int uid = Process.myUid();
            id.put("uid", uid);
            id.put("app_id", uid % 100000);
            id.put("user_id", uid / 100000);
            id.put("package_name", context.getPackageName());
            id.put("target_work_pkg", targetWorkPkg);
            id.put("files_dir", context.getFilesDir().getAbsolutePath());
            ApplicationInfo appInfo = context.getApplicationInfo();
            id.put("source_dir", appInfo != null ? appInfo.sourceDir : "");

            UserManager um = context.getSystemService(UserManager.class);
            if (um != null) {
                if (Build.VERSION.SDK_INT >= 30) {
                    id.put("is_managed_profile", um.isManagedProfile());
                }
                id.put("user_profiles_count", um.getUserProfiles().size());
            }

            DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
            if (dpm != null) {
                try {
                    id.put("dpm_is_profile_owner_target", dpm.isProfileOwnerApp(targetWorkPkg));
                } catch (Throwable t) {
                    id.put("dpm_is_profile_owner_target_error", t.getClass().getSimpleName());
                }
                try {
                    id.put("dpm_is_profile_owner_self", dpm.isProfileOwnerApp(context.getPackageName()));
                } catch (Throwable t) {
                    id.put("dpm_is_profile_owner_self_error", t.getClass().getSimpleName());
                }
            }

            ContentResolver cr = context.getContentResolver();
            id.put("android_id", safeStr(Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID)));
            id.put("widevine_device_id_sha256", readWidevineIdSha256());

            JSONObject build = new JSONObject();
            build.put("brand", Build.BRAND);
            build.put("manufacturer", Build.MANUFACTURER);
            build.put("model", Build.MODEL);
            build.put("device", Build.DEVICE);
            build.put("product", Build.PRODUCT);
            build.put("hardware", Build.HARDWARE);
            build.put("fingerprint", Build.FINGERPRINT);
            build.put("tags", Build.TAGS);
            build.put("type", Build.TYPE);
            build.put("release", Build.VERSION.RELEASE);
            build.put("sdk_int", Build.VERSION.SDK_INT);
            build.put("security_patch", Build.VERSION.SECURITY_PATCH);
            id.put("build", build);
        } catch (Throwable t) {
            try {
                id.put("error", t.getClass().getSimpleName() + ":" + safeStr(t.getMessage()));
            } catch (Exception ignored) {}
        }
        return id;
    }

    private static String readWidevineIdSha256() {
        MediaDrm drm = null;
        try {
            drm = new MediaDrm(WIDEVINE_UUID);
            byte[] raw = drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID);
            if (raw == null) {
                return "";
            }
            return KeyMintAttestationProbe.sha256Hex(raw, 0, raw.length);
        } catch (Throwable t) {
            return "error:" + t.getClass().getSimpleName();
        } finally {
            if (drm != null) {
                try {
                    if (Build.VERSION.SDK_INT >= 28) {
                        drm.close();
                    } else {
                        drm.release();
                    }
                } catch (Throwable ignored) {}
            }
        }
    }

    private static JSONObject collectEnvironment(Context context) {
        JSONObject env = new JSONObject();
        JSONObject conn = new JSONObject();
        try {
            ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
            if (cm != null) {
                Network active = cm.getActiveNetwork();
                conn.put("active_network_present", active != null);
                if (active != null) {
                    NetworkCapabilities nc = cm.getNetworkCapabilities(active);
                    if (nc != null) {
                        conn.put("transport_vpn", nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
                        conn.put("not_vpn", nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN));
                        conn.put("validated", nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED));
                        conn.put("transport_wifi", nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI));
                        conn.put("transport_cellular", nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
                    }
                    LinkProperties lp = cm.getLinkProperties(active);
                    if (lp != null) {
                        conn.put("link_interface", safeStr(lp.getInterfaceName()));
                        if (Build.VERSION.SDK_INT >= 29) {
                            conn.put("link_mtu", lp.getMtu());
                        }
                        JSONArray dnsArr = new JSONArray();
                        for (InetAddress addr : lp.getDnsServers()) {
                            dnsArr.put(addr.getHostAddress());
                        }
                        conn.put("link_dns", dnsArr);
                        JSONArray addrArr = new JSONArray();
                        for (LinkAddress la : lp.getLinkAddresses()) {
                            addrArr.put(la.toString());
                        }
                        conn.put("link_addresses", addrArr);
                    }
                }
                boolean anyVpn = false;
                Network[] all = cm.getAllNetworks();
                if (all != null) {
                    for (Network net : all) {
                        NetworkCapabilities cap = cm.getNetworkCapabilities(net);
                        if (cap != null && cap.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                            anyVpn = true;
                            break;
                        }
                    }
                }
                conn.put("all_networks_has_vpn", anyVpn);
            }
            JSONArray ifaces = new JSONArray();
            try {
                Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
                if (en != null) {
                    for (NetworkInterface ni : Collections.list(en)) {
                        if (ni.isUp()) {
                            ifaces.put(ni.getName());
                        }
                    }
                }
            } catch (Throwable t) {
                conn.put("java_net_interfaces_error", t.getClass().getSimpleName());
            }
            conn.put("java_net_interfaces", ifaces);
        } catch (Throwable t) {
            try {
                conn.put("error", t.getClass().getSimpleName());
            } catch (Exception ignored) {}
        }

        JSONObject geo = new JSONObject();
        try {
            geo.put("timezone", TimeZone.getDefault().getID());
            geo.put("locale", Locale.getDefault().toLanguageTag());
            TelephonyManager tm = context.getSystemService(TelephonyManager.class);
            if (tm != null) {
                geo.put("sim_country_iso", safeStr(tm.getSimCountryIso()));
                geo.put("network_country_iso", safeStr(tm.getNetworkCountryIso()));
                geo.put("sim_operator", safeStr(tm.getSimOperator()));
            }
        } catch (Throwable t) {
            try {
                geo.put("error", t.getClass().getSimpleName());
            } catch (Exception ignored) {}
        }

        JSONObject sg = new JSONObject();
        try {
            ContentResolver cr = context.getContentResolver();
            sg.put("adb_enabled", safeGlobalInt(cr, Settings.Global.ADB_ENABLED));
            sg.put("development_settings_enabled",
                safeGlobalInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED));
            sg.put("private_dns_mode", safeGlobalStr(cr, "private_dns_mode"));
        } catch (Throwable ignored) {}

        JSONObject ss = new JSONObject();
        try {
            ContentResolver cr = context.getContentResolver();
            String rawAcc = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            boolean accActive = rawAcc != null && !rawAcc.trim().isEmpty()
                && !"null".equalsIgnoreCase(rawAcc.trim());
            ss.put("accessibility_services_active", accActive);
        } catch (Throwable ignored) {}

        try {
            env.put("connectivity", conn);
            env.put("geo", geo);
            env.put("settings_global", sg);
            env.put("settings_secure", ss);
        } catch (Exception ignored) {}
        return env;
    }

    private static Object safeGlobalInt(ContentResolver cr, String key) {
        try {
            return Settings.Global.getInt(cr, key, -1);
        } catch (Throwable t) {
            return "error:" + t.getClass().getSimpleName();
        }
    }

    private static String safeGlobalStr(ContentResolver cr, String key) {
        try {
            String val = Settings.Global.getString(cr, key);
            return val != null ? val : "";
        } catch (Throwable t) {
            return "error:" + t.getClass().getSimpleName();
        }
    }

    private static JSONObject collectIsolated(Context context) {
        CompletableFuture<JSONObject> future = new CompletableFuture<>();
        HandlerThread replyThread = new HandlerThread("IsolatedProbeReply");
        replyThread.start();
        Messenger replyMessenger = new Messenger(new Handler(replyThread.getLooper()) {
            @Override
            public void handleMessage(Message msg) {
                if (msg.what == IsolatedProbeService.MSG_COLLECT_PROC_REPLY) {
                    try {
                        String raw = msg.getData().getString(IsolatedProbeService.EXTRA_JSON, "{}");
                        future.complete(new JSONObject(raw));
                    } catch (Throwable t) {
                        future.completeExceptionally(t);
                    }
                }
            }
        });

        ServiceConnection conn = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                try {
                    Messenger svc = new Messenger(service);
                    Message req = Message.obtain(null, IsolatedProbeService.MSG_COLLECT_PROC);
                    req.replyTo = replyMessenger;
                    svc.send(req);
                } catch (Throwable t) {
                    future.completeExceptionally(t);
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                if (!future.isDone()) {
                    future.completeExceptionally(new IOException("isolated service disconnected"));
                }
            }
        };

        boolean bound = false;
        try {
            Intent intent = new Intent(context, IsolatedProbeService.class);
            bound = context.bindService(intent, conn, Context.BIND_AUTO_CREATE);
            if (!bound) {
                return new JSONObject().put("error", "bindService_returned_false");
            }
            return future.get(4500, TimeUnit.MILLISECONDS);
        } catch (Throwable t) {
            try {
                return new JSONObject().put("error", t.getClass().getSimpleName() + ":" + safeStr(t.getMessage()));
            } catch (Exception ignored) {
                return new JSONObject();
            }
        } finally {
            if (bound) {
                try {
                    context.unbindService(conn);
                } catch (Throwable ignored) {}
            }
            replyThread.quitSafely();
        }
    }

    private static Callable<JSONObject> timed(Callable<JSONObject> probe) {
        return () -> {
            long startNs = SystemClock.elapsedRealtimeNanos();
            JSONObject result;
            try {
                result = probe.call();
            } catch (Exception error) {
                result = new JSONObject()
                    .put("error", error.getClass().getSimpleName())
                    .put("message", safeStr(error.getMessage()));
            }
            long endNs = SystemClock.elapsedRealtimeNanos();
            result.put("start_ns", startNs);
            result.put("end_ns", endNs);
            return result.put("ms", (endNs - startNs) / 1_000_000L);
        };
    }

    private static JSONObject httpsTrace(String host, int timeoutMs) throws Exception {
        URL endpoint = new URL("https://" + host + "/cdn-cgi/trace?probe=" + SystemClock.elapsedRealtimeNanos());
        HttpsURLConnection connection = (HttpsURLConnection) endpoint.openConnection(Proxy.NO_PROXY);
        connection.setConnectTimeout(timeoutMs);
        connection.setReadTimeout(timeoutMs);
        connection.setUseCaches(false);
        connection.setInstanceFollowRedirects(false);
        try {
            int code = connection.getResponseCode();
            String exitIp = "";
            String loc = "";
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                for (int count = 0; count < 64; count++) {
                    String line = reader.readLine();
                    if (line == null) break;
                    if (line.startsWith("ip=")) exitIp = line.substring(3);
                    if (line.startsWith("loc=")) loc = line.substring(4);
                }
            }
            if (exitIp.isEmpty()) {
                throw new IOException("missing trace address");
            }
            return new JSONObject().put("exit", exitIp).put("loc", loc).put("http_code", code);
        } finally {
            connection.disconnect();
        }
    }

    private static JSONObject httpsStatus(String urlStr) throws Exception {
        URL endpoint = new URL(urlStr);
        HttpsURLConnection connection = (HttpsURLConnection) endpoint.openConnection(Proxy.NO_PROXY);
        connection.setConnectTimeout(SOCKET_TIMEOUT_MS);
        connection.setReadTimeout(SOCKET_TIMEOUT_MS);
        connection.setUseCaches(false);
        connection.setInstanceFollowRedirects(false);
        try {
            int code = connection.getResponseCode();
            return new JSONObject().put("http_code", code).put("ok", code == 204 || code == 200);
        } finally {
            connection.disconnect();
        }
    }

    private static JSONObject httpsIpEcho() throws Exception {
        URL endpoint = new URL("https://api.ipify.org?format=text&probe=" + SystemClock.elapsedRealtimeNanos());
        HttpsURLConnection connection = (HttpsURLConnection) endpoint.openConnection(Proxy.NO_PROXY);
        connection.setConnectTimeout(SOCKET_TIMEOUT_MS);
        connection.setReadTimeout(SOCKET_TIMEOUT_MS);
        connection.setUseCaches(false);
        connection.setInstanceFollowRedirects(false);
        try {
            int code = connection.getResponseCode();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                String body = reader.readLine();
                if (body == null || body.trim().isEmpty()) {
                    throw new IOException("empty ip echo");
                }
                return new JSONObject().put("exit", body.trim()).put("http_code", code);
            }
        } finally {
            connection.disconnect();
        }
    }

    private static JSONObject probeTcpRejected(InetAddress addr, int port, int timeoutMs) {
        JSONObject out = new JSONObject();
        long startNs = SystemClock.elapsedRealtimeNanos();
        boolean synAcked = false;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(addr, port), timeoutMs);
            synAcked = true;
            socket.setSoTimeout(timeoutMs);
            // gVisor/tun2socket completes SYN-ACK before core rule matching; probe I/O observes REJECT RST/EOF.
            byte[] probe = ("GET / HTTP/1.0\r\nHost: probe.invalid\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
            socket.getOutputStream().write(probe);
            socket.getOutputStream().flush();
            int first = socket.getInputStream().read();
            long elapsedMs = (SystemClock.elapsedRealtimeNanos() - startNs) / 1_000_000L;
            if (first < 0) {
                out.put("connected", false);
                out.put("tun_syn_ack", true);
                out.put("rejected", true);
                out.put("rejected_fast", elapsedMs < 100);
                out.put("connect_ms", elapsedMs);
                out.put("error", "TunIoEof");
            } else {
                out.put("connected", true);
                out.put("tun_syn_ack", true);
                out.put("rejected", false);
                out.put("rejected_fast", false);
                out.put("connect_ms", elapsedMs);
            }
        } catch (java.net.SocketTimeoutException ste) {
            long elapsedMs = (SystemClock.elapsedRealtimeNanos() - startNs) / 1_000_000L;
            try {
                boolean rejected = !synAcked;
                out.put("connected", synAcked);
                out.put("tun_syn_ack", synAcked);
                out.put("rejected", rejected);
                out.put("rejected_fast", false);
                out.put("connect_ms", elapsedMs);
                out.put("error", synAcked ? "TunReadTimeout" : "SocketTimeoutException");
            } catch (Exception ignored) {}
        } catch (Throwable t) {
            long elapsedMs = (SystemClock.elapsedRealtimeNanos() - startNs) / 1_000_000L;
            try {
                out.put("connected", false);
                if (synAcked) {
                    out.put("tun_syn_ack", true);
                }
                out.put("rejected", true);
                out.put("rejected_fast", elapsedMs < 100);
                out.put("connect_ms", elapsedMs);
                out.put("error", (synAcked ? "TunIo:" : "") + t.getClass().getSimpleName());
            } catch (Exception ignored) {}
        }
        return out;
    }

    private static JSONObject probeDot853Portal() {
        try {
            return probeTcpRejected(
                InetAddress.getByAddress(new byte[] {(byte) 172, 19, 0, 2}), 853, FAST_REJECT_TIMEOUT_MS);
        } catch (Throwable t) {
            JSONObject out = new JSONObject();
            try {
                out.put("connected", false);
                out.put("rejected", true);
                out.put("rejected_fast", false);
                out.put("error", t.getClass().getSimpleName());
            } catch (Exception ignored) {}
            return out;
        }
    }

    private static JSONObject probePrivateIpReject() {
        JSONObject out = new JSONObject();
        JSONArray targets = new JSONArray();
        boolean allRejected = true;
        String[][] ips = { {"10.0.0.1", "80"}, {"100.64.0.1", "80"} };
        for (String[] target : ips) {
            JSONObject item;
            try {
                item = probeTcpRejected(
                    InetAddress.getByName(target[0]), Integer.parseInt(target[1]), FAST_REJECT_TIMEOUT_MS);
                item.put("target", target[0] + ":" + target[1]);
                if (!item.optBoolean("rejected", false)) {
                    allRejected = false;
                }
            } catch (Throwable t) {
                item = new JSONObject();
                try {
                    item.put("target", target[0] + ":" + target[1]);
                    item.put("connected", false);
                    item.put("rejected", true);
                    item.put("error", t.getClass().getSimpleName());
                } catch (Exception ignored) {}
            }
            targets.put(item);
        }
        try {
            out.put("all_rejected", allRejected);
            out.put("targets", targets);
        } catch (Exception ignored) {}
        return out;
    }

    private static JSONObject probeIpv6Blocked() {
        JSONObject out = new JSONObject();
        try {
            JSONObject res = httpsTrace("[2606:4700:4700::1111]", IPV6_TIMEOUT_MS);
            out.put("blocked", false);
            out.put("exit", res.optString("exit", ""));
        } catch (Throwable t) {
            try {
                out.put("blocked", true);
                out.put("error", t.getClass().getSimpleName());
            } catch (Exception ignored) {}
        }
        return out;
    }

    private static JSONObject udpQuery() throws Exception {
        byte[] query = {
            0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1
        };
        int id = new SecureRandom().nextInt(65536);
        query[0] = (byte) (id >>> 8);
        query[1] = (byte) id;
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByAddress(new byte[] {1, 1, 1, 1}), 53);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            socket.send(new DatagramPacket(query, query.length));
            byte[] reply = new byte[768];
            DatagramPacket packet = new DatagramPacket(reply, reply.length);
            socket.receive(packet);
            boolean valid = packet.getLength() >= 12 && reply[0] == query[0] && reply[1] == query[1]
                && (reply[2] & 0x80) != 0 && (reply[3] & 0x0f) == 0;
            return new JSONObject().put("reply", valid);
        }
    }

    private static JSONObject stun() throws Exception {
        final int cookie = 0x2112a442;
        byte[] transaction = new byte[12];
        new SecureRandom().nextBytes(transaction);
        byte[] query = ByteBuffer.allocate(20).putShort((short) 1).putShort((short) 0)
            .putInt(cookie).put(transaction).array();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByAddress(new byte[] {(byte) 162, (byte) 159, (byte) 207, 0}), 3478);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            socket.send(new DatagramPacket(query, query.length));
            byte[] reply = new byte[768];
            DatagramPacket packet = new DatagramPacket(reply, reply.length);
            socket.receive(packet);
            ByteBuffer buffer = ByteBuffer.wrap(reply, 0, packet.getLength());
            if (buffer.remaining() < 20 || buffer.getShort() != 0x0101) throw new IOException("STUN reply");
            int length = Short.toUnsignedInt(buffer.getShort());
            if (buffer.getInt() != cookie) throw new IOException("STUN cookie");
            byte[] receivedTransaction = new byte[12];
            buffer.get(receivedTransaction);
            if (!Arrays.equals(receivedTransaction, transaction) || length > buffer.remaining()) {
                throw new IOException("STUN transaction");
            }
            buffer.limit(buffer.position() + length);
            while (buffer.remaining() >= 4) {
                int type = Short.toUnsignedInt(buffer.getShort());
                int size = Short.toUnsignedInt(buffer.getShort());
                int padded = (size + 3) & ~3;
                if (padded > buffer.remaining()) break;
                int end = buffer.position() + padded;
                if (type == 0x0020 && size == 8 && buffer.getShort() == 1) {
                    buffer.getShort();
                    byte[] address = ByteBuffer.allocate(4).putInt(buffer.getInt() ^ cookie).array();
                    return new JSONObject().put("exit", InetAddress.getByAddress(address).getHostAddress());
                }
                buffer.position(end);
            }
            throw new IOException("STUN mapped address");
        }
    }

    private static JSONObject buildRealDeviceScorecard(
            JSONObject report, JSONObject env, JSONObject networkProbes) {
        JSONObject scorecard = new JSONObject();
        JSONObject checks = new JSONObject();
        int[] counts = new int[3]; // [passed, warnings, failed]
        try {
            JSONObject id = report.optJSONObject("identity");
            boolean workHidden = id != null
                && !id.optBoolean("is_managed_profile", true)
                && id.optInt("user_profiles_count", 2) <= 1
                && !id.optBoolean("dpm_is_profile_owner_target", true);
            recordScorecardCheck(checks, counts, "work_profile_hidden", workHidden ? "pass" : "fail");

            JSONObject conn = env != null ? env.optJSONObject("connectivity") : null;
            boolean hasTun = false;
            JSONArray ifaces = conn != null ? conn.optJSONArray("java_net_interfaces") : null;
            if (ifaces != null) {
                for (int i = 0; i < ifaces.length(); i++) {
                    String ifName = ifaces.optString(i, "");
                    if (ifName.startsWith("tun")) {
                        hasTun = true;
                        break;
                    }
                }
            }
            boolean vpnClean = conn != null
                && !conn.optBoolean("transport_vpn", false)
                && !conn.optBoolean("all_networks_has_vpn", false)
                && !hasTun;
            recordScorecardCheck(checks, counts, "vpn_footprint_clean", vpnClean ? "pass" : "fail");

            JSONObject ipv6 = networkProbes != null ? networkProbes.optJSONObject("ipv6_blocked") : null;
            boolean ipv6Blocked = ipv6 != null && ipv6.optBoolean("blocked", false);
            recordScorecardCheck(checks, counts, "ipv6_leak_blocked", ipv6Blocked ? "pass" : "fail");

            JSONObject proc = report.optJSONObject("proc_hygiene");
            recordScorecardCheck(checks, counts, "proc_mounts_clean", isMountsClean(proc) ? "pass" : "fail");
            recordScorecardCheck(checks, counts, "proc_maps_clean", isMapsClean(proc) ? "pass" : "fail");
            recordScorecardCheck(checks, counts, "su_paths_hidden", isSuHidden(proc) ? "pass" : "fail");

            JSONObject iso = report.optJSONObject("isolated_process");
            boolean isoClean = isMountsClean(iso) && isMapsClean(iso) && isSuHidden(iso);
            recordScorecardCheck(checks, counts, "isolated_proc_clean", isoClean ? "pass" : "fail");

            JSONObject bp = proc != null ? proc.optJSONObject("boot_props") : null;
            boolean bootLocked = bp != null
                && "green".equalsIgnoreCase(bp.optString("ro.boot.verifiedbootstate", ""))
                && "1".equals(bp.optString("ro.boot.flash.locked", ""))
                && "locked".equalsIgnoreCase(bp.optString("ro.boot.vbmeta.device_state", ""))
                && "0".equals(bp.optString("ro.debuggable", ""))
                && "1".equals(bp.optString("ro.secure", ""));
            recordScorecardCheck(checks, counts, "boot_props_locked", bootLocked ? "pass" : "fail");

            JSONObject sg = env != null ? env.optJSONObject("settings_global") : null;
            boolean adbOff = sg != null && sg.optInt("adb_enabled", -1) == 0;
            recordScorecardCheck(checks, counts, "usb_debugging_off", adbOff ? "pass" : "warn");

            JSONObject ss = env != null ? env.optJSONObject("settings_secure") : null;
            boolean accClean = ss != null
                && ss.has("accessibility_services_active")
                && !ss.optBoolean("accessibility_services_active", true);
            recordScorecardCheck(checks, counts, "accessibility_risk_clean", accClean ? "pass" : "warn");

            JSONObject integrity = report.optJSONObject("integrity");
            JSONObject rot = integrity != null ? integrity.optJSONObject("root_of_trust") : null;
            boolean keymintLocked = integrity != null
                && "ok".equals(integrity.optString("status", ""))
                && rot != null
                && rot.optBoolean("device_locked", false)
                && rot.optInt("verified_boot_state", -1) == 0;
            recordScorecardCheck(checks, counts, "keymint_rot_locked", keymintLocked ? "pass" : "warn");

            JSONObject geo = env != null ? env.optJSONObject("geo") : null;
            boolean geoConfigured = geo != null
                && !geo.optString("timezone", "").trim().isEmpty()
                && !geo.optString("locale", "").trim().isEmpty()
                && !geo.optString("sim_country_iso", "").trim().isEmpty()
                && !geo.optString("sim_operator", "").trim().isEmpty();
            recordScorecardCheck(checks, counts, "carrier_and_geo_configured", geoConfigured ? "pass" : "warn");

            scorecard.put("passed", counts[0]);
            scorecard.put("warnings", counts[1]);
            scorecard.put("failed", counts[2]);
            scorecard.put("checks", checks);
        } catch (Throwable t) {
            try {
                scorecard.put("error", t.getClass().getSimpleName() + ":" + safeStr(t.getMessage()));
            } catch (Exception ignored) {}
        }
        return scorecard;
    }

    private static boolean isMountsClean(JSONObject proc) {
        JSONObject mounts = proc != null ? proc.optJSONObject("mountinfo") : null;
        return mounts != null
            && mounts.optBoolean("readable", false)
            && mounts.optInt("suspicious_count", -1) == 0;
    }

    private static boolean isMapsClean(JSONObject proc) {
        JSONObject maps = proc != null ? proc.optJSONObject("maps") : null;
        return maps != null
            && maps.optBoolean("readable", false)
            && maps.optInt("suspicious_count", -1) == 0
            && maps.optInt("anon_rwxp_count", -1) == 0
            && maps.optInt("memfd_count", -1) == 0;
    }

    private static boolean isSuHidden(JSONObject proc) {
        JSONObject suPaths = proc != null ? proc.optJSONObject("su_paths") : null;
        return suPaths != null
            && suPaths.has("any_visible")
            && !suPaths.optBoolean("any_visible", true);
    }

    private static void recordScorecardCheck(JSONObject checks, int[] counts, String name, String status) throws Exception {
        checks.put(name, status);
        if ("pass".equals(status)) {
            counts[0]++;
        } else if ("warn".equals(status)) {
            counts[1]++;
        } else {
            counts[2]++;
        }
    }

    private static String safeStr(String s) {
        return s != null ? s : "";
    }
}
