package com.sandbox.controller;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Unprivileged UDS JSON-line client for /dev/socket/sandbox_ctrl/ctrl.sock.
 */
public final class BrokerClient {

    private static final int DEFAULT_TIMEOUT_MS = 8000;
    private static final int PROBE_TIMEOUT_MS = 34000;
    private static final int MAX_RESPONSE_BYTES = 65536;
    private static final AtomicInteger SEQ = new AtomicInteger(1);

    private String nextId() {
        return "kb-" + SEQ.getAndIncrement();
    }

    public BrokerProtocol.RpcResponse getStatus() {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildGetStatus(id), DEFAULT_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse startSandbox() {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildStartVpn(id), DEFAULT_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse pauseSandbox() {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildPauseVpn(id), DEFAULT_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse runProbe() {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildRunProbe(id), PROBE_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse reloadConfig(String quicUdp443Mode, String logLevel) {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildReloadConfig(id, quicUdp443Mode, logLevel), DEFAULT_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse syncHideApps() {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildSyncHideApps(id), DEFAULT_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse importExistingApp(String pkg) {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildImportExisting(id, pkg), PROBE_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse installApk(String apkPath) {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildInstallApk(id, apkPath), PROBE_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse installApks(List<String> apkPaths) {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildInstallApks(id, apkPaths), PROBE_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse launchApp(String pkg) {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildLaunchApp(id, pkg), DEFAULT_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse stopApp(String pkg) {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildStopApp(id, pkg), DEFAULT_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse removeApp(String pkg) {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildRemoveApp(id, pkg), PROBE_TIMEOUT_MS);
    }

    private BrokerProtocol.RpcResponse exchange(String id, String jsonLine, int timeoutMs) {
        LocalSocket socket = new LocalSocket();
        try {
            socket.connect(new LocalSocketAddress(
                    BrokerProtocol.SOCKET_PATH,
                    LocalSocketAddress.Namespace.FILESYSTEM
            ));
            socket.setSoTimeout(timeoutMs);

            OutputStream out = socket.getOutputStream();
            out.write((jsonLine + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();

            String line = readBoundedLine(socket.getInputStream());
            if (line == null || line.trim().isEmpty()) {
                return BrokerProtocol.RpcResponse.error(
                        id,
                        "broker closed connection (pin cert SHA-256 in policy.json)",
                        BrokerProtocol.OfflineReason.CERT_UNPINNED);
            }
            return BrokerProtocol.parseResponse(line);
        } catch (IOException ex) {
            String msg = ex.getMessage() != null ? ex.getMessage() : "socket unreachable";
            String lower = msg.toLowerCase(Locale.ROOT);
            BrokerProtocol.OfflineReason reason = (lower.contains("permission") || lower.contains("eacces"))
                    ? BrokerProtocol.OfflineReason.SELINUX_DENIED
                    : BrokerProtocol.OfflineReason.DAEMON_DOWN;
            return BrokerProtocol.RpcResponse.error(id, msg, reason);
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static String readBoundedLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(512);
        byte[] chunk = new byte[1024];
        while (true) {
            int n = in.read(chunk);
            if (n < 0) {
                break;
            }
            for (int i = 0; i < n; i++) {
                byte b = chunk[i];
                if (b == '\n') {
                    return new String(buf.toByteArray(), StandardCharsets.UTF_8);
                }
                if (buf.size() >= MAX_RESPONSE_BYTES) {
                    throw new IOException("RPC response exceeds 64 KiB limit");
                }
                buf.write(b);
            }
        }
        return buf.size() == 0 ? null : new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }
}
