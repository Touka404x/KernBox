package com.sandbox.controller;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Unprivileged UDS JSON-line client for /dev/socket/sandbox_ctrl/ctrl.sock.
 */
public final class BrokerClient {

    private static final int DEFAULT_TIMEOUT_MS = 8000;
    private static final int PROBE_TIMEOUT_MS = 22000;
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

    public BrokerProtocol.RpcResponse importExistingApp(String pkg) {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildImportExisting(id, pkg), PROBE_TIMEOUT_MS);
    }

    public BrokerProtocol.RpcResponse installApk(String apkPath) {
        String id = nextId();
        return exchange(id, BrokerProtocol.buildInstallApk(id, apkPath), PROBE_TIMEOUT_MS);
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

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)
            );
            String line = reader.readLine();
            if (line == null || line.trim().isEmpty()) {
                return BrokerProtocol.RpcResponse.error(id, "broker closed connection", true);
            }
            return BrokerProtocol.parseResponse(line);
        } catch (IOException ex) {
            return BrokerProtocol.RpcResponse.error(
                    id, ex.getMessage() != null ? ex.getMessage() : "socket unreachable", true);
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }
}
