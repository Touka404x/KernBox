package com.sandbox.controller;

import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import android.widget.Toast;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Native Android Quick Settings Tile for toggling and inspecting KernBox sandbox state.
 */
public final class SandboxTileService extends TileService {

    private final BrokerClient broker = new BrokerClient();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean busy = new AtomicBoolean(false);

    @Override
    public void onStartListening() {
        super.onStartListening();
        refreshTile();
    }

    @Override
    public void onClick() {
        super.onClick();
        if (isLocked()) {
            unlockAndRun(new Runnable() {
                @Override
                public void run() {
                    toggleSandbox();
                }
            });
            return;
        }
        toggleSandbox();
    }

    @Override
    public void onDestroy() {
        mainHandler.removeCallbacksAndMessages(null);
        executor.shutdownNow();
        super.onDestroy();
    }

    private void refreshTile() {
        executor.execute(new Runnable() {
            @Override
            public void run() {
                final BrokerProtocol.RpcResponse resp = broker.getStatus();
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        applyTile(resp);
                    }
                });
            }
        });
    }

    private void toggleSandbox() {
        if (!busy.compareAndSet(false, true)) {
            return;
        }
        Tile cur = getQsTile();
        if (cur != null) {
            Strings s = new Strings();
            cur.setLabel(s.brandTitle());
            if (Build.VERSION.SDK_INT >= 29) {
                cur.setSubtitle(s.btnSyncing());
            }
            cur.updateTile();
        }
        executor.execute(new Runnable() {
            @Override
            public void run() {
                BrokerProtocol.RpcResponse finalResp;
                try {
                    BrokerProtocol.RpcResponse status = broker.getStatus();
                    if (!status.ok) {
                        finalResp = status;
                    } else if (status.snapshot.paused) {
                        finalResp = broker.startSandbox();
                    } else {
                        finalResp = broker.pauseSandbox();
                    }
                } finally {
                    busy.set(false);
                }
                final BrokerProtocol.RpcResponse uiResp = finalResp;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        applyTile(uiResp);
                        maybeToastTileError(uiResp);
                    }
                });
            }
        });
    }

    private void maybeToastTileError(BrokerProtocol.RpcResponse resp) {
        Strings s = new Strings();
        if (resp == null) {
            Toast.makeText(getApplicationContext(), s.modeOffline(), Toast.LENGTH_LONG).show();
            return;
        }
        if (resp.offlineReason == BrokerProtocol.OfflineReason.RPC_TIMEOUT) {
            Toast.makeText(getApplicationContext(), s.alertRpcTimeout(), Toast.LENGTH_LONG).show();
            return;
        }
        if (resp.offline || !resp.ok) {
            String msg = !resp.error.isEmpty() ? (s.failPrefix() + resp.error) : s.modeOffline();
            Toast.makeText(getApplicationContext(), msg, Toast.LENGTH_LONG).show();
            return;
        }
        BrokerProtocol.StatusSnapshot snap = resp.snapshot;
        if (snap != null && !snap.paused && !snap.sbwOpen) {
            String detail = !snap.lastError.isEmpty() ? snap.lastError : s.alertGateNotOpen(snap.state);
            Toast.makeText(getApplicationContext(), s.qsError() + ": " + detail, Toast.LENGTH_LONG).show();
        } else if (snap != null && !snap.bootAlert.isEmpty()) {
            Toast.makeText(getApplicationContext(), s.qsError() + ": " + snap.bootAlert, Toast.LENGTH_LONG).show();
        }
    }

    private void applyTile(BrokerProtocol.RpcResponse resp) {
        Tile tile = getQsTile();
        if (tile == null) {
            return;
        }
        Strings s = new Strings();
        tile.setLabel(s.brandTitle());
        if (resp == null) {
            tile.setState(Tile.STATE_UNAVAILABLE);
            if (Build.VERSION.SDK_INT >= 29) {
                tile.setSubtitle(s.modeOffline());
            }
            tile.updateTile();
            return;
        }
        if (resp.offlineReason == BrokerProtocol.OfflineReason.RPC_TIMEOUT) {
            tile.setState(Tile.STATE_INACTIVE);
            if (Build.VERSION.SDK_INT >= 29) {
                tile.setSubtitle(s.qsTimeout());
            }
            tile.updateTile();
            return;
        }
        if (resp.offline) {
            tile.setState(Tile.STATE_UNAVAILABLE);
            if (Build.VERSION.SDK_INT >= 29) {
                tile.setSubtitle(s.modeOffline());
            }
            tile.updateTile();
            return;
        }
        if (!resp.ok) {
            tile.setState(Tile.STATE_INACTIVE);
            if (Build.VERSION.SDK_INT >= 29) {
                tile.setSubtitle(s.qsError());
            }
            tile.updateTile();
            return;
        }
        BrokerProtocol.StatusSnapshot snap = resp.snapshot;
        boolean active = snap.isGateHealthyOpen();
        boolean abnormal = (!snap.paused && !snap.sbwOpen) || snap.hasStartupOrHealthAlert();
        tile.setState(active ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        if (Build.VERSION.SDK_INT >= 29) {
            if (active && !abnormal) {
                tile.setSubtitle(s.qsActive());
            } else if (abnormal) {
                tile.setSubtitle(s.qsError());
            } else if (snap.hotFrozen || snap.frozen) {
                tile.setSubtitle(s.freezeHot());
            } else if (snap.paused && snap.hibernatedCount > 0) {
                tile.setSubtitle(s.freezeDeep());
            } else {
                tile.setSubtitle(s.modeStandby());
            }
        }
        tile.updateTile();
    }
}
