package com.sandbox.controller;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Handler;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.Locale;
import java.util.concurrent.ExecutorService;

/**
 * Minimalist diagnostic & runtime control sheet surfacing RUN_PROBE metrics,
 * 12-item scorecard summary, redacted JSON export, QUIC UDP/443 toggle, and HyperOS hide-app sync.
 */
public final class DiagnosticsSheet extends FrameLayout {

    public interface Callback {
        void onSnapshotRefreshed(BrokerProtocol.StatusSnapshot snapshot);
        void onToast(String message, boolean error);
        void onSheetDismissed();
    }

    private final Strings strings;
    private final BrokerClient broker;
    private final ExecutorService executor;
    private final Handler mainHandler;
    private final Callback callback;

    private final View backdrop;
    private final LinearLayout sheetContainer;
    private final ScrollView rowsScroll;
    private final LinearLayout rowsContainer;
    private final TextView copyReportBtn;
    private final TextView quicToggleBtn;
    private final TextView syncHideBtn;
    private final TextView probeBtn;

    private BrokerProtocol.StatusSnapshot latestSnapshot = BrokerProtocol.StatusSnapshot.empty();
    private String quicMode = "reject";
    private boolean open = false;
    private boolean probing = false;

    public DiagnosticsSheet(
            Context ctx,
            Strings strings,
            BrokerClient broker,
            ExecutorService executor,
            Handler mainHandler,
            Callback callback) {
        super(ctx);
        this.strings = strings;
        this.broker = broker;
        this.executor = executor;
        this.mainHandler = mainHandler;
        this.callback = callback;

        setVisibility(View.GONE);
        setClickable(true);

        backdrop = new View(ctx);
        backdrop.setBackgroundColor(ThemePalette.backdropDim(ctx));
        backdrop.setAlpha(0f);
        backdrop.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                dismiss();
            }
        });
        addView(backdrop, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT));

        sheetContainer = new LinearLayout(ctx);
        sheetContainer.setOrientation(LinearLayout.VERTICAL);
        sheetContainer.setBackground(ThemePalette.topSheetDrawable(
                ctx, ThemePalette.bgPaper(ctx), ThemePalette.borderHairline(ctx), 24f));
        sheetContainer.setClickable(true);
        int hPad = ThemePalette.dp(ctx, 20f);
        sheetContainer.setPadding(hPad, ThemePalette.dp(ctx, 12f), hPad, ThemePalette.dp(ctx, 24f));
        sheetContainer.setElevation(ThemePalette.dp(ctx, 18f));
        addView(sheetContainer, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT, Gravity.BOTTOM));

        View handle = new View(ctx);
        handle.setBackground(ThemePalette.cardDrawable(
                ctx, ThemePalette.borderHairline(ctx), Color.TRANSPARENT, 3f));
        LinearLayout.LayoutParams handleLp = new LinearLayout.LayoutParams(
                ThemePalette.dp(ctx, 40f), ThemePalette.dp(ctx, 4f));
        handleLp.gravity = Gravity.CENTER_HORIZONTAL;
        handleLp.bottomMargin = ThemePalette.dp(ctx, 12f);
        sheetContainer.addView(handle, handleLp);

        LinearLayout header = new LinearLayout(ctx);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = new TextView(ctx);
        title.setText(strings.diagTitle());
        title.setTextColor(ThemePalette.inkPrimary(ctx));
        title.setTextSize(18f);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        header.addView(title, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));

        TextView closeBtn = new TextView(ctx);
        closeBtn.setText("×");
        closeBtn.setTextSize(20f);
        closeBtn.setGravity(Gravity.CENTER);
        closeBtn.setContentDescription(strings.a11yClose());
        closeBtn.setTextColor(ThemePalette.inkSecondary(ctx));
        closeBtn.setBackground(ThemePalette.circleRippleDrawable(
                ctx, ThemePalette.surfaceSubtle(ctx), ThemePalette.surfacePressed(ctx), Color.TRANSPARENT));
        Motion.attachPressScale(closeBtn);
        closeBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                dismiss();
            }
        });
        header.addView(closeBtn, new LinearLayout.LayoutParams(
                ThemePalette.dp(ctx, 44f), ThemePalette.dp(ctx, 44f)));
        sheetContainer.addView(header);

        rowsScroll = new ScrollView(ctx);
        rowsScroll.setVerticalScrollBarEnabled(false);
        rowsContainer = new LinearLayout(ctx);
        rowsContainer.setOrientation(LinearLayout.VERTICAL);
        rowsContainer.setBackground(ThemePalette.cardDrawable(
                ctx, ThemePalette.surfaceCard(ctx), ThemePalette.borderHairline(ctx), 16f));
        rowsContainer.setPadding(ThemePalette.dp(ctx, 16f), ThemePalette.dp(ctx, 6f),
                ThemePalette.dp(ctx, 16f), ThemePalette.dp(ctx, 6f));
        rowsScroll.addView(rowsContainer, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams scrollLp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        scrollLp.topMargin = ThemePalette.dp(ctx, 12f);
        scrollLp.bottomMargin = ThemePalette.dp(ctx, 12f);
        sheetContainer.addView(rowsScroll, scrollLp);

        LinearLayout toolsRow = new LinearLayout(ctx);
        toolsRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams toolsLp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        toolsLp.bottomMargin = ThemePalette.dp(ctx, 10f);

        copyReportBtn = buildSecondaryButton(ctx, strings.diagCopyReport());
        copyReportBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                ClipboardManager cm = (ClipboardManager) getContext().getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) {
                    cm.setPrimaryClip(ClipData.newPlainText("kernbox-diag", latestSnapshot.toRedactedDiagnosticJson()));
                }
                callback.onToast(strings.diagCopiedReport(), false);
            }
        });
        LinearLayout.LayoutParams copyLp = new LinearLayout.LayoutParams(0, ThemePalette.dp(ctx, 40f), 1f);
        copyLp.setMarginEnd(ThemePalette.dp(ctx, 8f));
        toolsRow.addView(copyReportBtn, copyLp);

        quicToggleBtn = buildSecondaryButton(ctx, strings.diagQuicReject());
        quicToggleBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleQuicMode();
            }
        });
        LinearLayout.LayoutParams quicLp = new LinearLayout.LayoutParams(0, ThemePalette.dp(ctx, 40f), 1f);
        toolsRow.addView(quicToggleBtn, quicLp);

        syncHideBtn = buildSecondaryButton(ctx, strings.diagSyncHideApps());
        syncHideBtn.setVisibility(View.GONE);
        syncHideBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                triggerHideSync();
            }
        });
        LinearLayout.LayoutParams syncLp = new LinearLayout.LayoutParams(0, ThemePalette.dp(ctx, 40f), 1f);
        syncLp.setMarginStart(ThemePalette.dp(ctx, 8f));
        toolsRow.addView(syncHideBtn, syncLp);

        sheetContainer.addView(toolsRow, toolsLp);

        probeBtn = new TextView(ctx);
        probeBtn.setText(strings.diagRunProbe());
        probeBtn.setTextColor(Color.WHITE);
        probeBtn.setTextSize(14.5f);
        probeBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        probeBtn.setGravity(Gravity.CENTER);
        probeBtn.setBackground(ThemePalette.pillRippleDrawable(
                ctx, ThemePalette.accentCopper(ctx), ThemePalette.accentCopperPressed(ctx), Color.TRANSPARENT, 14f));
        Motion.attachPressScale(probeBtn);
        probeBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                runLiveProbe();
            }
        });
        sheetContainer.addView(probeBtn, new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, ThemePalette.dp(ctx, 46f)));
    }

    private TextView buildSecondaryButton(Context ctx, String label) {
        TextView tv = new TextView(ctx);
        tv.setText(label);
        tv.setTextColor(ThemePalette.inkPrimary(ctx));
        tv.setTextSize(12f);
        tv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        tv.setGravity(Gravity.CENTER);
        tv.setMaxLines(1);
        tv.setEllipsize(TextUtils.TruncateAt.END);
        tv.setPadding(ThemePalette.dp(ctx, 8f), 0, ThemePalette.dp(ctx, 8f), 0);
        tv.setBackground(ThemePalette.pillRippleDrawable(
                ctx, ThemePalette.surfaceCard(ctx), ThemePalette.surfacePressed(ctx), ThemePalette.borderHairline(ctx), 12f));
        Motion.attachPressScale(tv);
        return tv;
    }

    public void setBottomInset(int bottomPx) {
        int hPad = ThemePalette.dp(getContext(), 20f);
        sheetContainer.setPadding(hPad, ThemePalette.dp(getContext(), 12f), hPad,
                ThemePalette.dp(getContext(), 24f) + Math.max(0, bottomPx));
        refreshScrollHeight();
    }

    public void refreshScrollHeight() {
        int h = getContext().getResources().getDisplayMetrics().heightPixels;
        int maxH = Math.max(ThemePalette.dp(getContext(), 180f), Math.round(h * 0.44f));
        LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) rowsScroll.getLayoutParams();
        if (lp != null) {
            lp.height = maxH;
            rowsScroll.setLayoutParams(lp);
        }
    }

    public boolean isOpen() {
        return open;
    }

    public void show(BrokerProtocol.StatusSnapshot snapshot, boolean connected) {
        refreshScrollHeight();
        bindSnapshot(snapshot, connected);
        open = true;
        setVisibility(View.VISIBLE);
        backdrop.animate().cancel();
        backdrop.setAlpha(0f);
        backdrop.animate().alpha(1f).setDuration(200L).start();

        sheetContainer.animate().cancel();
        sheetContainer.setTranslationY(ThemePalette.dp(getContext(), 360f));
        sheetContainer.animate()
                .translationY(0f)
                .setDuration(260L)
                .setInterpolator(new DecelerateInterpolator(2.2f))
                .start();
    }

    public void dismiss() {
        if (!open) {
            return;
        }
        open = false;
        backdrop.animate().cancel();
        backdrop.animate().alpha(0f).setDuration(170L).start();
        sheetContainer.animate().cancel();
        sheetContainer.animate()
                .translationY(ThemePalette.dp(getContext(), 380f))
                .setDuration(190L)
                .setInterpolator(new AccelerateInterpolator(1.6f))
                .setListener(new AnimatorListenerAdapter() {
                    @Override
                    public void onAnimationEnd(Animator animation) {
                        sheetContainer.animate().setListener(null);
                        if (!open) {
                            setVisibility(View.GONE);
                            callback.onSheetDismissed();
                        }
                    }
                })
                .start();
    }

    private void bindSnapshot(BrokerProtocol.StatusSnapshot s, boolean connected) {
        Context ctx = getContext();
        latestSnapshot = s != null ? s : BrokerProtocol.StatusSnapshot.empty();
        rowsContainer.removeAllViews();

        boolean isHyperOs = latestSnapshot.variant != null
                && latestSnapshot.variant.toLowerCase(Locale.ROOT).startsWith("hyperos");
        syncHideBtn.setVisibility(connected && isHyperOs ? View.VISIBLE : View.GONE);
        if ("allow".equalsIgnoreCase(latestSnapshot.quicUdp443Mode)
                || "reject".equalsIgnoreCase(latestSnapshot.quicUdp443Mode)) {
            quicMode = latestSnapshot.quicUdp443Mode.toLowerCase(Locale.ROOT);
        }
        quicToggleBtn.setText("reject".equals(quicMode) ? strings.diagQuicReject() : strings.diagQuicAllow());
        quicToggleBtn.setEnabled(connected && !probing);
        quicToggleBtn.setAlpha(connected && !probing ? 1f : 0.55f);

        if (!connected) {
            addRow(ctx, strings.diagLabelGate(), strings.modeOffline(), false, true);
            probeBtn.setEnabled(false);
            probeBtn.setAlpha(0.55f);
            return;
        }
        probeBtn.setEnabled(!probing);
        probeBtn.setAlpha(probing ? 0.55f : 1f);

        if (latestSnapshot.bootAlert != null && !latestSnapshot.bootAlert.trim().isEmpty()) {
            addRow(ctx, strings.diagLabelBootAlert(), latestSnapshot.bootAlert.trim(), false, false);
        }

        if (latestSnapshot.lastError != null && !latestSnapshot.lastError.trim().isEmpty()) {
            addRow(ctx, strings.diagLabelLastError(), latestSnapshot.lastError.trim(), false, false);
        }

        if (latestSnapshot.crossPool12c6Hits > 0) {
            addRow(ctx, strings.diagLabelCrossPool(), String.valueOf(latestSnapshot.crossPool12c6Hits), false, true);
        }

        addRow(ctx, strings.diagLabelGate(),
                latestSnapshot.sbwOpen ? strings.gateOpen() : (latestSnapshot.state + " (" + strings.gateLocked() + ")"),
                latestSnapshot.sbwOpen, true);

        if ("tproxy".equalsIgnoreCase(latestSnapshot.mode)) {
            int port = latestSnapshot.tproxyPort > 0 ? latestSnapshot.tproxyPort : 1537;
            addRow(ctx, strings.diagLabelTProxy() + " (:" + port + ")",
                    latestSnapshot.tproxyReady ? strings.diagValOk() : strings.diagValWarn(),
                    latestSnapshot.tproxyReady, true);
        } else {
            String vpnVal = latestSnapshot.exitIp != null && !latestSnapshot.exitIp.isEmpty()
                    ? latestSnapshot.exitIp
                    : (latestSnapshot.vpnRunning ? strings.diagValOk() : strings.diagValWarn());
            addRow(ctx, strings.diagLabelVpn(), vpnVal, latestSnapshot.vpnRunning, true);
        }

        addRow(ctx, strings.diagLabelPreset(),
                latestSnapshot.activePreset != null && !latestSnapshot.activePreset.isEmpty()
                        ? latestSnapshot.activePreset : "neutral",
                true, true);

        addRow(ctx, strings.diagLabelStealth(),
                latestSnapshot.zygiskDisabled ? strings.diagValDisabled() : strings.diagValEnabled(),
                !latestSnapshot.zygiskDisabled, true);

        String dnsVal = latestSnapshot.privateDnsWarning
                ? strings.diagValWarn() + (latestSnapshot.privateDnsMode.isEmpty() ? "" : " (" + latestSnapshot.privateDnsMode + ")")
                : strings.diagValOk();
        addRow(ctx, strings.diagLabelDns(), dnsVal, !latestSnapshot.privateDnsWarning, true);

        addRow(ctx, strings.diagLabelSockets(),
                String.valueOf(latestSnapshot.stuckWorkSockets),
                latestSnapshot.stuckWorkSockets == 0, true);

        String probeText;
        boolean probeHealthy;
        if (!latestSnapshot.hasProbeData) {
            probeText = strings.diagValProbeUnknown();
            probeHealthy = true;
        } else if (latestSnapshot.probeApkInstalled) {
            probeText = latestSnapshot.instrumentOk ? strings.diagValProbePass() : strings.diagValProbeInstalled();
            probeHealthy = latestSnapshot.instrumentOk;
        } else {
            probeText = strings.diagValProbeAbsent();
            probeHealthy = true;
        }
        addRow(ctx, strings.diagLabelVerify(), probeText, probeHealthy, true);

        if (latestSnapshot.scorecardTotal > 0) {
            addRow(ctx, strings.diagLabelScorecard(),
                    strings.diagScorecardFmt(
                            latestSnapshot.scorecardPassed,
                            latestSnapshot.scorecardTotal,
                            latestSnapshot.scorecardWarn,
                            latestSnapshot.scorecardFailed),
                    latestSnapshot.scorecardFailed == 0, true);
        }
    }

    private void addRow(Context ctx, String key, String val, boolean healthy, boolean singleLine) {
        if (rowsContainer.getChildCount() > 0) {
            View div = new View(ctx);
            div.setBackgroundColor(ThemePalette.borderHairline(ctx));
            rowsContainer.addView(div, new LinearLayout.LayoutParams(
                    LayoutParams.MATCH_PARENT, Math.max(1, ThemePalette.dp(ctx, 1f))));
        }
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, ThemePalette.dp(ctx, 10f), 0, ThemePalette.dp(ctx, 10f));

        TextView kTv = new TextView(ctx);
        kTv.setText(key);
        kTv.setTextColor(ThemePalette.inkSecondary(ctx));
        kTv.setTextSize(13f);
        kTv.setPadding(0, 0, ThemePalette.dp(ctx, 8f), 0);
        row.addView(kTv, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));

        TextView vTv = new TextView(ctx);
        vTv.setText(val);
        vTv.setTextColor(healthy ? ThemePalette.accentSage(ctx) : ThemePalette.accentError(ctx));
        vTv.setTextSize(13f);
        vTv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        if (singleLine) {
            vTv.setMaxLines(1);
            vTv.setEllipsize(TextUtils.TruncateAt.END);
        } else {
            vTv.setMaxLines(4);
            vTv.setEllipsize(TextUtils.TruncateAt.END);
        }
        row.addView(vTv);
        rowsContainer.addView(row);
    }

    private void toggleQuicMode() {
        final String nextMode = "reject".equals(quicMode) ? "allow" : "reject";
        quicToggleBtn.setEnabled(false);
        executor.execute(new Runnable() {
            @Override
            public void run() {
                BrokerProtocol.RpcResponse r;
                try {
                    r = broker.reloadConfig(nextMode, "");
                } catch (Throwable t) {
                    r = BrokerProtocol.RpcResponse.error("", String.valueOf(t.getMessage()), false);
                }
                final BrokerProtocol.RpcResponse resp = r;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        quicToggleBtn.setEnabled(true);
                        if (!isAttachedToWindow()) {
                            return;
                        }
                        if (resp.ok) {
                            quicMode = nextMode;
                            quicToggleBtn.setText("reject".equals(quicMode)
                                    ? strings.diagQuicReject()
                                    : strings.diagQuicAllow());
                            callback.onToast(strings.diagQuicUpdated(quicMode), false);
                        } else {
                            callback.onToast(strings.failPrefix() + resp.error, true);
                        }
                    }
                });
            }
        });
    }

    private void triggerHideSync() {
        syncHideBtn.setEnabled(false);
        executor.execute(new Runnable() {
            @Override
            public void run() {
                BrokerProtocol.RpcResponse r;
                try {
                    r = broker.syncHideApps();
                } catch (Throwable t) {
                    r = BrokerProtocol.RpcResponse.error("", String.valueOf(t.getMessage()), false);
                }
                final BrokerProtocol.RpcResponse resp = r;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        syncHideBtn.setEnabled(true);
                        if (!isAttachedToWindow()) {
                            return;
                        }
                        if (resp.ok) {
                            callback.onToast(strings.diagSyncedHideApps(), false);
                        } else {
                            callback.onToast(strings.failPrefix() + resp.error, true);
                        }
                    }
                });
            }
        });
    }

    private void runLiveProbe() {
        if (probing) {
            return;
        }
        probing = true;
        probeBtn.setEnabled(false);
        probeBtn.setText(strings.diagRunning());
        probeBtn.setAlpha(0.6f);
        executor.execute(new Runnable() {
            @Override
            public void run() {
                BrokerProtocol.RpcResponse r;
                try {
                    r = broker.runProbe();
                } catch (Throwable t) {
                    r = BrokerProtocol.RpcResponse.error("", String.valueOf(t.getMessage()), false);
                }
                final BrokerProtocol.RpcResponse resp = r;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        probing = false;
                        probeBtn.setText(strings.diagRunProbe());
                        probeBtn.setEnabled(true);
                        probeBtn.setAlpha(1f);
                        if (!isAttachedToWindow()) {
                            return;
                        }
                        if (resp.ok) {
                            bindSnapshot(resp.snapshot, true);
                            callback.onSnapshotRefreshed(resp.snapshot);
                        } else {
                            if (resp.snapshot != null && resp.snapshot.policyLoaded) {
                                bindSnapshot(resp.snapshot, !resp.offline);
                            }
                            callback.onToast(strings.failPrefix() + resp.error, true);
                        }
                    }
                });
            }
        });
    }
}
