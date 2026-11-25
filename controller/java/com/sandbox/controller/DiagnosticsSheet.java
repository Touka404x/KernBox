package com.sandbox.controller;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Handler;
import android.view.Gravity;
import android.view.View;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.concurrent.ExecutorService;

/**
 * Minimalist diagnostic health sheet surfacing RUN_PROBE isolation & readiness metrics.
 */
public final class DiagnosticsSheet extends FrameLayout {

    public interface Callback {
        void onSnapshotRefreshed(BrokerProtocol.StatusSnapshot snapshot);
        void onToast(String message, boolean error);
    }

    private final Strings strings;
    private final BrokerClient broker;
    private final ExecutorService executor;
    private final Handler mainHandler;
    private final Callback callback;

    private final View backdrop;
    private final LinearLayout sheetContainer;
    private final LinearLayout rowsContainer;
    private final TextView probeBtn;

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
        handleLp.bottomMargin = ThemePalette.dp(ctx, 14f);
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
                ThemePalette.dp(ctx, 32f), ThemePalette.dp(ctx, 32f)));
        sheetContainer.addView(header);

        rowsContainer = new LinearLayout(ctx);
        rowsContainer.setOrientation(LinearLayout.VERTICAL);
        rowsContainer.setBackground(ThemePalette.cardDrawable(
                ctx, ThemePalette.surfaceCard(ctx), ThemePalette.borderHairline(ctx), 16f));
        rowsContainer.setPadding(ThemePalette.dp(ctx, 16f), ThemePalette.dp(ctx, 8f),
                ThemePalette.dp(ctx, 16f), ThemePalette.dp(ctx, 8f));
        LinearLayout.LayoutParams rowsLp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        rowsLp.topMargin = ThemePalette.dp(ctx, 14f);
        rowsLp.bottomMargin = ThemePalette.dp(ctx, 14f);
        sheetContainer.addView(rowsContainer, rowsLp);

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

    public boolean isOpen() {
        return open;
    }

    public void show(BrokerProtocol.StatusSnapshot snapshot, boolean connected) {
        bindSnapshot(snapshot, connected);
        open = true;
        setVisibility(View.VISIBLE);
        backdrop.animate().cancel();
        backdrop.setAlpha(0f);
        backdrop.animate().alpha(1f).setDuration(200L).start();

        sheetContainer.animate().cancel();
        sheetContainer.setTranslationY(ThemePalette.dp(getContext(), 340f));
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
                .translationY(ThemePalette.dp(getContext(), 360f))
                .setDuration(190L)
                .setInterpolator(new AccelerateInterpolator(1.6f))
                .setListener(new AnimatorListenerAdapter() {
                    @Override
                    public void onAnimationEnd(Animator animation) {
                        sheetContainer.animate().setListener(null);
                        if (!open) {
                            setVisibility(View.GONE);
                        }
                    }
                })
                .start();
    }

    private void bindSnapshot(BrokerProtocol.StatusSnapshot s, boolean connected) {
        Context ctx = getContext();
        rowsContainer.removeAllViews();
        if (!connected) {
            addRow(ctx, strings.diagLabelGate(), strings.modeOffline(), false);
            probeBtn.setEnabled(false);
            probeBtn.setAlpha(0.55f);
            return;
        }
        probeBtn.setEnabled(!probing);
        probeBtn.setAlpha(probing ? 0.55f : 1f);

        addRow(ctx, strings.diagLabelGate(),
                s.sbwOpen ? strings.gateOpen() : (s.state + " (" + strings.gateLocked() + ")"),
                s.sbwOpen);
        addRow(ctx, strings.diagLabelTProxy(),
                s.tproxyReady ? strings.diagValOk() : strings.diagValWarn(),
                s.tproxyReady);
        addRow(ctx, strings.diagLabelPreset(),
                s.activePreset != null && !s.activePreset.isEmpty() ? s.activePreset : "neutral",
                true);
        addRow(ctx, strings.diagLabelStealth(),
                s.zygiskDisabled ? strings.diagValDisabled() : strings.diagValEnabled(),
                !s.zygiskDisabled);
        addRow(ctx, strings.diagLabelDns(),
                s.privateDnsWarning ? strings.diagValWarn() : strings.diagValOk(),
                !s.privateDnsWarning);
        addRow(ctx, strings.diagLabelSockets(),
                String.valueOf(s.stuckWorkSockets),
                s.stuckWorkSockets == 0);
        String probeText = s.probeApkInstalled
                ? (s.instrumentOk ? strings.diagValProbePass() : strings.diagValProbeInstalled())
                : strings.diagValProbeAbsent();
        addRow(ctx, strings.diagLabelVerify(), probeText, s.instrumentOk || !s.probeApkInstalled);
    }

    private void addRow(Context ctx, String key, String val, boolean healthy) {
        if (rowsContainer.getChildCount() > 0) {
            View div = new View(ctx);
            div.setBackgroundColor(ThemePalette.borderHairline(ctx));
            rowsContainer.addView(div, new LinearLayout.LayoutParams(
                    LayoutParams.MATCH_PARENT, Math.max(1, ThemePalette.dp(ctx, 1f))));
        }
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, ThemePalette.dp(ctx, 11f), 0, ThemePalette.dp(ctx, 11f));

        TextView kTv = new TextView(ctx);
        kTv.setText(key);
        kTv.setTextColor(ThemePalette.inkSecondary(ctx));
        kTv.setTextSize(13.5f);
        row.addView(kTv, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));

        TextView vTv = new TextView(ctx);
        vTv.setText(val);
        vTv.setTextColor(healthy ? ThemePalette.accentSage(ctx) : ThemePalette.accentError(ctx));
        vTv.setTextSize(13.5f);
        vTv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        row.addView(vTv);
        rowsContainer.addView(row);
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
                final BrokerProtocol.RpcResponse resp = broker.runProbe();
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        probing = false;
                        probeBtn.setText(strings.diagRunProbe());
                        probeBtn.setEnabled(true);
                        probeBtn.setAlpha(1f);
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
