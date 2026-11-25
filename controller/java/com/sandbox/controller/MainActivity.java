package com.sandbox.controller;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsetsController;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * KernBox Companion Controller Activity:
 * Adaptive Light/Dark Dieter Rams / Swiss Monograph surface with animated status ring,
 * offline SHA-256 cert fingerprint helper, diagnostics sheet, responsive workspace grid
 * with long-press management, and animated "+" FAB add-app bottom sheet.
 */
public final class MainActivity extends Activity {

    private final Strings strings = new Strings();
    private final BrokerClient broker = new BrokerClient();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private BreathingHaloView haloView;
    private TextView modePill;
    private TextView statusTitleView;
    private TextView statusSubtitleView;
    private LinearLayout offlineCertBox;
    private TextView offlineCertDigestView;
    private TextView primaryToggleBtn;
    private TextView metricAppsVal;
    private TextView metricGateVal;
    private TextView metricFreezeVal;
    private TextView appsCountPill;
    private GridLayout appsGrid;
    private LinearLayout emptyStateCard;
    private ImageView diagIconBtn;
    private ImageView refreshIconBtn;
    private FrameLayout fabButton;
    private TextView toastCapsule;

    private AddAppSheet addAppSheet;
    private AppActionSheet appActionSheet;
    private DiagnosticsSheet diagnosticsSheet;
    private Object backCallbackToken;

    private BrokerProtocol.StatusSnapshot currentSnapshot = BrokerProtocol.StatusSnapshot.empty();
    private String certSha256 = "";
    private boolean connected = false;
    private boolean busy = false;

    private final Runnable hideToastTask = new Runnable() {
        @Override
        public void run() {
            if (toastCapsule != null) {
                toastCapsule.animate().alpha(0f).translationY(ThemePalette.dp(MainActivity.this, 10f))
                        .setDuration(220L).withEndAction(new Runnable() {
                            @Override
                            public void run() {
                                toastCapsule.setVisibility(View.GONE);
                            }
                        }).start();
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.certSha256 = CertUtil.getSigningCertSha256(this);
        configureSystemBars();
        setContentView(buildRootLayout());
        registerPredictiveBack();
        renderSnapshot();
        refreshStatus(false);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (haloView != null) {
            haloView.setHostResumed(true);
        }
        refreshStatus(false);
    }

    @Override
    protected void onPause() {
        if (haloView != null) {
            haloView.setHostResumed(false);
        }
        super.onPause();
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        if (dismissTopOverlayIfOpen()) {
            return;
        }
        super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        unregisterPredictiveBack();
        mainHandler.removeCallbacksAndMessages(null);
        executor.shutdownNow();
        super.onDestroy();
    }

    private void registerPredictiveBack() {
        if (Build.VERSION.SDK_INT >= 33) {
            OnBackInvokedCallback cb = new OnBackInvokedCallback() {
                @Override
                public void onBackInvoked() {
                    if (!dismissTopOverlayIfOpen()) {
                        finish();
                    }
                }
            };
            getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
                    OnBackInvokedDispatcher.PRIORITY_DEFAULT, cb);
            this.backCallbackToken = cb;
        }
    }

    private void unregisterPredictiveBack() {
        if (Build.VERSION.SDK_INT >= 33 && backCallbackToken instanceof OnBackInvokedCallback) {
            getOnBackInvokedDispatcher().unregisterOnBackInvokedCallback((OnBackInvokedCallback) backCallbackToken);
            backCallbackToken = null;
        }
    }

    private boolean dismissTopOverlayIfOpen() {
        if (appActionSheet != null && appActionSheet.isOpen()) {
            appActionSheet.dismiss();
            return true;
        }
        if (diagnosticsSheet != null && diagnosticsSheet.isOpen()) {
            diagnosticsSheet.dismiss();
            return true;
        }
        if (addAppSheet != null && addAppSheet.isOpen()) {
            addAppSheet.dismiss();
            Motion.animateFabToggle(fabButton, false);
            return true;
        }
        return false;
    }

    private void configureSystemBars() {
        if (Build.VERSION.SDK_INT >= 30) {
            WindowInsetsController ctrl = getWindow().getInsetsController();
            if (ctrl != null) {
                boolean dark = ThemePalette.isDark(this);
                int mask = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                        | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                ctrl.setSystemBarsAppearance(dark ? 0 : mask, mask);
            }
        }
    }

    private View buildRootLayout() {
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(ThemePalette.bgPaper(this));
        root.setFitsSystemWindows(true);

        ScrollView scroll = new ScrollView(this);
        scroll.setVerticalScrollBarEnabled(false);

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int hPad = ThemePalette.dp(this, 20f);
        content.setPadding(hPad, ThemePalette.dp(this, 16f), hPad, ThemePalette.dp(this, 100f));

        content.addView(buildHeaderRow());
        content.addView(buildHeroStatusCard());
        content.addView(buildAppsHeaderRow());
        content.addView(buildAppsGridSection());

        scroll.addView(content, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT));
        root.addView(scroll, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        fabButton = new FrameLayout(this);
        fabButton.setBackground(ThemePalette.circleRippleDrawable(
                this, ThemePalette.accentCopper(this), ThemePalette.accentCopperPressed(this), Color.TRANSPARENT));
        fabButton.setElevation(ThemePalette.dp(this, 8f));
        fabButton.setContentDescription(strings.sheetTitle());
        PlusMarkView fabPlusMark = new PlusMarkView(this);
        int iconSize = ThemePalette.dp(this, 28f);
        fabButton.addView(fabPlusMark, new FrameLayout.LayoutParams(iconSize, iconSize, Gravity.CENTER));
        Motion.attachPressScale(fabButton);
        fabButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleAddSheet();
            }
        });
        int fabSize = ThemePalette.dp(this, 58f);
        FrameLayout.LayoutParams fabLp = new FrameLayout.LayoutParams(fabSize, fabSize, Gravity.BOTTOM | Gravity.END);
        fabLp.rightMargin = ThemePalette.dp(this, 22f);
        fabLp.bottomMargin = ThemePalette.dp(this, 24f);
        root.addView(fabButton, fabLp);

        addAppSheet = new AddAppSheet(this, strings, broker, executor, mainHandler, new AddAppSheet.HostCallback() {
            @Override
            public void onAppImported(String pkg, String label) {
                showToast(strings.importedFmt(label), false);
                refreshStatus(false);
            }

            @Override
            public void onApkInstalled(String path) {
                showToast(strings.installedApkOk(), false);
                refreshStatus(false);
            }

            @Override
            public void onToast(String message, boolean error) {
                showToast(message, error);
            }

            @Override
            public void onDismissed() {
                Motion.animateFabToggle(fabButton, false);
            }
        });
        root.addView(addAppSheet, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        appActionSheet = new AppActionSheet(this, strings, broker, executor, mainHandler, new AppActionSheet.Callback() {
            @Override
            public void onActionSuccess(BrokerProtocol.StatusSnapshot snapshot, String toastMessage) {
                if (snapshot != null && snapshot.policyLoaded) {
                    connected = true;
                    currentSnapshot = snapshot;
                    renderSnapshot();
                } else {
                    refreshStatus(false);
                }
                showToast(toastMessage, false);
            }

            @Override
            public void onActionError(String errorMessage) {
                showToast(errorMessage, true);
            }

            @Override
            public void onCopyToast(String message) {
                showToast(message, false);
            }
        });
        root.addView(appActionSheet, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        diagnosticsSheet = new DiagnosticsSheet(this, strings, broker, executor, mainHandler, new DiagnosticsSheet.Callback() {
            @Override
            public void onSnapshotRefreshed(BrokerProtocol.StatusSnapshot snapshot) {
                if (snapshot != null && snapshot.policyLoaded) {
                    connected = true;
                    currentSnapshot = snapshot;
                    renderSnapshot();
                }
            }

            @Override
            public void onToast(String message, boolean error) {
                showToast(message, error);
            }
        });
        root.addView(diagnosticsSheet, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        toastCapsule = new TextView(this);
        toastCapsule.setVisibility(View.GONE);
        toastCapsule.setTextColor(Color.WHITE);
        toastCapsule.setTextSize(13f);
        toastCapsule.setGravity(Gravity.CENTER);
        toastCapsule.setPadding(ThemePalette.dp(this, 16f), ThemePalette.dp(this, 10f),
                ThemePalette.dp(this, 16f), ThemePalette.dp(this, 10f));
        toastCapsule.setElevation(ThemePalette.dp(this, 10f));
        FrameLayout.LayoutParams toastLp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        toastLp.bottomMargin = ThemePalette.dp(this, 96f);
        root.addView(toastCapsule, toastLp);

        return root;
    }

    private View buildHeaderRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = ThemePalette.dp(this, 18f);
        row.setLayoutParams(lp);

        ImageView logo = new ImageView(this);
        logo.setImageResource(R.mipmap.ic_launcher);
        LinearLayout.LayoutParams logoLp = new LinearLayout.LayoutParams(
                ThemePalette.dp(this, 36f), ThemePalette.dp(this, 36f));
        logoLp.rightMargin = ThemePalette.dp(this, 10f);
        row.addView(logo, logoLp);

        TextView wordmark = new TextView(this);
        wordmark.setText(strings.brandTitle());
        wordmark.setTextColor(ThemePalette.inkPrimary(this));
        wordmark.setTextSize(21f);
        wordmark.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        wordmark.setLetterSpacing(-0.02f);
        row.addView(wordmark, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        modePill = new TextView(this);
        modePill.setText(strings.modeOffline());
        modePill.setTextColor(ThemePalette.inkSecondary(this));
        modePill.setTextSize(11.5f);
        modePill.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        modePill.setBackground(ThemePalette.cardDrawable(
                this, ThemePalette.surfaceSubtle(this), ThemePalette.borderHairline(this), 16f));
        modePill.setPadding(ThemePalette.dp(this, 11f), ThemePalette.dp(this, 5f),
                ThemePalette.dp(this, 11f), ThemePalette.dp(this, 5f));
        LinearLayout.LayoutParams pillLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        pillLp.rightMargin = ThemePalette.dp(this, 8f);
        row.addView(modePill, pillLp);

        diagIconBtn = new ImageView(this);
        diagIconBtn.setImageResource(android.R.drawable.ic_menu_info_details);
        diagIconBtn.setColorFilter(ThemePalette.inkSecondary(this));
        diagIconBtn.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        diagIconBtn.setContentDescription(strings.diagTitle());
        diagIconBtn.setPadding(ThemePalette.dp(this, 8f), ThemePalette.dp(this, 8f),
                ThemePalette.dp(this, 8f), ThemePalette.dp(this, 8f));
        diagIconBtn.setBackground(ThemePalette.circleRippleDrawable(
                this, ThemePalette.surfaceCard(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this)));
        Motion.attachPressScale(diagIconBtn);
        diagIconBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                diagnosticsSheet.show(currentSnapshot, connected);
            }
        });
        LinearLayout.LayoutParams diagLp = new LinearLayout.LayoutParams(
                ThemePalette.dp(this, 36f), ThemePalette.dp(this, 36f));
        diagLp.rightMargin = ThemePalette.dp(this, 8f);
        row.addView(diagIconBtn, diagLp);

        refreshIconBtn = new ImageView(this);
        refreshIconBtn.setImageResource(android.R.drawable.ic_popup_sync);
        refreshIconBtn.setColorFilter(ThemePalette.inkSecondary(this));
        refreshIconBtn.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        refreshIconBtn.setPadding(ThemePalette.dp(this, 8f), ThemePalette.dp(this, 8f),
                ThemePalette.dp(this, 8f), ThemePalette.dp(this, 8f));
        refreshIconBtn.setBackground(ThemePalette.circleRippleDrawable(
                this, ThemePalette.surfaceCard(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this)));
        Motion.attachPressScale(refreshIconBtn);
        refreshIconBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Motion.spinOnce(refreshIconBtn);
                refreshStatus(true);
            }
        });
        row.addView(refreshIconBtn, new LinearLayout.LayoutParams(
                ThemePalette.dp(this, 36f), ThemePalette.dp(this, 36f)));
        return row;
    }

    private View buildHeroStatusCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(ThemePalette.cardDrawable(
                this, ThemePalette.surfaceCard(this), ThemePalette.borderHairline(this), 22f));
        card.setElevation(ThemePalette.dp(this, 2f));
        int pad = ThemePalette.dp(this, 20f);
        card.setPadding(pad, pad, pad, pad);
        LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        cardLp.bottomMargin = ThemePalette.dp(this, 22f);
        card.setLayoutParams(cardLp);

        LinearLayout topRow = new LinearLayout(this);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);

        haloView = new BreathingHaloView(this);
        LinearLayout.LayoutParams haloLp = new LinearLayout.LayoutParams(
                ThemePalette.dp(this, 52f), ThemePalette.dp(this, 52f));
        haloLp.rightMargin = ThemePalette.dp(this, 14f);
        topRow.addView(haloView, haloLp);

        LinearLayout infoCol = new LinearLayout(this);
        infoCol.setOrientation(LinearLayout.VERTICAL);
        statusTitleView = new TextView(this);
        statusTitleView.setTextColor(ThemePalette.inkPrimary(this));
        statusTitleView.setTextSize(19f);
        statusTitleView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        infoCol.addView(statusTitleView);

        statusSubtitleView = new TextView(this);
        statusSubtitleView.setTextColor(ThemePalette.inkSecondary(this));
        statusSubtitleView.setTextSize(13f);
        statusSubtitleView.setPadding(0, ThemePalette.dp(this, 3f), 0, 0);
        infoCol.addView(statusSubtitleView);
        topRow.addView(infoCol, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        card.addView(topRow);

        // Compact Offline Setup Cert Helper
        offlineCertBox = new LinearLayout(this);
        offlineCertBox.setOrientation(LinearLayout.HORIZONTAL);
        offlineCertBox.setGravity(Gravity.CENTER_VERTICAL);
        offlineCertBox.setBackground(ThemePalette.cardDrawable(
                this, ThemePalette.surfaceSubtle(this), ThemePalette.borderHairline(this), 14f));
        offlineCertBox.setPadding(ThemePalette.dp(this, 12f), ThemePalette.dp(this, 10f),
                ThemePalette.dp(this, 12f), ThemePalette.dp(this, 10f));
        LinearLayout.LayoutParams certBoxLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        certBoxLp.topMargin = ThemePalette.dp(this, 14f);

        LinearLayout certTextCol = new LinearLayout(this);
        certTextCol.setOrientation(LinearLayout.VERTICAL);
        TextView certCap = new TextView(this);
        certCap.setText(strings.offlineCertTitle());
        certCap.setTextColor(ThemePalette.inkMuted(this));
        certCap.setTextSize(11f);
        certTextCol.addView(certCap);

        offlineCertDigestView = new TextView(this);
        offlineCertDigestView.setText(certSha256.isEmpty() ? "—" : CertUtil.shortDigest(certSha256));
        offlineCertDigestView.setTextColor(ThemePalette.inkPrimary(this));
        offlineCertDigestView.setTextSize(12.5f);
        offlineCertDigestView.setTypeface(Typeface.MONOSPACE);
        certTextCol.addView(offlineCertDigestView);
        offlineCertBox.addView(certTextCol, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        TextView copyCertBtn = new TextView(this);
        copyCertBtn.setText(strings.btnCopyCert());
        copyCertBtn.setTextColor(Color.WHITE);
        copyCertBtn.setTextSize(12f);
        copyCertBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        copyCertBtn.setBackground(ThemePalette.pillRippleDrawable(
                this, ThemePalette.accentCopper(this), ThemePalette.accentCopperPressed(this), Color.TRANSPARENT, 14f));
        copyCertBtn.setPadding(ThemePalette.dp(this, 12f), ThemePalette.dp(this, 6f),
                ThemePalette.dp(this, 12f), ThemePalette.dp(this, 6f));
        Motion.attachPressScale(copyCertBtn);
        copyCertBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (!certSha256.isEmpty()) {
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(ClipData.newPlainText("kernbox-cert-sha256", certSha256));
                    }
                    showToast(strings.copiedCertToast(), false);
                }
            }
        });
        offlineCertBox.addView(copyCertBtn);
        card.addView(offlineCertBox, certBoxLp);

        primaryToggleBtn = new TextView(this);
        primaryToggleBtn.setTextSize(15f);
        primaryToggleBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        primaryToggleBtn.setGravity(Gravity.CENTER);
        Motion.attachPressScale(primaryToggleBtn);
        primaryToggleBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onPrimaryToggleClicked();
            }
        });
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, ThemePalette.dp(this, 48f));
        btnLp.topMargin = ThemePalette.dp(this, 16f);
        btnLp.bottomMargin = ThemePalette.dp(this, 16f);
        card.addView(primaryToggleBtn, btnLp);

        View divider = new View(this);
        divider.setBackgroundColor(ThemePalette.borderHairline(this));
        card.addView(divider, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Math.max(1, ThemePalette.dp(this, 1f))));

        LinearLayout metricsRow = new LinearLayout(this);
        metricsRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams metricsLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        metricsLp.topMargin = ThemePalette.dp(this, 14f);
        card.addView(metricsRow, metricsLp);

        metricAppsVal = addMetricCell(metricsRow, strings.metricApps());
        metricGateVal = addMetricCell(metricsRow, strings.metricGate());
        metricFreezeVal = addMetricCell(metricsRow, strings.metricFreeze());
        Motion.animateEntrance(card, 0, ThemePalette.dp(this, 12f));
        return card;
    }

    private TextView addMetricCell(LinearLayout parent, String caption) {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setGravity(Gravity.CENTER_HORIZONTAL);

        TextView valTv = new TextView(this);
        valTv.setTextColor(ThemePalette.inkPrimary(this));
        valTv.setTextSize(14f);
        valTv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        col.addView(valTv);

        TextView capTv = new TextView(this);
        capTv.setText(caption);
        capTv.setTextColor(ThemePalette.inkMuted(this));
        capTv.setTextSize(11.5f);
        capTv.setPadding(0, ThemePalette.dp(this, 2f), 0, 0);
        col.addView(capTv);

        parent.addView(col, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        return valTv;
    }

    private View buildAppsHeaderRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = ThemePalette.dp(this, 12f);
        row.setLayoutParams(lp);

        TextView title = new TextView(this);
        title.setText(strings.sectionApps());
        title.setTextColor(ThemePalette.inkPrimary(this));
        title.setTextSize(16f);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        row.addView(title, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        appsCountPill = new TextView(this);
        appsCountPill.setText("0");
        appsCountPill.setTextColor(ThemePalette.inkSecondary(this));
        appsCountPill.setTextSize(12f);
        appsCountPill.setBackground(ThemePalette.cardDrawable(
                this, ThemePalette.surfaceSubtle(this), ThemePalette.borderHairline(this), 12f));
        appsCountPill.setPadding(ThemePalette.dp(this, 10f), ThemePalette.dp(this, 3f),
                ThemePalette.dp(this, 10f), ThemePalette.dp(this, 3f));
        row.addView(appsCountPill);
        return row;
    }

    private View buildAppsGridSection() {
        LinearLayout wrapper = new LinearLayout(this);
        wrapper.setOrientation(LinearLayout.VERTICAL);

        appsGrid = new GridLayout(this);
        appsGrid.setColumnCount(4);
        appsGrid.setAlignmentMode(GridLayout.ALIGN_BOUNDS);
        wrapper.addView(appsGrid, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        emptyStateCard = new LinearLayout(this);
        emptyStateCard.setOrientation(LinearLayout.VERTICAL);
        emptyStateCard.setGravity(Gravity.CENTER_HORIZONTAL);
        emptyStateCard.setBackground(ThemePalette.cardDrawable(
                this, ThemePalette.surfaceCard(this), ThemePalette.borderHairline(this), 18f));
        emptyStateCard.setPadding(ThemePalette.dp(this, 24f), ThemePalette.dp(this, 28f),
                ThemePalette.dp(this, 24f), ThemePalette.dp(this, 28f));

        TextView emptyTitle = new TextView(this);
        emptyTitle.setText(strings.emptyTitle());
        emptyTitle.setTextColor(ThemePalette.inkPrimary(this));
        emptyTitle.setTextSize(15f);
        emptyTitle.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        emptyStateCard.addView(emptyTitle);

        TextView emptySub = new TextView(this);
        emptySub.setText(strings.emptySubtitle());
        emptySub.setTextColor(ThemePalette.inkSecondary(this));
        emptySub.setTextSize(13f);
        emptySub.setGravity(Gravity.CENTER);
        emptySub.setPadding(0, ThemePalette.dp(this, 6f), 0, 0);
        emptyStateCard.addView(emptySub);

        Motion.attachPressScale(emptyStateCard);
        emptyStateCard.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleAddSheet();
            }
        });
        wrapper.addView(emptyStateCard, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        return wrapper;
    }

    private void toggleAddSheet() {
        if (addAppSheet.isOpen()) {
            addAppSheet.dismiss();
            Motion.animateFabToggle(fabButton, false);
        } else {
            Motion.animateFabToggle(fabButton, true);
            addAppSheet.show(currentSnapshot.sandboxApps);
        }
    }

    private void onPrimaryToggleClicked() {
        if (busy) {
            return;
        }
        if (!connected) {
            refreshStatus(true);
            return;
        }
        final boolean targetPause = !currentSnapshot.paused;
        busy = true;
        renderSnapshot();
        executor.execute(new Runnable() {
            @Override
            public void run() {
                final BrokerProtocol.RpcResponse resp = targetPause
                        ? broker.pauseSandbox()
                        : broker.startSandbox();
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        busy = false;
                        applyRpcResponse(resp, true);
                    }
                });
            }
        });
    }

    private void refreshStatus(final boolean notifyOnSuccess) {
        if (busy) {
            return;
        }
        busy = true;
        renderSnapshot();
        executor.execute(new Runnable() {
            @Override
            public void run() {
                final BrokerProtocol.RpcResponse resp = broker.getStatus();
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        busy = false;
                        applyRpcResponse(resp, notifyOnSuccess);
                    }
                });
            }
        });
    }

    private void applyRpcResponse(BrokerProtocol.RpcResponse resp, boolean notifyError) {
        if (resp.offline) {
            connected = false;
            currentSnapshot = BrokerProtocol.StatusSnapshot.empty();
            if (notifyError && !resp.error.isEmpty()) {
                showToast(resp.error, true);
            }
        } else if (!resp.ok) {
            connected = true;
            if (!resp.error.isEmpty()) {
                showToast(strings.failPrefix() + resp.error, true);
            }
        } else {
            connected = true;
            currentSnapshot = resp.snapshot;
        }
        renderSnapshot();
    }

    private void renderSnapshot() {
        if (busy) {
            haloView.setMode(BreathingHaloView.Mode.BUSY);
            statusTitleView.setText(strings.statusBusyTitle());
            primaryToggleBtn.setText(strings.btnSyncing());
            primaryToggleBtn.setEnabled(false);
            primaryToggleBtn.setBackground(ThemePalette.pillRippleDrawable(
                    this, ThemePalette.accentCopper(this), ThemePalette.accentCopperPressed(this), Color.TRANSPARENT, 16f));
            primaryToggleBtn.setTextColor(Color.WHITE);
            return;
        }

        primaryToggleBtn.setEnabled(true);
        if (!connected) {
            haloView.setMode(BreathingHaloView.Mode.OFFLINE);
            modePill.setText(strings.modeOffline());
            modePill.setTextColor(ThemePalette.inkSecondary(this));
            modePill.setBackground(ThemePalette.cardDrawable(
                    this, ThemePalette.surfaceSubtle(this), ThemePalette.borderHairline(this), 16f));
            statusTitleView.setText(strings.statusOfflineTitle());
            statusSubtitleView.setText(strings.offlineHint());
            offlineCertBox.setVisibility(certSha256.isEmpty() ? View.GONE : View.VISIBLE);
            primaryToggleBtn.setText(strings.btnRetry());
            primaryToggleBtn.setTextColor(ThemePalette.inkPrimary(this));
            primaryToggleBtn.setBackground(ThemePalette.pillRippleDrawable(
                    this, ThemePalette.surfaceSubtle(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this), 16f));
            metricAppsVal.setText("—");
            metricGateVal.setText("—");
            metricFreezeVal.setText("—");
            renderSandboxApps(currentSnapshot.sandboxApps);
            return;
        }

        offlineCertBox.setVisibility(View.GONE);
        boolean active = !currentSnapshot.paused;
        haloView.setMode(active ? BreathingHaloView.Mode.ACTIVE : BreathingHaloView.Mode.PAUSED);

        if ("tproxy".equalsIgnoreCase(currentSnapshot.mode)) {
            modePill.setText(active ? strings.modeTProxy() : strings.modeStandby());
        } else {
            modePill.setText(active ? strings.modeIsolated() : strings.modeStandby());
        }
        modePill.setTextColor(active ? ThemePalette.accentSage(this) : ThemePalette.inkSecondary(this));
        modePill.setBackground(ThemePalette.cardDrawable(
                this,
                active ? ThemePalette.accentSageSoft(this) : ThemePalette.surfaceSubtle(this),
                ThemePalette.borderHairline(this),
                16f));

        statusTitleView.setText(active ? strings.statusActiveTitle() : strings.statusPausedTitle());
        statusSubtitleView.setText(strings.userLineFmt(
                currentSnapshot.userId, currentSnapshot.runningProcs, currentSnapshot.variant));

        if (active) {
            primaryToggleBtn.setText(strings.btnPause());
            primaryToggleBtn.setTextColor(ThemePalette.inkPrimary(this));
            primaryToggleBtn.setBackground(ThemePalette.pillRippleDrawable(
                    this, ThemePalette.surfaceSubtle(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this), 16f));
        } else {
            primaryToggleBtn.setText(strings.btnStart());
            primaryToggleBtn.setTextColor(Color.WHITE);
            primaryToggleBtn.setBackground(ThemePalette.pillRippleDrawable(
                    this, ThemePalette.accentCopper(this), ThemePalette.accentCopperPressed(this), Color.TRANSPARENT, 16f));
        }

        metricAppsVal.setText(String.valueOf(currentSnapshot.sandboxApps.size()));
        metricGateVal.setText(currentSnapshot.sbwOpen ? strings.gateOpen() : strings.gateLocked());
        metricFreezeVal.setText((currentSnapshot.hotFrozen || currentSnapshot.frozen)
                ? strings.freezeHot()
                : strings.freezeAwake());

        renderSandboxApps(currentSnapshot.sandboxApps);
    }

    private void renderSandboxApps(List<String> apps) {
        appsGrid.removeAllViews();
        appsCountPill.setText(String.valueOf(apps.size()));
        if (apps.isEmpty()) {
            appsGrid.setVisibility(View.GONE);
            emptyStateCard.setVisibility(View.VISIBLE);
            return;
        }
        appsGrid.setVisibility(View.VISIBLE);
        emptyStateCard.setVisibility(View.GONE);

        PackageManager pm = getPackageManager();
        for (int i = 0; i < apps.size(); i++) {
            final String pkg = apps.get(i);
            final AppTileInfo info = resolveTileInfo(pm, pkg);
            View tile = buildAppTile(info, i);
            GridLayout.LayoutParams glp = new GridLayout.LayoutParams();
            glp.width = 0;
            glp.columnSpec = GridLayout.spec(GridLayout.UNDEFINED, 1f);
            int margin = ThemePalette.dp(this, 4f);
            glp.setMargins(margin, margin, margin, ThemePalette.dp(this, 8f));
            appsGrid.addView(tile, glp);
        }
    }

    private static final class AppTileInfo {
        final String pkg;
        final String label;
        final Drawable icon;

        AppTileInfo(String pkg, String label, Drawable icon) {
            this.pkg = pkg;
            this.label = label;
            this.icon = icon;
        }
    }

    private AppTileInfo resolveTileInfo(PackageManager pm, String pkg) {
        try {
            @SuppressWarnings("deprecation")
            ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
            CharSequence cs = pm.getApplicationLabel(ai);
            String label = cs != null ? cs.toString().trim() : shortPkgLabel(pkg);
            Drawable icon = pm.getApplicationIcon(ai);
            return new AppTileInfo(pkg, label, icon);
        } catch (PackageManager.NameNotFoundException ex) {
            return new AppTileInfo(pkg, shortPkgLabel(pkg), null);
        }
    }

    private String shortPkgLabel(String pkg) {
        int dot = pkg.lastIndexOf('.');
        return (dot >= 0 && dot + 1 < pkg.length()) ? pkg.substring(dot + 1) : pkg;
    }

    private View buildAppTile(final AppTileInfo info, int index) {
        LinearLayout tile = new LinearLayout(this);
        tile.setOrientation(LinearLayout.VERTICAL);
        tile.setGravity(Gravity.CENTER_HORIZONTAL);
        tile.setBackground(ThemePalette.pillRippleDrawable(
                this, ThemePalette.surfaceCard(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this), 16f));
        tile.setPadding(ThemePalette.dp(this, 6f), ThemePalette.dp(this, 12f),
                ThemePalette.dp(this, 6f), ThemePalette.dp(this, 10f));

        if (info.icon != null) {
            ImageView iv = new ImageView(this);
            iv.setImageDrawable(info.icon);
            LinearLayout.LayoutParams ivLp = new LinearLayout.LayoutParams(
                    ThemePalette.dp(this, 40f), ThemePalette.dp(this, 40f));
            ivLp.bottomMargin = ThemePalette.dp(this, 6f);
            tile.addView(iv, ivLp);
        } else {
            TextView mono = new TextView(this);
            String first = info.label.isEmpty() ? "?" : info.label.substring(0, 1).toUpperCase(Locale.ROOT);
            mono.setText(first);
            mono.setTextColor(ThemePalette.accentCopper(this));
            mono.setTextSize(16f);
            mono.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
            mono.setGravity(Gravity.CENTER);
            mono.setBackground(ThemePalette.circleRippleDrawable(
                    this, ThemePalette.accentCopperSoft(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this)));
            LinearLayout.LayoutParams mLp = new LinearLayout.LayoutParams(
                    ThemePalette.dp(this, 40f), ThemePalette.dp(this, 40f));
            mLp.bottomMargin = ThemePalette.dp(this, 6f);
            tile.addView(mono, mLp);
        }

        TextView labelTv = new TextView(this);
        labelTv.setText(info.label);
        labelTv.setTextColor(ThemePalette.inkPrimary(this));
        labelTv.setTextSize(11.5f);
        labelTv.setMaxLines(1);
        labelTv.setEllipsize(TextUtils.TruncateAt.END);
        labelTv.setGravity(Gravity.CENTER);
        tile.addView(labelTv);

        Motion.attachPressScale(tile);
        Motion.animateEntrance(tile, index, ThemePalette.dp(this, 10f));
        tile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                launchSandboxApp(info);
            }
        });
        tile.setOnLongClickListener(new View.OnLongClickListener() {
            @Override
            public boolean onLongClick(View v) {
                appActionSheet.show(info.pkg, info.label, info.icon);
                return true;
            }
        });
        return tile;
    }

    private void launchSandboxApp(final AppTileInfo info) {
        showToast(strings.launchingFmt(info.label), false);
        executor.execute(new Runnable() {
            @Override
            public void run() {
                final BrokerProtocol.RpcResponse resp = broker.launchApp(info.pkg);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (!resp.ok) {
                            showToast(strings.failPrefix() + resp.error, true);
                        } else {
                            refreshStatus(false);
                        }
                    }
                });
            }
        });
    }

    private void showToast(String message, boolean isError) {
        mainHandler.removeCallbacks(hideToastTask);
        toastCapsule.setText(message);
        toastCapsule.setBackground(ThemePalette.cardDrawable(
                this,
                isError ? ThemePalette.accentError(this) : ThemePalette.INK_PRIMARY,
                ThemePalette.isDark(this) ? ThemePalette.borderHairline(this) : Color.TRANSPARENT,
                20f));
        toastCapsule.setVisibility(View.VISIBLE);
        toastCapsule.animate().cancel();
        toastCapsule.setAlpha(0f);
        toastCapsule.setTranslationY(ThemePalette.dp(this, 10f));
        toastCapsule.animate().alpha(1f).translationY(0f).setDuration(180L).start();
        mainHandler.postDelayed(hideToastTask, 2600L);
    }
}
