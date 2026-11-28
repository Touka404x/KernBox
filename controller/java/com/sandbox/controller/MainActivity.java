package com.sandbox.controller;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.LauncherActivityInfo;
import android.content.pm.LauncherApps;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.UserHandle;
import android.os.UserManager;
import android.text.TextUtils;
import android.view.DisplayCutout;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * KernBox Companion Controller Activity:
 * Adaptive Light/Dark Dieter Rams / Swiss Monograph surface with animated status ring,
 * offline SHA-256 cert fingerprint helper, diagnostics sheet, responsive workspace grid
 * with long-press management, and animated "+" FAB add-app bottom sheet.
 */
public final class MainActivity extends Activity {

    private static final String PREF_UI_CACHE = "kernbox_ui_cache";
    private static final String KEY_UI_SNAPSHOT = "snapshot_json";
    private static final String PREF_LABEL_CACHE = "kernbox_label_cache";

    private final Strings strings = new Strings();
    private final BrokerClient broker = new BrokerClient();
    private final ExecutorService rpcExecutor = Executors.newFixedThreadPool(2);
    private final ExecutorService iconExecutor = Executors.newFixedThreadPool(3);
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Map<String, AppTileInfo> tileCache = new ConcurrentHashMap<String, AppTileInfo>();

    private FrameLayout rootContainer;
    private LinearLayout alertBannerCard;
    private TextView alertBannerTitle;
    private TextView alertBannerBody;
    private TextView alertBannerHint;
    private ScrollView mainScroll;
    private LinearLayout scrollContent;
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
    private int lastBottomInset = 0;
    private int lastImeBottomInset = 0;
    private int iconLoadSeq = 0;
    private String lastToggleVisualKey = "";
    private String lastModePillVisualKey = "";

    private BrokerProtocol.StatusSnapshot currentSnapshot = BrokerProtocol.StatusSnapshot.empty();
    private BrokerProtocol.OfflineReason lastOfflineReason = BrokerProtocol.OfflineReason.DAEMON_DOWN;
    private List<String> renderedApps = Collections.emptyList();
    private String certSha256 = "";
    private String busyStatusText = "";
    private String lastActionError = "";
    private boolean connected = false;
    private boolean busy = false;
    private boolean silentRefreshing = false;
    private boolean pendingRefresh = false;
    private int rpcSeq = 0;

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
        restoreLabelAndSnapshotCache();
        setContentView(buildRootLayout());
        configureSystemBars();
        registerPredictiveBack();
        loadSigningCertAsync();
        renderSnapshot();
        refreshStatus(false, connected);
    }

    private void restoreLabelAndSnapshotCache() {
        try {
            SharedPreferences lblPrefs = getSharedPreferences(PREF_LABEL_CACHE, MODE_PRIVATE);
            for (Map.Entry<String, ?> entry : lblPrefs.getAll().entrySet()) {
                if (entry.getKey() != null && entry.getValue() instanceof String) {
                    String lbl = ((String) entry.getValue()).trim();
                    if (!lbl.isEmpty()) {
                        tileCache.put(entry.getKey(), new AppTileInfo(entry.getKey(), lbl, null));
                    }
                }
            }
            SharedPreferences uiPrefs = getSharedPreferences(PREF_UI_CACHE, MODE_PRIVATE);
            BrokerProtocol.StatusSnapshot cached = BrokerProtocol.StatusSnapshot.fromSafeCacheJson(
                    uiPrefs.getString(KEY_UI_SNAPSHOT, ""));
            if (cached != null && cached.policyLoaded) {
                this.currentSnapshot = cached;
                this.connected = true;
                this.lastOfflineReason = BrokerProtocol.OfflineReason.NONE;
            }
        } catch (RuntimeException ignored) {
        }
    }

    private void persistSafeSnapshot(BrokerProtocol.StatusSnapshot snap) {
        if (snap == null || !snap.policyLoaded) {
            return;
        }
        try {
            getSharedPreferences(PREF_UI_CACHE, MODE_PRIVATE)
                    .edit()
                    .putString(KEY_UI_SNAPSHOT, snap.toSafeCacheJson())
                    .apply();
        } catch (RuntimeException ignored) {
        }
    }

    private void loadSigningCertAsync() {
        final Context appCtx = getApplicationContext();
        iconExecutor.execute(new Runnable() {
            @Override
            public void run() {
                final String sha = CertUtil.getSigningCertSha256(appCtx);
                if (sha == null || sha.isEmpty()) {
                    return;
                }
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        certSha256 = sha;
                        if (offlineCertDigestView != null) {
                            offlineCertDigestView.setText(CertUtil.shortDigest(sha));
                        }
                        if (!connected && offlineCertBox != null) {
                            offlineCertBox.setVisibility(View.VISIBLE);
                        }
                    }
                });
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (haloView != null) {
            haloView.setHostResumed(true);
        }
        refreshStatus(false, connected);
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
        rpcExecutor.shutdownNow();
        iconExecutor.shutdownNow();
        super.onDestroy();
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        configureSystemBars();
        if (appsGrid != null) {
            int cols = computeGridColumns();
            if (appsGrid.getColumnCount() != cols) {
                appsGrid.setColumnCount(cols);
                renderedApps = Collections.emptyList();
                renderSandboxApps(currentSnapshot.sandboxApps);
            }
        }
        if (addAppSheet != null) {
            addAppSheet.refreshMaxHeight();
        }
        if (diagnosticsSheet != null) {
            diagnosticsSheet.refreshScrollHeight();
        }
    }

    private int computeGridColumns() {
        float density = getResources().getDisplayMetrics().density;
        int widthDp = Math.round(getResources().getDisplayMetrics().widthPixels / Math.max(1f, density));
        return Math.max(3, Math.min(6, widthDp / 88));
    }

    private void updateMainAccessibility() {
        boolean anyOpen = (addAppSheet != null && addAppSheet.isOpen())
                || (appActionSheet != null && appActionSheet.isOpen())
                || (diagnosticsSheet != null && diagnosticsSheet.isOpen());
        int mode = anyOpen
                ? View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                : View.IMPORTANT_FOR_ACCESSIBILITY_YES;
        if (mainScroll != null) {
            mainScroll.setImportantForAccessibility(mode);
        }
        if (fabButton != null) {
            fabButton.setImportantForAccessibility(mode);
        }
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

    @SuppressWarnings("deprecation")
    private void configureSystemBars() {
        if (getWindow() == null) {
            return;
        }
        View decor = getWindow().getDecorView();
        boolean dark = ThemePalette.isDark(this);
        if (Build.VERSION.SDK_INT >= 30) {
            getWindow().setDecorFitsSystemWindows(false);
            WindowInsetsController ctrl = decor != null ? decor.getWindowInsetsController() : null;
            if (ctrl != null) {
                int mask = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                        | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                ctrl.setSystemBarsAppearance(dark ? 0 : mask, mask);
            }
        } else if (decor != null) {
            int flags = View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                    | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN;
            if (!dark) {
                flags |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
                if (Build.VERSION.SDK_INT >= 27) {
                    flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
                }
            }
            decor.setSystemUiVisibility(flags);
            getWindow().setStatusBarColor(Color.TRANSPARENT);
            getWindow().setNavigationBarColor(Color.TRANSPARENT);
        }
    }

    private View buildRootLayout() {
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(ThemePalette.bgPaper(this));

        mainScroll = new ScrollView(this);
        mainScroll.setVerticalScrollBarEnabled(false);

        scrollContent = new LinearLayout(this);
        scrollContent.setOrientation(LinearLayout.VERTICAL);
        int hPad = ThemePalette.dp(this, 20f);
        scrollContent.setPadding(hPad, ThemePalette.dp(this, 16f), hPad, ThemePalette.dp(this, 100f));

        scrollContent.addView(buildHeaderRow());
        scrollContent.addView(buildAlertBannerCard());
        scrollContent.addView(buildHeroStatusCard());
        scrollContent.addView(buildAppsHeaderRow());
        scrollContent.addView(buildAppsGridSection());

        mainScroll.addView(scrollContent, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT));
        root.addView(mainScroll, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        rootContainer = root;
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
                Motion.hapticTap(v);
                toggleAddSheet();
            }
        });
        int fabSize = ThemePalette.dp(this, 58f);
        FrameLayout.LayoutParams fabLp = new FrameLayout.LayoutParams(fabSize, fabSize, Gravity.BOTTOM | Gravity.END);
        fabLp.setMarginEnd(ThemePalette.dp(this, 22f));
        fabLp.bottomMargin = ThemePalette.dp(this, 24f);
        root.addView(fabButton, fabLp);

        toastCapsule = new TextView(this);
        toastCapsule.setVisibility(View.GONE);
        toastCapsule.setTextColor(ThemePalette.toastInk(this));
        toastCapsule.setTextSize(13f);
        toastCapsule.setGravity(Gravity.CENTER);
        toastCapsule.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        toastCapsule.setPadding(ThemePalette.dp(this, 16f), ThemePalette.dp(this, 10f),
                ThemePalette.dp(this, 16f), ThemePalette.dp(this, 10f));
        toastCapsule.setElevation(ThemePalette.dp(this, 10f));
        FrameLayout.LayoutParams toastLp = new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        toastLp.bottomMargin = ThemePalette.dp(this, 96f);
        root.addView(toastCapsule, toastLp);

        attachWindowInsets(root);
        return root;
    }

    @SuppressWarnings("deprecation")
    private void attachWindowInsets(FrameLayout root) {
        root.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
            @Override
            public WindowInsets onApplyWindowInsets(View v, WindowInsets insets) {
                int left;
                int top;
                int right;
                int bottom;
                int imeBottom = 0;
                if (Build.VERSION.SDK_INT >= 30) {
                    Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                    Insets ime = insets.getInsets(WindowInsets.Type.ime());
                    left = bars.left;
                    top = bars.top;
                    right = bars.right;
                    bottom = bars.bottom;
                    imeBottom = ime.bottom;
                } else {
                    left = insets.getSystemWindowInsetLeft();
                    top = insets.getSystemWindowInsetTop();
                    right = insets.getSystemWindowInsetRight();
                    bottom = insets.getSystemWindowInsetBottom();
                    if (Build.VERSION.SDK_INT >= 28) {
                        DisplayCutout cutout = insets.getDisplayCutout();
                        if (cutout != null) {
                            left = Math.max(left, cutout.getSafeInsetLeft());
                            top = Math.max(top, cutout.getSafeInsetTop());
                            right = Math.max(right, cutout.getSafeInsetRight());
                            bottom = Math.max(bottom, cutout.getSafeInsetBottom());
                        }
                    }
                }

                int baseH = ThemePalette.dp(MainActivity.this, 20f);
                int baseTop = ThemePalette.dp(MainActivity.this, 16f);
                int baseBot = ThemePalette.dp(MainActivity.this, 100f);
                scrollContent.setPadding(baseH + left, baseTop + top, baseH + right, baseBot + bottom);

                boolean rtl = getResources().getConfiguration().getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;
                int endInset = rtl ? left : right;

                FrameLayout.LayoutParams fLp = (FrameLayout.LayoutParams) fabButton.getLayoutParams();
                fLp.setMarginEnd(ThemePalette.dp(MainActivity.this, 22f) + endInset);
                fLp.bottomMargin = ThemePalette.dp(MainActivity.this, 24f) + bottom;
                fabButton.setLayoutParams(fLp);

                FrameLayout.LayoutParams tLp = (FrameLayout.LayoutParams) toastCapsule.getLayoutParams();
                tLp.bottomMargin = ThemePalette.dp(MainActivity.this, 96f) + bottom;
                toastCapsule.setLayoutParams(tLp);

                lastBottomInset = bottom;
                lastImeBottomInset = imeBottom;
                if (addAppSheet != null) {
                    addAppSheet.setBottomInset(Math.max(bottom, imeBottom));
                }
                if (appActionSheet != null) {
                    appActionSheet.setBottomInset(bottom);
                }
                if (diagnosticsSheet != null) {
                    diagnosticsSheet.setBottomInset(bottom);
                }
                return insets;
            }
        });
        root.requestApplyInsets();
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
        logo.setContentDescription(strings.a11yLogo());
        LinearLayout.LayoutParams logoLp = new LinearLayout.LayoutParams(
                ThemePalette.dp(this, 36f), ThemePalette.dp(this, 36f));
        logoLp.setMarginEnd(ThemePalette.dp(this, 10f));
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
        pillLp.setMarginEnd(ThemePalette.dp(this, 8f));
        row.addView(modePill, pillLp);

        diagIconBtn = new ImageView(this);
        diagIconBtn.setImageResource(android.R.drawable.ic_menu_info_details);
        diagIconBtn.setColorFilter(ThemePalette.inkSecondary(this));
        diagIconBtn.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        diagIconBtn.setContentDescription(strings.diagTitle());
        diagIconBtn.setPadding(ThemePalette.dp(this, 10f), ThemePalette.dp(this, 10f),
                ThemePalette.dp(this, 10f), ThemePalette.dp(this, 10f));
        diagIconBtn.setBackground(ThemePalette.circleRippleDrawable(
                this, ThemePalette.surfaceCard(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this)));
        Motion.attachPressScale(diagIconBtn);
        diagIconBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Motion.hapticTap(v);
                ensureDiagnosticsSheet().show(currentSnapshot, connected);
                updateMainAccessibility();
            }
        });
        LinearLayout.LayoutParams diagLp = new LinearLayout.LayoutParams(
                ThemePalette.dp(this, 42f), ThemePalette.dp(this, 42f));
        diagLp.setMarginEnd(ThemePalette.dp(this, 8f));
        row.addView(diagIconBtn, diagLp);

        refreshIconBtn = new ImageView(this);
        refreshIconBtn.setImageResource(android.R.drawable.ic_popup_sync);
        refreshIconBtn.setColorFilter(ThemePalette.inkSecondary(this));
        refreshIconBtn.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        refreshIconBtn.setContentDescription(strings.a11yRefresh());
        refreshIconBtn.setPadding(ThemePalette.dp(this, 10f), ThemePalette.dp(this, 10f),
                ThemePalette.dp(this, 10f), ThemePalette.dp(this, 10f));
        refreshIconBtn.setBackground(ThemePalette.circleRippleDrawable(
                this, ThemePalette.surfaceCard(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this)));
        Motion.attachPressScale(refreshIconBtn);
        refreshIconBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Motion.hapticTap(v);
                Motion.spinOnce(refreshIconBtn);
                refreshStatus(true);
            }
        });
        row.addView(refreshIconBtn, new LinearLayout.LayoutParams(
                ThemePalette.dp(this, 42f), ThemePalette.dp(this, 42f)));
        return row;
    }

    private View buildAlertBannerCard() {
        alertBannerCard = new LinearLayout(this);
        alertBannerCard.setOrientation(LinearLayout.VERTICAL);
        alertBannerCard.setVisibility(View.GONE);
        alertBannerCard.setBackground(ThemePalette.pillRippleDrawable(
                this,
                ThemePalette.accentErrorSoft(this),
                ThemePalette.surfacePressed(this),
                ThemePalette.accentError(this),
                16f));
        int hPad = ThemePalette.dp(this, 16f);
        int vPad = ThemePalette.dp(this, 12f);
        alertBannerCard.setPadding(hPad, vPad, hPad, vPad);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = ThemePalette.dp(this, 14f);
        alertBannerCard.setLayoutParams(lp);

        alertBannerTitle = new TextView(this);
        alertBannerTitle.setText(strings.alertBannerTitle());
        alertBannerTitle.setTextColor(ThemePalette.accentError(this));
        alertBannerTitle.setTextSize(13.5f);
        alertBannerTitle.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        alertBannerCard.addView(alertBannerTitle);

        alertBannerBody = new TextView(this);
        alertBannerBody.setTextColor(ThemePalette.inkPrimary(this));
        alertBannerBody.setTextSize(12.5f);
        alertBannerBody.setLineSpacing(0f, 1.25f);
        alertBannerBody.setPadding(0, ThemePalette.dp(this, 4f), 0, ThemePalette.dp(this, 6f));
        alertBannerCard.addView(alertBannerBody);

        alertBannerHint = new TextView(this);
        alertBannerHint.setText(strings.alertTapDiagHint());
        alertBannerHint.setTextColor(ThemePalette.accentError(this));
        alertBannerHint.setTextSize(11.5f);
        alertBannerHint.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        alertBannerCard.addView(alertBannerHint);

        Motion.attachPressScale(alertBannerCard);
        alertBannerCard.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Motion.hapticTap(v);
                if (connected) {
                    ensureDiagnosticsSheet().show(currentSnapshot, connected);
                    updateMainAccessibility();
                } else {
                    refreshStatus(true);
                }
            }
        });
        return alertBannerCard;
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
        haloLp.setMarginEnd(ThemePalette.dp(this, 14f));
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
                Motion.hapticTap(v);
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

        TextView copyPolicyBtn = new TextView(this);
        copyPolicyBtn.setText(strings.btnCopyPolicySnippet());
        copyPolicyBtn.setTextColor(ThemePalette.inkPrimary(this));
        copyPolicyBtn.setTextSize(11.5f);
        copyPolicyBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        copyPolicyBtn.setBackground(ThemePalette.pillRippleDrawable(
                this, ThemePalette.surfaceCard(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this), 14f));
        copyPolicyBtn.setPadding(ThemePalette.dp(this, 10f), ThemePalette.dp(this, 6f),
                ThemePalette.dp(this, 10f), ThemePalette.dp(this, 6f));
        LinearLayout.LayoutParams polBtnLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        polBtnLp.setMarginStart(ThemePalette.dp(this, 6f));
        Motion.attachPressScale(copyPolicyBtn);
        copyPolicyBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Motion.hapticTap(v);
                if (!certSha256.isEmpty()) {
                    String snippet = "{\n"
                            + "  \"caller_package\": \"com.sandbox.controller\",\n"
                            + "  \"caller_cert_sha256\": \"" + certSha256 + "\"\n"
                            + "}";
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(ClipData.newPlainText("kernbox-policy-snippet", snippet));
                    }
                    showToast(strings.copiedPolicySnippetToast(), false);
                }
            }
        });
        offlineCertBox.addView(copyPolicyBtn, polBtnLp);
        card.addView(offlineCertBox, certBoxLp);

        primaryToggleBtn = new TextView(this);
        primaryToggleBtn.setTextSize(15f);
        primaryToggleBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        primaryToggleBtn.setGravity(Gravity.CENTER);
        Motion.attachPressScale(primaryToggleBtn);
        primaryToggleBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Motion.hapticTap(v);
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
        appsGrid.setColumnCount(computeGridColumns());
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
                Motion.hapticTap(v);
                toggleAddSheet();
            }
        });
        wrapper.addView(emptyStateCard, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        return wrapper;
    }

    private void addOverlayBeforeToast(View overlay) {
        int idx = rootContainer.indexOfChild(toastCapsule);
        if (idx < 0) {
            idx = rootContainer.getChildCount();
        }
        rootContainer.addView(overlay, idx, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
    }

    private AddAppSheet ensureAddAppSheet() {
        if (addAppSheet == null) {
            addAppSheet = new AddAppSheet(this, strings, broker, rpcExecutor, mainHandler, new AddAppSheet.HostCallback() {
                @Override
                public void onAppImported(String pkg, String label) {
                    Motion.hapticConfirm(rootContainer);
                    showToast(strings.importedFmt(label), false);
                    refreshStatus(false);
                }

                @Override
                public void onApkInstalled(String path) {
                    Motion.hapticConfirm(rootContainer);
                    showToast(strings.installedApkOk(), false);
                    refreshStatus(false);
                }

                @Override
                public void onToast(String message, boolean error) {
                    if (error) {
                        Motion.hapticReject(rootContainer);
                    }
                    showToast(message, error);
                }

                @Override
                public void onDismissed() {
                    Motion.animateFabToggle(fabButton, false);
                    updateMainAccessibility();
                }
            });
            addOverlayBeforeToast(addAppSheet);
            addAppSheet.setBottomInset(Math.max(lastBottomInset, lastImeBottomInset));
        }
        return addAppSheet;
    }

    private AppActionSheet ensureAppActionSheet() {
        if (appActionSheet == null) {
            appActionSheet = new AppActionSheet(this, strings, broker, rpcExecutor, mainHandler, new AppActionSheet.Callback() {
                @Override
                public void onActionSuccess(BrokerProtocol.StatusSnapshot snapshot, String toastMessage) {
                    lastActionError = "";
                    rpcSeq++;
                    Motion.hapticConfirm(rootContainer);
                    if (snapshot != null && snapshot.policyLoaded) {
                        connected = true;
                        currentSnapshot = snapshot.withPreservedProbeFrom(currentSnapshot);
                        persistSafeSnapshot(currentSnapshot);
                        renderSnapshot();
                    } else {
                        refreshStatus(false);
                    }
                    showToast(toastMessage, false);
                }

                @Override
                public void onActionError(String errorMessage) {
                    Motion.hapticReject(rootContainer);
                    showToast(errorMessage, true);
                }

                @Override
                public void onCopyToast(String message) {
                    Motion.hapticTap(rootContainer);
                    showToast(message, false);
                }

                @Override
                public void onSheetDismissed() {
                    updateMainAccessibility();
                }
            });
            addOverlayBeforeToast(appActionSheet);
            appActionSheet.setBottomInset(lastBottomInset);
        }
        return appActionSheet;
    }

    private DiagnosticsSheet ensureDiagnosticsSheet() {
        if (diagnosticsSheet == null) {
            diagnosticsSheet = new DiagnosticsSheet(this, strings, broker, rpcExecutor, mainHandler, new DiagnosticsSheet.Callback() {
                @Override
                public void onSnapshotRefreshed(BrokerProtocol.StatusSnapshot snapshot) {
                    lastActionError = "";
                    if (snapshot != null && snapshot.policyLoaded) {
                        connected = true;
                        currentSnapshot = snapshot.withPreservedProbeFrom(currentSnapshot);
                        persistSafeSnapshot(currentSnapshot);
                        renderSnapshot();
                    }
                }

                @Override
                public void onToast(String message, boolean error) {
                    if (error) {
                        Motion.hapticReject(rootContainer);
                    }
                    showToast(message, error);
                }

                @Override
                public void onSheetDismissed() {
                    updateMainAccessibility();
                }
            });
            addOverlayBeforeToast(diagnosticsSheet);
            diagnosticsSheet.setBottomInset(lastBottomInset);
        }
        return diagnosticsSheet;
    }

    private void toggleAddSheet() {
        AddAppSheet sheet = ensureAddAppSheet();
        if (sheet.isOpen()) {
            sheet.dismiss();
            Motion.animateFabToggle(fabButton, false);
        } else {
            Motion.animateFabToggle(fabButton, true);
            sheet.show(currentSnapshot.sandboxApps);
        }
        updateMainAccessibility();
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
        final int seq = ++rpcSeq;
        renderSnapshot();
        rpcExecutor.execute(new Runnable() {
            @Override
            public void run() {
                BrokerProtocol.RpcResponse r;
                try {
                    r = targetPause ? broker.pauseSandbox() : broker.startSandbox();
                } catch (Throwable t) {
                    r = BrokerProtocol.RpcResponse.error("", String.valueOf(t.getMessage()), false);
                }
                final BrokerProtocol.RpcResponse resp = r;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        busy = false;
                        if (seq == rpcSeq) {
                            applyRpcResponse(resp, true, true);
                        } else {
                            renderSnapshot();
                        }
                        if (pendingRefresh) {
                            pendingRefresh = false;
                            refreshStatus(false);
                        }
                    }
                });
            }
        });
    }

    private void refreshStatus(final boolean notifyOnSuccess) {
        refreshStatus(notifyOnSuccess, false);
    }

    private void refreshStatus(final boolean notifyOnSuccess, final boolean silent) {
        if (busy) {
            if (!silent) {
                pendingRefresh = true;
            }
            return;
        }
        if (silent) {
            if (silentRefreshing) {
                return;
            }
            silentRefreshing = true;
            final int seq = rpcSeq;
            rpcExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    BrokerProtocol.RpcResponse r;
                    try {
                        r = broker.getStatus();
                    } catch (Throwable t) {
                        r = BrokerProtocol.RpcResponse.error("", String.valueOf(t.getMessage()), false);
                    }
                    final BrokerProtocol.RpcResponse resp = r;
                    mainHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            if (isFinishing() || isDestroyed()) {
                                return;
                            }
                            silentRefreshing = false;
                            if (!busy && seq == rpcSeq) {
                                applyRpcResponse(resp, notifyOnSuccess);
                            }
                        }
                    });
                }
            });
            return;
        }
        busy = true;
        final int seq = ++rpcSeq;
        renderSnapshot();
        rpcExecutor.execute(new Runnable() {
            @Override
            public void run() {
                BrokerProtocol.RpcResponse r;
                try {
                    r = broker.getStatus();
                } catch (Throwable t) {
                    r = BrokerProtocol.RpcResponse.error("", String.valueOf(t.getMessage()), false);
                }
                final BrokerProtocol.RpcResponse resp = r;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        busy = false;
                        if (seq == rpcSeq) {
                            applyRpcResponse(resp, notifyOnSuccess);
                        } else {
                            renderSnapshot();
                        }
                        if (pendingRefresh) {
                            pendingRefresh = false;
                            refreshStatus(false);
                        }
                    }
                });
            }
        });
    }

    private void applyRpcResponse(BrokerProtocol.RpcResponse resp, boolean notifyError) {
        applyRpcResponse(resp, notifyError, false);
    }

    private void applyRpcResponse(BrokerProtocol.RpcResponse resp, boolean notifyError, boolean hapticFeedback) {
        if (resp.offlineReason == BrokerProtocol.OfflineReason.RPC_TIMEOUT) {
            lastOfflineReason = BrokerProtocol.OfflineReason.RPC_TIMEOUT;
            lastActionError = strings.alertRpcTimeout();
            if (hapticFeedback) {
                Motion.hapticReject(primaryToggleBtn);
            }
            if (notifyError) {
                showToast(strings.alertRpcTimeout(), true);
            }
        } else if (resp.offline) {
            connected = false;
            lastOfflineReason = resp.offlineReason;
            currentSnapshot = BrokerProtocol.StatusSnapshot.empty();
            lastActionError = !resp.error.isEmpty() ? resp.error : "";
            if (hapticFeedback) {
                Motion.hapticReject(primaryToggleBtn);
            }
            if (notifyError && !resp.error.isEmpty()) {
                showToast(resp.error, true);
            }
        } else if (!resp.ok) {
            connected = true;
            lastOfflineReason = BrokerProtocol.OfflineReason.NONE;
            if (resp.snapshot != null && resp.snapshot.policyLoaded) {
                currentSnapshot = resp.snapshot.withPreservedProbeFrom(currentSnapshot);
                persistSafeSnapshot(currentSnapshot);
            }
            lastActionError = !resp.error.isEmpty() ? resp.error : strings.statusErrorTitle();
            if (hapticFeedback) {
                Motion.hapticReject(primaryToggleBtn);
            }
            if (notifyError && !resp.error.isEmpty()) {
                showToast(strings.failPrefix() + resp.error, true);
            }
        } else {
            connected = true;
            lastOfflineReason = BrokerProtocol.OfflineReason.NONE;
            currentSnapshot = resp.snapshot.withPreservedProbeFrom(currentSnapshot);
            persistSafeSnapshot(currentSnapshot);
            lastActionError = "";
            if (hapticFeedback) {
                Motion.hapticConfirm(primaryToggleBtn);
            }
        }
        renderSnapshot();
    }

    private void renderAlertBanner() {
        if (alertBannerCard == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        if (!lastActionError.trim().isEmpty()) {
            sb.append("• ").append(lastActionError.trim());
        }
        if (connected) {
            String snapAlert = currentSnapshot.buildAlertSummary(strings);
            if (!snapAlert.isEmpty()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(snapAlert);
            }
        }
        if (sb.length() == 0) {
            alertBannerCard.setVisibility(View.GONE);
            return;
        }
        alertBannerTitle.setText(strings.alertBannerTitle());
        alertBannerBody.setText(sb.toString());
        alertBannerHint.setText(connected ? strings.alertTapDiagHint() : strings.alertTapRetryHint());
        alertBannerCard.setVisibility(View.VISIBLE);
    }

    private void renderSnapshot() {
        renderAlertBanner();
        if (busy) {
            haloView.setMode(BreathingHaloView.Mode.BUSY);
            statusTitleView.setText(busyStatusText.isEmpty() ? strings.statusBusyTitle() : busyStatusText);
            primaryToggleBtn.setText(strings.btnSyncing());
            primaryToggleBtn.setEnabled(false);
            if (!"busy".equals(lastToggleVisualKey)) {
                lastToggleVisualKey = "busy";
                primaryToggleBtn.setBackground(ThemePalette.pillRippleDrawable(
                        this, ThemePalette.accentCopper(this), ThemePalette.accentCopperPressed(this), Color.TRANSPARENT, 16f));
                primaryToggleBtn.setTextColor(Color.WHITE);
            }
            return;
        }

        primaryToggleBtn.setEnabled(true);
        if (!connected) {
            haloView.setMode(BreathingHaloView.Mode.OFFLINE);
            modePill.setText(lastOfflineReason == BrokerProtocol.OfflineReason.RPC_TIMEOUT
                    ? strings.qsTimeout() : strings.modeOffline());
            if (!"offline".equals(lastModePillVisualKey)) {
                lastModePillVisualKey = "offline";
                modePill.setTextColor(ThemePalette.inkSecondary(this));
                modePill.setBackground(ThemePalette.cardDrawable(
                        this, ThemePalette.surfaceSubtle(this), ThemePalette.borderHairline(this), 16f));
            }
            statusTitleView.setText(strings.statusOfflineTitle());
            if (lastOfflineReason == BrokerProtocol.OfflineReason.CERT_UNPINNED) {
                statusSubtitleView.setText(strings.offlineCertUnpinnedHint());
            } else if (lastOfflineReason == BrokerProtocol.OfflineReason.SELINUX_DENIED) {
                statusSubtitleView.setText(strings.offlineSelinuxHint());
            } else if (lastOfflineReason == BrokerProtocol.OfflineReason.RPC_TIMEOUT) {
                statusSubtitleView.setText(strings.alertRpcTimeout());
            } else {
                statusSubtitleView.setText(strings.offlineHint());
            }
            offlineCertBox.setVisibility(certSha256.isEmpty() ? View.GONE : View.VISIBLE);
            primaryToggleBtn.setText(strings.btnRetry());
            if (!"offline".equals(lastToggleVisualKey)) {
                lastToggleVisualKey = "offline";
                primaryToggleBtn.setTextColor(ThemePalette.inkPrimary(this));
                primaryToggleBtn.setBackground(ThemePalette.pillRippleDrawable(
                        this, ThemePalette.surfaceSubtle(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this), 16f));
            }
            metricAppsVal.setText("—");
            metricGateVal.setText("—");
            metricFreezeVal.setText("—");
            renderSandboxApps(currentSnapshot.sandboxApps);
            return;
        }

        offlineCertBox.setVisibility(View.GONE);
        boolean active = currentSnapshot.isGateHealthyOpen();
        boolean notPaused = !currentSnapshot.paused;
        boolean abnormalActive = notPaused && !currentSnapshot.sbwOpen;

        if (abnormalActive) {
            haloView.setMode(BreathingHaloView.Mode.ERROR);
            modePill.setText(strings.qsError());
            if (!"error".equals(lastModePillVisualKey)) {
                lastModePillVisualKey = "error";
                modePill.setTextColor(ThemePalette.accentError(this));
                modePill.setBackground(ThemePalette.cardDrawable(
                        this, ThemePalette.accentErrorSoft(this), ThemePalette.accentError(this), 16f));
            }
            if ("AckWait".equalsIgnoreCase(currentSnapshot.state)) {
                statusTitleView.setText(strings.statusWaitingAckTitle());
            } else if ("UpgradingFence".equalsIgnoreCase(currentSnapshot.state)) {
                statusTitleView.setText(strings.statusUpgradingTitle());
            } else {
                statusTitleView.setText(strings.statusErrorTitle());
            }
        } else {
            haloView.setMode(active ? BreathingHaloView.Mode.ACTIVE : BreathingHaloView.Mode.PAUSED);
            if ("tproxy".equalsIgnoreCase(currentSnapshot.mode)) {
                modePill.setText(active ? strings.modeTProxy() : strings.modeStandby());
            } else {
                modePill.setText(active ? strings.modeIsolated() : strings.modeStandby());
            }
            String modeKey = active ? "active" : "paused";
            if (!modeKey.equals(lastModePillVisualKey)) {
                lastModePillVisualKey = modeKey;
                modePill.setTextColor(active ? ThemePalette.accentSage(this) : ThemePalette.inkSecondary(this));
                modePill.setBackground(ThemePalette.cardDrawable(
                        this,
                        active ? ThemePalette.accentSageSoft(this) : ThemePalette.surfaceSubtle(this),
                        ThemePalette.borderHairline(this),
                        16f));
            }
            statusTitleView.setText(active ? strings.statusActiveTitle() : strings.statusPausedTitle());
        }

        statusSubtitleView.setText(strings.userLineFmt(
                currentSnapshot.userId, currentSnapshot.runningProcs, currentSnapshot.variant));

        if (notPaused) {
            primaryToggleBtn.setText(strings.btnPause());
            if (!"pause".equals(lastToggleVisualKey)) {
                lastToggleVisualKey = "pause";
                primaryToggleBtn.setTextColor(ThemePalette.inkPrimary(this));
                primaryToggleBtn.setBackground(ThemePalette.pillRippleDrawable(
                        this, ThemePalette.surfaceSubtle(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this), 16f));
            }
        } else {
            primaryToggleBtn.setText(strings.btnStart());
            if (!"start".equals(lastToggleVisualKey)) {
                lastToggleVisualKey = "start";
                primaryToggleBtn.setTextColor(Color.WHITE);
                primaryToggleBtn.setBackground(ThemePalette.pillRippleDrawable(
                        this, ThemePalette.accentCopper(this), ThemePalette.accentCopperPressed(this), Color.TRANSPARENT, 16f));
            }
        }

        metricAppsVal.setText(String.valueOf(currentSnapshot.sandboxApps.size()));
        metricGateVal.setText(currentSnapshot.sbwOpen ? strings.gateOpen() : strings.gateLocked());
        if (currentSnapshot.hotFrozen || currentSnapshot.frozen) {
            metricFreezeVal.setText(strings.freezeHot());
        } else if (currentSnapshot.paused && currentSnapshot.hibernatedCount > 0) {
            metricFreezeVal.setText(strings.freezeDeep());
        } else {
            metricFreezeVal.setText(strings.freezeAwake());
        }

        renderSandboxApps(currentSnapshot.sandboxApps);
    }

    private void renderSandboxApps(List<String> apps) {
        appsCountPill.setText(String.valueOf(apps.size()));
        if (apps.isEmpty()) {
            renderedApps = Collections.emptyList();
            appsGrid.removeAllViews();
            appsGrid.setVisibility(View.GONE);
            emptyStateCard.setVisibility(View.VISIBLE);
            return;
        }
        if (apps.equals(renderedApps) && appsGrid.getChildCount() == apps.size()) {
            return;
        }
        renderedApps = new ArrayList<String>(apps);
        appsGrid.removeAllViews();
        appsGrid.setVisibility(View.VISIBLE);
        emptyStateCard.setVisibility(View.GONE);

        final List<String> missingIcons = new ArrayList<String>();
        for (int i = 0; i < apps.size(); i++) {
            final String pkg = apps.get(i);
            AppTileInfo info = tileCache.get(pkg);
            if (info == null) {
                info = new AppTileInfo(pkg, shortPkgLabel(pkg), null);
                missingIcons.add(pkg);
            } else if (info.icon == null && !currentSnapshot.paused) {
                missingIcons.add(pkg);
            }
            View tile = buildAppTile(info, i);
            GridLayout.LayoutParams glp = new GridLayout.LayoutParams();
            glp.width = 0;
            glp.columnSpec = GridLayout.spec(GridLayout.UNDEFINED, 1f);
            int margin = ThemePalette.dp(this, 4f);
            glp.setMargins(margin, margin, margin, ThemePalette.dp(this, 8f));
            appsGrid.addView(tile, glp);
        }
        if (!missingIcons.isEmpty()) {
            loadTileInfoAsync(missingIcons);
        }
    }

    private void loadTileInfoAsync(final List<String> pkgs) {
        final Context appCtx = getApplicationContext();
        final int seq = ++iconLoadSeq;
        for (final String pkg : pkgs) {
            iconExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    PackageManager pm = appCtx.getPackageManager();
                    LauncherApps la = (LauncherApps) appCtx.getSystemService(Context.LAUNCHER_APPS_SERVICE);
                    UserManager um = (UserManager) appCtx.getSystemService(Context.USER_SERVICE);
                    List<UserHandle> profiles = um != null ? um.getUserProfiles() : Collections.<UserHandle>emptyList();
                    final AppTileInfo item = resolveTileInfoWorker(pm, la, profiles, pkg);
                    if (item.label != null && !item.label.isEmpty()) {
                        try {
                            appCtx.getSharedPreferences(PREF_LABEL_CACHE, MODE_PRIVATE)
                                    .edit()
                                    .putString(pkg, item.label)
                                    .apply();
                        } catch (RuntimeException ignored) {
                        }
                    }
                    mainHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            if (seq != iconLoadSeq || isFinishing() || isDestroyed()) {
                                return;
                            }
                            tileCache.put(item.pkg, item);
                            if (renderedApps.isEmpty()) {
                                return;
                            }
                            for (int i = 0; i < appsGrid.getChildCount(); i++) {
                                View child = appsGrid.getChildAt(i);
                                if (child.getTag() instanceof AppTileHolder) {
                                    AppTileHolder h = (AppTileHolder) child.getTag();
                                    if (item.pkg.equals(h.pkg)) {
                                        h.bind(item);
                                    }
                                }
                            }
                        }
                    });
                }
            });
        }
    }

    private AppTileInfo resolveTileInfoWorker(
            PackageManager pm, LauncherApps la, List<UserHandle> profiles, String pkg) {
        try {
            @SuppressWarnings("deprecation")
            ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
            CharSequence cs = pm.getApplicationLabel(ai);
            String label = cs != null ? cs.toString().trim() : shortPkgLabel(pkg);
            Drawable icon = pm.getApplicationIcon(ai);
            return new AppTileInfo(pkg, label.isEmpty() ? shortPkgLabel(pkg) : label, icon);
        } catch (PackageManager.NameNotFoundException ignored) {
        }
        if (la != null && profiles != null) {
            for (UserHandle uh : profiles) {
                try {
                    List<LauncherActivityInfo> acts = la.getActivityList(pkg, uh);
                    if (acts != null && !acts.isEmpty()) {
                        LauncherActivityInfo act = acts.get(0);
                        CharSequence lbl = act.getLabel();
                        String label = lbl != null ? lbl.toString().trim() : shortPkgLabel(pkg);
                        Drawable icon = act.getIcon(0);
                        return new AppTileInfo(pkg, label.isEmpty() ? shortPkgLabel(pkg) : label, icon);
                    }
                } catch (SecurityException ignored) {
                }
            }
        }
        return new AppTileInfo(pkg, shortPkgLabel(pkg), null);
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

    private static final class AppTileHolder {
        final String pkg;
        final ImageView iconView;
        final TextView monoView;
        final TextView labelView;
        AppTileInfo boundInfo;

        AppTileHolder(String pkg, ImageView iconView, TextView monoView, TextView labelView, AppTileInfo initial) {
            this.pkg = pkg;
            this.iconView = iconView;
            this.monoView = monoView;
            this.labelView = labelView;
            this.boundInfo = initial;
        }

        void bind(AppTileInfo info) {
            this.boundInfo = info;
            labelView.setText(info.label);
            if (info.icon != null) {
                iconView.setVisibility(View.VISIBLE);
                monoView.setVisibility(View.GONE);
                iconView.setImageDrawable(info.icon);
            } else {
                iconView.setVisibility(View.GONE);
                monoView.setVisibility(View.VISIBLE);
                String first = info.label.isEmpty() ? "?" : info.label.substring(0, 1).toUpperCase(Locale.ROOT);
                monoView.setText(first);
            }
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

        int iconPx = ThemePalette.dp(this, 40f);
        FrameLayout iconSlot = new FrameLayout(this);
        LinearLayout.LayoutParams slotLp = new LinearLayout.LayoutParams(iconPx, iconPx);
        slotLp.bottomMargin = ThemePalette.dp(this, 6f);

        ImageView iv = new ImageView(this);
        iconSlot.addView(iv, new FrameLayout.LayoutParams(iconPx, iconPx));

        TextView mono = new TextView(this);
        mono.setTextColor(ThemePalette.accentCopper(this));
        mono.setTextSize(16f);
        mono.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        mono.setGravity(Gravity.CENTER);
        mono.setBackground(ThemePalette.circleRippleDrawable(
                this, ThemePalette.accentCopperSoft(this), ThemePalette.surfacePressed(this), ThemePalette.borderHairline(this)));
        iconSlot.addView(mono, new FrameLayout.LayoutParams(iconPx, iconPx));
        tile.addView(iconSlot, slotLp);

        TextView labelTv = new TextView(this);
        labelTv.setTextColor(ThemePalette.inkPrimary(this));
        labelTv.setTextSize(11.5f);
        labelTv.setMaxLines(1);
        labelTv.setEllipsize(TextUtils.TruncateAt.END);
        labelTv.setGravity(Gravity.CENTER);
        tile.addView(labelTv);

        final AppTileHolder holder = new AppTileHolder(info.pkg, iv, mono, labelTv, info);
        holder.bind(info);
        tile.setTag(holder);

        Motion.attachPressScale(tile);
        Motion.animateEntrance(tile, index, ThemePalette.dp(this, 10f));
        tile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Motion.hapticTap(v);
                launchSandboxApp(holder.boundInfo);
            }
        });
        tile.setOnLongClickListener(new View.OnLongClickListener() {
            @Override
            public boolean onLongClick(View v) {
                Motion.hapticLongPress(v);
                AppTileInfo cur = holder.boundInfo;
                ensureAppActionSheet().show(cur.pkg, cur.label, cur.icon);
                updateMainAccessibility();
                return true;
            }
        });
        return tile;
    }

    private void launchSandboxApp(final AppTileInfo info) {
        if (busy) {
            return;
        }
        busy = true;
        busyStatusText = strings.statusLaunchingTitle(info.label);
        renderSnapshot();
        showToast(strings.launchingFmt(info.label), false);
        rpcExecutor.execute(new Runnable() {
            @Override
            public void run() {
                final BrokerProtocol.RpcResponse resp = broker.launchApp(info.pkg);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        busy = false;
                        busyStatusText = "";
                        applyRpcResponse(resp, true, true);
                    }
                });
            }
        });
    }

    private void showToast(String message, boolean isError) {
        mainHandler.removeCallbacks(hideToastTask);
        toastCapsule.setText(message);
        toastCapsule.setTextColor(isError ? Color.WHITE : ThemePalette.toastInk(this));
        toastCapsule.setBackground(ThemePalette.cardDrawable(
                this,
                isError ? ThemePalette.accentError(this) : ThemePalette.toastSurface(this),
                ThemePalette.isDark(this) ? ThemePalette.borderHairline(this) : Color.TRANSPARENT,
                20f));
        toastCapsule.setVisibility(View.VISIBLE);
        toastCapsule.animate().cancel();
        toastCapsule.setAlpha(0f);
        toastCapsule.setTranslationY(ThemePalette.dp(this, 10f));
        toastCapsule.animate().alpha(1f).translationY(0f).setDuration(180L).start();
        mainHandler.postDelayed(hideToastTask, isError ? 4500L : 2600L);
    }
}
