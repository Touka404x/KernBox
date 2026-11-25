package com.sandbox.controller;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.text.Editable;
import android.text.InputType;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;

/**
 * Animated bottom-sheet overlay opened by the "+" FAB to search & import User 0 apps
 * into the sandbox (IMPORT_EXISTING) or install a staged APK (INSTALL_APK).
 */
public final class AddAppSheet extends FrameLayout {

    public interface HostCallback {
        void onAppImported(String pkg, String label);
        void onApkInstalled(String path);
        void onToast(String message, boolean error);
        void onDismissed();
    }

    private static final class AppItem {
        final String pkg;
        final String label;
        final Drawable icon;
        boolean imported;

        AppItem(String pkg, String label, Drawable icon) {
            this.pkg = pkg;
            this.label = label;
            this.icon = icon;
        }
    }

    private final Strings strings;
    private final BrokerClient broker;
    private final ExecutorService executor;
    private final Handler mainHandler;
    private final HostCallback callback;

    private final View backdrop;
    private final LinearLayout sheetContainer;
    private final TextView tabDeviceBtn;
    private final TextView tabApkBtn;
    private final LinearLayout devicePane;
    private final LinearLayout apkPane;
    private final EditText searchInput;
    private final LinearLayout appsListContainer;
    private final TextView emptyMsgView;
    private final EditText apkPathInput;
    private final TextView installApkBtn;

    private final List<AppItem> allDeviceApps = new ArrayList<AppItem>();
    private final Set<String> importedPackages = new HashSet<String>();
    private boolean open = false;
    private boolean loadingApps = false;

    public AddAppSheet(
            Context context,
            Strings strings,
            BrokerClient broker,
            ExecutorService executor,
            Handler mainHandler,
            HostCallback callback) {
        super(context);
        this.strings = strings;
        this.broker = broker;
        this.executor = executor;
        this.mainHandler = mainHandler;
        this.callback = callback;

        setVisibility(View.GONE);
        setClickable(true);

        backdrop = new View(context);
        backdrop.setBackgroundColor(ThemePalette.backdropDim(context));
        backdrop.setAlpha(0f);
        backdrop.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                dismiss();
            }
        });
        addView(backdrop, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT));

        sheetContainer = new LinearLayout(context);
        sheetContainer.setOrientation(LinearLayout.VERTICAL);
        sheetContainer.setBackground(ThemePalette.topSheetDrawable(
                context, ThemePalette.bgPaper(context), ThemePalette.borderHairline(context), 24f));
        sheetContainer.setClickable(true);
        int hPad = ThemePalette.dp(context, 20f);
        sheetContainer.setPadding(hPad, ThemePalette.dp(context, 12f), hPad, ThemePalette.dp(context, 22f));
        LayoutParams sheetLp = new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT, Gravity.BOTTOM);
        sheetContainer.setElevation(ThemePalette.dp(context, 18f));
        addView(sheetContainer, sheetLp);

        View handle = new View(context);
        handle.setBackground(ThemePalette.cardDrawable(
                context, ThemePalette.borderHairline(context), Color.TRANSPARENT, 3f));
        LinearLayout.LayoutParams handleLp = new LinearLayout.LayoutParams(
                ThemePalette.dp(context, 40f), ThemePalette.dp(context, 4f));
        handleLp.gravity = Gravity.CENTER_HORIZONTAL;
        handleLp.bottomMargin = ThemePalette.dp(context, 14f);
        sheetContainer.addView(handle, handleLp);

        LinearLayout headerRow = new LinearLayout(context);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView titleView = new TextView(context);
        titleView.setText(strings.sheetTitle());
        titleView.setTextColor(ThemePalette.inkPrimary(context));
        titleView.setTextSize(18f);
        titleView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        LinearLayout.LayoutParams titleLp = new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f);
        headerRow.addView(titleView, titleLp);

        TextView closeBtn = new TextView(context);
        closeBtn.setText("×");
        closeBtn.setTextSize(20f);
        closeBtn.setGravity(Gravity.CENTER);
        closeBtn.setTextColor(ThemePalette.inkSecondary(context));
        closeBtn.setBackground(ThemePalette.circleRippleDrawable(
                context, ThemePalette.surfaceSubtle(context), ThemePalette.surfacePressed(context), Color.TRANSPARENT));
        closeBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                dismiss();
            }
        });
        Motion.attachPressScale(closeBtn);
        headerRow.addView(closeBtn, new LinearLayout.LayoutParams(
                ThemePalette.dp(context, 32f), ThemePalette.dp(context, 32f)));
        sheetContainer.addView(headerRow);

        LinearLayout tabStrip = new LinearLayout(context);
        tabStrip.setOrientation(LinearLayout.HORIZONTAL);
        tabStrip.setPadding(ThemePalette.dp(context, 4f), ThemePalette.dp(context, 4f),
                ThemePalette.dp(context, 4f), ThemePalette.dp(context, 4f));
        tabStrip.setBackground(ThemePalette.cardDrawable(
                context, ThemePalette.surfaceSubtle(context), ThemePalette.borderHairline(context), 14f));
        LinearLayout.LayoutParams tabStripLp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        tabStripLp.topMargin = ThemePalette.dp(context, 14f);
        tabStripLp.bottomMargin = ThemePalette.dp(context, 12f);

        tabDeviceBtn = buildTabButton(context, strings.tabDeviceApps());
        tabApkBtn = buildTabButton(context, strings.tabInstallApk());
        tabDeviceBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                switchTab(true);
            }
        });
        tabApkBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                switchTab(false);
            }
        });
        tabStrip.addView(tabDeviceBtn, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));
        tabStrip.addView(tabApkBtn, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));
        sheetContainer.addView(tabStrip, tabStripLp);

        devicePane = new LinearLayout(context);
        devicePane.setOrientation(LinearLayout.VERTICAL);

        searchInput = new EditText(context);
        searchInput.setHint(strings.searchHint());
        searchInput.setHintTextColor(ThemePalette.inkMuted(context));
        searchInput.setTextColor(ThemePalette.inkPrimary(context));
        searchInput.setTextSize(14f);
        searchInput.setSingleLine(true);
        searchInput.setBackground(ThemePalette.cardDrawable(
                context, ThemePalette.surfaceCard(context), ThemePalette.borderHairline(context), 12f));
        int sPad = ThemePalette.dp(context, 12f);
        searchInput.setPadding(sPad, ThemePalette.dp(context, 10f), sPad, ThemePalette.dp(context, 10f));
        searchInput.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) {
                renderFilteredApps();
            }
        });
        LinearLayout.LayoutParams searchLp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        searchLp.bottomMargin = ThemePalette.dp(context, 10f);
        devicePane.addView(searchInput, searchLp);

        ScrollView scroll = new ScrollView(context);
        scroll.setVerticalScrollBarEnabled(false);
        appsListContainer = new LinearLayout(context);
        appsListContainer.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(appsListContainer, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT));
        int listMaxHeight = Math.round(context.getResources().getDisplayMetrics().heightPixels * 0.44f);
        devicePane.addView(scroll, new LinearLayout.LayoutParams(LayoutParams.MATCH_PARENT, listMaxHeight));

        emptyMsgView = new TextView(context);
        emptyMsgView.setTextColor(ThemePalette.inkMuted(context));
        emptyMsgView.setTextSize(13f);
        emptyMsgView.setGravity(Gravity.CENTER);
        emptyMsgView.setPadding(0, ThemePalette.dp(context, 28f), 0, ThemePalette.dp(context, 28f));
        emptyMsgView.setVisibility(View.GONE);
        appsListContainer.addView(emptyMsgView);

        sheetContainer.addView(devicePane);

        apkPane = new LinearLayout(context);
        apkPane.setOrientation(LinearLayout.VERTICAL);
        apkPane.setVisibility(View.GONE);

        TextView apkDesc = new TextView(context);
        apkDesc.setText(strings.apkPathLabel());
        apkDesc.setTextColor(ThemePalette.inkSecondary(context));
        apkDesc.setTextSize(13f);
        apkDesc.setLineSpacing(0f, 1.25f);
        LinearLayout.LayoutParams descLp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        descLp.bottomMargin = ThemePalette.dp(context, 10f);
        apkPane.addView(apkDesc, descLp);

        apkPathInput = new EditText(context);
        apkPathInput.setHint(strings.apkPathHint());
        apkPathInput.setHintTextColor(ThemePalette.inkMuted(context));
        apkPathInput.setTextColor(ThemePalette.inkPrimary(context));
        apkPathInput.setTextSize(13.5f);
        apkPathInput.setTypeface(Typeface.MONOSPACE);
        apkPathInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        apkPathInput.setSingleLine(true);
        apkPathInput.setBackground(ThemePalette.cardDrawable(
                context, ThemePalette.surfaceCard(context), ThemePalette.borderHairline(context), 12f));
        apkPathInput.setPadding(sPad, ThemePalette.dp(context, 11f), sPad, ThemePalette.dp(context, 11f));
        LinearLayout.LayoutParams inputLp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        inputLp.bottomMargin = ThemePalette.dp(context, 14f);
        apkPane.addView(apkPathInput, inputLp);

        installApkBtn = new TextView(context);
        installApkBtn.setText(strings.btnInstallApk());
        installApkBtn.setTextColor(Color.WHITE);
        installApkBtn.setTextSize(14.5f);
        installApkBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        installApkBtn.setGravity(Gravity.CENTER);
        installApkBtn.setBackground(ThemePalette.pillRippleDrawable(
                context, ThemePalette.accentCopper(context), ThemePalette.accentCopperPressed(context), Color.TRANSPARENT, 14f));
        Motion.attachPressScale(installApkBtn);
        installApkBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                handleApkInstall();
            }
        });
        apkPane.addView(installApkBtn, new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, ThemePalette.dp(context, 46f)));

        sheetContainer.addView(apkPane);
        switchTab(true);
    }

    private TextView buildTabButton(Context context, String label) {
        TextView tv = new TextView(context);
        tv.setText(label);
        tv.setTextSize(13f);
        tv.setGravity(Gravity.CENTER);
        tv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        tv.setPadding(0, ThemePalette.dp(context, 8f), 0, ThemePalette.dp(context, 8f));
        return tv;
    }

    private void switchTab(boolean deviceTab) {
        Context ctx = getContext();
        tabDeviceBtn.setBackground(deviceTab
                ? ThemePalette.cardDrawable(ctx, ThemePalette.surfaceCard(ctx), ThemePalette.borderHairline(ctx), 10f)
                : null);
        tabDeviceBtn.setTextColor(deviceTab ? ThemePalette.inkPrimary(ctx) : ThemePalette.inkSecondary(ctx));
        tabApkBtn.setBackground(!deviceTab
                ? ThemePalette.cardDrawable(ctx, ThemePalette.surfaceCard(ctx), ThemePalette.borderHairline(ctx), 10f)
                : null);
        tabApkBtn.setTextColor(!deviceTab ? ThemePalette.inkPrimary(ctx) : ThemePalette.inkSecondary(ctx));
        devicePane.setVisibility(deviceTab ? View.VISIBLE : View.GONE);
        apkPane.setVisibility(deviceTab ? View.GONE : View.VISIBLE);
    }

    public boolean isOpen() {
        return open;
    }

    public void show(List<String> alreadyImported) {
        importedPackages.clear();
        if (alreadyImported != null) {
            importedPackages.addAll(alreadyImported);
        }
        for (AppItem item : allDeviceApps) {
            item.imported = importedPackages.contains(item.pkg);
        }

        open = true;
        setVisibility(View.VISIBLE);
        backdrop.animate().cancel();
        backdrop.setAlpha(0f);
        backdrop.animate().alpha(1f).setDuration(220L).start();

        float startY = ThemePalette.dp(getContext(), 340f);
        sheetContainer.animate().cancel();
        sheetContainer.setTranslationY(startY);
        sheetContainer.animate()
                .translationY(0f)
                .setDuration(260L)
                .setInterpolator(new DecelerateInterpolator(2.2f))
                .start();

        if (allDeviceApps.isEmpty() && !loadingApps) {
            loadDeviceAppsAsync();
        } else {
            renderFilteredApps();
        }
    }

    public void dismiss() {
        if (!open) {
            return;
        }
        open = false;
        backdrop.animate().cancel();
        backdrop.animate().alpha(0f).setDuration(180L).start();
        sheetContainer.animate().cancel();
        sheetContainer.animate()
                .translationY(ThemePalette.dp(getContext(), 360f))
                .setDuration(200L)
                .setInterpolator(new AccelerateInterpolator(1.6f))
                .setListener(new AnimatorListenerAdapter() {
                    @Override
                    public void onAnimationEnd(Animator animation) {
                        sheetContainer.animate().setListener(null);
                        if (!open) {
                            setVisibility(View.GONE);
                            callback.onDismissed();
                        }
                    }
                })
                .start();
    }

    private void loadDeviceAppsAsync() {
        loadingApps = true;
        renderFilteredApps();
        final Context appCtx = getContext().getApplicationContext();
        executor.execute(new Runnable() {
            @Override
            public void run() {
                PackageManager pm = appCtx.getPackageManager();
                Intent mainIntent = new Intent(Intent.ACTION_MAIN, null);
                mainIntent.addCategory(Intent.CATEGORY_LAUNCHER);
                @SuppressWarnings("deprecation")
                List<ResolveInfo> resolved = pm.queryIntentActivities(mainIntent, PackageManager.MATCH_ALL);
                Set<String> seen = new HashSet<String>();
                final List<AppItem> loaded = new ArrayList<AppItem>();
                for (ResolveInfo ri : resolved) {
                    if (ri.activityInfo == null || ri.activityInfo.packageName == null) {
                        continue;
                    }
                    String pkg = ri.activityInfo.packageName;
                    if ("com.sandbox.controller".equals(pkg)
                            || "com.sandbox.verify".equals(pkg)
                            || !seen.add(pkg)) {
                        continue;
                    }
                    CharSequence labelCs = ri.loadLabel(pm);
                    String label = labelCs != null ? labelCs.toString().trim() : pkg;
                    if (label.isEmpty()) {
                        label = pkg;
                    }
                    Drawable icon = ri.loadIcon(pm);
                    AppItem item = new AppItem(pkg, label, icon);
                    item.imported = importedPackages.contains(pkg);
                    loaded.add(item);
                }
                Collections.sort(loaded, new Comparator<AppItem>() {
                    @Override
                    public int compare(AppItem a, AppItem b) {
                        return a.label.compareToIgnoreCase(b.label);
                    }
                });
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        loadingApps = false;
                        allDeviceApps.clear();
                        allDeviceApps.addAll(loaded);
                        renderFilteredApps();
                    }
                });
            }
        });
    }

    private void renderFilteredApps() {
        appsListContainer.removeAllViews();
        if (loadingApps) {
            emptyMsgView.setText(strings.scanningApps());
            emptyMsgView.setVisibility(View.VISIBLE);
            appsListContainer.addView(emptyMsgView);
            return;
        }
        String q = searchInput.getText().toString().trim().toLowerCase(Locale.ROOT);
        Context ctx = getContext();
        int shown = 0;
        for (final AppItem item : allDeviceApps) {
            if (!q.isEmpty()
                    && !item.label.toLowerCase(Locale.ROOT).contains(q)
                    && !item.pkg.toLowerCase(Locale.ROOT).contains(q)) {
                continue;
            }
            View row = buildAppRow(ctx, item);
            appsListContainer.addView(row);
            shown++;
        }
        if (shown == 0) {
            emptyMsgView.setText(strings.noMatches());
            emptyMsgView.setVisibility(View.VISIBLE);
            appsListContainer.addView(emptyMsgView);
        }
    }

    private View buildAppRow(final Context ctx, final AppItem item) {
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setBackground(ThemePalette.cardDrawable(
                ctx, ThemePalette.surfaceCard(ctx), ThemePalette.borderHairline(ctx), 14f));
        int hPad = ThemePalette.dp(ctx, 12f);
        int vPad = ThemePalette.dp(ctx, 10f);
        row.setPadding(hPad, vPad, hPad, vPad);
        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        rowLp.bottomMargin = ThemePalette.dp(ctx, 8f);
        row.setLayoutParams(rowLp);

        ImageView iconView = new ImageView(ctx);
        iconView.setImageDrawable(item.icon);
        LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(
                ThemePalette.dp(ctx, 38f), ThemePalette.dp(ctx, 38f));
        iconLp.rightMargin = ThemePalette.dp(ctx, 12f);
        row.addView(iconView, iconLp);

        LinearLayout textCol = new LinearLayout(ctx);
        textCol.setOrientation(LinearLayout.VERTICAL);
        TextView nameTv = new TextView(ctx);
        nameTv.setText(item.label);
        nameTv.setTextColor(ThemePalette.inkPrimary(ctx));
        nameTv.setTextSize(14f);
        nameTv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        nameTv.setMaxLines(1);
        nameTv.setEllipsize(TextUtils.TruncateAt.END);
        textCol.addView(nameTv);

        TextView pkgTv = new TextView(ctx);
        pkgTv.setText(item.pkg);
        pkgTv.setTextColor(ThemePalette.inkMuted(ctx));
        pkgTv.setTextSize(11.5f);
        pkgTv.setMaxLines(1);
        pkgTv.setEllipsize(TextUtils.TruncateAt.END);
        textCol.addView(pkgTv);
        row.addView(textCol, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));

        final TextView actionBtn = new TextView(ctx);
        actionBtn.setTextSize(12.5f);
        actionBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        actionBtn.setGravity(Gravity.CENTER);
        actionBtn.setPadding(ThemePalette.dp(ctx, 12f), ThemePalette.dp(ctx, 6f),
                ThemePalette.dp(ctx, 12f), ThemePalette.dp(ctx, 6f));
        applyActionState(ctx, actionBtn, item.imported);
        Motion.attachPressScale(actionBtn);
        actionBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                if (item.imported) {
                    return;
                }
                actionBtn.setEnabled(false);
                actionBtn.setAlpha(0.55f);
                executor.execute(new Runnable() {
                    @Override
                    public void run() {
                        final BrokerProtocol.RpcResponse resp = broker.importExistingApp(item.pkg);
                        mainHandler.post(new Runnable() {
                            @Override
                            public void run() {
                                actionBtn.setEnabled(true);
                                actionBtn.setAlpha(1f);
                                if (resp.ok) {
                                    item.imported = true;
                                    importedPackages.add(item.pkg);
                                    applyActionState(ctx, actionBtn, true);
                                    Motion.animatePulse(actionBtn);
                                    callback.onAppImported(item.pkg, item.label);
                                } else {
                                    callback.onToast(strings.failPrefix() + resp.error, true);
                                }
                            }
                        });
                    }
                });
            }
        });
        row.addView(actionBtn);
        return row;
    }

    private void applyActionState(Context ctx, TextView btn, boolean imported) {
        if (imported) {
            btn.setText("✓ " + strings.btnAdded());
            btn.setTextColor(ThemePalette.accentSage(ctx));
            btn.setBackground(ThemePalette.cardDrawable(
                    ctx, ThemePalette.accentSageSoft(ctx), ThemePalette.borderHairline(ctx), 18f));
        } else {
            btn.setText("+ " + strings.btnImport());
            btn.setTextColor(Color.WHITE);
            btn.setBackground(ThemePalette.pillRippleDrawable(
                    ctx, ThemePalette.accentCopper(ctx), ThemePalette.accentCopperPressed(ctx), Color.TRANSPARENT, 18f));
        }
    }

    private void handleApkInstall() {
        final String path = apkPathInput.getText().toString().trim();
        if (!BrokerProtocol.isAllowedApkPath(path)) {
            Motion.animatePulse(apkPathInput);
            callback.onToast(strings.invalidApkPath(), true);
            return;
        }
        installApkBtn.setEnabled(false);
        installApkBtn.setText(strings.btnSyncing());
        executor.execute(new Runnable() {
            @Override
            public void run() {
                final BrokerProtocol.RpcResponse resp = broker.installApk(path);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        installApkBtn.setEnabled(true);
                        installApkBtn.setText(strings.btnInstallApk());
                        if (resp.ok) {
                            apkPathInput.setText("");
                            callback.onApkInstalled(path);
                            dismiss();
                        } else {
                            callback.onToast(strings.failPrefix() + resp.error, true);
                        }
                    }
                });
            }
        });
    }
}
