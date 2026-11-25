package com.sandbox.controller;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.Locale;
import java.util.concurrent.ExecutorService;

/**
 * Animated contextual bottom sheet opened on long-press of a workspace app tile:
 * Launch, Force Stop (STOP_APP), Copy Package, or Remove (REMOVE_APP with 2nd-tap confirm).
 */
public final class AppActionSheet extends FrameLayout {

    public interface Callback {
        void onActionSuccess(BrokerProtocol.StatusSnapshot snapshot, String toastMessage);
        void onActionError(String errorMessage);
        void onCopyToast(String message);
        void onSheetDismissed();
    }

    private final Strings strings;
    private final BrokerClient broker;
    private final ExecutorService executor;
    private final Handler mainHandler;
    private final Callback callback;

    private final View backdrop;
    private final LinearLayout sheetContainer;
    private final ImageView appIconView;
    private final TextView appMonoView;
    private final TextView appLabelView;
    private final TextView appPkgView;
    private final TextView launchBtn;
    private final TextView stopBtn;
    private final TextView copyBtn;
    private final TextView removeBtn;

    private String currentPkg = "";
    private String currentLabel = "";
    private boolean open = false;
    private boolean removeArmed = false;
    private boolean working = false;

    public AppActionSheet(
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
        handleLp.bottomMargin = ThemePalette.dp(ctx, 16f);
        sheetContainer.addView(handle, handleLp);

        // App identity header
        LinearLayout idRow = new LinearLayout(ctx);
        idRow.setOrientation(LinearLayout.HORIZONTAL);
        idRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams idLp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        idLp.bottomMargin = ThemePalette.dp(ctx, 16f);

        FrameLayout iconBox = new FrameLayout(ctx);
        int iconPx = ThemePalette.dp(ctx, 44f);
        appIconView = new ImageView(ctx);
        iconBox.addView(appIconView, new FrameLayout.LayoutParams(iconPx, iconPx));
        appMonoView = new TextView(ctx);
        appMonoView.setTextSize(17f);
        appMonoView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        appMonoView.setGravity(Gravity.CENTER);
        appMonoView.setTextColor(ThemePalette.accentCopper(ctx));
        appMonoView.setBackground(ThemePalette.circleRippleDrawable(
                ctx, ThemePalette.accentCopperSoft(ctx), ThemePalette.surfacePressed(ctx), ThemePalette.borderHairline(ctx)));
        iconBox.addView(appMonoView, new FrameLayout.LayoutParams(iconPx, iconPx));
        LinearLayout.LayoutParams boxLp = new LinearLayout.LayoutParams(iconPx, iconPx);
        boxLp.setMarginEnd(ThemePalette.dp(ctx, 12f));
        idRow.addView(iconBox, boxLp);

        LinearLayout metaCol = new LinearLayout(ctx);
        metaCol.setOrientation(LinearLayout.VERTICAL);
        appLabelView = new TextView(ctx);
        appLabelView.setTextColor(ThemePalette.inkPrimary(ctx));
        appLabelView.setTextSize(17f);
        appLabelView.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        appLabelView.setMaxLines(1);
        appLabelView.setEllipsize(TextUtils.TruncateAt.END);
        metaCol.addView(appLabelView);

        appPkgView = new TextView(ctx);
        appPkgView.setTextColor(ThemePalette.inkMuted(ctx));
        appPkgView.setTextSize(12f);
        appPkgView.setTypeface(Typeface.MONOSPACE);
        appPkgView.setMaxLines(1);
        appPkgView.setEllipsize(TextUtils.TruncateAt.END);
        metaCol.addView(appPkgView);
        idRow.addView(metaCol, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));
        sheetContainer.addView(idRow, idLp);

        launchBtn = buildActionButton(ctx, strings.actionLaunch(),
                Color.WHITE, ThemePalette.accentCopper(ctx), ThemePalette.accentCopperPressed(ctx), Color.TRANSPARENT);
        stopBtn = buildActionButton(ctx, strings.actionStop(),
                ThemePalette.inkPrimary(ctx), ThemePalette.surfaceCard(ctx), ThemePalette.surfacePressed(ctx), ThemePalette.borderHairline(ctx));
        copyBtn = buildActionButton(ctx, strings.actionCopyPkg(),
                ThemePalette.inkPrimary(ctx), ThemePalette.surfaceCard(ctx), ThemePalette.surfacePressed(ctx), ThemePalette.borderHairline(ctx));
        removeBtn = buildActionButton(ctx, strings.actionRemove(),
                ThemePalette.accentError(ctx), ThemePalette.accentErrorSoft(ctx), ThemePalette.surfacePressed(ctx), ThemePalette.borderHairline(ctx));

        launchBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                runPackageRpc(0);
            }
        });
        stopBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                runPackageRpc(1);
            }
        });
        copyBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                ClipboardManager cm = (ClipboardManager) getContext().getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) {
                    cm.setPrimaryClip(ClipData.newPlainText("kernbox-package", currentPkg));
                }
                callback.onCopyToast(strings.copiedPkgToast());
                dismiss();
            }
        });
        removeBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                if (working) {
                    return;
                }
                if (!removeArmed) {
                    removeArmed = true;
                    removeBtn.setText(strings.actionRemoveConfirm());
                    removeBtn.setTextColor(Color.WHITE);
                    removeBtn.setBackground(ThemePalette.pillRippleDrawable(
                            getContext(), ThemePalette.accentError(getContext()),
                            ThemePalette.surfacePressed(getContext()), Color.TRANSPARENT, 14f));
                    Motion.animatePulse(removeBtn);
                    return;
                }
                runPackageRpc(2);
            }
        });

        sheetContainer.addView(launchBtn);
        sheetContainer.addView(stopBtn);
        sheetContainer.addView(copyBtn);
        sheetContainer.addView(removeBtn);
    }

    private TextView buildActionButton(
            Context ctx, String text, int fg, int fill, int ripple, int stroke) {
        TextView tv = new TextView(ctx);
        tv.setText(text);
        tv.setTextColor(fg);
        tv.setTextSize(14.5f);
        tv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        tv.setGravity(Gravity.CENTER);
        tv.setBackground(ThemePalette.pillRippleDrawable(ctx, fill, ripple, stroke, 14f));
        Motion.attachPressScale(tv);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, ThemePalette.dp(ctx, 46f));
        lp.bottomMargin = ThemePalette.dp(ctx, 10f);
        tv.setLayoutParams(lp);
        return tv;
    }

    public void setBottomInset(int bottomPx) {
        int hPad = ThemePalette.dp(getContext(), 20f);
        sheetContainer.setPadding(hPad, ThemePalette.dp(getContext(), 12f), hPad,
                ThemePalette.dp(getContext(), 24f) + Math.max(0, bottomPx));
    }

    public boolean isOpen() {
        return open;
    }

    public void show(String pkg, String label, Drawable icon) {
        Context ctx = getContext();
        this.currentPkg = pkg;
        this.currentLabel = label;
        this.removeArmed = false;
        this.working = false;

        appLabelView.setText(label);
        appPkgView.setText(pkg);
        if (icon != null) {
            appIconView.setVisibility(View.VISIBLE);
            appMonoView.setVisibility(View.GONE);
            appIconView.setImageDrawable(icon);
        } else {
            appIconView.setVisibility(View.GONE);
            appMonoView.setVisibility(View.VISIBLE);
            appMonoView.setText(label.isEmpty() ? "?" : label.substring(0, 1).toUpperCase(Locale.ROOT));
        }

        removeBtn.setText(strings.actionRemove());
        removeBtn.setTextColor(ThemePalette.accentError(ctx));
        removeBtn.setBackground(ThemePalette.pillRippleDrawable(
                ctx, ThemePalette.accentErrorSoft(ctx), ThemePalette.surfacePressed(ctx), ThemePalette.borderHairline(ctx), 14f));
        setButtonsEnabled(true);

        open = true;
        setVisibility(View.VISIBLE);
        backdrop.animate().cancel();
        backdrop.setAlpha(0f);
        backdrop.animate().alpha(1f).setDuration(200L).start();

        sheetContainer.animate().cancel();
        sheetContainer.setTranslationY(ThemePalette.dp(ctx, 320f));
        sheetContainer.animate()
                .translationY(0f)
                .setDuration(250L)
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
                .translationY(ThemePalette.dp(getContext(), 340f))
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

    private void setButtonsEnabled(boolean enabled) {
        launchBtn.setEnabled(enabled);
        stopBtn.setEnabled(enabled);
        copyBtn.setEnabled(enabled);
        removeBtn.setEnabled(enabled);
        float alpha = enabled ? 1f : 0.55f;
        launchBtn.setAlpha(alpha);
        stopBtn.setAlpha(alpha);
        removeBtn.setAlpha(alpha);
    }

    private void runPackageRpc(final int kind) {
        if (working) {
            return;
        }
        working = true;
        setButtonsEnabled(false);
        final String pkg = currentPkg;
        final String label = currentLabel;
        executor.execute(new Runnable() {
            @Override
            public void run() {
                final BrokerProtocol.RpcResponse resp;
                final String okMsg;
                if (kind == 0) {
                    resp = broker.launchApp(pkg);
                    okMsg = strings.launchingFmt(label);
                } else if (kind == 1) {
                    resp = broker.stopApp(pkg);
                    okMsg = strings.stoppedFmt(label);
                } else {
                    resp = broker.removeApp(pkg);
                    okMsg = strings.removedFmt(label);
                }
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        working = false;
                        setButtonsEnabled(true);
                        if (resp.ok) {
                            callback.onActionSuccess(resp.snapshot, okMsg);
                            dismiss();
                        } else {
                            callback.onActionError(strings.failPrefix() + resp.error);
                        }
                    }
                });
            }
        });
    }
}
