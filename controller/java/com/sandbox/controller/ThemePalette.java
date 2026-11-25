package com.sandbox.controller;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.util.TypedValue;

/**
 * Quiet-luxury Swiss Industrial Monograph palette (Light Ivory & Dark Charcoal Obsidian)
 * aligned with the KernBox cube & brushed-copper ring identity.
 */
public final class ThemePalette {

    // Light palette defaults (also retained as constants for custom views)
    public static final int BG_PAPER = 0xFFF6F3EC;
    public static final int SURFACE_CARD = 0xFFFFFFFF;
    public static final int SURFACE_SUBTLE = 0xFFEDE8DC;
    public static final int SURFACE_PRESSED = 0xFFE3DDD0;
    public static final int BORDER_HAIRLINE = 0xFFE2DDD1;
    public static final int BACKDROP_DIM = 0x661C2026;

    public static final int INK_PRIMARY = 0xFF1C2026;
    public static final int INK_SECONDARY = 0xFF6B6F76;
    public static final int INK_MUTED = 0xFF6E6B63;

    public static final int ACCENT_COPPER = 0xFFB8704F;
    public static final int ACCENT_COPPER_PRESSED = 0xFF9E5D3F;
    public static final int ACCENT_COPPER_SOFT = 0xFFF2E5DE;

    public static final int ACCENT_SAGE = 0xFF2F7A58;
    public static final int ACCENT_SAGE_SOFT = 0xFFE5F0EA;
    public static final int ACCENT_STONE = 0xFF8C887E;
    public static final int ACCENT_ERROR = 0xFFB34A3C;
    public static final int ACCENT_ERROR_SOFT = 0xFFF7E7E5;

    // Dark warm-obsidian palette
    private static final int DARK_BG_PAPER = 0xFF16181C;
    private static final int DARK_SURFACE_CARD = 0xFF202329;
    private static final int DARK_SURFACE_SUBTLE = 0xFF2A2E36;
    private static final int DARK_SURFACE_PRESSED = 0xFF343944;
    private static final int DARK_BORDER_HAIRLINE = 0xFF323741;
    private static final int DARK_BACKDROP_DIM = 0x880B0C0E;

    private static final int DARK_INK_PRIMARY = 0xFFF2EEE6;
    private static final int DARK_INK_SECONDARY = 0xFFB0ACA3;
    private static final int DARK_INK_MUTED = 0xFF9E9A91;

    private static final int DARK_ACCENT_COPPER = 0xFFC97F5D;
    private static final int DARK_ACCENT_COPPER_PRESSED = 0xFFAF6A4A;
    private static final int DARK_ACCENT_COPPER_SOFT = 0xFF342721;

    private static final int DARK_ACCENT_SAGE = 0xFF4AA37A;
    private static final int DARK_ACCENT_SAGE_SOFT = 0xFF1D3128;
    private static final int DARK_ACCENT_STONE = 0xFF949087;
    private static final int DARK_ACCENT_ERROR = 0xFFD46A5C;
    private static final int DARK_ACCENT_ERROR_SOFT = 0xFF362220;

    private ThemePalette() {}

    public static boolean isDark(Context ctx) {
        int night = ctx.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        return night == Configuration.UI_MODE_NIGHT_YES;
    }

    public static int bgPaper(Context ctx) { return isDark(ctx) ? DARK_BG_PAPER : BG_PAPER; }
    public static int surfaceCard(Context ctx) { return isDark(ctx) ? DARK_SURFACE_CARD : SURFACE_CARD; }
    public static int surfaceSubtle(Context ctx) { return isDark(ctx) ? DARK_SURFACE_SUBTLE : SURFACE_SUBTLE; }
    public static int surfacePressed(Context ctx) { return isDark(ctx) ? DARK_SURFACE_PRESSED : SURFACE_PRESSED; }
    public static int borderHairline(Context ctx) { return isDark(ctx) ? DARK_BORDER_HAIRLINE : BORDER_HAIRLINE; }
    public static int backdropDim(Context ctx) { return isDark(ctx) ? DARK_BACKDROP_DIM : BACKDROP_DIM; }

    public static int inkPrimary(Context ctx) { return isDark(ctx) ? DARK_INK_PRIMARY : INK_PRIMARY; }
    public static int inkSecondary(Context ctx) { return isDark(ctx) ? DARK_INK_SECONDARY : INK_SECONDARY; }
    public static int inkMuted(Context ctx) { return isDark(ctx) ? DARK_INK_MUTED : INK_MUTED; }

    public static int accentCopper(Context ctx) { return isDark(ctx) ? DARK_ACCENT_COPPER : ACCENT_COPPER; }
    public static int accentCopperPressed(Context ctx) { return isDark(ctx) ? DARK_ACCENT_COPPER_PRESSED : ACCENT_COPPER_PRESSED; }
    public static int accentCopperSoft(Context ctx) { return isDark(ctx) ? DARK_ACCENT_COPPER_SOFT : ACCENT_COPPER_SOFT; }
    public static int accentSage(Context ctx) { return isDark(ctx) ? DARK_ACCENT_SAGE : ACCENT_SAGE; }
    public static int accentSageSoft(Context ctx) { return isDark(ctx) ? DARK_ACCENT_SAGE_SOFT : ACCENT_SAGE_SOFT; }
    public static int accentStone(Context ctx) { return isDark(ctx) ? DARK_ACCENT_STONE : ACCENT_STONE; }
    public static int accentError(Context ctx) { return isDark(ctx) ? DARK_ACCENT_ERROR : ACCENT_ERROR; }
    public static int accentErrorSoft(Context ctx) { return isDark(ctx) ? DARK_ACCENT_ERROR_SOFT : ACCENT_ERROR_SOFT; }
    public static int toastSurface(Context ctx) { return isDark(ctx) ? DARK_INK_PRIMARY : INK_PRIMARY; }
    public static int toastInk(Context ctx) { return isDark(ctx) ? DARK_BG_PAPER : Color.WHITE; }

    public static int dp(Context ctx, float value) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, ctx.getResources().getDisplayMetrics()
        ));
    }

    public static Drawable cardDrawable(Context ctx, int fillColor, int strokeColor, float radiusDp) {
        GradientDrawable gd = new GradientDrawable();
        gd.setShape(GradientDrawable.RECTANGLE);
        gd.setColor(fillColor);
        gd.setCornerRadius(dp(ctx, radiusDp));
        if (strokeColor != Color.TRANSPARENT) {
            gd.setStroke(Math.max(1, dp(ctx, 1f)), strokeColor);
        }
        return gd;
    }

    public static Drawable topSheetDrawable(Context ctx, int fillColor, int strokeColor, float topRadiusDp) {
        int r = dp(ctx, topRadiusDp);
        GradientDrawable gd = new GradientDrawable();
        gd.setShape(GradientDrawable.RECTANGLE);
        gd.setColor(fillColor);
        gd.setCornerRadii(new float[]{r, r, r, r, 0f, 0f, 0f, 0f});
        gd.setStroke(Math.max(1, dp(ctx, 1f)), strokeColor);
        return gd;
    }

    public static Drawable pillRippleDrawable(
            Context ctx, int fillColor, int rippleColor, int strokeColor, float radiusDp) {
        GradientDrawable content = new GradientDrawable();
        content.setShape(GradientDrawable.RECTANGLE);
        content.setColor(fillColor);
        content.setCornerRadius(dp(ctx, radiusDp));
        if (strokeColor != Color.TRANSPARENT) {
            content.setStroke(Math.max(1, dp(ctx, 1f)), strokeColor);
        }
        GradientDrawable mask = new GradientDrawable();
        mask.setShape(GradientDrawable.RECTANGLE);
        mask.setColor(Color.WHITE);
        mask.setCornerRadius(dp(ctx, radiusDp));
        return new RippleDrawable(ColorStateList.valueOf(rippleColor), content, mask);
    }

    public static Drawable circleRippleDrawable(Context ctx, int fillColor, int rippleColor, int strokeColor) {
        GradientDrawable content = new GradientDrawable();
        content.setShape(GradientDrawable.OVAL);
        content.setColor(fillColor);
        if (strokeColor != Color.TRANSPARENT) {
            content.setStroke(Math.max(1, dp(ctx, 1f)), strokeColor);
        }
        GradientDrawable mask = new GradientDrawable();
        mask.setShape(GradientDrawable.OVAL);
        mask.setColor(Color.WHITE);
        return new RippleDrawable(ColorStateList.valueOf(rippleColor), content, mask);
    }
}
