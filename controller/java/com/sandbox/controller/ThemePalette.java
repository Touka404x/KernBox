package com.sandbox.controller;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.util.TypedValue;

/**
 * Quiet-luxury Swiss Industrial Monograph palette aligned with the KernBox icon.
 */
public final class ThemePalette {

    public static final int BG_PAPER = 0xFFF6F3EC;
    public static final int SURFACE_CARD = 0xFFFFFFFF;
    public static final int SURFACE_SUBTLE = 0xFFEDE8DC;
    public static final int SURFACE_PRESSED = 0xFFE3DDD0;
    public static final int BORDER_HAIRLINE = 0xFFE2DDD1;
    public static final int BACKDROP_DIM = 0x661C2026;

    public static final int INK_PRIMARY = 0xFF1C2026;
    public static final int INK_SECONDARY = 0xFF6B6F76;
    public static final int INK_MUTED = 0xFF96938A;

    public static final int ACCENT_COPPER = 0xFFB8704F;
    public static final int ACCENT_COPPER_PRESSED = 0xFF9E5D3F;
    public static final int ACCENT_COPPER_SOFT = 0xFFF2E5DE;

    public static final int ACCENT_SAGE = 0xFF2F7A58;
    public static final int ACCENT_SAGE_SOFT = 0xFFE5F0EA;
    public static final int ACCENT_STONE = 0xFF8C887E;
    public static final int ACCENT_ERROR = 0xFFB34A3C;

    private ThemePalette() {}

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
