package com.sandbox.controller;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.view.View;

/**
 * Crisp precision-drawn vector "+" icon with rounded stroke caps.
 */
public final class PlusMarkView extends View {

    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

    public PlusMarkView(Context context, int color, float strokeDp) {
        super(context);
        float density = context.getResources().getDisplayMetrics().density;
        paint.setColor(color);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeCap(Paint.Cap.ROUND);
        paint.setStrokeWidth(strokeDp * density);
    }

    public PlusMarkView(Context context) {
        this(context, Color.WHITE, 2.4f);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float cx = getWidth() * 0.5f;
        float cy = getHeight() * 0.5f;
        float arm = Math.min(getWidth(), getHeight()) * 0.24f;
        canvas.drawLine(cx - arm, cy, cx + arm, cy, paint);
        canvas.drawLine(cx, cy - arm, cx, cy + arm, paint);
    }
}
