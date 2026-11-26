package com.sandbox.controller;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;
import android.view.animation.LinearInterpolator;

/**
 * Quiet-luxury Swiss dial ring with smooth state color transitions,
 * soft breathing pulse when active, and subtle rotating arc when syncing.
 */
public final class BreathingHaloView extends View {

    public enum Mode {
        ACTIVE,
        PAUSED,
        OFFLINE,
        BUSY,
        ERROR
    }

    private final Paint dialPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint haloPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint corePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint arcPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF arcBounds = new RectF();
    private final ArgbEvaluator colorEval = new ArgbEvaluator();

    private Mode mode = Mode.OFFLINE;
    private int currentColor;
    private float breathPhase = 0f;
    private float spinAngle = 0f;
    private boolean hostResumed = true;

    private final ValueAnimator breathAnim;
    private final ValueAnimator spinAnim;
    private ValueAnimator colorAnim;

    public BreathingHaloView(Context context) {
        super(context);
        float density = context.getResources().getDisplayMetrics().density;
        currentColor = ThemePalette.accentStone(context);

        dialPaint.setStyle(Paint.Style.STROKE);
        dialPaint.setStrokeWidth(1.25f * density);
        dialPaint.setColor(ThemePalette.borderHairline(context));

        haloPaint.setStyle(Paint.Style.FILL);
        corePaint.setStyle(Paint.Style.FILL);

        arcPaint.setStyle(Paint.Style.STROKE);
        arcPaint.setStrokeCap(Paint.Cap.ROUND);
        arcPaint.setStrokeWidth(2.2f * density);

        breathAnim = ValueAnimator.ofFloat(0f, 1f);
        breathAnim.setDuration(2200L);
        breathAnim.setRepeatMode(ValueAnimator.REVERSE);
        breathAnim.setRepeatCount(ValueAnimator.INFINITE);
        breathAnim.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator animation) {
                breathPhase = ((Float) animation.getAnimatedValue()).floatValue();
                invalidate();
            }
        });

        spinAnim = ValueAnimator.ofFloat(0f, 360f);
        spinAnim.setDuration(900L);
        spinAnim.setInterpolator(new LinearInterpolator());
        spinAnim.setRepeatCount(ValueAnimator.INFINITE);
        spinAnim.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator animation) {
                spinAngle = ((Float) animation.getAnimatedValue()).floatValue();
                invalidate();
            }
        });
    }

    public void setMode(Mode nextMode) {
        if (this.mode == nextMode) {
            return;
        }
        this.mode = nextMode;
        Context ctx = getContext();
        int targetColor;
        switch (nextMode) {
            case ACTIVE:
                targetColor = ThemePalette.accentSage(ctx);
                break;
            case BUSY:
                targetColor = ThemePalette.accentCopper(ctx);
                break;
            case ERROR:
                targetColor = ThemePalette.accentError(ctx);
                break;
            case PAUSED:
            case OFFLINE:
            default:
                targetColor = ThemePalette.accentStone(ctx);
                break;
        }
        animateColorTo(targetColor);
        syncAnimators();
        invalidate();
    }

    public void setHostResumed(boolean resumed) {
        this.hostResumed = resumed;
        syncAnimators();
    }

    private void animateColorTo(final int targetColor) {
        if (colorAnim != null) {
            colorAnim.cancel();
        }
        final int startColor = currentColor;
        colorAnim = ValueAnimator.ofFloat(0f, 1f);
        colorAnim.setDuration(280L);
        colorAnim.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator animation) {
                float f = ((Float) animation.getAnimatedValue()).floatValue();
                currentColor = ((Integer) colorEval.evaluate(f, startColor, targetColor)).intValue();
                invalidate();
            }
        });
        colorAnim.start();
    }

    private void syncAnimators() {
        if (!hostResumed || !isAttachedToWindow()) {
            breathAnim.cancel();
            spinAnim.cancel();
            return;
        }
        if (mode == Mode.ACTIVE) {
            if (!breathAnim.isStarted()) {
                breathAnim.start();
            }
        } else {
            breathAnim.cancel();
            breathPhase = 0.25f;
        }
        if (mode == Mode.BUSY) {
            if (!spinAnim.isStarted()) {
                spinAnim.start();
            }
        } else {
            spinAnim.cancel();
        }
    }

    @Override
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        syncAnimators();
    }

    @Override
    protected void onDetachedFromWindow() {
        breathAnim.cancel();
        spinAnim.cancel();
        if (colorAnim != null) {
            colorAnim.cancel();
        }
        super.onDetachedFromWindow();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float w = getWidth();
        float h = getHeight();
        float cx = w * 0.5f;
        float cy = h * 0.5f;
        float maxR = Math.min(w, h) * 0.44f;

        canvas.drawCircle(cx, cy, maxR, dialPaint);

        float haloScale = mode == Mode.ACTIVE ? (0.58f + 0.26f * breathPhase) : 0.54f;
        int haloAlpha = mode == Mode.ACTIVE ? Math.round(52 - 22 * breathPhase) : 26;
        haloPaint.setColor((currentColor & 0x00FFFFFF) | (haloAlpha << 24));
        canvas.drawCircle(cx, cy, maxR * haloScale, haloPaint);

        corePaint.setColor(currentColor);
        canvas.drawCircle(cx, cy, maxR * 0.28f, corePaint);

        if (mode == Mode.BUSY) {
            arcPaint.setColor(currentColor);
            float r = maxR * 0.88f;
            arcBounds.set(cx - r, cy - r, cx + r, cy + r);
            canvas.drawArc(arcBounds, spinAngle - 90f, 110f, false, arcPaint);
        }
    }
}
