package com.sandbox.controller;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.os.Build;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;
import android.view.animation.OvershootInterpolator;

/**
 * Restraint-first motion & haptic helpers with crisp 120Hz spring-feel feedback.
 */
public final class Motion {

    private static final DecelerateInterpolator DECEL = new DecelerateInterpolator(2.0f);
    private static final OvershootInterpolator OVERSHOOT = new OvershootInterpolator(1.6f);

    private Motion() {}

    public static void hapticTap(View v) {
        if (v != null) {
            v.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK);
        }
    }

    public static void hapticLongPress(View v) {
        if (v != null) {
            v.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS);
        }
    }

    public static void hapticConfirm(View v) {
        if (v != null) {
            int code = Build.VERSION.SDK_INT >= 30
                    ? HapticFeedbackConstants.CONFIRM
                    : HapticFeedbackConstants.VIRTUAL_KEY;
            v.performHapticFeedback(code);
        }
    }

    public static void hapticReject(View v) {
        if (v != null) {
            int code = Build.VERSION.SDK_INT >= 30
                    ? HapticFeedbackConstants.REJECT
                    : HapticFeedbackConstants.LONG_PRESS;
            v.performHapticFeedback(code);
        }
    }

    public static void attachPressScale(final View target) {
        target.setOnTouchListener(new View.OnTouchListener() {
            @Override
            public boolean onTouch(View v, MotionEvent event) {
                int action = event.getActionMasked();
                if (action == MotionEvent.ACTION_DOWN) {
                    v.animate().cancel();
                    v.animate()
                            .scaleX(0.95f)
                            .scaleY(0.95f)
                            .setDuration(65L)
                            .setInterpolator(DECEL)
                            .start();
                } else if (action == MotionEvent.ACTION_UP || action == MotionEvent.ACTION_CANCEL) {
                    v.animate().cancel();
                    v.animate()
                            .scaleX(1.0f)
                            .scaleY(1.0f)
                            .setDuration(160L)
                            .setInterpolator(OVERSHOOT)
                            .start();
                }
                return false;
            }
        });
    }

    public static void animateEntrance(View view, int index, float travelPx) {
        view.setAlpha(0f);
        view.setTranslationY(travelPx);
        view.animate()
                .alpha(1f)
                .translationY(0f)
                .setStartDelay(Math.min(index, 10) * 28L)
                .setDuration(260L)
                .setInterpolator(DECEL)
                .start();
    }

    public static void animateFabToggle(View fab, boolean open) {
        fab.animate().cancel();
        fab.animate()
                .rotation(open ? 45f : 0f)
                .scaleX(open ? 0.94f : 1.0f)
                .scaleY(open ? 0.94f : 1.0f)
                .setDuration(250L)
                .setInterpolator(OVERSHOOT)
                .start();
    }

    public static void animatePulse(View view) {
        ObjectAnimator sx = ObjectAnimator.ofFloat(view, View.SCALE_X, 1f, 0.96f, 1.02f, 1f);
        ObjectAnimator sy = ObjectAnimator.ofFloat(view, View.SCALE_Y, 1f, 0.96f, 1.02f, 1f);
        AnimatorSet set = new AnimatorSet();
        set.playTogether(sx, sy);
        set.setDuration(260L);
        set.setInterpolator(DECEL);
        set.start();
    }

    public static void spinOnce(View view) {
        view.animate().cancel();
        view.setRotation(0f);
        view.animate()
                .rotation(360f)
                .setDuration(420L)
                .setInterpolator(new LinearInterpolator())
                .setListener(new AnimatorListenerAdapter() {
                    @Override
                    public void onAnimationEnd(Animator animation) {
                        view.setRotation(0f);
                    }
                })
                .start();
    }
}
