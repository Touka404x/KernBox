package com.sandbox.controller;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import java.security.MessageDigest;

/**
 * Computes this controller APK's lowercase SHA-256 signing certificate digest
 * so users can bind caller_cert_sha256 in /data/adb/sandbox_guard/policy.json.
 */
public final class CertUtil {

    private CertUtil() {}

    public static String getSigningCertSha256(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();
            Signature[] sigs = extractSignatures(pm, pkg);
            if (sigs == null || sigs.length == 0 || sigs[0] == null) {
                return "";
            }
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sigs[0].toByteArray());
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    @SuppressWarnings("deprecation")
    private static Signature[] extractSignatures(PackageManager pm, String pkg) throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT >= 28) {
            PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
            SigningInfo si = info.signingInfo;
            if (si == null) {
                return null;
            }
            return si.getApkContentsSigners();
        }
        PackageInfo legacy = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
        return legacy.signatures;
    }

    public static String shortDigest(String hex) {
        if (hex == null || hex.length() < 16) {
            return hex == null ? "" : hex;
        }
        return hex.substring(0, 8) + "…" + hex.substring(hex.length() - 8);
    }
}
