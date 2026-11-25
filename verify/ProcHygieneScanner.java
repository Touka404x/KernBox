package com.sandbox.verify;

import android.os.Process;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Pure-Java /proc and filesystem hygiene scanner (zero JNI/NDK). */
final class ProcHygieneScanner {
    private static final int MAX_SAMPLES = 10;
    private static final int MAX_LINE_LEN = 180;

    private static final String[] MOUNT_TOKENS = {
        "/data/adb", "overlay", "ksu", "kernelsu", "apatch", "susfs", "shamiko", "debug_ramdisk",
        "magisk", "zygisk", "riru", "lsposed", "lspd"
    };

    private static final String[] MAPS_TOKENS = {
        "zygisk", "lspd", "lsposed", "frida", "xposed", "riru", "edxposed", "kernelsu", "apatch",
        "susfs", "shamiko", "debug_ramdisk", "/data/adb"
    };

    private static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/vendor/bin/su",
        "/data/adb/ksu/bin/su", "/data/adb/ap/bin/su", "/debug_ramdisk/su"
    };

    private static final String[] BOOT_PROPS = {
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "ro.debuggable",
        "ro.secure"
    };

    private static final String[] STEALTH_PROPS = {
        "persist.sys.timezone",
        "persist.sys.locale",
        "gsm.sim.operator.numeric",
        "gsm.sim.state"
    };

    private static final String[] STOCK_OVERLAY_PREFIXES = {
        "/mnt/vendor/mi_ext/", "/my_product/", "/my_region/", "/vendor_dlkm/",
        "/product/", "product/", "/system/", "/system_ext/", "/vendor/", "/odm/"
    };

    private ProcHygieneScanner() {}

    static JSONObject scan() {
        JSONObject out = new JSONObject();
        try {
            int uid = Process.myUid();
            out.put("uid", uid);
            out.put("app_id", uid % 100000);
            out.put("user_id", uid / 100000);
            out.put("pid", Process.myPid());
            out.put("mountinfo", scanMountinfo());
            out.put("maps", scanMaps());
            out.put("su_paths", scanSuPaths());
            out.put("selinux_current", readSmallFile("/proc/self/attr/current"));
            out.put("boot_props", readPropsList(BOOT_PROPS));
            out.put("stealth_props", readPropsList(STEALTH_PROPS));
        } catch (Exception e) {
            try {
                out.put("error", e.getClass().getSimpleName() + ":" + safeMsg(e));
            } catch (Exception ignored) {}
        }
        return out;
    }

    private static boolean isStockVendorOverlay(String line) {
        if (!line.contains(" - overlay overlay ")) {
            return false;
        }
        String lower = line.toLowerCase(Locale.ROOT);
        if (lower.contains("upperdir=") || lower.contains("workdir=")
                || lower.contains("/data/") || lower.contains("adb")
                || lower.contains("ksu") || lower.contains("magisk")
                || lower.contains("zygisk") || lower.contains("riru")
                || lower.contains("lsposed") || lower.contains("lspd")
                || lower.contains("apatch")) {
            return false;
        }
        int idx = line.indexOf("lowerdir=");
        if (idx < 0) {
            return false;
        }
        String rest = line.substring(idx + "lowerdir=".length()).trim();
        int sp = rest.indexOf(' ');
        if (sp >= 0) {
            rest = rest.substring(0, sp);
        }
        int comma = rest.indexOf(',');
        if (comma >= 0) {
            rest = rest.substring(0, comma);
        }
        String[] dirs = rest.split(":");
        if (dirs.length == 0) {
            return false;
        }
        for (String dir : dirs) {
            if (dir.isEmpty()) {
                return false;
            }
            boolean ok = false;
            for (String prefix : STOCK_OVERLAY_PREFIXES) {
                if (dir.startsWith(prefix)) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean isStockArtJitMemfd(String path, String perms) {
        if ("rwxp".equals(perms)) {
            return false;
        }
        return path.startsWith("/memfd:jit-cache") || path.startsWith("/memfd:jit-zygote-cache");
    }

    private static JSONObject scanMountinfo() {
        JSONObject obj = new JSONObject();
        JSONArray samples = new JSONArray();
        int total = 0;
        int suspicious = 0;
        int stockOverlays = 0;
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new FileInputStream("/proc/self/mountinfo"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                total++;
                String lower = line.toLowerCase(Locale.ROOT);
                for (String token : MOUNT_TOKENS) {
                    if (lower.contains(token)) {
                        if ("overlay".equals(token) && isStockVendorOverlay(line)) {
                            stockOverlays++;
                            continue;
                        }
                        suspicious++;
                        if (samples.length() < MAX_SAMPLES) {
                            samples.put(truncate(line));
                        }
                        break;
                    }
                }
            }
            obj.put("readable", true);
            obj.put("total_lines", total);
            obj.put("stock_vendor_overlay_count", stockOverlays);
            obj.put("suspicious_count", suspicious);
            obj.put("suspicious_samples", samples);
        } catch (Throwable t) {
            try {
                obj.put("readable", false);
                obj.put("error", t.getClass().getSimpleName() + ":" + safeMsg(t));
            } catch (Exception ignored) {}
        }
        return obj;
    }

    private static JSONObject scanMaps() {
        JSONObject obj = new JSONObject();
        JSONArray tokenSamples = new JSONArray();
        JSONArray rwxpSamples = new JSONArray();
        JSONArray memfdSamples = new JSONArray();
        int total = 0;
        int anonRwxp = 0;
        int memfdCount = 0;
        int jitMemfdCount = 0;
        int tokenHits = 0;
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new FileInputStream("/proc/self/maps"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                total++;
                String lower = line.toLowerCase(Locale.ROOT);
                String[] parts = line.trim().split("\\s+", 6);
                String perms = parts.length >= 2 ? parts[1] : "";
                String path = parts.length >= 6 ? parts[5].trim() : "";

                if ("rwxp".equals(perms)) {
                    boolean isAnon = path.isEmpty() || path.startsWith("[anon") || path.startsWith("/memfd:");
                    if (isAnon) {
                        anonRwxp++;
                        if (rwxpSamples.length() < MAX_SAMPLES) {
                            rwxpSamples.put(truncate(line));
                        }
                    }
                }
                if (path.contains("/memfd:") || lower.contains("memfd:")) {
                    if (isStockArtJitMemfd(path, perms)) {
                        jitMemfdCount++;
                    } else {
                        memfdCount++;
                        if (memfdSamples.length() < MAX_SAMPLES) {
                            memfdSamples.put(truncate(line));
                        }
                    }
                }
                for (String token : MAPS_TOKENS) {
                    if (lower.contains(token)) {
                        tokenHits++;
                        if (tokenSamples.length() < MAX_SAMPLES) {
                            tokenSamples.put(truncate(line));
                        }
                        break;
                    }
                }
            }
            obj.put("readable", true);
            obj.put("total_lines", total);
            obj.put("anon_rwxp_count", anonRwxp);
            obj.put("anon_rwxp_samples", rwxpSamples);
            obj.put("jit_memfd_count", jitMemfdCount);
            obj.put("memfd_count", memfdCount);
            obj.put("memfd_samples", memfdSamples);
            obj.put("suspicious_count", tokenHits);
            obj.put("suspicious_samples", tokenSamples);
        } catch (Throwable t) {
            try {
                obj.put("readable", false);
                obj.put("error", t.getClass().getSimpleName() + ":" + safeMsg(t));
            } catch (Exception ignored) {}
        }
        return obj;
    }

    private static JSONObject scanSuPaths() {
        JSONObject obj = new JSONObject();
        JSONArray found = new JSONArray();
        for (String path : SU_PATHS) {
            try {
                boolean exists = new File(path).exists();
                obj.put(path, exists);
                if (exists) {
                    found.put(path);
                }
            } catch (Throwable t) {
                try {
                    obj.put(path, "error:" + t.getClass().getSimpleName());
                } catch (Exception ignored) {}
            }
        }
        try {
            obj.put("any_visible", found.length() > 0);
            obj.put("visible_paths", found);
        } catch (Exception ignored) {}
        return obj;
    }

    private static String readSmallFile(String path) {
        try (FileInputStream fis = new FileInputStream(path)) {
            byte[] buf = new byte[256];
            int n = fis.read(buf);
            if (n <= 0) {
                return "";
            }
            String s = new String(buf, 0, n, StandardCharsets.UTF_8);
            int nul = s.indexOf('\0');
            if (nul >= 0) {
                s = s.substring(0, nul);
            }
            return s.trim();
        } catch (Throwable t) {
            return "error:" + t.getClass().getSimpleName();
        }
    }

    private static JSONObject readPropsList(String[] keys) {
        JSONObject props = new JSONObject();
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class, String.class);
            for (String key : keys) {
                try {
                    Object val = get.invoke(null, key, "");
                    props.put(key, val != null ? val.toString() : "");
                } catch (Throwable inner) {
                    props.put(key, "error:" + inner.getClass().getSimpleName());
                }
            }
        } catch (Throwable t) {
            try {
                props.put("error", t.getClass().getSimpleName() + ":" + safeMsg(t));
            } catch (Exception ignored) {}
        }
        return props;
    }

    private static String truncate(String s) {
        if (s.length() <= MAX_LINE_LEN) {
            return s;
        }
        return s.substring(0, MAX_LINE_LEN) + "...";
    }

    private static String safeMsg(Throwable t) {
        String m = t.getMessage();
        return m == null ? "" : truncate(m);
    }
}
