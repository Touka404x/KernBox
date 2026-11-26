package com.sandbox.stealth;

import android.os.IBinder;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;

/**
 * Installs a dynamic Proxy around ServiceManager.sServiceManager in system_server
 * or com.android.phone so selected system services are wrapped on addService().
 * Internal system_server lookups receive the raw unwrapped delegate (preventing direct
 * ClassCastException such as RestrictionsManagerService casting to IUserManager), while
 * ActivityManagerService.addServiceToMap()/getCommonServicesLocked() and cross-process
 * clients receive the wrapped SandboxBinderWrapper.
 */
public final class SystemServerHook {
    private static final String TAG = "SandboxStealthHook";
    private static volatile boolean installed = false;

    private static final Set<String> SYSTEM_SERVER_SERVICES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "user", "device_policy", "crossprofileapps",
                    "location", "wifi", "connectivity", "bluetooth_manager",
                    "usb", "adb")));

    private static final Set<String> PHONE_SERVICES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("phone", "isub", "iphonesubinfo")));

    private SystemServerHook() {}

    private static void logInfo(String msg) {
        try {
            Log.i(TAG, msg);
        } catch (Throwable ignored) {
        }
    }

    private static void logWarn(String msg) {
        try {
            Log.w(TAG, msg);
        } catch (Throwable ignored) {
        }
    }

    public static Set<String> targetServicesForProcess(String targetProcess) {
        if ("system_server".equals(targetProcess)) {
            return SYSTEM_SERVER_SERVICES;
        }
        if ("com.android.phone".equals(targetProcess)) {
            return PHONE_SERVICES;
        }
        return Collections.emptySet();
    }

    public static boolean install(String configJson, String targetProcess) {
        if (installed) {
            return true;
        }
        try {
            StealthConfig cfg = StealthConfig.fromJson(configJson);
            if (!cfg.enabled) {
                logInfo("disabled in stealth config; skipping hook for " + targetProcess);
                return false;
            }
            Set<String> targets = targetServicesForProcess(targetProcess);
            if (targets.isEmpty()) {
                return false;
            }

            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getIsm = smClass.getDeclaredMethod("getIServiceManager");
            getIsm.setAccessible(true);
            Object realSm = getIsm.invoke(null);
            if (realSm == null) {
                logWarn("real IServiceManager is null");
                return false;
            }

            Field sSmField = smClass.getDeclaredField("sServiceManager");
            sSmField.setAccessible(true);

            Class<?> ismClass = Class.forName("android.os.IServiceManager");
            Object proxy = createProxy(realSm, ismClass, targets, cfg);
            sSmField.set(null, proxy);
            installed = true;
            logInfo("installed IServiceManager hook for " + targetProcess + " targets=" + targets);
            return true;
        } catch (Throwable t) {
            logWarn("install failed for " + targetProcess + ": " + t);
            return false;
        }
    }

    /** Hook factory interface so host JVM tests can swap in a pure-Java wrapper without Binder stubs. */
    public interface BinderWrapperFactory {
        boolean isWrappable(Object candidate);
        boolean isAlreadyWrapped(Object candidate);
        Object wrap(Object delegate, String serviceName, StealthConfig config);
    }

    private static final BinderWrapperFactory BINDER_FACTORY = new BinderWrapperFactory() {
        @Override
        public boolean isWrappable(Object candidate) {
            return candidate instanceof IBinder;
        }

        @Override
        public boolean isAlreadyWrapped(Object candidate) {
            return candidate instanceof SandboxBinderWrapper;
        }

        @Override
        public Object wrap(Object delegate, String serviceName, StealthConfig config) {
            return new SandboxBinderWrapper((IBinder) delegate, serviceName, config);
        }
    };

    static boolean isAppBindCaller(StackTraceElement[] frames) {
        if (frames == null) {
            return false;
        }
        int limit = Math.min(frames.length, 24);
        for (int i = 0; i < limit; i++) {
            StackTraceElement f = frames[i];
            if (f != null && "com.android.server.am.ActivityManagerService".equals(f.getClassName())) {
                String m = f.getMethodName();
                if ("addServiceToMap".equals(m) || "getCommonServicesLocked".equals(m)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Visible to host JVM unit tests to verify addService wrapping & caller-aware getService routing. */
    public static Object createProxy(
            final Object realSm,
            Class<?> ismInterface,
            final Set<String> targetServices,
            final StealthConfig config) {
        return createProxy(realSm, ismInterface, targetServices, config, BINDER_FACTORY);
    }

    public static Object createProxy(
            final Object realSm,
            Class<?> ismInterface,
            final Set<String> targetServices,
            final StealthConfig config,
            final BinderWrapperFactory factory) {
        return createProxy(realSm, ismInterface, targetServices, config, factory,
                () -> isAppBindCaller(Thread.currentThread().getStackTrace()));
    }

    public static Object createProxy(
            final Object realSm,
            Class<?> ismInterface,
            final Set<String> targetServices,
            final StealthConfig config,
            final BinderWrapperFactory factory,
            final BooleanSupplier exportWrappedPredicate) {
        final ConcurrentHashMap<String, Object> rawServices = new ConcurrentHashMap<>();
        InvocationHandler handler = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                String name = method.getName();
                if ("addService".equals(name) && args != null && args.length >= 2 && args[0] instanceof String) {
                    String svcName = (String) args[0];
                    Object svcBinder = args[1];
                    if (factory.isWrappable(svcBinder) && targetServices.contains(svcName) && !factory.isAlreadyWrapped(svcBinder)) {
                        rawServices.put(svcName, svcBinder);
                        args[1] = factory.wrap(svcBinder, svcName, config);
                        logInfo("wrapped service " + svcName);
                    }
                } else if (("getService".equals(name) || "checkService".equals(name) || "waitForService".equals(name))
                        && args != null && args.length >= 1 && args[0] instanceof String) {
                    String svcName = (String) args[0];
                    Object raw = rawServices.get(svcName);
                    if (raw != null) {
                        if (exportWrappedPredicate != null && exportWrappedPredicate.getAsBoolean()) {
                            logInfo("exporting wrapped service " + svcName + " to AMS commonServices");
                        } else {
                            return raw;
                        }
                    }
                } else if (("getService2".equals(name) || "checkService2".equals(name))
                        && args != null && args.length >= 1 && args[0] instanceof String) {
                    String svcName = (String) args[0];
                    Object raw = rawServices.get(svcName);
                    if (raw != null) {
                        Object res;
                        try {
                            res = method.invoke(realSm, args);
                        } catch (InvocationTargetException e) {
                            throw e.getTargetException() != null ? e.getTargetException() : e;
                        }
                        if (exportWrappedPredicate != null && exportWrappedPredicate.getAsBoolean()) {
                            logInfo("exporting wrapped service2 " + svcName + " to AMS commonServices");
                            return res;
                        }
                        if (res != null) {
                            replaceServiceWithMetadataBinder(res, raw);
                        }
                        return res;
                    }
                }
                try {
                    return method.invoke(realSm, args);
                } catch (InvocationTargetException e) {
                    throw e.getTargetException() != null ? e.getTargetException() : e;
                }
            }
        };
        return Proxy.newProxyInstance(ismInterface.getClassLoader(), new Class<?>[]{ismInterface}, handler);
    }

    /**
     * Android 15/16 ServiceManager.rawGetService() queries IServiceManager.getService2()/checkService2(),
     * returning a ServiceWithMetadata/Service carrier whose binder field must be unwrapped for internal callers.
     */
    private static void replaceServiceWithMetadataBinder(Object holder, Object rawBinder) {
        if (holder == null || rawBinder == null) {
            return;
        }
        try {
            Field svcField = findField(holder.getClass(), "service");
            if (svcField == null) {
                svcField = findField(holder.getClass(), "binder");
            }
            if (svcField == null) {
                return;
            }
            svcField.setAccessible(true);
            Object current = svcField.get(holder);
            if (svcField.getType().isInstance(rawBinder)) {
                svcField.set(holder, rawBinder);
                return;
            }
            if (current != null && current != holder) {
                Field nested = findField(current.getClass(), "binder");
                if (nested == null) {
                    nested = findField(current.getClass(), "service");
                }
                if (nested != null && nested.getType().isInstance(rawBinder)) {
                    nested.setAccessible(true);
                    nested.set(current, rawBinder);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static Field findField(Class<?> cls, String name) {
        for (Class<?> c = cls; c != null && c != Object.class; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
        }
        return null;
    }
}
