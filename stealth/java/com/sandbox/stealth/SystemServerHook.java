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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
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
    private static final AtomicBoolean settingsWrapped = new AtomicBoolean(false);
    private static final AtomicBoolean settingsRetryStarted = new AtomicBoolean(false);
    private static volatile Object activityServiceRef = null;

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
                    if ("activity".equals(svcName) && svcBinder != null) {
                        activityServiceRef = svcBinder;
                        if (config.hideAdb && !tryWrapSettingsProvider(svcBinder, config)) {
                            startSettingsRetryThread(config);
                        }
                    } else if (config.hideAdb && !settingsWrapped.get() && activityServiceRef != null
                            && ("device_policy".equals(svcName) || "usb".equals(svcName) || "adb".equals(svcName))) {
                        tryWrapSettingsProvider(activityServiceRef, config);
                    }
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

    public interface SettingsProviderWrapperFactory {
        Class<?> providerInterface(Object provider) throws ClassNotFoundException;
        Object asBinder(Object provider);
        Object wrapBinder(Object delegateBinder, StealthConfig config);
    }

    private static final SettingsProviderWrapperFactory SETTINGS_FACTORY = new SettingsProviderWrapperFactory() {
        @Override
        public Class<?> providerInterface(Object provider) throws ClassNotFoundException {
            Class<?> icp = Class.forName("android.content.IContentProvider");
            if (icp.isInstance(provider)) {
                return icp;
            }
            for (Class<?> iface : provider.getClass().getInterfaces()) {
                if ("android.content.IContentProvider".equals(iface.getName())) {
                    return iface;
                }
            }
            return icp;
        }

        @Override
        public Object asBinder(Object provider) {
            return provider instanceof android.os.IInterface
                    ? ((android.os.IInterface) provider).asBinder()
                    : null;
        }

        @Override
        public Object wrapBinder(Object delegateBinder, StealthConfig config) {
            return delegateBinder instanceof IBinder
                    ? new SandboxSettingsBinder((IBinder) delegateBinder, config)
                    : delegateBinder;
        }
    };

    private static final class SettingsProviderHandler implements InvocationHandler {
        private final Object realProvider;
        private final Object wrappedBinder;

        SettingsProviderHandler(Object realProvider, Object wrappedBinder) {
            this.realProvider = realProvider;
            this.wrappedBinder = wrappedBinder;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String mname = method.getName();
            if ("asBinder".equals(mname) && (args == null || args.length == 0)) {
                return wrappedBinder;
            }
            if (Object.class.equals(method.getDeclaringClass())) {
                if ("equals".equals(mname) && args != null && args.length == 1) {
                    return proxy == args[0];
                }
                if ("hashCode".equals(mname)) {
                    return System.identityHashCode(proxy);
                }
                if ("toString".equals(mname)) {
                    return "SandboxSettingsProviderProxy(" + realProvider + ")";
                }
            }
            try {
                return method.invoke(realProvider, args);
            } catch (InvocationTargetException e) {
                throw e.getTargetException() != null ? e.getTargetException() : e;
            }
        }
    }

    public static boolean tryWrapSettingsProvider(Object ams, StealthConfig config) {
        return tryWrapSettingsProvider(ams, config, SETTINGS_FACTORY);
    }

    static boolean tryWrapSettingsProvider(
            Object ams, StealthConfig config, SettingsProviderWrapperFactory factory) {
        if (ams == null || config == null || !config.enabled || !config.hideAdb || factory == null) {
            return false;
        }
        if (settingsWrapped.get()) {
            return true;
        }
        try {
            Field providerMapField = findField(ams.getClass(), "mProviderMap");
            if (providerMapField == null) {
                return false;
            }
            providerMapField.setAccessible(true);
            Object providerMap = providerMapField.get(ams);
            if (providerMap == null) {
                return false;
            }
            Field singletonField = findField(providerMap.getClass(), "mSingletonByName");
            if (singletonField == null) {
                return false;
            }
            singletonField.setAccessible(true);
            Object rawMap = singletonField.get(providerMap);
            if (!(rawMap instanceof Map<?, ?>)) {
                return false;
            }
            Object cpr = ((Map<?, ?>) rawMap).get("settings");
            if (cpr == null) {
                return false;
            }
            Field providerField = findField(cpr.getClass(), "provider");
            if (providerField == null) {
                return false;
            }
            providerField.setAccessible(true);
            Object realProvider = providerField.get(cpr);
            if (realProvider == null) {
                return false;
            }
            if (Proxy.isProxyClass(realProvider.getClass())
                    && Proxy.getInvocationHandler(realProvider) instanceof SettingsProviderHandler) {
                settingsWrapped.set(true);
                return true;
            }
            Object realBinder = factory.asBinder(realProvider);
            if (realBinder == null) {
                return false;
            }
            Class<?> iface = factory.providerInterface(realProvider);
            if (iface == null) {
                return false;
            }
            Object wrappedBinder = factory.wrapBinder(realBinder, config);
            Object proxy = Proxy.newProxyInstance(
                    iface.getClassLoader(),
                    new Class<?>[]{iface},
                    new SettingsProviderHandler(realProvider, wrappedBinder));
            providerField.set(cpr, proxy);
            settingsWrapped.set(true);
            logInfo("wrapped settings ContentProvider for sandbox user " + config.sandboxUserId);
            return true;
        } catch (Throwable t) {
            logWarn("tryWrapSettingsProvider failed: " + t);
            return false;
        }
    }

    private static void startSettingsRetryThread(final StealthConfig config) {
        if (!config.hideAdb || settingsWrapped.get() || !settingsRetryStarted.compareAndSet(false, true)) {
            return;
        }
        Thread t = new Thread(() -> {
            for (int attempt = 0; attempt < 40 && !settingsWrapped.get(); attempt++) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ignored) {
                    return;
                }
                Object ams = activityServiceRef;
                if (ams != null && tryWrapSettingsProvider(ams, config)) {
                    return;
                }
            }
        }, "SandboxSettingsWrap");
        t.setDaemon(true);
        t.start();
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
