package com.sandbox.stealth;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;

/**
 * Host JDK 21 test harness covering StealthConfig, dynamic AIDL transaction maps,
 * BinderInterceptionPolicy decisions across all 10 system services, and SystemServerHook proxy.
 */
public final class StealthHookHostTest {
    public interface FakeIServiceManager {
        void addService(String name, Object service, boolean allowIsolated, int dumpPriority);
        Object getService(String name);
        Object checkService(String name);
        Object getService2(String name);
        Object checkService2(String name);
    }

    public static final class FakeServiceWithMetadata {
        public Object service;
        public FakeServiceWithMetadata(Object service) {
            this.service = service;
        }
    }

    public static final class FakeNestedService {
        public Object binder;
        public FakeNestedService(Object binder) {
            this.binder = binder;
        }
    }

    public static final class FakeNestedServiceWithMetadata {
        public FakeNestedService service;
        public FakeNestedServiceWithMetadata(Object binder) {
            this.service = new FakeNestedService(binder);
        }
    }

    public static class MockStubBase {
        public static final int TRANSACTION_getProfileType = 17;
        public static final int TRANSACTION_isUserOfType = 19;
        public static final int TRANSACTION_getProfileIds = 41;
        public static final int TRANSACTION_getProfileParent = 55;
        public static final int TRANSACTION_getProfileParentId = 56;
        public static final int TRANSACTION_isManagedProfile = 99;
    }

    public static final class ShiftedVendorUserManagerService extends MockStubBase {
        public static final int TRANSACTION_isProfile = 105;
        public static final int TRANSACTION_isPrivateProfile = 108;
        public static final int TRANSACTION_unrelated = 200;
    }

    public static final class FakeWrapper {
        public final Object delegate;
        public final String serviceName;
        public FakeWrapper(Object delegate, String serviceName) {
            this.delegate = delegate;
            this.serviceName = serviceName;
        }
    }

    private static void check(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError("ASSERT FAILED: " + msg);
        }
    }

    private static StealthConfig japanSampleConfig() {
        return StealthConfig.fromJson("{\n"
                + "  \"enabled\": true,\n"
                + "  \"sandbox_user_id\": 10,\n"
                + "  \"exempt_work_uid\": 1010376,\n"
                + "  \"exempt_uids\": [1010076, 1010376],\n"
                + "  \"timezone\": \"Asia/Tokyo\",\n"
                + "  \"locale\": \"ja-JP\",\n"
                + "  \"sim_operator\": \"44010\",\n"
                + "  \"sim_operator_name\": \"NTT DOCOMO\",\n"
                + "  \"sim_country_iso\": \"jp\",\n"
                + "  \"spoof_location_mode\": \"block\",\n"
                + "  \"hide_managed_profile\": true,\n"
                + "  \"block_wifi_scan\": true,\n"
                + "  \"spoof_carrier\": true,\n"
                + "  \"spoof_device_region\": true,\n"
                + "  \"device_name\": \"Pixel 9\",\n"
                + "  \"device_region\": \"JP\",\n"
                + "  \"boot_hwc\": \"JP\"\n"
                + "}");
    }

    private static void testStealthConfig() {
        StealthConfig empty = StealthConfig.fromJson("");
        check(!empty.enabled, "empty json must disable");
        check("UTC".equals(empty.timezone), "neutral default timezone=UTC");
        check("en-US".equals(empty.locale), "neutral default locale=en-US");
        check(!empty.spoofCarrier, "neutral default spoofCarrier=false");
        check(!empty.spoofDeviceRegion, "neutral default spoofDeviceRegion=false");
        check("Android".equals(empty.deviceName), "neutral default deviceName=Android");
        check("".equals(empty.deviceRegion), "neutral default deviceRegion empty");
        check(!empty.shouldIntercept(1010377), "disabled config must not intercept");

        StealthConfig cfg = japanSampleConfig();
        check(cfg.enabled, "enabled=true");
        check(cfg.sandboxUserId == 10, "sandboxUserId=10");
        check(cfg.exemptWorkUid == 1010376, "exemptWorkUid=1010376");
        check(cfg.exemptUids.length == 2, "deduped exemptUids len=2");
        check("44010".equals(cfg.networkOperator), "networkOperator fallback to sim_operator");
        check("jp".equals(cfg.networkCountryIso), "networkCountryIso fallback");

        // UID scoping tests
        check(!cfg.shouldIntercept(10377), "User 0 must NEVER be intercepted");
        check(!cfg.shouldIntercept(1000), "SYSTEM_UID 1000 must pass through");
        check(!cfg.shouldIntercept(1001), "PHONE_UID 1001 must pass through");
        check(!cfg.shouldIntercept(1001000), "User 10 system UID must pass through");
        check(!cfg.shouldIntercept(1010376), "exempt sandbox controller UID must pass through");
        check(!cfg.shouldIntercept(1010076), "exempt com.android.managedprovisioning UID must pass through");
        check(cfg.shouldIntercept(1099211), "User 10 isolated process UID must intercept");
        check(!cfg.shouldIntercept(99910123), "Dual-clone user 999 must pass through");
        check(cfg.shouldIntercept(1010377), "User 10 app UID 1010377 must intercept");
        check(cfg.shouldIntercept(1010122), "User 10 GMS UID 1010122 must intercept");
        check(cfg.sanitizeNetwork && cfg.spoofBluetooth, "anti-linkage flags default true");
        check("10.172.10.2".equals(cfg.sandboxLinkIpv4), "default sandboxLinkIpv4=10.172.10.2");
        check("Pixel 9".equals(cfg.deviceName), "parsed deviceName=Pixel 9");
        check(cfg.spoofDeviceRegion, "parsed spoofDeviceRegion=true");
        check("JP".equals(cfg.deviceRegion), "parsed deviceRegion=JP");
        check("JP".equals(cfg.bootHwc), "parsed bootHwc=JP");

        StealthConfig customCfg = StealthConfig.fromJson(
                "{\"enabled\":true,\"sanitize_network\":false,\"spoof_bluetooth\":false,"
                        + "\"spoof_device_region\":false,\"miui_region\":\"US\",\"boot_hwc\":\"Global\","
                        + "\"sandbox_link_ipv4\":\"10.172.99.2\",\"device_name\":\"ModelX\"}");
        check(!customCfg.sanitizeNetwork && !customCfg.spoofBluetooth, "custom anti-linkage false honored");
        check(!customCfg.spoofDeviceRegion && "US".equals(customCfg.deviceRegion) && "Global".equals(customCfg.bootHwc),
                "legacy miui_region alias parsed");
        check("10.172.99.2".equals(customCfg.sandboxLinkIpv4), "custom sandboxLinkIpv4 parsed");
        check("ModelX".equals(customCfg.deviceName), "custom deviceName parsed");
    }

    private static void testTransactionReflection() {
        Map<Integer, String> m = BinderInterceptionPolicy.buildTransactionMap(
                ShiftedVendorUserManagerService.class, null);
        check("getProfileType".equals(m.get(17)), "tx 17 -> getProfileType");
        check("isUserOfType".equals(m.get(19)), "tx 19 -> isUserOfType");
        check("getProfileIds".equals(m.get(41)), "tx 41 -> getProfileIds");
        check("isProfile".equals(m.get(105)), "tx 105 -> isProfile");
        check("isPrivateProfile".equals(m.get(108)), "tx 108 -> isPrivateProfile");
        check("isManagedProfile".equals(m.get(99)), "tx 99 -> isManagedProfile");
    }

    private static void testBinderInterceptionDecisions() {
        StealthConfig cfg = japanSampleConfig();
        int u10 = 1010377;
        int u0 = 10377;

        // User 0 always passthrough
        check(BinderInterceptionPolicy.decide("user", "getProfileType", cfg, u0, null).action
                == BinderInterceptionPolicy.Action.PASSTHROUGH, "u0 passthrough");

        // User service in User 10
        BinderInterceptionPolicy.Decision d = BinderInterceptionPolicy.decide("user", "getProfileType", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "".equals(d.stringValue), "getProfileType empty");

        d = BinderInterceptionPolicy.decide("user", "isUserOfType", cfg, u10, "android.os.usertype.profile.MANAGED");
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !d.boolValue, "isUserOfType managed false");

        d = BinderInterceptionPolicy.decide("user", "isUserOfType", cfg, u10, "android.os.usertype.full.SYSTEM");
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && d.boolValue, "isUserOfType full system true");

        d = BinderInterceptionPolicy.decide("user", "isPrivateProfile", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !d.boolValue, "isPrivateProfile false");

        d = BinderInterceptionPolicy.decide("user", "getProfileIds", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_INT_ARRAY
                && Arrays.equals(d.intArrayValue, new int[]{10}), "getProfileIds [10]");

        d = BinderInterceptionPolicy.decide("user", "getProfileParent", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_NULL_PARCELABLE, "getProfileParent null");

        d = BinderInterceptionPolicy.decide("user", "isSameProfileGroup", cfg, u10, null, 10, 10);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && d.boolValue, "isSameProfileGroup(10,10) true");

        d = BinderInterceptionPolicy.decide("user", "isSameProfileGroup", cfg, u10, null, 10, 0);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !d.boolValue, "isSameProfileGroup(10,0) false");
        d = BinderInterceptionPolicy.decide("user", "getCredentialOwnerProfile", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_INT && d.intValue == 10, "getCredentialOwnerProfile 10");
        d = BinderInterceptionPolicy.decide("user", "isDemoUser", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !d.boolValue, "isDemoUser false");
        d = BinderInterceptionPolicy.decide("user", "isRestricted", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !d.boolValue, "isRestricted false");

        // DevicePolicyManager
        check(BinderInterceptionPolicy.decide("device_policy", "getProfileOwnerAsUser", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_NULL_PARCELABLE, "dpm getProfileOwnerAsUser null");
        check(BinderInterceptionPolicy.decide("device_policy", "getDeviceOwnerComponent", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_NULL_PARCELABLE, "dpm getDeviceOwnerComponent null");
        check(BinderInterceptionPolicy.decide("device_policy", "getDeviceOwnerComponentOnAnyUser", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_NULL_PARCELABLE, "dpm getDeviceOwnerComponentOnAnyUser null");
        d = BinderInterceptionPolicy.decide("device_policy", "getDeviceOwnerName", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && d.stringValue == null, "dpm getDeviceOwnerName null");
        d = BinderInterceptionPolicy.decide("device_policy", "getDeviceOwnerNameOnAnyUser", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && d.stringValue == null, "dpm getDeviceOwnerNameOnAnyUser null");
        check(BinderInterceptionPolicy.decide("device_policy", "getActiveAdmins", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_EMPTY_TYPED_LIST, "dpm getActiveAdmins empty");
        d = BinderInterceptionPolicy.decide("device_policy", "isOrganizationOwnedDeviceWithManagedProfile", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !d.boolValue, "dpm org owned false");
        d = BinderInterceptionPolicy.decide("device_policy", "hasDeviceOwner", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !d.boolValue, "dpm hasDeviceOwner false");
        d = BinderInterceptionPolicy.decide("device_policy", "isDeviceManaged", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !d.boolValue, "dpm isDeviceManaged false");

        // CrossProfileApps
        check(BinderInterceptionPolicy.decide("crossprofileapps", "getTargetUserProfiles", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_EMPTY_TYPED_LIST, "crossprofileapps empty");

        // Location & WiFi
        d = BinderInterceptionPolicy.decide("location", "isLocationEnabledForUser", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !d.boolValue, "location disabled");
        d = BinderInterceptionPolicy.decide("location", "getAllProviders", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING_LIST
                && d.stringListValue != null
                && d.stringListValue.size() == 4
                && d.stringListValue.contains("gps")
                && d.stringListValue.contains("fused"),
                "location getAllProviders standard provider list");
        check(BinderInterceptionPolicy.decide("location", "getProviders", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_EMPTY_STRING_LIST, "location enabled providers empty");
        check(BinderInterceptionPolicy.decide("wifi", "getScanResults", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_EMPTY_TYPED_LIST, "wifi scan results empty");
        check(BinderInterceptionPolicy.decide("wifi", "getConnectionInfo", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_REDACTED_WIFI_INFO, "wifi connection info redacted");

        // Connectivity & Bluetooth anti-linkage
        check(BinderInterceptionPolicy.decide("connectivity", "getActiveLinkProperties", cfg, u0, null).action
                == BinderInterceptionPolicy.Action.PASSTHROUGH, "connectivity u0 passthrough");
        check(BinderInterceptionPolicy.decide("connectivity", "getActiveLinkProperties", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.SANITIZE_LINK_PROPERTIES, "connectivity active LP sanitized");
        check(BinderInterceptionPolicy.decide("connectivity", "getNetworkCapabilities", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.SANITIZE_NETWORK_CAPABILITIES, "connectivity getNetworkCapabilities sanitized");
        check(BinderInterceptionPolicy.decide("connectivity", "getAllNetworks", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.PASSTHROUGH, "connectivity getAllNetworks passthrough");

        check(BinderInterceptionPolicy.decide("bluetooth_manager", "getName", cfg, u0, null).action
                == BinderInterceptionPolicy.Action.PASSTHROUGH, "bt u0 passthrough");
        d = BinderInterceptionPolicy.decide("bluetooth_manager", "getName", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "Pixel 9".equals(d.stringValue),
                "bt getName spoofed");
        d = BinderInterceptionPolicy.decide("bluetooth_manager", "getAddress", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "02:00:00:00:00:00".equals(d.stringValue),
                "bt getAddress locally-administered");
        check(BinderInterceptionPolicy.decide("bluetooth_manager", "getBondedDevices", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_EMPTY_TYPED_LIST, "bt bonded devices empty");

        // Phone, SubscriptionManager (isub), and carrier ID lookup
        check(BinderInterceptionPolicy.decide("phone", "getAllCellInfo", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_EMPTY_TYPED_LIST, "phone cell info empty");
        check(BinderInterceptionPolicy.decide("phone", "getCellLocation", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.WRITE_NULL_PARCELABLE, "phone cell location null");
        d = BinderInterceptionPolicy.decide("phone", "getNetworkCountryIsoForPhone", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "jp".equals(d.stringValue), "phone country jp");
        d = BinderInterceptionPolicy.decide("phone", "getSimState", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_INT && d.intValue == 5, "phone getSimState ready");
        d = BinderInterceptionPolicy.decide("phone", "getSimOperator", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "44010".equals(d.stringValue), "phone getSimOperator 44010");
        d = BinderInterceptionPolicy.decide("phone", "getNetworkOperator", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "44010".equals(d.stringValue), "phone getNetworkOperator 44010");
        d = BinderInterceptionPolicy.decide("phone", "getSimCountryIso", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "jp".equals(d.stringValue), "phone getSimCountryIso jp");
        d = BinderInterceptionPolicy.decide("phone", "getNetworkCountryIso", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "jp".equals(d.stringValue), "phone getNetworkCountryIso jp");
        d = BinderInterceptionPolicy.decide("phone", "getSimOperatorName", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "NTT DOCOMO".equals(d.stringValue), "phone getSimOperatorName");
        d = BinderInterceptionPolicy.decide("phone", "getNetworkOperatorName", cfg, u10, null);
        check(d.action == BinderInterceptionPolicy.Action.WRITE_STRING && "NTT DOCOMO".equals(d.stringValue), "phone getNetworkOperatorName");

        check(BinderInterceptionPolicy.carrierIdForOperator("44010") == 850, "carrierId JP NTT DOCOMO");
        check(BinderInterceptionPolicy.carrierIdForOperator("310260") == 1, "carrierId US T-Mobile");
        check(BinderInterceptionPolicy.carrierIdForOperator("23430") == 1839, "carrierId UK EE");
        check(BinderInterceptionPolicy.carrierIdForOperator("52501") == 1436, "carrierId SG Singtel");
        check(BinderInterceptionPolicy.carrierIdForOperator("26201") == 1159, "carrierId DE Telekom");
        check(BinderInterceptionPolicy.carrierIdForOperator("") == -1, "carrierId empty unknown");

        // Unknown methods fail open
        check(BinderInterceptionPolicy.decide("user", "getUserName", cfg, u10, null).action
                == BinderInterceptionPolicy.Action.PASSTHROUGH, "unrelated method passthrough");
    }

    private static void testSystemServerHookProxy() {
        final Map<String, Object> stored = new HashMap<>();
        FakeIServiceManager real = new FakeIServiceManager() {
            @Override
            public void addService(String name, Object service, boolean allowIsolated, int dumpPriority) {
                stored.put(name, service);
            }
            @Override
            public Object getService(String name) {
                return stored.get(name);
            }
            @Override
            public Object checkService(String name) {
                return stored.get(name);
            }
            @Override
            public Object getService2(String name) {
                Object v = stored.get(name);
                return v == null ? null : new FakeServiceWithMetadata(v);
            }
            @Override
            public Object checkService2(String name) {
                Object v = stored.get(name);
                return v == null ? null : new FakeNestedServiceWithMetadata(v);
            }
        };

        Set<String> targets = SystemServerHook.targetServicesForProcess("system_server");
        check(targets.contains("user") && targets.contains("device_policy")
                && targets.contains("crossprofileapps") && targets.contains("location")
                && targets.contains("wifi") && targets.contains("connectivity")
                && targets.contains("bluetooth_manager") && !targets.contains("phone"), "system_server target set");

        Set<String> phoneTargets = SystemServerHook.targetServicesForProcess("com.android.phone");
        check(phoneTargets.size() == 3 && phoneTargets.contains("phone")
                && phoneTargets.contains("isub") && phoneTargets.contains("iphonesubinfo"),
                "phone target set includes phone, isub, and iphonesubinfo");

        SystemServerHook.BinderWrapperFactory testFactory = new SystemServerHook.BinderWrapperFactory() {
            @Override public boolean isWrappable(Object c) { return c != null; }
            @Override public boolean isAlreadyWrapped(Object c) { return c instanceof FakeWrapper; }
            @Override public Object wrap(Object d, String s, StealthConfig c) { return new FakeWrapper(d, s); }
        };

        FakeIServiceManager proxy = (FakeIServiceManager) SystemServerHook.createProxy(
                real, FakeIServiceManager.class, new HashSet<>(targets), japanSampleConfig(), testFactory);

        Object rawUser = new Object();
        Object rawActivity = new Object();
        Object rawConn = new Object();
        Object rawBt = new Object();

        proxy.addService("user", rawUser, false, 0);
        proxy.addService("activity", rawActivity, false, 0);
        proxy.addService("connectivity", rawConn, false, 0);
        proxy.addService("bluetooth_manager", rawBt, false, 0);

        check(stored.get("user") instanceof FakeWrapper, "target service must be wrapped in real ServiceManager");
        check(((FakeWrapper) stored.get("user")).delegate == rawUser, "wrapper must delegate to rawUser");
        check(stored.get("activity") == rawActivity, "non-target service must stay unwrapped");
        check(stored.get("connectivity") instanceof FakeWrapper, "connectivity must be wrapped");
        check(stored.get("bluetooth_manager") instanceof FakeWrapper, "bluetooth_manager must be wrapped");

        check(proxy.getService("user") == rawUser, "default proxy getService must return rawUser");
        check(proxy.checkService("user") == rawUser, "default proxy checkService must return rawUser");
        check(proxy.getService("connectivity") == rawConn, "default proxy getService(connectivity) must return rawConn");
        FakeServiceWithMetadata meta2 = (FakeServiceWithMetadata) proxy.getService2("user");
        check(meta2 != null && meta2.service == rawUser, "default proxy getService2(user) must unwrap ServiceWithMetadata.service");
        FakeNestedServiceWithMetadata nestedMeta2 = (FakeNestedServiceWithMetadata) proxy.checkService2("connectivity");
        check(nestedMeta2 != null && nestedMeta2.service.binder == rawConn,
                "default proxy checkService2(connectivity) must unwrap nested service.binder");

        FakeIServiceManager exportProxy = (FakeIServiceManager) SystemServerHook.createProxy(
                real, FakeIServiceManager.class, new HashSet<>(targets), japanSampleConfig(), testFactory,
                () -> true);
        Object rawWifi = new Object();
        exportProxy.addService("user", rawUser, false, 0);
        exportProxy.addService("wifi", rawWifi, false, 0);
        exportProxy.addService("connectivity", rawConn, false, 0);
        exportProxy.addService("bluetooth_manager", rawBt, false, 0);
        check(exportProxy.getService("user") instanceof FakeWrapper, "export proxy getService(user) must return wrapped");
        check(((FakeServiceWithMetadata) exportProxy.getService2("user")).service instanceof FakeWrapper,
                "export proxy getService2(user) must keep wrapped binder");
        check(((FakeNestedServiceWithMetadata) exportProxy.checkService2("connectivity")).service.binder instanceof FakeWrapper,
                "export proxy checkService2(connectivity) must keep wrapped binder");
        check(exportProxy.getService("connectivity") instanceof FakeWrapper, "export proxy getService(connectivity) wrapped");
        check(exportProxy.getService("wifi") instanceof FakeWrapper, "export proxy getService(wifi) wrapped");
        check(exportProxy.getService("bluetooth_manager") instanceof FakeWrapper, "export proxy getService(bt) wrapped");

        check(SystemServerHook.isAppBindCaller(new StackTraceElement[]{
                new StackTraceElement("android.os.ServiceManager", "getService", "ServiceManager.java", 140),
                new StackTraceElement("com.android.server.am.ActivityManagerService", "addServiceToMap", "ActivityManagerService.java", 1),
        }), "addServiceToMap frame must match");
        check(!SystemServerHook.isAppBindCaller(new StackTraceElement[]{
                new StackTraceElement("com.android.server.restrictions.RestrictionsManagerService$RestrictionsManagerImpl", "<init>", "RestrictionsManagerService.java", 66),
        }), "RestrictionsManagerService frame must not export wrapped binder");
    }

    private static final class BenchSlot {
        final String methodName;
        final BinderInterceptionPolicy.Decision decision;
        BenchSlot(String methodName, BinderInterceptionPolicy.Decision decision) {
            this.methodName = methodName;
            this.decision = decision;
        }
    }

    private static void testStaticDecisionCacheAndBenchmark() {
        StealthConfig cfg = japanSampleConfig();
        check(BinderInterceptionPolicy.supportsStaticDecisionCache("user", "getProfileType"), "getProfileType cacheable");
        check(!BinderInterceptionPolicy.supportsStaticDecisionCache("user", "isUserOfType"), "isUserOfType not static-cacheable");
        check(!BinderInterceptionPolicy.supportsStaticDecisionCache("user", "isSameProfileGroup"), "isSameProfileGroup not static-cacheable");

        AtomicReferenceArray<BenchSlot> table = new AtomicReferenceArray<>(256);
        BinderInterceptionPolicy.Decision d17 = BinderInterceptionPolicy.decideForIntercepted("user", "getProfileType", cfg, null, -1, -2);
        table.set(17, new BenchSlot("getProfileType", d17));

        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch doneGate = new CountDownLatch(4);
        AtomicInteger anomalies = new AtomicInteger(0);
        for (int t = 0; t < 4; t++) {
            new Thread(() -> {
                try {
                    startGate.await();
                    for (int k = 0; k < 200; k++) {
                        int idx = 32 + (k % 64);
                        BenchSlot s = table.get(idx);
                        if (s == null) {
                            BenchSlot cand = new BenchSlot("getProfileIds", BinderInterceptionPolicy.decideForIntercepted("user", "getProfileIds", cfg, null, -1, -2));
                            table.compareAndSet(idx, null, cand);
                            s = table.get(idx);
                        }
                        if (s == null || s.methodName == null || s.decision == null) {
                            anomalies.incrementAndGet();
                        }
                    }
                } catch (Throwable ex) {
                    anomalies.incrementAndGet();
                } finally {
                    doneGate.countDown();
                }
            }).start();
        }
        startGate.countDown();
        try {
            doneGate.await();
        } catch (InterruptedException ex) {
            throw new AssertionError(ex);
        }
        check(anomalies.get() == 0, "concurrent AtomicReferenceArray publication must have 0 anomalies");
    }

    private static void testHardeningPolicies() {
        StealthConfig cfg = japanSampleConfig();
        int u10Isolated = 1099001;
        int u0Isolated = 99001;
        int u0App = 10100;
        int u10App = 1010395;

        check(cfg.shouldIntercept(u10Isolated), "u10 isolated UID must be intercepted");
        check(!cfg.shouldIntercept(u0Isolated), "u0 isolated UID must not be intercepted");

        check(BinderInterceptionPolicy.decide("bluetooth_manager", "registerAdapter", cfg, u10App, null).action
                == BinderInterceptionPolicy.Action.WRITE_NULL_STRONG_BINDER, "bluetooth_manager.registerAdapter -> null binder");
        BinderInterceptionPolicy.Decision dBtState = BinderInterceptionPolicy.decide("bluetooth_manager", "getState", cfg, u10Isolated, null);
        check(dBtState.action == BinderInterceptionPolicy.Action.WRITE_INT && dBtState.intValue == 10,
                "bluetooth_manager.getState -> STATE_OFF (10)");

        BinderInterceptionPolicy.Decision dWifiCc = BinderInterceptionPolicy.decide("wifi", "getCountryCode", cfg, u10App, null);
        check(dWifiCc.action == BinderInterceptionPolicy.Action.WRITE_STRING && "JP".equals(dWifiCc.stringValue),
                "wifi.getCountryCode -> JP");
        check(BinderInterceptionPolicy.decide("wifi", "getCountryCode", StealthConfig.defaults(), u10App, null).action
                == BinderInterceptionPolicy.Action.PASSTHROUGH, "wifi.getCountryCode neutral defaults passthrough");
        check(BinderInterceptionPolicy.decide("wifi", "getDhcpInfo", cfg, u10App, null).action
                == BinderInterceptionPolicy.Action.WRITE_NULL_PARCELABLE, "wifi.getDhcpInfo redacted");

        check(BinderInterceptionPolicy.decide("phone", "requestCellInfoUpdate", cfg, u10App, null).action
                == BinderInterceptionPolicy.Action.WRITE_VOID, "phone.requestCellInfoUpdate blocked");
        check(BinderInterceptionPolicy.decide("phone", "getCellLocationForSubscriber", cfg, u10App, null).action
                == BinderInterceptionPolicy.Action.WRITE_NULL_PARCELABLE, "phone.getCellLocationForSubscriber blocked");
        check(BinderInterceptionPolicy.decide("phone", "getNeighboringCellInfo", cfg, u10App, null).action
                == BinderInterceptionPolicy.Action.WRITE_EMPTY_TYPED_LIST, "phone.getNeighboringCellInfo empty");
        BinderInterceptionPolicy.Decision dCidName = BinderInterceptionPolicy.decide("phone", "getSimCarrierIdName", cfg, u10App, null);
        check(dCidName.action == BinderInterceptionPolicy.Action.WRITE_STRING && "NTT DOCOMO".equals(dCidName.stringValue),
                "phone.getSimCarrierIdName -> NTT DOCOMO");
        BinderInterceptionPolicy.Decision dDoUid = BinderInterceptionPolicy.decide("device_policy", "getDeviceOwnerUserId", cfg, u10App, null);
        check(dDoUid.action == BinderInterceptionPolicy.Action.WRITE_INT && dDoUid.intValue == -1,
                "device_policy.getDeviceOwnerUserId -> -1");
        BinderInterceptionPolicy.Decision dAdminActive = BinderInterceptionPolicy.decide("device_policy", "isAdminActiveAsUser", cfg, u10App, null);
        check(dAdminActive.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !dAdminActive.boolValue,
                "device_policy.isAdminActiveAsUser -> false");

        check(BinderInterceptionPolicy.decide("connectivity", "getNetworkInfo", cfg, u10App, null, 17, -1).action
                == BinderInterceptionPolicy.Action.WRITE_NULL_PARCELABLE,
                "connectivity.getNetworkInfo(TYPE_VPN=17) returns null");
        check(BinderInterceptionPolicy.decide("connectivity", "listenForNetwork", cfg, u10App, null).action
                == BinderInterceptionPolicy.Action.WRAP_CONNECTIVITY_MESSENGER,
                "connectivity.listenForNetwork wraps Messenger");

        BinderInterceptionPolicy.Decision dCid = BinderInterceptionPolicy.decide("phone", "getSubscriptionCarrierId", cfg, u10App, null);
        check(dCid.action == BinderInterceptionPolicy.Action.WRITE_INT && dCid.intValue == 850,
                "phone.getSubscriptionCarrierId -> 850");
        check(BinderInterceptionPolicy.decide("isub", "getPhoneNumber", cfg, u0App, null).action
                == BinderInterceptionPolicy.Action.PASSTHROUGH, "isub u0 passthrough");

        StealthConfig nestedCfg = StealthConfig.fromJson(
                "{\"enabled\":false,\"extra\":{\"enabled\":false,\"device_region\":\"CN\"},"
                + "\"sim_operator_name\":\"NTT]DOCOMO\",\"exempt_uids\":[1010376],\"enabled\":true}");
        check(nestedCfg.enabled, "Java parseFlatJson last-wins & skips nested objects");
        check("".equals(nestedCfg.deviceRegion), "nested device_region must not leak into top-level");
        check("NTT]DOCOMO".equals(nestedCfg.simOperatorName), "bracket inside string must preserve value");
        check(!nestedCfg.shouldIntercept(1010376), "exempt_uids array parsed past string bracket");

        // USB / ADB / hardened wifi / location / bluetooth decisions
        check(cfg.hideAdb, "hideAdb defaults to true");
        Set<String> sysTargets = SystemServerHook.targetServicesForProcess("system_server");
        check(sysTargets.contains("usb") && sysTargets.contains("adb"), "system_server targets include usb and adb");

        BinderInterceptionPolicy.Decision dUsbFn = BinderInterceptionPolicy.decide("usb", "getCurrentFunctions", cfg, u10App, null);
        check(dUsbFn.action == BinderInterceptionPolicy.Action.WRITE_LONG && dUsbFn.longValue == 0L,
                "usb.getCurrentFunctions -> 0L");
        BinderInterceptionPolicy.Decision dUsbAdb = BinderInterceptionPolicy.decide("usb", "isFunctionEnabled", cfg, u10App, null);
        check(dUsbAdb.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !dUsbAdb.boolValue,
                "usb.isFunctionEnabled -> false");
        BinderInterceptionPolicy.Decision dAdbWifi = BinderInterceptionPolicy.decide("adb", "isAdbWifiSupported", cfg, u10App, null);
        check(dAdbWifi.action == BinderInterceptionPolicy.Action.WRITE_BOOL && !dAdbWifi.boolValue,
                "adb.isAdbWifiSupported -> false");
        StealthConfig noAdbCfg = StealthConfig.fromJson("{\"enabled\":true,\"hide_adb\":false}");
        check(!noAdbCfg.hideAdb, "hide_adb=false parsed");
        check(BinderInterceptionPolicy.decide("usb", "getCurrentFunctions", noAdbCfg, u10App, null).action
                == BinderInterceptionPolicy.Action.PASSTHROUGH, "usb passthrough when hide_adb=false");
        check(BinderInterceptionPolicy.decide("wifi", "getWifiApState", cfg, u10App, null).intValue == 11,
                "wifi.getWifiApState -> WIFI_AP_STATE_DISABLED (11)");
        check(BinderInterceptionPolicy.decide("bluetooth_manager", "getAdapter", cfg, u10App, null).action
                == BinderInterceptionPolicy.Action.WRITE_NULL_STRONG_BINDER, "bluetooth_manager.getAdapter -> null binder");
        check(BinderInterceptionPolicy.decide("location", "getGnssYearOfHardware", cfg, u10App, null).intValue == 0,
                "location.getGnssYearOfHardware -> 0");

        // Settings.Global ADB/DevOptions spoofing & tryWrapSettingsProvider host tests
        check("0".equals(BinderInterceptionPolicy.spoofedSettingsGlobalValue("adb_enabled", cfg)),
                "spoofedSettingsGlobalValue(adb_enabled) -> 0");
        check("0".equals(BinderInterceptionPolicy.spoofedSettingsGlobalValue("adb_wifi_enabled", cfg)),
                "spoofedSettingsGlobalValue(adb_wifi_enabled) -> 0");
        check("0".equals(BinderInterceptionPolicy.spoofedSettingsGlobalValue("development_settings_enabled", cfg)),
                "spoofedSettingsGlobalValue(development_settings_enabled) -> 0");
        check("0".equals(BinderInterceptionPolicy.spoofedSettingsGlobalValue("stay_on_while_plugged_in", cfg)),
                "spoofedSettingsGlobalValue(stay_on_while_plugged_in) -> 0");
        check(BinderInterceptionPolicy.spoofedSettingsGlobalValue("private_dns_mode", cfg) == null,
                "spoofedSettingsGlobalValue(private_dns_mode) -> null");
        check(BinderInterceptionPolicy.spoofedSettingsGlobalValue("adb_enabled", noAdbCfg) == null,
                "spoofedSettingsGlobalValue with hide_adb=false -> null");
        check(BinderInterceptionPolicy.spoofedSettingsGlobalValue("adb_enabled",
                StealthConfig.fromJson("{\"enabled\":false,\"hide_adb\":true}")) == null,
                "spoofedSettingsGlobalValue when disabled -> null");

        testSettingsProviderWrapping(cfg);
    }

    public interface FakeIContentProvider {
        Object asBinder();
        String callDirect(String arg);
    }

    public static final class FakeContentProviderRecord {
        public FakeIContentProvider provider;
        public FakeContentProviderRecord(FakeIContentProvider provider) {
            this.provider = provider;
        }
    }

    public static final class FakeProviderMap {
        public final Map<String, FakeContentProviderRecord> mSingletonByName = new HashMap<>();
    }

    public static final class FakeActivityManagerService {
        public final FakeProviderMap mProviderMap = new FakeProviderMap();
    }

    public static final class FakeSettingsBinderWrapper {
        public final Object delegate;
        public FakeSettingsBinderWrapper(Object delegate) {
            this.delegate = delegate;
        }
    }

    private static void testSettingsProviderWrapping(StealthConfig cfg) {
        final Object rawSettingsBinder = new Object();
        FakeIContentProvider realProvider = new FakeIContentProvider() {
            @Override public Object asBinder() { return rawSettingsBinder; }
            @Override public String callDirect(String arg) { return "direct:" + arg; }
        };
        FakeActivityManagerService fakeAms = new FakeActivityManagerService();
        fakeAms.mProviderMap.mSingletonByName.put("settings", new FakeContentProviderRecord(realProvider));

        SystemServerHook.SettingsProviderWrapperFactory mockFactory = new SystemServerHook.SettingsProviderWrapperFactory() {
            @Override public Class<?> providerInterface(Object provider) { return FakeIContentProvider.class; }
            @Override public Object asBinder(Object provider) { return ((FakeIContentProvider) provider).asBinder(); }
            @Override public Object wrapBinder(Object delegateBinder, StealthConfig c) { return new FakeSettingsBinderWrapper(delegateBinder); }
        };

        boolean wrapped = SystemServerHook.tryWrapSettingsProvider(fakeAms, cfg, mockFactory);
        check(wrapped, "tryWrapSettingsProvider must wrap settings record");
        FakeIContentProvider storedProvider = fakeAms.mProviderMap.mSingletonByName.get("settings").provider;
        check(storedProvider != realProvider, "stored settings provider must be wrapped proxy");
        check(storedProvider.asBinder() instanceof FakeSettingsBinderWrapper, "asBinder() must return wrapped binder");
        check(((FakeSettingsBinderWrapper) storedProvider.asBinder()).delegate == rawSettingsBinder, "wrapped binder delegates to rawSettingsBinder");
        check("direct:ok".equals(storedProvider.callDirect("ok")), "in-process direct methods must pass through to real provider");
        check(SystemServerHook.tryWrapSettingsProvider(fakeAms, cfg, mockFactory), "idempotent re-wrap must return true");
        check(fakeAms.mProviderMap.mSingletonByName.get("settings").provider == storedProvider, "idempotent re-wrap must preserve existing proxy");
    }

    public static void main(String[] args) {
        testStealthConfig();
        testTransactionReflection();
        testBinderInterceptionDecisions();
        testSystemServerHookProxy();
        testStaticDecisionCacheAndBenchmark();
        testHardeningPolicies();
        System.out.println("ALL StealthHookHostTest CHECKS PASSED (6 test groups)");
    }
}
