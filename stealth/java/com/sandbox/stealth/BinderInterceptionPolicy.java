package com.sandbox.stealth;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Pure-Java decision engine mapping (serviceName, methodName, config, optionalArgs)
 * to deterministic Binder reply actions. Kept free of native Android Binder calls so
 * host JVM unit tests can validate every service branch exhaustively.
 */
public final class BinderInterceptionPolicy {
    public enum Action {
        PASSTHROUGH,
        WRITE_BOOL,
        WRITE_INT,
        WRITE_INT_ARRAY,
        WRITE_VOID,
        WRITE_STRING,
        WRITE_STRING_LIST,
        WRITE_NULL_PARCELABLE,
        WRITE_NULL_STRONG_BINDER,
        WRITE_EMPTY_STRING_LIST,
        WRITE_EMPTY_TYPED_LIST,
        WRITE_REDACTED_WIFI_INFO,
        SANITIZE_LINK_PROPERTIES,
        SANITIZE_NETWORK_CAPABILITIES,
        SANITIZE_NETWORK_CAPABILITIES_ARRAY,
        SANITIZE_NETWORK_INFO,
        SANITIZE_NETWORK_INFO_ARRAY,
        WRAP_CONNECTIVITY_MESSENGER,
        SANITIZE_SUBSCRIPTION_INFO,
        SANITIZE_SUBSCRIPTION_LIST,
        SANITIZE_SERVICE_STATE
    }

    public static final class Decision {
        public final Action action;
        public final boolean boolValue;
        public final int intValue;
        public final int[] intArrayValue;
        public final String stringValue;
        public final List<String> stringListValue;

        private Decision(
                Action action,
                boolean boolValue,
                int intValue,
                int[] intArrayValue,
                String stringValue,
                List<String> stringListValue) {
            this.action = action;
            this.boolValue = boolValue;
            this.intValue = intValue;
            this.intArrayValue = intArrayValue;
            this.stringValue = stringValue;
            this.stringListValue = stringListValue;
        }

        public static Decision passthrough() {
            return new Decision(Action.PASSTHROUGH, false, 0, null, null, null);
        }

        public static Decision writeBool(boolean v) {
            return new Decision(Action.WRITE_BOOL, v, v ? 1 : 0, null, null, null);
        }

        public static Decision writeInt(int v) {
            return new Decision(Action.WRITE_INT, v != 0, v, null, null, null);
        }

        public static Decision writeIntArray(int[] arr) {
            return new Decision(Action.WRITE_INT_ARRAY, false, 0, arr, null, null);
        }

        public static Decision writeVoid() {
            return new Decision(Action.WRITE_VOID, false, 0, null, null, null);
        }

        public static Decision writeString(String s) {
            return new Decision(Action.WRITE_STRING, false, 0, null, s, null);
        }

        public static Decision writeStringList(List<String> list) {
            return new Decision(Action.WRITE_STRING_LIST, false, 0, null, null,
                    list == null ? Collections.emptyList() : list);
        }

        public static Decision writeNullParcelable() {
            return new Decision(Action.WRITE_NULL_PARCELABLE, false, 0, null, null, null);
        }

        public static Decision writeNullStrongBinder() {
            return new Decision(Action.WRITE_NULL_STRONG_BINDER, false, 0, null, null, null);
        }

        public static Decision writeEmptyStringList() {
            return new Decision(Action.WRITE_EMPTY_STRING_LIST, false, 0, null, null, null);
        }

        public static Decision writeEmptyTypedList() {
            return new Decision(Action.WRITE_EMPTY_TYPED_LIST, false, 0, null, null, null);
        }

        public static Decision writeRedactedWifiInfo() {
            return new Decision(Action.WRITE_REDACTED_WIFI_INFO, false, 0, null, null, null);
        }

        public static Decision sanitizeLinkProperties() {
            return new Decision(Action.SANITIZE_LINK_PROPERTIES, false, 0, null, null, null);
        }

        public static Decision sanitizeNetworkCapabilities() {
            return new Decision(Action.SANITIZE_NETWORK_CAPABILITIES, false, 0, null, null, null);
        }

        public static Decision sanitizeNetworkCapabilitiesArray() {
            return new Decision(Action.SANITIZE_NETWORK_CAPABILITIES_ARRAY, false, 0, null, null, null);
        }

        public static Decision sanitizeNetworkInfo() {
            return new Decision(Action.SANITIZE_NETWORK_INFO, false, 0, null, null, null);
        }

        public static Decision sanitizeNetworkInfoArray() {
            return new Decision(Action.SANITIZE_NETWORK_INFO_ARRAY, false, 0, null, null, null);
        }

        public static Decision wrapConnectivityMessenger() {
            return new Decision(Action.WRAP_CONNECTIVITY_MESSENGER, false, 0, null, null, null);
        }

        public static Decision sanitizeSubscriptionInfo() {
            return new Decision(Action.SANITIZE_SUBSCRIPTION_INFO, false, 0, null, null, null);
        }

        public static Decision sanitizeSubscriptionList() {
            return new Decision(Action.SANITIZE_SUBSCRIPTION_LIST, false, 0, null, null, null);
        }

        public static Decision sanitizeServiceState() {
            return new Decision(Action.SANITIZE_SERVICE_STATE, false, 0, null, null, null);
        }
    }

    private static final List<String> STANDARD_LOCATION_PROVIDERS =
            Collections.unmodifiableList(Arrays.asList("passive", "gps", "network", "fused"));

    private BinderInterceptionPolicy() {}

    private static Class<?> loadStubClass(Class<?> implClass, String descriptor) {
        if (descriptor == null || descriptor.isEmpty()) {
            return null;
        }
        String stubName = descriptor + "$Stub";
        ClassLoader[] candidates = new ClassLoader[]{
                implClass != null ? implClass.getClassLoader() : null,
                ClassLoader.getSystemClassLoader(),
                Thread.currentThread().getContextClassLoader()
        };
        for (ClassLoader cl : candidates) {
            try {
                if (cl == null) {
                    return Class.forName(stubName, false, null);
                }
                return Class.forName(stubName, false, cl);
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    /**
     * Reflects TRANSACTION_* static int fields across the class hierarchy (and optionally the
     * descriptor + "$Stub" class) so OEM/version AIDL transaction code shifts are handled dynamically.
     */
    public static Map<Integer, String> buildTransactionMap(Class<?> implClass, String descriptor) {
        Map<Integer, String> map = new HashMap<>();
        for (Class<?> c = implClass; c != null && c != Object.class; c = c.getSuperclass()) {
            collectTransactionFields(c, map);
        }
        Class<?> stubCls = loadStubClass(implClass, descriptor);
        if (stubCls != null) {
            collectTransactionFields(stubCls, map);
        }
        return map;
    }

    private static void collectTransactionFields(Class<?> cls, Map<Integer, String> map) {
        try {
            for (Field f : cls.getDeclaredFields()) {
                int mod = f.getModifiers();
                if (!Modifier.isStatic(mod) || f.getType() != int.class) {
                    continue;
                }
                String name = f.getName();
                if (!name.startsWith("TRANSACTION_")) {
                    continue;
                }
                f.setAccessible(true);
                int code = f.getInt(null);
                map.putIfAbsent(code, name.substring("TRANSACTION_".length()));
            }
        } catch (Throwable ignored) {
        }
    }

    public static String resolveViaStubMethod(Class<?> implClass, String descriptor, int code) {
        Class<?> stubCls = loadStubClass(implClass, descriptor);
        if (stubCls == null) {
            return null;
        }
        try {
            Method m = stubCls.getMethod("getDefaultTransactionName", int.class);
            Object res = m.invoke(null, code);
            return (res instanceof String) ? (String) res : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    public static boolean needsStringSecondArg(String serviceName, String methodName) {
        return "user".equals(serviceName) && "isUserOfType".equals(methodName);
    }

    public static boolean needsTwoIntArgs(String serviceName, String methodName) {
        return "user".equals(serviceName) && "isSameProfileGroup".equals(methodName);
    }

    public static boolean needsFirstIntArg(String serviceName, String methodName) {
        return "connectivity".equals(serviceName) && "getNetworkInfo".equals(methodName);
    }

    public static boolean supportsStaticDecisionCache(String serviceName, String methodName) {
        return !needsStringSecondArg(serviceName, methodName)
                && !needsTwoIntArgs(serviceName, methodName)
                && !needsFirstIntArg(serviceName, methodName);
    }

    public static Decision decide(
            String serviceName,
            String methodName,
            StealthConfig cfg,
            int callingUid,
            String secondStringArg) {
        return decide(serviceName, methodName, cfg, callingUid, secondStringArg, -1, -2);
    }

    public static Decision decide(
            String serviceName,
            String methodName,
            StealthConfig cfg,
            int callingUid,
            String secondStringArg,
            int firstIntArg,
            int secondIntArg) {
        if (serviceName == null || methodName == null || cfg == null || !cfg.shouldIntercept(callingUid)) {
            return Decision.passthrough();
        }
        return decideForIntercepted(serviceName, methodName, cfg, secondStringArg, firstIntArg, secondIntArg);
    }

    /** Evaluates policy for a caller UID that already passed cfg.shouldIntercept(callingUid). */
    public static Decision decideForIntercepted(
            String serviceName,
            String methodName,
            StealthConfig cfg,
            String secondStringArg,
            int firstIntArg,
            int secondIntArg) {
        if (serviceName == null || methodName == null || cfg == null || !cfg.enabled) {
            return Decision.passthrough();
        }
        switch (serviceName) {
            case "user":
                return decideUser(methodName, cfg, secondStringArg, firstIntArg, secondIntArg);
            case "device_policy":
                return decideDevicePolicy(methodName, cfg);
            case "crossprofileapps":
                return decideCrossProfileApps(methodName, cfg);
            case "location":
                return decideLocation(methodName, cfg);
            case "wifi":
                return decideWifi(methodName, cfg);
            case "phone":
                return decidePhone(methodName, cfg);
            case "isub":
                return decideIsub(methodName, cfg);
            case "iphonesubinfo":
                return decideIphoneSubInfo(methodName, cfg);
            case "connectivity":
                return decideConnectivity(methodName, cfg, firstIntArg);
            case "bluetooth_manager":
                return decideBluetooth(methodName, cfg);
            default:
                return Decision.passthrough();
        }
    }

    private static Decision decideUser(String m, StealthConfig cfg, String userTypeArg, int firstIntArg, int secondIntArg) {
        if (!cfg.hideManagedProfile) {
            return Decision.passthrough();
        }
        switch (m) {
            case "getProfileType":
                // Android 13+ UserManager.getProfileType() calls result.intern() and isProfile() checks !"".equals(result).
                return Decision.writeString("");
            case "isUserOfType":
                if (userTypeArg != null && userTypeArg.startsWith("android.os.usertype.profile.")) {
                    return Decision.writeBool(false);
                }
                if ("android.os.usertype.full.SYSTEM".equals(userTypeArg)) {
                    return Decision.writeBool(true);
                }
                return Decision.passthrough();
            case "isManagedProfile":
            case "isProfile":
            case "isCloneProfile":
            case "isPrivateProfile":
            case "isManagedProfileWithDeviceId":
                return Decision.writeBool(false);
            case "isSameProfileGroup":
                return Decision.writeBool(firstIntArg >= 0 && firstIntArg == secondIntArg);
            case "getProfileIds":
                return Decision.writeIntArray(new int[]{cfg.sandboxUserId});
            case "getProfileParent":
                return Decision.writeNullParcelable();
            case "getProfileParentId":
                return Decision.writeInt(cfg.sandboxUserId);
            default:
                return Decision.passthrough();
        }
    }

    private static Decision decideDevicePolicy(String m, StealthConfig cfg) {
        if (!cfg.hideManagedProfile) {
            return Decision.passthrough();
        }
        switch (m) {
            case "getProfileOwnerAsUser":
            case "getProfileOwnerComponent":
            case "getProfileOwnerOrDeviceOwnerSupervisionComponent":
                return Decision.writeNullParcelable();
            case "getProfileOwnerName":
            case "getProfileOwnerNameAsUser":
                return Decision.writeString(null);
            case "isManagedProfile":
            case "isProfileOwnerApp":
            case "isOrganizationOwnedDeviceWithManagedProfile":
                return Decision.writeBool(false);
            case "getActiveAdmins":
            case "getPolicyManagedProfiles":
                return Decision.writeEmptyTypedList();
            default:
                return Decision.passthrough();
        }
    }

    private static Decision decideCrossProfileApps(String m, StealthConfig cfg) {
        if (!cfg.hideManagedProfile) {
            return Decision.passthrough();
        }
        if ("getTargetUserProfiles".equals(m)) {
            return Decision.writeEmptyTypedList();
        }
        return Decision.passthrough();
    }

    private static Decision decideLocation(String m, StealthConfig cfg) {
        if (!"block".equalsIgnoreCase(cfg.spoofLocationMode)) {
            return Decision.passthrough();
        }
        switch (m) {
            case "isLocationEnabledForUser":
            case "isProviderEnabledForUser":
                return Decision.writeBool(false);
            case "getLastLocation":
                return Decision.writeNullParcelable();
            case "getCurrentLocation":
                return Decision.writeNullStrongBinder();
            case "registerLocationListener":
            case "registerLocationPendingIntent":
            case "requestLocationUpdates":
            case "requestListenerFlush":
            case "requestPendingIntentFlush":
            case "registerGnssStatusCallback":
            case "addGnssMeasurementsListener":
            case "addGnssNavigationMessageListener":
            case "requestGeofence":
                return Decision.writeVoid();
            case "getProviders":
                return Decision.writeEmptyStringList();
            case "getAllProviders":
                return Decision.writeStringList(STANDARD_LOCATION_PROVIDERS);
            case "getBestProvider":
                return Decision.writeString(null);
            default:
                return Decision.passthrough();
        }
    }

    private static String upperIso(String iso, String fallback) {
        String s = (iso == null || iso.trim().isEmpty())
                ? (fallback != null ? fallback.trim() : "")
                : iso.trim();
        return s.toUpperCase(Locale.ROOT);
    }

    private static Decision decideWifi(String m, StealthConfig cfg) {
        if ("getCountryCode".equals(m)) {
            if (cfg.spoofDeviceRegion || cfg.spoofCarrier) {
                String cc = upperIso(cfg.simCountryIso, cfg.deviceRegion);
                if (!cc.isEmpty()) {
                    return Decision.writeString(cc);
                }
            }
            return Decision.passthrough();
        }
        if (!cfg.blockWifiScan) {
            return Decision.passthrough();
        }
        switch (m) {
            case "getScanResults":
                return Decision.writeEmptyTypedList();
            case "getConnectionInfo":
                return Decision.writeRedactedWifiInfo();
            default:
                return Decision.passthrough();
        }
    }

    private static Decision decideConnectivity(String m, StealthConfig cfg, int firstIntArg) {
        if (!cfg.sanitizeNetwork) {
            return Decision.passthrough();
        }
        switch (m) {
            case "getActiveLinkProperties":
            case "getLinkProperties":
            case "getLinkPropertiesForType":
            case "getRedactedLinkPropertiesForPackage":
                return Decision.sanitizeLinkProperties();
            case "getNetworkCapabilities":
            case "getRedactedNetworkCapabilitiesForPackage":
                return Decision.sanitizeNetworkCapabilities();
            case "getDefaultNetworkCapabilitiesForUser":
                return Decision.sanitizeNetworkCapabilitiesArray();
            case "getActiveNetworkInfo":
            case "getActiveNetworkInfoForUid":
            case "getNetworkInfoForUid":
                return Decision.sanitizeNetworkInfo();
            case "getNetworkInfo":
                // ConnectivityManager.TYPE_VPN == 17: hide VPN existence when explicitly probed.
                if (firstIntArg == 17) {
                    return Decision.writeNullParcelable();
                }
                return Decision.sanitizeNetworkInfo();
            case "getAllNetworkInfo":
                return Decision.sanitizeNetworkInfoArray();
            case "listenForNetwork":
            case "requestNetwork":
                return Decision.wrapConnectivityMessenger();
            default:
                return Decision.passthrough();
        }
    }

    private static Decision decideBluetooth(String m, StealthConfig cfg) {
        if (!cfg.spoofBluetooth) {
            return Decision.passthrough();
        }
        switch (m) {
            case "registerAdapter":
            case "getBluetoothGatt":
                return Decision.writeNullStrongBinder();
            case "isEnabled":
            case "isBleScanAlwaysAvailable":
                return Decision.writeBool(false);
            case "getState":
                return Decision.writeInt(10); // BluetoothAdapter.STATE_OFF
            case "getName":
                return Decision.writeString(cfg.deviceName);
            case "getAddress":
                return Decision.writeString("02:00:00:00:00:00");
            case "getBondedDevices":
                return Decision.writeEmptyTypedList();
            default:
                return Decision.passthrough();
        }
    }

    private static Decision decideIsub(String m, StealthConfig cfg) {
        if (!cfg.spoofCarrier) {
            return Decision.passthrough();
        }
        switch (m) {
            case "getActiveSubscriptionInfo":
            case "getActiveSubscriptionInfoForSimSlotIndex":
            case "getActiveSubInfoForSimSlotIndex":
            case "getActiveSubscriptionInfoForIccId":
            case "getActiveSubscriptionInfoForPhone":
            case "getDefaultDataSubscriptionInfo":
                return Decision.sanitizeSubscriptionInfo();
            case "getActiveSubscriptionInfoList":
            case "getAccessibleSubscriptionInfoList":
            case "getAllSubscriptionInfoList":
            case "getAllSubInfoList":
            case "getActiveSubInfoList":
            case "getAvailableSubscriptionInfoList":
            case "getSubscriptionsInGroup":
            case "getOpportunisticSubscriptions":
                return Decision.sanitizeSubscriptionList();
            case "getPhoneNumber":
            case "getPhoneNumberFromFirstAvailableSource":
                return Decision.writeString("");
            default:
                return Decision.passthrough();
        }
    }

    private static Decision decideIphoneSubInfo(String m, StealthConfig cfg) {
        if (!cfg.spoofCarrier) {
            return Decision.passthrough();
        }
        switch (m) {
            case "getSubscriberIdForSubscriber":
            case "getIccSerialNumberForSubscriber":
            case "getLine1NumberForSubscriber":
            case "getGroupIdLevel1ForSubscriber":
                return Decision.writeString("");
            default:
                return Decision.passthrough();
        }
    }

    private static Decision decidePhone(String m, StealthConfig cfg) {
        if (!cfg.spoofCarrier) {
            return Decision.passthrough();
        }
        switch (m) {
            case "getAllCellInfo":
                return Decision.writeEmptyTypedList();
            case "getCellLocation":
                return Decision.writeNullParcelable();
            case "getSimStateForSlotIndex":
                return Decision.writeInt(5); // TelephonyManager.SIM_STATE_READY
            case "getPhoneType":
                return Decision.writeInt(1); // TelephonyManager.PHONE_TYPE_GSM
            case "getSimOperatorForPhone":
            case "getSimOperatorNumericForPhone":
                return Decision.writeString(cfg.simOperator);
            case "getNetworkOperatorForPhone":
                return Decision.writeString(cfg.networkOperator);
            case "getSimCountryIsoForPhone":
                return Decision.writeString(cfg.simCountryIso);
            case "getNetworkCountryIsoForPhone":
            case "getCountryIso":
                return Decision.writeString(cfg.networkCountryIso);
            case "getSimOperatorNameForPhone":
            case "getSubscriptionCarrierName":
            case "getSubscriptionSpecificCarrierName":
                return Decision.writeString(cfg.simOperatorName);
            case "getNetworkOperatorNameForPhone":
                return Decision.writeString(cfg.networkOperatorName);
            case "getSubscriptionCarrierId":
            case "getSubscriptionSpecificCarrierId":
            case "getCarrierIdFromSimMccMnc":
                return Decision.writeInt(carrierIdForOperator(cfg.simOperator));
            case "getServiceStateForSubscriber":
            case "getServiceStateForSubscriberWithFeature":
            case "getServiceStateForSlot":
                return Decision.sanitizeServiceState();
            default:
                return Decision.passthrough();
        }
    }

    static int carrierIdForOperator(String simOperator) {
        if (simOperator == null) {
            return -1;
        }
        switch (simOperator.trim()) {
            case "44010":
                return 850;  // NTT DOCOMO (JP)
            case "44020":
                return 1047; // SoftBank (JP)
            case "44050":
            case "44051":
                return 851;  // KDDI au (JP)
            case "310260":
                return 1;    // T-Mobile US
            case "310410":
                return 1187; // AT&T US
            case "23430":
                return 1839; // EE (UK)
            case "52501":
                return 1436; // Singtel (SG)
            case "26201":
                return 1159; // Telekom.de (DE)
            default:
                return -1;   // TelephonyManager.UNKNOWN_CARRIER_ID
        }
    }
}
