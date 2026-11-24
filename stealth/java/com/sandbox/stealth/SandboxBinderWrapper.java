package com.sandbox.stealth;

import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.net.TransportInfo;
import android.net.wifi.WifiInfo;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Message;
import android.os.Messenger;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import android.telephony.NetworkRegistrationInfo;
import android.telephony.ServiceState;
import android.telephony.SubscriptionInfo;

import java.io.FileDescriptor;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReferenceArray;

/**
 * Wraps a registered SystemService IBinder in system_server or com.android.phone.
 * Uses a precomputed 256-slot AtomicReferenceArray of immutable FastSlot entries for O(1),
 * JMM-safe Binder method/decision dispatch on intercepted sandbox calls; all non-sandbox UIDs
 * bypass straight to delegate.
 */
public final class SandboxBinderWrapper extends Binder {
    private static final int FAST_TABLE_SIZE = 256;
    private static final String NO_METHOD = "";

    private static final class FastSlot {
        final String methodName;
        final BinderInterceptionPolicy.Decision staticDecision;

        FastSlot(String methodName, BinderInterceptionPolicy.Decision staticDecision) {
            this.methodName = methodName;
            this.staticDecision = staticDecision;
        }
    }

    private static final FastSlot NO_METHOD_SLOT = new FastSlot(NO_METHOD, null);
    private static final WifiInfo DEFAULT_REDACTED_WIFI_INFO = createRedactedWifiInfo();
    private static final Constructor<LinkAddress> LINK_ADDRESS_CTOR = findLinkAddressCtor();
    private static final Constructor<RouteInfo> ROUTE_INFO_CTOR_4 =
            findConstructor(RouteInfo.class, IpPrefix.class, InetAddress.class, String.class, int.class);
    private static final Constructor<RouteInfo> ROUTE_INFO_CTOR_3 =
            findConstructor(RouteInfo.class, IpPrefix.class, InetAddress.class, String.class);
    private static final Method NC_SET_TRANSPORT_INFO = findMethod(NetworkCapabilities.class, "setTransportInfo", TransportInfo.class);
    private static final Method NC_REMOVE_TRANSPORT_TYPE = findMethod(NetworkCapabilities.class, "removeTransportType", int.class);
    private static final Method NC_ADD_TRANSPORT_TYPE = findMethod(NetworkCapabilities.class, "addTransportType", int.class);
    private static final Method NC_ADD_CAPABILITY = findMethod(NetworkCapabilities.class, "addCapability", int.class);
    private static final Method NC_SET_UNDERLYING_NETWORKS = findMethod(NetworkCapabilities.class, "setUnderlyingNetworks", List.class);
    private static final Method NC_SET_OWNER_UID = findMethod(NetworkCapabilities.class, "setOwnerUid", int.class);
    private static final Method NC_SET_ADMIN_UIDS = findMethod(NetworkCapabilities.class, "setAdministratorUids", int[].class);
    private static final Method NC_GET_ADMIN_UIDS = findMethod(NetworkCapabilities.class, "getAdministratorUids");
    private static final Method NC_SET_SSID = findMethod(NetworkCapabilities.class, "setSSID", String.class);
    private static final Method NC_SET_UIDS = findMethod(NetworkCapabilities.class, "setUids", java.util.Set.class);
    private static final Field NC_TRANSPORT_INFO_FIELD = findField(NetworkCapabilities.class, "mTransportInfo");
    private static final Field NC_TRANSPORT_TYPES_FIELD = findField(NetworkCapabilities.class, "mTransportTypes");
    private static final Field NC_CAPABILITIES_FIELD = findField(NetworkCapabilities.class, "mNetworkCapabilities");
    private static final Field NC_UNDERLYING_NETWORKS_FIELD = findField(NetworkCapabilities.class, "mUnderlyingNetworks");
    private static final Field NC_OWNER_UID_FIELD = findField(NetworkCapabilities.class, "mOwnerUid");
    private static final Field NC_ADMIN_UIDS_FIELD = findField(NetworkCapabilities.class, "mAdministratorUids");
    private static final Field NC_SSID_FIELD = findField(NetworkCapabilities.class, "mSSID");
    private static final Field NC_UIDS_FIELD = findField(NetworkCapabilities.class, "mUids");
    private static final Field NC_ESTABLISHING_VPN_UID_FIELD = findField(NetworkCapabilities.class, "mEstablishingVpnAppUid");
    private static final Class<?> NI_CLASS = findClass("android.net.NetworkInfo");
    private static final Method NI_SET_IS_AVAILABLE = findMethod(NI_CLASS, "setIsAvailable", boolean.class);
    private static final Method NI_SET_FAILOVER = findMethod(NI_CLASS, "setFailover", boolean.class);
    private static final Method NI_SET_ROAMING = findMethod(NI_CLASS, "setRoaming", boolean.class);
    private static final Field NI_IS_AVAILABLE_FIELD = findField(NI_CLASS, "mIsAvailable");
    private static final Field NI_IS_FAILOVER_FIELD = findField(NI_CLASS, "mIsFailover");
    private static final Field NI_IS_ROAMING_FIELD = findField(NI_CLASS, "mIsRoaming");
    private static final Field SUB_CARRIER_NAME = findField(SubscriptionInfo.class, "mCarrierName");
    private static final Field SUB_DISPLAY_NAME = findField(SubscriptionInfo.class, "mDisplayName");
    private static final Field SUB_COUNTRY_ISO = findField(SubscriptionInfo.class, "mCountryIso");
    private static final Field SUB_MCC = findField(SubscriptionInfo.class, "mMcc");
    private static final Field SUB_MNC = findField(SubscriptionInfo.class, "mMnc");
    private static final Field SUB_MCC_STR = findField(SubscriptionInfo.class, "mMccString");
    private static final Field SUB_MNC_STR = findField(SubscriptionInfo.class, "mMncString");
    private static final Field SUB_CARRIER_ID = findField(SubscriptionInfo.class, "mCarrierId");
    private static final Field SUB_CARD_STRING = findField(SubscriptionInfo.class, "mCardString");
    private static final Field SUB_HPLMNS = findField(SubscriptionInfo.class, "mHplmns");
    private static final Field SUB_EHPLMNS = findField(SubscriptionInfo.class, "mEhplmns");
    private static final Field SUB_GROUP_UUID = findField(SubscriptionInfo.class, "mGroupUuid");
    private static final Field SUB_GROUP_OWNER = findField(SubscriptionInfo.class, "mGroupOwner");
    private static final Field SUB_ICC_ID = findField(SubscriptionInfo.class, "mIccId");
    private static final Field SUB_NUMBER = findField(SubscriptionInfo.class, "mNumber");
    private static final Method SS_CREATE_LOCATION_SANITIZED =
            findMethod(ServiceState.class, "createLocationInfoSanitizedCopy", boolean.class);
    private static final Field NRI_CELL_IDENTITY = findField(NetworkRegistrationInfo.class, "mCellIdentity");
    private static final Field NRI_REGISTERED_PLMN = findField(NetworkRegistrationInfo.class, "mRegisteredPlmn");

    private final IBinder delegate;
    private final String serviceName;
    private final String descriptor;
    private final StealthConfig config;
    private final Map<Integer, String> codeToMethod;
    private final AtomicReferenceArray<FastSlot> fastSlots = new AtomicReferenceArray<>(FAST_TABLE_SIZE);
    private final List<LinkAddress> sanitizedLinkAddresses;
    private final List<InetAddress> sanitizedDnsServers;
    private final Map<String, Class<?>[]> connectivityMessengerPrefixes;

    public SandboxBinderWrapper(IBinder delegate, String serviceName, StealthConfig config) {
        this.delegate = delegate;
        this.serviceName = serviceName;
        this.config = config;
        this.sanitizedLinkAddresses = buildSanitizedLinkAddresses(config.sandboxLinkIpv4);
        this.sanitizedDnsServers = buildSanitizedDnsServers();
        String desc = null;
        try {
            desc = delegate.getInterfaceDescriptor();
        } catch (Throwable ignored) {
        }
        this.descriptor = desc;
        this.connectivityMessengerPrefixes = "connectivity".equals(serviceName)
                ? resolveConnectivityMessengerPrefixes(delegate.getClass(), desc)
                : Collections.emptyMap();
        Map<Integer, String> reflected = BinderInterceptionPolicy.buildTransactionMap(delegate.getClass(), desc);
        this.codeToMethod = new ConcurrentHashMap<>(reflected);
        for (Map.Entry<Integer, String> entry : reflected.entrySet()) {
            cacheFastSlot(entry.getKey(), entry.getValue());
        }
    }

    private static WifiInfo createRedactedWifiInfo() {
        try {
            Constructor<WifiInfo> ctor = WifiInfo.class.getDeclaredConstructor();
            ctor.setAccessible(true);
            return ctor.newInstance();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Constructor<LinkAddress> findLinkAddressCtor() {
        try {
            Constructor<LinkAddress> ctor = LinkAddress.class.getDeclaredConstructor(InetAddress.class, int.class);
            ctor.setAccessible(true);
            return ctor;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static <T> Constructor<T> findConstructor(Class<T> cls, Class<?>... params) {
        try {
            Constructor<T> ctor = cls.getDeclaredConstructor(params);
            ctor.setAccessible(true);
            return ctor;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Class<?> findClass(String name) {
        try {
            return Class.forName(name);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Method findMethod(Class<?> cls, String name, Class<?>... params) {
        if (cls == null) {
            return null;
        }
        try {
            Method m = cls.getDeclaredMethod(name, params);
            m.setAccessible(true);
            return m;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Field findField(Class<?> cls, String name) {
        for (Class<?> c = cls; c != null && c != Object.class; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f;
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    private static byte[] parseIpv4Octets(String ip) {
        if (ip != null) {
            String trimmed = ip.trim();
            String[] parts = trimmed.split("\\.");
            if (parts.length == 4) {
                byte[] out = new byte[4];
                boolean ok = true;
                for (int i = 0; i < 4; i++) {
                    try {
                        int v = Integer.parseInt(parts[i]);
                        if (v < 0 || v > 255) {
                            ok = false;
                            break;
                        }
                        out[i] = (byte) v;
                    } catch (NumberFormatException ignored) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    return out;
                }
            }
        }
        return new byte[]{10, (byte) 172, 10, 2};
    }

    private static List<LinkAddress> buildSanitizedLinkAddresses(String sandboxIpv4) {
        if (LINK_ADDRESS_CTOR == null) {
            return null;
        }
        try {
            InetAddress addr = InetAddress.getByAddress(parseIpv4Octets(sandboxIpv4));
            return Collections.singletonList(LINK_ADDRESS_CTOR.newInstance(addr, 24));
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static List<InetAddress> buildSanitizedDnsServers() {
        try {
            return Collections.unmodifiableList(Arrays.asList(
                    InetAddress.getByAddress(new byte[]{1, 1, 1, 1}),
                    InetAddress.getByAddress(new byte[]{8, 8, 8, 8})));
        } catch (Throwable ignored) {
            return null;
        }
    }

    private FastSlot cacheFastSlot(int code, String methodName) {
        int idx = code - FIRST_CALL_TRANSACTION;
        if (methodName == null || methodName.isEmpty()) {
            if (idx >= 0 && idx < FAST_TABLE_SIZE) {
                fastSlots.compareAndSet(idx, null, NO_METHOD_SLOT);
                FastSlot existing = fastSlots.get(idx);
                return existing != null ? existing : NO_METHOD_SLOT;
            }
            return NO_METHOD_SLOT;
        }
        BinderInterceptionPolicy.Decision decision = null;
        if (BinderInterceptionPolicy.supportsStaticDecisionCache(serviceName, methodName)) {
            decision = BinderInterceptionPolicy.decideForIntercepted(
                    serviceName, methodName, config, null, -1, -2);
        }
        FastSlot slot = new FastSlot(methodName, decision);
        if (idx >= 0 && idx < FAST_TABLE_SIZE) {
            fastSlots.compareAndSet(idx, null, slot);
            FastSlot existing = fastSlots.get(idx);
            if (existing != null) {
                return existing;
            }
        }
        return slot;
    }

    public IBinder unwrap() {
        return delegate;
    }

    @Override
    public String getInterfaceDescriptor() {
        return descriptor != null ? descriptor : super.getInterfaceDescriptor();
    }

    @Override
    public boolean pingBinder() {
        return delegate.pingBinder();
    }

    @Override
    public boolean isBinderAlive() {
        return delegate.isBinderAlive();
    }

    @Override
    public IInterface queryLocalInterface(String descriptor) {
        return delegate.queryLocalInterface(descriptor);
    }

    @Override
    public void dump(FileDescriptor fd, String[] args) {
        try {
            delegate.dump(fd, args);
        } catch (RemoteException ignored) {
        }
    }

    @Override
    public void dumpAsync(FileDescriptor fd, String[] args) {
        try {
            delegate.dumpAsync(fd, args);
        } catch (RemoteException ignored) {
        }
    }

    @Override
    public void linkToDeath(DeathRecipient recipient, int flags) {
        try {
            delegate.linkToDeath(recipient, flags);
        } catch (RemoteException ignored) {
        }
    }

    @Override
    public boolean unlinkToDeath(DeathRecipient recipient, int flags) {
        return delegate.unlinkToDeath(recipient, flags);
    }

    @Override
    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        int callingUid = Binder.getCallingUid();
        if (!config.shouldIntercept(callingUid) || code < FIRST_CALL_TRANSACTION || code > LAST_CALL_TRANSACTION) {
            return delegate.transact(code, data, reply, flags);
        }

        int fastIdx = code - FIRST_CALL_TRANSACTION;
        BinderInterceptionPolicy.Decision cachedDecision = null;
        String methodName;
        if (fastIdx >= 0 && fastIdx < FAST_TABLE_SIZE) {
            FastSlot slot = fastSlots.get(fastIdx);
            if (slot == null) {
                slot = resolveFastSlot(code);
            }
            if (slot == NO_METHOD_SLOT || slot.methodName.isEmpty()) {
                return delegate.transact(code, data, reply, flags);
            }
            methodName = slot.methodName;
            cachedDecision = slot.staticDecision;
        } else {
            methodName = resolveMethodName(code);
        }
        if (methodName == null) {
            return delegate.transact(code, data, reply, flags);
        }

        int savedPos = data != null ? data.dataPosition() : 0;
        boolean passthrough = false;
        BinderInterceptionPolicy.Action postAction = null;
        Parcel rewrittenData = null;
        try {
            BinderInterceptionPolicy.Decision d = cachedDecision;
            boolean readArgs = false;
            if (d == null) {
                String userTypeArg = null;
                int firstIntArg = -1;
                int secondIntArg = -2;
                if (BinderInterceptionPolicy.needsStringSecondArg(serviceName, methodName) && data != null) {
                    if (descriptor != null) {
                        data.enforceInterface(descriptor);
                    }
                    data.readInt(); // userId
                    userTypeArg = data.readString();
                    readArgs = true;
                } else if (BinderInterceptionPolicy.needsTwoIntArgs(serviceName, methodName) && data != null) {
                    if (descriptor != null) {
                        data.enforceInterface(descriptor);
                    }
                    firstIntArg = data.readInt();
                    secondIntArg = data.readInt();
                    readArgs = true;
                } else if (BinderInterceptionPolicy.needsFirstIntArg(serviceName, methodName) && data != null) {
                    if (descriptor != null) {
                        data.enforceInterface(descriptor);
                    }
                    firstIntArg = data.readInt();
                    readArgs = true;
                }
                d = BinderInterceptionPolicy.decideForIntercepted(
                        serviceName, methodName, config, userTypeArg, firstIntArg, secondIntArg);
            }

            if (d.action == BinderInterceptionPolicy.Action.WRAP_CONNECTIVITY_MESSENGER) {
                rewrittenData = tryRewriteConnectivityMessengerParcel(methodName, data, savedPos);
                passthrough = true;
            } else if (d.action == BinderInterceptionPolicy.Action.PASSTHROUGH) {
                passthrough = true;
            } else if (d.action == BinderInterceptionPolicy.Action.SANITIZE_LINK_PROPERTIES
                    || d.action == BinderInterceptionPolicy.Action.SANITIZE_NETWORK_CAPABILITIES
                    || d.action == BinderInterceptionPolicy.Action.SANITIZE_NETWORK_CAPABILITIES_ARRAY
                    || d.action == BinderInterceptionPolicy.Action.SANITIZE_NETWORK_INFO
                    || d.action == BinderInterceptionPolicy.Action.SANITIZE_NETWORK_INFO_ARRAY
                    || d.action == BinderInterceptionPolicy.Action.SANITIZE_SUBSCRIPTION_INFO
                    || d.action == BinderInterceptionPolicy.Action.SANITIZE_SUBSCRIPTION_LIST
                    || d.action == BinderInterceptionPolicy.Action.SANITIZE_SERVICE_STATE) {
                if (reply != null) {
                    postAction = d.action;
                }
                passthrough = true;
            } else if (d.action == BinderInterceptionPolicy.Action.WRITE_REDACTED_WIFI_INFO) {
                if (DEFAULT_REDACTED_WIFI_INFO == null && reply != null) {
                    passthrough = true;
                } else {
                    if (data != null && descriptor != null && !readArgs) {
                        data.enforceInterface(descriptor);
                    }
                    if (reply != null) {
                        reply.writeNoException();
                        reply.writeInt(1);
                        DEFAULT_REDACTED_WIFI_INFO.writeToParcel(reply, Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
                    }
                    return true;
                }
            } else {
                if (data != null && descriptor != null && !readArgs) {
                    data.enforceInterface(descriptor);
                }
                if (reply == null) {
                    return true;
                }
                reply.writeNoException();
                switch (d.action) {
                    case WRITE_BOOL:
                    case WRITE_INT:
                        reply.writeInt(d.intValue);
                        return true;
                    case WRITE_INT_ARRAY:
                        reply.writeIntArray(d.intArrayValue);
                        return true;
                    case WRITE_VOID:
                        return true;
                    case WRITE_STRING:
                        reply.writeString(d.stringValue);
                        return true;
                    case WRITE_STRING_LIST:
                        reply.writeStringList(d.stringListValue);
                        return true;
                    case WRITE_NULL_PARCELABLE:
                        reply.writeInt(0);
                        return true;
                    case WRITE_NULL_STRONG_BINDER:
                        reply.writeStrongBinder(null);
                        return true;
                    case WRITE_EMPTY_STRING_LIST:
                        reply.writeStringList(Collections.emptyList());
                        return true;
                    case WRITE_EMPTY_TYPED_LIST:
                        reply.writeTypedList(Collections.emptyList());
                        return true;
                    default:
                        passthrough = true;
                        break;
                }
            }
        } catch (Throwable ignored) {
            if (rewrittenData != null) {
                rewrittenData.recycle();
                rewrittenData = null;
            }
            if (reply != null) {
                reply.setDataSize(0);
                reply.setDataPosition(0);
            }
            postAction = null;
            passthrough = true;
        }
        if (passthrough && data != null) {
            data.setDataPosition(savedPos);
        }
        boolean ok;
        try {
            Parcel txData = (rewrittenData != null) ? rewrittenData : data;
            ok = delegate.transact(code, txData, reply, flags);
        } finally {
            if (rewrittenData != null) {
                rewrittenData.recycle();
            }
        }
        if (ok && postAction != null && reply != null) {
            switch (postAction) {
                case SANITIZE_LINK_PROPERTIES:
                    sanitizeLinkPropertiesReply(reply);
                    break;
                case SANITIZE_NETWORK_CAPABILITIES:
                    sanitizeNetworkCapabilitiesReply(reply);
                    break;
                case SANITIZE_NETWORK_CAPABILITIES_ARRAY:
                    sanitizeNetworkCapabilitiesArrayReply(reply);
                    break;
                case SANITIZE_NETWORK_INFO:
                    sanitizeNetworkInfoReply(reply);
                    break;
                case SANITIZE_NETWORK_INFO_ARRAY:
                    sanitizeNetworkInfoArrayReply(reply);
                    break;
                case SANITIZE_SUBSCRIPTION_INFO:
                    sanitizeSubscriptionInfoReply(reply, false);
                    break;
                case SANITIZE_SUBSCRIPTION_LIST:
                    sanitizeSubscriptionInfoReply(reply, true);
                    break;
                case SANITIZE_SERVICE_STATE:
                    sanitizeServiceStateReply(reply);
                    break;
                default:
                    break;
            }
        }
        return ok;
    }

    private static void commitReplyParcel(Parcel reply, Parcel tmp) {
        reply.setDataSize(0);
        reply.setDataPosition(0);
        reply.appendFrom(tmp, 0, tmp.dataSize());
        reply.setDataPosition(0);
    }

    private static void writeParcelableToReply(Parcel reply, Parcelable obj) {
        Parcel tmp = Parcel.obtain();
        try {
            tmp.writeNoException();
            tmp.writeInt(1);
            obj.writeToParcel(tmp, Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
            commitReplyParcel(reply, tmp);
        } finally {
            tmp.recycle();
        }
    }

    private static void writeTypedListToReply(Parcel reply, List<? extends Parcelable> list) {
        Parcel tmp = Parcel.obtain();
        try {
            tmp.writeNoException();
            tmp.writeTypedList(list);
            commitReplyParcel(reply, tmp);
        } finally {
            tmp.recycle();
        }
    }

    private static Map<String, Class<?>[]> resolveConnectivityMessengerPrefixes(Class<?> implClass, String desc) {
        Map<String, Class<?>[]> out = new java.util.HashMap<>();
        Class<?> iface = null;
        ClassLoader[] loaders = new ClassLoader[]{
                implClass != null ? implClass.getClassLoader() : null,
                ClassLoader.getSystemClassLoader(),
                Thread.currentThread().getContextClassLoader()
        };
        String ifaceName = (desc != null && !desc.isEmpty()) ? desc : "android.net.IConnectivityManager";
        for (ClassLoader cl : loaders) {
            try {
                iface = Class.forName(ifaceName, false, cl);
                if (iface != null) {
                    break;
                }
            } catch (Throwable ignored) {
            }
        }
        if (iface == null) {
            return Collections.emptyMap();
        }
        for (String targetMethod : new String[]{"listenForNetwork", "requestNetwork"}) {
            Class<?>[] agreedPrefix = null;
            boolean conflict = false;
            for (Method m : iface.getDeclaredMethods()) {
                if (!targetMethod.equals(m.getName())) {
                    continue;
                }
                Class<?>[] params = m.getParameterTypes();
                int msgIdx = -1;
                for (int i = 0; i < params.length; i++) {
                    if (params[i] == Messenger.class) {
                        msgIdx = i;
                        break;
                    }
                }
                if (msgIdx < 0) {
                    continue; // e.g. PendingIntent overload
                }
                boolean safePrefix = true;
                for (int i = 0; i < msgIdx; i++) {
                    if (params[i] != int.class && params[i] != NetworkCapabilities.class) {
                        safePrefix = false;
                        break;
                    }
                }
                if (!safePrefix) {
                    conflict = true;
                    break;
                }
                Class<?>[] cand = Arrays.copyOf(params, msgIdx);
                if (agreedPrefix == null) {
                    agreedPrefix = cand;
                } else if (!Arrays.equals(agreedPrefix, cand)) {
                    conflict = true;
                    break;
                }
            }
            if (!conflict && agreedPrefix != null) {
                out.put(targetMethod, agreedPrefix);
            }
        }
        return out;
    }

    private Parcel tryRewriteConnectivityMessengerParcel(String methodName, Parcel data, int savedPos) {
        Class<?>[] prefix = connectivityMessengerPrefixes.get(methodName);
        if (prefix == null || data == null) {
            return null;
        }
        Parcel rebuilt = Parcel.obtain();
        try {
            data.setDataPosition(savedPos);
            if (descriptor != null) {
                data.enforceInterface(descriptor);
                rebuilt.writeInterfaceToken(descriptor);
            }
            for (Class<?> pt : prefix) {
                if (pt == int.class) {
                    rebuilt.writeInt(data.readInt());
                } else if (pt == NetworkCapabilities.class) {
                    NetworkCapabilities reqNc = data.readTypedObject(NetworkCapabilities.CREATOR);
                    rebuilt.writeTypedObject(reqNc, 0);
                } else {
                    rebuilt.recycle();
                    return null;
                }
            }
            Messenger origMessenger = data.readTypedObject(Messenger.CREATOR);
            if (origMessenger == null || origMessenger.getBinder() == null
                    || origMessenger.getBinder() instanceof SanitizingMessengerBinder) {
                rebuilt.recycle();
                return null;
            }
            Messenger wrapped = new Messenger(
                    new SanitizingMessengerBinder(origMessenger.getBinder(), origMessenger, this));
            rebuilt.writeTypedObject(wrapped, 0);
            int remaining = data.dataSize() - data.dataPosition();
            if (remaining > 0) {
                rebuilt.appendFrom(data, data.dataPosition(), remaining);
            }
            rebuilt.setDataPosition(0);
            return rebuilt;
        } catch (Throwable ignored) {
            rebuilt.recycle();
            return null;
        }
    }

    private static final class SanitizingMessengerBinder extends Binder {
        private static final String IMESSENGER_DESC = "android.os.IMessenger";
        private final IBinder origBinder;
        private final Messenger origMessenger;
        private final SandboxBinderWrapper owner;

        SanitizingMessengerBinder(IBinder origBinder, Messenger origMessenger, SandboxBinderWrapper owner) {
            this.origBinder = origBinder;
            this.origMessenger = origMessenger;
            this.owner = owner;
        }

        // Keep queryLocalInterface() returning null so ConnectivityService uses IMessenger.Stub.Proxy -> onTransact.
        @Override
        public boolean pingBinder() {
            return origBinder.pingBinder();
        }

        @Override
        public boolean isBinderAlive() {
            return origBinder.isBinderAlive();
        }

        @Override
        public void linkToDeath(DeathRecipient recipient, int flags) {
            try {
                origBinder.linkToDeath(recipient, flags);
            } catch (RemoteException ignored) {
            }
        }

        @Override
        public boolean unlinkToDeath(DeathRecipient recipient, int flags) {
            return origBinder.unlinkToDeath(recipient, flags);
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            if (code != FIRST_CALL_TRANSACTION || data == null) {
                return origBinder.transact(code, data, reply, flags);
            }
            int savedPos = data.dataPosition();
            try {
                data.enforceInterface(IMESSENGER_DESC);
                if (data.readInt() == 0) {
                    data.setDataPosition(savedPos);
                    return origBinder.transact(code, data, reply, flags);
                }
                Message msg = Message.CREATOR.createFromParcel(data);
                if (msg == null) {
                    data.setDataPosition(savedPos);
                    return origBinder.transact(code, data, reply, flags);
                }
                owner.sanitizeCallbackMessage(msg);
                origMessenger.send(msg);
                return true;
            } catch (Throwable ignored) {
                data.setDataPosition(savedPos);
                return origBinder.transact(code, data, reply, flags);
            }
        }
    }

    @SuppressWarnings("deprecation")
    private void sanitizeCallbackMessage(Message msg) {
        if (msg == null) {
            return;
        }
        if (msg.obj instanceof NetworkCapabilities) {
            sanitizeNetworkCapabilitiesInPlace((NetworkCapabilities) msg.obj);
        } else if (msg.obj instanceof LinkProperties) {
            LinkProperties cleanLp = buildSanitizedLinkProperties((LinkProperties) msg.obj);
            if (cleanLp != null) {
                msg.obj = cleanLp;
            }
        }
        Bundle dataBundle = msg.peekData();
        if (dataBundle == null) {
            return;
        }
        try {
            dataBundle.setClassLoader(NetworkCapabilities.class.getClassLoader());
            for (String key : new ArrayList<>(dataBundle.keySet())) {
                Object val = dataBundle.get(key);
                if (val instanceof NetworkCapabilities) {
                    NetworkCapabilities nc = (NetworkCapabilities) val;
                    if (sanitizeNetworkCapabilitiesInPlace(nc)) {
                        dataBundle.putParcelable(key, nc);
                    }
                } else if (val instanceof LinkProperties) {
                    LinkProperties cleanLp = buildSanitizedLinkProperties((LinkProperties) val);
                    if (cleanLp != null) {
                        dataBundle.putParcelable(key, cleanLp);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private boolean sanitizeNetworkCapabilitiesInPlace(NetworkCapabilities orig) {
        if (orig == null) {
            return false;
        }
        boolean dirty = false;
        try {
            TransportInfo ti = orig.getTransportInfo();
            if (ti instanceof WifiInfo) {
                if (DEFAULT_REDACTED_WIFI_INFO != null) {
                    if (NC_SET_TRANSPORT_INFO != null) {
                        NC_SET_TRANSPORT_INFO.invoke(orig, DEFAULT_REDACTED_WIFI_INFO);
                        dirty = true;
                    } else if (NC_TRANSPORT_INFO_FIELD != null) {
                        NC_TRANSPORT_INFO_FIELD.set(orig, DEFAULT_REDACTED_WIFI_INFO);
                        dirty = true;
                    }
                }
            } else if (ti != null) {
                // Clear VpnTransportInfo or any non-WifiInfo TransportInfo unconditionally.
                if (NC_SET_TRANSPORT_INFO != null) {
                    NC_SET_TRANSPORT_INFO.invoke(orig, new Object[]{null});
                    dirty = true;
                } else if (NC_TRANSPORT_INFO_FIELD != null) {
                    NC_TRANSPORT_INFO_FIELD.set(orig, null);
                    dirty = true;
                }
            }
            if (orig.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                boolean removed = false;
                if (NC_REMOVE_TRANSPORT_TYPE != null) {
                    try {
                        NC_REMOVE_TRANSPORT_TYPE.invoke(orig, NetworkCapabilities.TRANSPORT_VPN);
                        removed = true;
                    } catch (Throwable ignored) {
                    }
                }
                if (!removed && NC_TRANSPORT_TYPES_FIELD != null && NC_TRANSPORT_TYPES_FIELD.getType() == long.class) {
                    long types = NC_TRANSPORT_TYPES_FIELD.getLong(orig);
                    types &= ~(1L << NetworkCapabilities.TRANSPORT_VPN);
                    NC_TRANSPORT_TYPES_FIELD.setLong(orig, types);
                    removed = true;
                }
                if (removed) {
                    boolean capAdded = false;
                    if (NC_ADD_CAPABILITY != null) {
                        try {
                            NC_ADD_CAPABILITY.invoke(orig, NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
                            capAdded = true;
                        } catch (Throwable ignored) {
                        }
                    }
                    if (!capAdded && NC_CAPABILITIES_FIELD != null && NC_CAPABILITIES_FIELD.getType() == long.class) {
                        long caps = NC_CAPABILITIES_FIELD.getLong(orig);
                        caps |= (1L << NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
                        NC_CAPABILITIES_FIELD.setLong(orig, caps);
                    }
                    if (!orig.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                            && !orig.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                            && !orig.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                            && !orig.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) {
                        boolean wifiAdded = false;
                        if (NC_ADD_TRANSPORT_TYPE != null) {
                            try {
                                NC_ADD_TRANSPORT_TYPE.invoke(orig, NetworkCapabilities.TRANSPORT_WIFI);
                                wifiAdded = true;
                            } catch (Throwable ignored) {
                            }
                        }
                        if (!wifiAdded && NC_TRANSPORT_TYPES_FIELD != null && NC_TRANSPORT_TYPES_FIELD.getType() == long.class) {
                            long types = NC_TRANSPORT_TYPES_FIELD.getLong(orig);
                            types |= (1L << NetworkCapabilities.TRANSPORT_WIFI);
                            NC_TRANSPORT_TYPES_FIELD.setLong(orig, types);
                        }
                    }
                    dirty = true;
                }
            }
            if (NC_UNDERLYING_NETWORKS_FIELD != null) {
                Object curUnderlying = NC_UNDERLYING_NETWORKS_FIELD.get(orig);
                if (curUnderlying != null) {
                    boolean cleared = false;
                    if (NC_SET_UNDERLYING_NETWORKS != null) {
                        try {
                            NC_SET_UNDERLYING_NETWORKS.invoke(orig, new Object[]{null});
                            cleared = true;
                        } catch (Throwable ignored) {
                        }
                    }
                    if (!cleared) {
                        NC_UNDERLYING_NETWORKS_FIELD.set(orig, null);
                    }
                    dirty = true;
                }
            }
            if (orig.getOwnerUid() != -1) {
                if (NC_SET_OWNER_UID != null) {
                    try {
                        NC_SET_OWNER_UID.invoke(orig, -1);
                        dirty = true;
                    } catch (Throwable ignored) {
                    }
                }
                if (orig.getOwnerUid() != -1 && NC_OWNER_UID_FIELD != null && NC_OWNER_UID_FIELD.getType() == int.class) {
                    NC_OWNER_UID_FIELD.setInt(orig, -1);
                    dirty = true;
                }
            }
            int[] curAdmin = null;
            if (NC_ADMIN_UIDS_FIELD != null) {
                Object rawAdmin = NC_ADMIN_UIDS_FIELD.get(orig);
                if (rawAdmin instanceof int[]) {
                    curAdmin = (int[]) rawAdmin;
                }
            } else if (NC_GET_ADMIN_UIDS != null) {
                Object rawAdmin = NC_GET_ADMIN_UIDS.invoke(orig);
                if (rawAdmin instanceof int[]) {
                    curAdmin = (int[]) rawAdmin;
                }
            }
            if (curAdmin != null && curAdmin.length > 0) {
                boolean adminCleared = false;
                if (NC_SET_ADMIN_UIDS != null) {
                    try {
                        NC_SET_ADMIN_UIDS.invoke(orig, new Object[]{new int[0]});
                        adminCleared = true;
                    } catch (Throwable ignored) {
                    }
                }
                if (!adminCleared && NC_ADMIN_UIDS_FIELD != null) {
                    NC_ADMIN_UIDS_FIELD.set(orig, new int[0]);
                    adminCleared = true;
                }
                if (adminCleared) {
                    dirty = true;
                }
            }
            if (clearObjectPropIfNonNull(NC_SET_SSID, NC_SSID_FIELD, orig)) {
                dirty = true;
            }
            if (clearObjectPropIfNonNull(NC_SET_UIDS, NC_UIDS_FIELD, orig)) {
                dirty = true;
            }
            if (NC_ESTABLISHING_VPN_UID_FIELD != null
                    && NC_ESTABLISHING_VPN_UID_FIELD.getType() == int.class
                    && NC_ESTABLISHING_VPN_UID_FIELD.getInt(orig) != -1) {
                NC_ESTABLISHING_VPN_UID_FIELD.setInt(orig, -1);
                dirty = true;
            }
        } catch (Throwable ignored) {
        }
        return dirty;
    }

    private static boolean clearObjectPropIfNonNull(Method setter, Field field, Object target) {
        if (field == null) {
            return false;
        }
        try {
            if (field.get(target) == null) {
                return false;
            }
            if (setter != null) {
                try {
                    setter.invoke(target, new Object[]{null});
                    return true;
                } catch (Throwable ignored) {
                }
            }
            field.set(target, null);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void applyBoolProp(Method setter, Field field, Object target, boolean val) {
        if (setter != null) {
            try {
                setter.invoke(target, val);
                return;
            } catch (Throwable ignored) {
            }
        }
        if (field != null) {
            try {
                field.setBoolean(target, val);
            } catch (Throwable ignored) {
            }
        }
    }

    @SuppressWarnings("deprecation")
    private static android.net.NetworkInfo sanitizeNetworkInfo(android.net.NetworkInfo orig) {
        if (orig == null) {
            return null;
        }
        if (orig.getType() == 17) { // ConnectivityManager.TYPE_VPN
            android.net.NetworkInfo clean = new android.net.NetworkInfo(1, 0, "WIFI", "");
            clean.setDetailedState(orig.getDetailedState(), null, null);
            applyBoolProp(NI_SET_IS_AVAILABLE, NI_IS_AVAILABLE_FIELD, clean, orig.isAvailable());
            applyBoolProp(NI_SET_FAILOVER, NI_IS_FAILOVER_FIELD, clean, orig.isFailover());
            applyBoolProp(NI_SET_ROAMING, NI_IS_ROAMING_FIELD, clean, orig.isRoaming());
            return clean;
        }
        if (orig.getExtraInfo() != null) { // Scrub SSID / carrier APN extraInfo on all non-VPN NetworkInfo objects
            orig.setDetailedState(orig.getDetailedState(), orig.getReason(), null);
            return orig;
        }
        return null;
    }

    @SuppressWarnings("deprecation")
    private void sanitizeNetworkInfoReply(Parcel reply) {
        int savedPos = reply.dataPosition();
        try {
            reply.setDataPosition(0);
            reply.readException();
            if (reply.readInt() == 0) {
                reply.setDataPosition(savedPos);
                return;
            }
            android.net.NetworkInfo orig = android.net.NetworkInfo.CREATOR.createFromParcel(reply);
            android.net.NetworkInfo clean = sanitizeNetworkInfo(orig);
            if (clean == null) {
                reply.setDataPosition(savedPos);
                return;
            }
            writeParcelableToReply(reply, clean);
        } catch (Throwable ignored) {
            reply.setDataPosition(savedPos);
        }
    }

    @SuppressWarnings("deprecation")
    private void sanitizeNetworkInfoArrayReply(Parcel reply) {
        int savedPos = reply.dataPosition();
        Parcel tmp = null;
        try {
            reply.setDataPosition(0);
            reply.readException();
            android.net.NetworkInfo[] arr = reply.createTypedArray(android.net.NetworkInfo.CREATOR);
            if (arr == null || arr.length == 0) {
                reply.setDataPosition(savedPos);
                return;
            }
            boolean hasNonVpn = false;
            for (android.net.NetworkInfo ni : arr) {
                if (ni != null && ni.getType() != 17) {
                    hasNonVpn = true;
                    break;
                }
            }
            boolean dirty = false;
            List<android.net.NetworkInfo> out = new ArrayList<>(arr.length);
            for (android.net.NetworkInfo ni : arr) {
                if (ni == null) {
                    out.add(null);
                    continue;
                }
                if (ni.getType() == 17 && hasNonVpn) {
                    dirty = true;
                    continue;
                }
                android.net.NetworkInfo clean = sanitizeNetworkInfo(ni);
                if (clean != null) {
                    out.add(clean);
                    dirty = true;
                } else {
                    out.add(ni);
                }
            }
            if (!dirty) {
                reply.setDataPosition(savedPos);
                return;
            }
            tmp = Parcel.obtain();
            tmp.writeNoException();
            tmp.writeTypedArray(out.toArray(new android.net.NetworkInfo[0]), Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
            commitReplyParcel(reply, tmp);
        } catch (Throwable ignored) {
            reply.setDataPosition(savedPos);
        } finally {
            if (tmp != null) {
                tmp.recycle();
            }
        }
    }

    private void sanitizeNetworkCapabilitiesReply(Parcel reply) {
        int savedPos = reply.dataPosition();
        try {
            reply.setDataPosition(0);
            reply.readException();
            if (reply.readInt() == 0) {
                reply.setDataPosition(savedPos);
                return;
            }
            NetworkCapabilities orig = NetworkCapabilities.CREATOR.createFromParcel(reply);
            if (orig == null || !sanitizeNetworkCapabilitiesInPlace(orig)) {
                reply.setDataPosition(savedPos);
                return;
            }
            writeParcelableToReply(reply, orig);
        } catch (Throwable ignored) {
            reply.setDataPosition(savedPos);
        }
    }

    private void sanitizeNetworkCapabilitiesArrayReply(Parcel reply) {
        int savedPos = reply.dataPosition();
        Parcel tmp = null;
        try {
            reply.setDataPosition(0);
            reply.readException();
            NetworkCapabilities[] arr = reply.createTypedArray(NetworkCapabilities.CREATOR);
            if (arr == null || arr.length == 0) {
                reply.setDataPosition(savedPos);
                return;
            }
            boolean dirty = false;
            for (NetworkCapabilities nc : arr) {
                if (nc != null && sanitizeNetworkCapabilitiesInPlace(nc)) {
                    dirty = true;
                }
            }
            if (!dirty) {
                reply.setDataPosition(savedPos);
                return;
            }
            tmp = Parcel.obtain();
            tmp.writeNoException();
            tmp.writeTypedArray(arr, Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
            commitReplyParcel(reply, tmp);
        } catch (Throwable ignored) {
            reply.setDataPosition(savedPos);
        } finally {
            if (tmp != null) {
                tmp.recycle();
            }
        }
    }

    private void sanitizeServiceStateReply(Parcel reply) {
        int savedPos = reply.dataPosition();
        try {
            reply.setDataPosition(0);
            reply.readException();
            if (reply.readInt() == 0) {
                reply.setDataPosition(savedPos);
                return;
            }
            ServiceState orig = ServiceState.CREATOR.createFromParcel(reply);
            if (orig == null) {
                reply.setDataPosition(savedPos);
                return;
            }
            ServiceState clean = orig;
            if (SS_CREATE_LOCATION_SANITIZED != null) {
                try {
                    Object copy = SS_CREATE_LOCATION_SANITIZED.invoke(orig, true);
                    if (copy instanceof ServiceState) {
                        clean = (ServiceState) copy;
                    }
                } catch (Throwable ignored) {
                }
            }
            String carrier = (config.networkOperatorName != null && !config.networkOperatorName.isEmpty())
                    ? config.networkOperatorName
                    : config.simOperatorName;
            String netOp = (config.networkOperator != null && !config.networkOperator.isEmpty())
                    ? config.networkOperator
                    : config.simOperator;
            List<NetworkRegistrationInfo> regList = clean.getNetworkRegistrationInfoList();
            if (regList != null) {
                for (NetworkRegistrationInfo nri : regList) {
                    if (nri == null) {
                        continue;
                    }
                    setFieldIfPresent(NRI_CELL_IDENTITY, nri, null);
                    if (!netOp.isEmpty()) {
                        setFieldIfPresent(NRI_REGISTERED_PLMN, nri, netOp);
                    }
                }
            }
            if (!carrier.isEmpty() || !netOp.isEmpty()) {
                clean.setOperatorName(carrier, carrier, netOp);
            }
            writeParcelableToReply(reply, clean);
        } catch (Throwable ignored) {
            reply.setDataPosition(savedPos);
        }
    }

    private void mutateSubscriptionInfo(SubscriptionInfo info) {
        if (info == null) {
            return;
        }
        String simOp = config.simOperator != null ? config.simOperator.trim() : "";
        String mccStr = simOp.length() >= 3 ? simOp.substring(0, 3) : "";
        String mncStr = simOp.length() > 3 ? simOp.substring(3) : "";
        int mccInt = 0;
        int mncInt = 0;
        if (!mccStr.isEmpty()) {
            try {
                mccInt = Integer.parseInt(mccStr);
            } catch (NumberFormatException ignored) {
            }
        }
        if (!mncStr.isEmpty()) {
            try {
                mncInt = Integer.parseInt(mncStr);
            } catch (NumberFormatException ignored) {
            }
        }
        String carrier = config.simOperatorName != null ? config.simOperatorName : "";
        String iso = config.simCountryIso != null ? config.simCountryIso : "";

        if (!carrier.isEmpty()) {
            setFieldIfPresent(SUB_CARRIER_NAME, info, carrier);
            setFieldIfPresent(SUB_DISPLAY_NAME, info, carrier);
        }
        if (!iso.isEmpty()) {
            setFieldIfPresent(SUB_COUNTRY_ISO, info, iso);
        }
        if (!mccStr.isEmpty()) {
            setFieldIfPresent(SUB_MCC_STR, info, mccStr);
            if (SUB_MCC != null) {
                if (SUB_MCC.getType() == String.class) {
                    setFieldIfPresent(SUB_MCC, info, mccStr);
                } else if (SUB_MCC.getType() == int.class) {
                    setFieldIntIfPresent(SUB_MCC, info, mccInt);
                }
            }
        }
        if (!mncStr.isEmpty()) {
            setFieldIfPresent(SUB_MNC_STR, info, mncStr);
            if (SUB_MNC != null) {
                if (SUB_MNC.getType() == String.class) {
                    setFieldIfPresent(SUB_MNC, info, mncStr);
                } else if (SUB_MNC.getType() == int.class) {
                    setFieldIntIfPresent(SUB_MNC, info, mncInt);
                }
            }
        }
        if (SUB_CARRIER_ID != null && SUB_CARRIER_ID.getType() == int.class) {
            setFieldIntIfPresent(SUB_CARRIER_ID, info, BinderInterceptionPolicy.carrierIdForOperator(simOp));
        }
        setFieldIfPresent(SUB_CARD_STRING, info, "");
        String[] plmnArr = simOp.isEmpty() ? new String[0] : new String[]{simOp};
        if (SUB_HPLMNS != null && SUB_HPLMNS.getType() == String[].class) {
            setFieldIfPresent(SUB_HPLMNS, info, plmnArr);
        }
        if (SUB_EHPLMNS != null && SUB_EHPLMNS.getType() == String[].class) {
            setFieldIfPresent(SUB_EHPLMNS, info, plmnArr);
        }
        setFieldIfPresent(SUB_GROUP_UUID, info, null);
        setFieldIfPresent(SUB_GROUP_OWNER, info, null);
        setFieldIfPresent(SUB_ICC_ID, info, "");
        setFieldIfPresent(SUB_NUMBER, info, "");
    }

    private static void setFieldIfPresent(Field f, Object target, Object val) {
        if (f != null) {
            try {
                f.set(target, val);
            } catch (Throwable ignored) {
            }
        }
    }

    private static void setFieldIntIfPresent(Field f, Object target, int val) {
        if (f != null) {
            try {
                f.setInt(target, val);
            } catch (Throwable ignored) {
            }
        }
    }

    private void sanitizeSubscriptionInfoReply(Parcel reply, boolean isList) {
        int savedPos = reply.dataPosition();
        try {
            reply.setDataPosition(0);
            reply.readException();
            if (isList) {
                List<SubscriptionInfo> list = reply.createTypedArrayList(SubscriptionInfo.CREATOR);
                if (list == null || list.isEmpty()) {
                    reply.setDataPosition(savedPos);
                    return;
                }
                for (SubscriptionInfo item : list) {
                    mutateSubscriptionInfo(item);
                }
                writeTypedListToReply(reply, list);
            } else {
                if (reply.readInt() == 0) {
                    reply.setDataPosition(savedPos);
                    return;
                }
                SubscriptionInfo info = SubscriptionInfo.CREATOR.createFromParcel(reply);
                if (info == null) {
                    reply.setDataPosition(savedPos);
                    return;
                }
                mutateSubscriptionInfo(info);
                writeParcelableToReply(reply, info);
            }
        } catch (Throwable ignored) {
            reply.setDataPosition(savedPos);
        }
    }

    private static RouteInfo buildRouteInfo(IpPrefix prefix, InetAddress gateway, String ifName) {
        try {
            if (ROUTE_INFO_CTOR_4 != null) {
                return ROUTE_INFO_CTOR_4.newInstance(prefix, gateway, ifName, RouteInfo.RTN_UNICAST);
            }
            if (ROUTE_INFO_CTOR_3 != null) {
                return ROUTE_INFO_CTOR_3.newInstance(prefix, gateway, ifName);
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private void addSynthesizedIpv4Routes(LinkProperties clean, String ifName) {
        if (ROUTE_INFO_CTOR_4 == null && ROUTE_INFO_CTOR_3 == null) {
            return;
        }
        try {
            byte[] linkOctets = parseIpv4Octets(config.sandboxLinkIpv4);
            byte[] subnetBytes = new byte[]{linkOctets[0], linkOctets[1], linkOctets[2], 0};
            byte[] gwBytes = new byte[]{
                    linkOctets[0],
                    linkOctets[1],
                    linkOctets[2],
                    (byte) ((linkOctets[3] == 1) ? 254 : 1)
            };
            IpPrefix localSubnet = new IpPrefix(InetAddress.getByAddress(subnetBytes), 24);
            RouteInfo localRoute = buildRouteInfo(localSubnet, null, ifName);
            if (localRoute != null) {
                clean.addRoute(localRoute);
            }
            IpPrefix defaultPrefix = new IpPrefix(InetAddress.getByAddress(new byte[]{0, 0, 0, 0}), 0);
            RouteInfo defaultRoute = buildRouteInfo(defaultPrefix, InetAddress.getByAddress(gwBytes), ifName);
            if (defaultRoute != null) {
                clean.addRoute(defaultRoute);
            }
        } catch (Throwable ignored) {
        }
    }

    private LinkProperties buildSanitizedLinkProperties(LinkProperties orig) {
        if (orig == null || sanitizedLinkAddresses == null || sanitizedDnsServers == null) {
            return null;
        }
        LinkProperties clean = new LinkProperties();
        String rawIfName = orig.getInterfaceName();
        String ifName = (rawIfName != null && !rawIfName.isEmpty()) ? rawIfName : "wlan0";
        if (ifName.startsWith("tun")) {
            ifName = "wlan0";
        }
        clean.setInterfaceName(ifName);
        int mtu = orig.getMtu();
        if (mtu > 0) {
            clean.setMtu(mtu);
        }
        clean.setLinkAddresses(sanitizedLinkAddresses);
        clean.setDnsServers(sanitizedDnsServers);
        addSynthesizedIpv4Routes(clean, ifName);
        return clean;
    }

    private void sanitizeLinkPropertiesReply(Parcel reply) {
        if (sanitizedLinkAddresses == null || sanitizedDnsServers == null) {
            return;
        }
        int savedPos = reply.dataPosition();
        try {
            reply.setDataPosition(0);
            reply.readException();
            if (reply.readInt() == 0) {
                reply.setDataPosition(savedPos);
                return;
            }
            LinkProperties orig = LinkProperties.CREATOR.createFromParcel(reply);
            LinkProperties clean = buildSanitizedLinkProperties(orig);
            if (clean == null) {
                reply.setDataPosition(savedPos);
                return;
            }
            writeParcelableToReply(reply, clean);
        } catch (Throwable ignored) {
            reply.setDataPosition(savedPos);
        }
    }

    private FastSlot resolveFastSlot(int code) {
        String name = codeToMethod.get(code);
        if (name != null) {
            return cacheFastSlot(code, name);
        }
        String resolved = BinderInterceptionPolicy.resolveViaStubMethod(delegate.getClass(), descriptor, code);
        if (resolved != null && !resolved.isEmpty()) {
            codeToMethod.putIfAbsent(code, resolved);
            return cacheFastSlot(code, resolved);
        }
        codeToMethod.putIfAbsent(code, NO_METHOD);
        return cacheFastSlot(code, NO_METHOD);
    }

    private String resolveMethodName(int code) {
        FastSlot slot = resolveFastSlot(code);
        return (slot == NO_METHOD_SLOT || slot.methodName.isEmpty()) ? null : slot.methodName;
    }
}
