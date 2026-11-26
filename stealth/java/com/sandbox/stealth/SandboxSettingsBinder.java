package com.sandbox.stealth;

import android.content.AttributionSource;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.util.ArrayList;

/**
 * Wraps the Settings ContentProvider's Binder inside system_server so that sandbox UIDs
 * see adb_enabled=0 / development_settings_enabled=0 via Settings.Global.getInt/getString,
 * while User 0, User 999, shell, and system callers bypass directly to delegate.
 */
public final class SandboxSettingsBinder extends Binder {
    private static final String ICONTENT_PROVIDER_DESCRIPTOR = "android.content.IContentProvider";
    private static final int CALL_TRANSACTION_CODE = resolveCallTransactionCode();

    private final IBinder delegate;
    private final StealthConfig config;

    public SandboxSettingsBinder(IBinder delegate, StealthConfig config) {
        this.delegate = delegate;
        this.config = config;
    }

    private static int resolveCallTransactionCode() {
        try {
            Class<?> icp = Class.forName(ICONTENT_PROVIDER_DESCRIPTOR);
            Field f = icp.getDeclaredField("CALL_TRANSACTION");
            f.setAccessible(true);
            return f.getInt(null);
        } catch (Throwable ignored) {
            return 21;
        }
    }

    public IBinder unwrap() {
        return delegate;
    }

    @Override
    public String getInterfaceDescriptor() {
        try {
            String desc = delegate.getInterfaceDescriptor();
            if (desc != null) {
                return desc;
            }
        } catch (Throwable ignored) {
        }
        return ICONTENT_PROVIDER_DESCRIPTOR;
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
        if (!config.hideAdb || !config.shouldIntercept(Binder.getCallingUid())
                || code != CALL_TRANSACTION_CODE || data == null) {
            return delegate.transact(code, data, reply, flags);
        }

        int savedPos = data.dataPosition();
        try {
            data.enforceInterface(ICONTENT_PROVIDER_DESCRIPTOR);
            AttributionSource.CREATOR.createFromParcel(data);
            String authority = data.readString();
            String method = data.readString();
            String arg = data.readString();
            if ("settings".equals(authority)) {
                if ("GET_global".equals(method)) {
                    String spoofed = BinderInterceptionPolicy.spoofedSettingsGlobalValue(arg, config);
                    if (spoofed != null && reply != null) {
                        reply.writeNoException();
                        Bundle out = new Bundle();
                        out.putString("value", spoofed);
                        reply.writeBundle(out);
                        return true;
                    }
                } else if ("LIST_global".equals(method) && reply != null) {
                    data.setDataPosition(savedPos);
                    boolean ok = delegate.transact(code, data, reply, flags);
                    if (ok) {
                        sanitizeListGlobalReply(reply, config);
                    }
                    return ok;
                }
            }
        } catch (Throwable ignored) {
            // Fail open on unexpected OEM Parcel layout.
        }
        data.setDataPosition(savedPos);
        return delegate.transact(code, data, reply, flags);
    }

    private static void sanitizeListGlobalReply(Parcel reply, StealthConfig cfg) {
        try {
            reply.setDataPosition(0);
            reply.readException();
            Bundle b = reply.readBundle();
            if (b == null) {
                reply.setDataPosition(0);
                return;
            }
            boolean modified = false;
            for (String key : new ArrayList<>(b.keySet())) {
                if (BinderInterceptionPolicy.spoofedSettingsGlobalValue(key, cfg) != null) {
                    b.putString(key, "0");
                    modified = true;
                }
            }
            if (modified) {
                reply.setDataPosition(0);
                reply.setDataSize(0);
                reply.writeNoException();
                reply.writeBundle(b);
            } else {
                reply.setDataPosition(0);
            }
        } catch (Throwable ignored) {
            try {
                reply.setDataPosition(0);
            } catch (Throwable ignored2) {
            }
        }
    }
}
