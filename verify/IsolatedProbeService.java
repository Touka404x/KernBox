package com.sandbox.verify;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;

import org.json.JSONObject;

import java.util.Locale;
import java.util.TimeZone;

/** Isolated sandboxed service (uid = userId*100000 + 99000..99999) for /proc & stealth hygiene audit. */
public final class IsolatedProbeService extends Service {
    static final int MSG_COLLECT_PROC = 1;
    static final int MSG_COLLECT_PROC_REPLY = 2;
    static final String EXTRA_JSON = "json";

    private HandlerThread workerThread;
    private Messenger messenger;

    @Override
    public void onCreate() {
        super.onCreate();
        workerThread = new HandlerThread("IsolatedProbeWorker");
        workerThread.start();
        messenger = new Messenger(new IncomingHandler(workerThread.getLooper()));
    }

    @Override
    public IBinder onBind(Intent intent) {
        return messenger.getBinder();
    }

    @Override
    public void onDestroy() {
        if (workerThread != null) {
            workerThread.quitSafely();
        }
        super.onDestroy();
    }

    private static final class IncomingHandler extends Handler {
        IncomingHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            if (msg.what != MSG_COLLECT_PROC || msg.replyTo == null) {
                super.handleMessage(msg);
                return;
            }
            JSONObject scan = ProcHygieneScanner.scan();
            try {
                scan.put("timezone", TimeZone.getDefault().getID());
                scan.put("locale", Locale.getDefault().toLanguageTag());
            } catch (Exception ignored) {
            }
            Bundle bundle = new Bundle();
            bundle.putString(EXTRA_JSON, scan.toString());
            Message reply = Message.obtain(null, MSG_COLLECT_PROC_REPLY);
            reply.setData(bundle);
            try {
                msg.replyTo.send(reply);
            } catch (Exception ignored) {
                // Caller disconnected before reply.
            }
        }
    }
}
