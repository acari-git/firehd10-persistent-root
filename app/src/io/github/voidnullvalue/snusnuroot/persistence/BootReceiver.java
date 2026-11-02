package io.github.voidnullvalue.snusnuroot.persistence;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public final class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "SnuSnuPersist";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent == null ? null : intent.getAction();
        if (!Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            Log.w(TAG, "ignored non-system receiver action");
            return;
        }
        Log.i(TAG, "receiver action=" + action);
        try {
            context.startForegroundService(new Intent(context, PersistenceService.class));
        } catch (Throwable error) {
            Log.e(TAG, "startForegroundService failed", error);
        }
    }
}
