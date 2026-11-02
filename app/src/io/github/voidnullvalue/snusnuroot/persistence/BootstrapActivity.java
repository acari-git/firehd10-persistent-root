package io.github.voidnullvalue.snusnuroot.persistence;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

/** One-time explicit launch used by the installer to clear package stopped state. */
public final class BootstrapActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Log.i("SnuSnuPersist", "bootstrap launch; package is boot-deliverable");
        finish();
    }
}
