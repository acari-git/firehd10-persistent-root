"""Execute the v2 PersistenceService proof-drop gate on the host.

Regression coverage for the 2026-11-01 boot-196 genesis_rejected
incident (diagnosis: diagnostics/genesis-rejected-diagnosis-20261102).
The genesis drop consumed by a successful genesis stays in the app
mailbox as evidence and the app never deletes drops. Before the fix,
every later start with journal INFLIGHT and a resolvable boot id
re-evaluated that stale drop as a lockout-recovery candidate; its
inevitable verification failure overwrote snusnu_proof_status with
genesis_rejected and consumed the standing genesis challenge.

This module compiles the REAL PersistenceService and journal classes
from the journal-gated implementation tree against host Android
doubles and drives processProofDrops through the real code paths:

  A. genesis install from EMPTY (drop bound to the standing challenge);
  B. the boot-196 trigger: journal INFLIGHT, the stale consumed drop
     still in the mailbox, a resolvable boot id -- the proof status
     and the standing challenge must both survive two app starts
     byte-identical, and the journal must not move;
  C. a genuine lockout recovery (drop signed over the standing
     challenge) must still be accepted through the gate;
  D. genesisChallengeOf parsing;
  E. from EMPTY, a drop bound to a foreign challenge is inert, and
     the genuine drop then installs.

This proves host-side protocol behaviour only. It does NOT prove
Android storage durability, SELinux behaviour, or that any signature
was produced by a process really holding MagiskSU uid=0.
"""

from pathlib import Path
import subprocess
import tempfile
import unittest

from test_execute_firehd10_journal_on_host_20261014 import JAVA_SOURCES, ROOT, JDK


V2_TREE = (ROOT / 'build/journal-gated-implementation-20261101/v2')
V2_PKG = (V2_TREE / 'stage4-persistent/app/src/io/github/voidnullvalue'
          '/snusnuroot/persistence')
REAL_CLASSES = ('PersistenceService.java', 'Stage4AttemptJournalV2.java',
                'Stage4GenesisVerifier.java', 'Stage4BootWitness.java',
                'Stage4ProofDrop.java', 'Stage4ProofVerifier.java',
                'NativeOutputSanitizer.java')

# Same property-controlled boot identity double as the v2 journal test.
BOOT_IDENTITY_STUB = r'''
package io.github.voidnullvalue.snusnuroot.persistence;
final class Stage4BootIdentity {
    static String readCurrentBootId() {
        String value = System.getProperty("snu.test.boot.id", "NONE");
        return "NONE".equals(value) ? null : value;
    }
}
'''

EXTRA_SOURCES = {
    # Extended Context double: the journal harness one only knows a
    # File ctor; the Service needs a no-arg ctor (files dir from a
    # system property), a content resolver, shared preferences, a
    # notification manager and a permission check.
    'android/content/Context.java': r'''
package android.content;
import java.io.File;
public class Context {
    public static final int MODE_PRIVATE = 0;
    public static final String NOTIFICATION_SERVICE = "notification";
    private final File dir;
    private final ContentResolver resolver = new ContentResolver();
    public Context() {
        this.dir = new File(
            System.getProperty("snu.test.filesdir", "."));
    }
    public Context(File dir) { this.dir = dir; }
    public Context createDeviceProtectedStorageContext() { return this; }
    public File getFilesDir() { return dir; }
    public ContentResolver getContentResolver() { return resolver; }
    public SharedPreferences getSharedPreferences(String name, int mode) {
        return new SharedPreferences();
    }
    public Object getSystemService(String name) {
        if (NOTIFICATION_SERVICE.equals(name)) {
            return new android.app.NotificationManager();
        }
        return null;
    }
    public <T> T getSystemService(Class<T> serviceClass) {
        if (serviceClass == android.app.NotificationManager.class) {
            return serviceClass.cast(
                new android.app.NotificationManager());
        }
        return null;
    }
    public int checkSelfPermission(String permission) { return 0; }
    public Context getApplicationContext() { return this; }
    public String getPackageName() {
        return "io.github.voidnullvalue.snusnuroot.persistence";
    }
}
''',
    'android/R.java': r'''
package android;
public class R {
    public static class drawable {
        public static final int stat_notify_sync = 0x01030000;
    }
}
''',
    'android/content/ContentResolver.java': r'''
package android.content;
import android.net.Uri;
public class ContentResolver {
    public int delete(Uri uri, String where, String[] args) { return 0; }
}
''',
    'android/content/SharedPreferences.java': r'''
package android.content;
public class SharedPreferences {
    public String getString(String key, String defValue) {
        return defValue;
    }
}
''',
    'android/content/Intent.java': r'''
package android.content;
public class Intent {
    private String action;
    public Intent() {}
    public Intent(String action) { this.action = action; }
    public String getAction() { return action; }
    public Intent setAction(String action) {
        this.action = action;
        return this;
    }
}
''',
    'android/content/pm/PackageManager.java': r'''
package android.content.pm;
public class PackageManager {
    public static final int PERMISSION_GRANTED = 0;
    public static final int PERMISSION_DENIED = -1;
}
''',
    'android/Manifest.java': r'''
package android;
public class Manifest {
    public static class permission {
        public static final String WRITE_SECURE_SETTINGS =
            "android.permission.WRITE_SECURE_SETTINGS";
    }
}
''',
    'android/app/Service.java': r'''
package android.app;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
public abstract class Service extends Context {
    public static final int START_STICKY = 1;
    public static final int START_NOT_STICKY = 2;
    public abstract IBinder onBind(Intent intent);
    public void onCreate() {}
    public void onDestroy() {}
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_NOT_STICKY;
    }
    public final void stopSelf() {}
    public final void startForeground(int id, Notification n) {}
}
''',
    'android/app/Notification.java': r'''
package android.app;
import android.content.Context;
public class Notification {
    public static class Builder {
        public Builder(Context context, String channelId) {}
        public Builder setSmallIcon(int icon) { return this; }
        public Builder setContentTitle(CharSequence t) { return this; }
        public Builder setContentText(CharSequence t) { return this; }
        public Builder setOngoing(boolean b) { return this; }
        public Notification build() { return new Notification(); }
    }
}
''',
    'android/app/NotificationChannel.java': r'''
package android.app;
public class NotificationChannel {
    public NotificationChannel(String id, CharSequence name,
            int importance) {}
    public void setDescription(String description) {}
}
''',
    'android/app/NotificationManager.java': r'''
package android.app;
public class NotificationManager {
    public static final int IMPORTANCE_DEFAULT = 3;
    public static final int IMPORTANCE_LOW = 2;
    public static final int IMPORTANCE_HIGH = 4;
    public void createNotificationChannel(NotificationChannel c) {}
    public void notify(int id, Notification n) {}
}
''',
    'android/net/Uri.java': r'''
package android.net;
public class Uri {
    private final String value;
    public Uri(String value) { this.value = value; }
    public String toString() { return value; }
}
''',
    'android/os/IBinder.java': r'''
package android.os;
public interface IBinder {}
''',
    'android/os/SystemClock.java': r'''
package android.os;
public class SystemClock {
    public static long elapsedRealtime() {
        return Long.parseLong(
            System.getProperty("snu.test.elapsed", "100000"));
    }
}
''',
    'android/provider/Settings.java': r'''
package android.provider;
import android.content.ContentResolver;
import android.net.Uri;
import java.util.HashMap;
import java.util.Map;
public class Settings {
    public static class Global {
        public static final String BOOT_COUNT = "boot_count";
        public static final Map<String, String> VALUES = new HashMap<>();
        public static String getString(ContentResolver r, String name) {
            return VALUES.get(name);
        }
        public static boolean putString(ContentResolver r, String name,
                String value) {
            if (value == null) VALUES.remove(name);
            else VALUES.put(name, value);
            return true;
        }
        public static Uri getUriFor(String name) {
            return new Uri("content://settings/global/" + name);
        }
    }
}
''',
    'android/util/Log.java': r'''
package android.util;
public class Log {
    public static int i(String tag, String msg) {
        System.err.println("I/" + tag + ": " + msg);
        return 0;
    }
    public static int w(String tag, String msg) {
        System.err.println("W/" + tag + ": " + msg);
        return 0;
    }
    public static int e(String tag, String msg) {
        System.err.println("E/" + tag + ": " + msg);
        return 0;
    }
    public static int e(String tag, String msg, Throwable tr) {
        System.err.println("E/" + tag + ": " + msg + " (" + tr + ")");
        return 0;
    }
    public static int d(String tag, String msg) { return 0; }
}
''',
}

HARNESS = r'''
import android.provider.Settings;
import io.github.voidnullvalue.snusnuroot.persistence.PersistenceService;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4AttemptJournalV2;
import java.io.File;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class HostProofDropGateHarness {
    static final String B1 = "11111111-1111-1111-1111-111111111111";
    static final String B2 = "22222222-2222-2222-2222-222222222222";
    static int passed = 0;
    static Path priv;
    static File dps;
    static PersistenceService service;
    static Stage4AttemptJournalV2 journal;
    static Method processDrops;

    static void check(boolean good, String name) {
        if (!good) throw new AssertionError("FAILED: " + name);
        passed++;
        System.out.println("PASS " + name);
    }

    static void setProc(String boot) {
        System.setProperty("snu.test.boot.id",
            boot == null ? "NONE" : boot);
    }

    static PersistenceService newService(File dir) throws Exception {
        System.setProperty("snu.test.filesdir", dir.getAbsolutePath());
        return new PersistenceService();
    }

    static void drops(PersistenceService svc) throws Exception {
        processDrops.invoke(svc, svc.getContentResolver());
    }

    static String read(File file) throws Exception {
        return new String(Files.readAllBytes(file.toPath()),
            StandardCharsets.UTF_8);
    }

    static File challengeFile(File dir) {
        return new File(dir, "stage4-genesis-challenge.state");
    }

    static File stateFile(File dir) {
        return new File(dir, "stage4-native-attempt-v2.state");
    }

    static String status() {
        return Settings.Global.VALUES.get("snusnu_proof_status");
    }

    static void placeDrop(File dir, String[] msgSig) throws Exception {
        File dropDir = new File(dir, "proof-drop");
        dropDir.mkdirs();
        Files.write(new File(dropDir, "stage4-genesis.txt").toPath(),
            (msgSig[0] + "\n" + msgSig[1] + "\n")
                .getBytes(StandardCharsets.UTF_8));
    }

    static String[] genesis(String boot, String challenge)
            throws Exception {
        return HostReferenceSigner.signGenesis(priv, boot, challenge);
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 2, "sandbox and private key arguments");
        File sandbox = new File(args[0]);
        priv = Paths.get(args[1]);
        processDrops = PersistenceService.class.getDeclaredMethod(
            "processProofDrops", android.content.ContentResolver.class);
        processDrops.setAccessible(true);
        Method challengeOf = PersistenceService.class.getDeclaredMethod(
            "genesisChallengeOf", String.class);
        challengeOf.setAccessible(true);

        // --- A: genesis install from EMPTY through the real service.
        dps = new File(sandbox, "dps");
        check(dps.mkdirs(), "dps dir");
        service = newService(dps);
        journal = new Stage4AttemptJournalV2(service);
        setProc(B1);
        Settings.Global.VALUES.put("boot_count", "190");
        check("EMPTY".equals(journal.stateKind()), "A starts EMPTY");
        drops(service);  // trailing issuance creates the challenge
        String c1 = read(challengeFile(dps)).trim();
        check(c1.matches("[0-9a-f]{64}"), "A challenge issued");
        String[] g1 = genesis(B1, c1);
        placeDrop(dps, g1);
        drops(service);
        check(read(stateFile(dps)).trim()
                .equals("READY:" + B1 + ":190"),
            "A genesis installs to READY");
        check("genesis_installed".equals(status()),
            "A proof status installed");
        check(!challengeFile(dps).exists(),
            "A standing challenge consumed by genuine genesis");

        // --- B: the boot-196 trigger. Journal INFLIGHT on a new boot,
        // the stale consumed drop (bound to spent c1) still in the
        // mailbox, a resolvable boot id. Two app starts must leave
        // the proof status, the standing challenge and the journal
        // byte-identical.
        setProc(B2);
        Settings.Global.VALUES.put("boot_count", "195");
        String attempt = journal.beginOneShot(B2, 195);
        check(attempt != null, "B beginOneShot to INFLIGHT");
        String inflightBytes = read(stateFile(dps));
        drops(service);  // first INFLIGHT start: issues standing c2
        check("genesis_installed".equals(status()),
            "B status survives first INFLIGHT start");
        String c2 = read(challengeFile(dps)).trim();
        check(c2.matches("[0-9a-f]{64}") && !c2.equals(c1),
            "B standing challenge is fresh");
        String challengeBytes = read(challengeFile(dps));
        drops(service);  // second INFLIGHT start: the boot-196 analog
        check("genesis_installed".equals(status()),
            "B status survives second INFLIGHT start");
        check(read(challengeFile(dps)).equals(challengeBytes),
            "B standing challenge not consumed or reissued");
        check(read(stateFile(dps)).equals(inflightBytes),
            "B journal unchanged by stale drop");

        // --- C: a genuine lockout recovery passes the gate.
        String[] g2 = genesis(B2, c2);
        placeDrop(dps, g2);
        drops(service);
        check(read(stateFile(dps)).trim()
                .equals("READY:" + B2 + ":195"),
            "C genuine recovery reaches READY");
        check("genesis_installed".equals(status()),
            "C proof status installed");
        check(!challengeFile(dps).exists(),
            "C standing challenge consumed by genuine recovery");

        // --- D: genesisChallengeOf parsing.
        check(c1.equals(challengeOf.invoke(null, g1[0])),
            "D challenge extracted from genuine message");
        check(challengeOf.invoke(null, (String) null) == null,
            "D null message rejected");
        check(challengeOf.invoke(null, "garbage") == null,
            "D garbage rejected");
        check(challengeOf.invoke(null,
                "stage4-genesis-v1|" + B1 + "|xyz|PS7331.4463N")
                == null,
            "D malformed challenge rejected");
        check(challengeOf.invoke(null,
                "stage4-root-v1|" + B1 + "|" + c1 + "|x") == null,
            "D wrong domain rejected");

        // --- E: from EMPTY, a drop bound to a foreign challenge is
        // inert; the genuine drop then installs.
        File dps2 = new File(sandbox, "dps2");
        check(dps2.mkdirs(), "E dps2 dir");
        PersistenceService service2 = newService(dps2);
        Stage4AttemptJournalV2 journal2 =
            new Stage4AttemptJournalV2(service2);
        setProc(B1);
        Settings.Global.VALUES.put("boot_count", "190");
        Settings.Global.VALUES.put("snusnu_proof_status", "sentinel");
        drops(service2);  // issues standing challenge c3
        String c3 = read(challengeFile(dps2)).trim();
        placeDrop(dps2, genesis(B1, c1));  // bound to scenario A's c1
        drops(service2);
        check("EMPTY".equals(journal2.stateKind()),
            "E foreign drop leaves journal EMPTY");
        check("sentinel".equals(status()),
            "E foreign drop leaves proof status untouched");
        check(read(challengeFile(dps2)).trim().equals(c3),
            "E foreign drop leaves standing challenge untouched");
        placeDrop(dps2, genesis(B1, c3));
        drops(service2);
        check(read(stateFile(dps2)).trim()
                .equals("READY:" + B1 + ":190"),
            "E genuine drop installs from EMPTY");
        check("genesis_installed".equals(status()),
            "E proof status installed");

        System.out.println("TOTAL " + passed);
    }
}
'''

EXPECTED_PASS = 27


class ProofDropGateHostTests(unittest.TestCase):
    def test_proof_drop_challenge_gate(self):
        javac = JDK / 'javac'
        java = JDK / 'java'
        self.assertTrue(javac.is_file() and java.is_file(),
                        'JDK 17 is required')
        with tempfile.TemporaryDirectory(
                prefix='snu-proofdrop-gate-host-') as directory:
            root = Path(directory)
            sources = dict(JAVA_SOURCES)
            sources.pop('HostJournalHarness.java')
            sources['io/github/voidnullvalue/snusnuroot/persistence/'
                    'Stage4BootIdentity.java'] = BOOT_IDENTITY_STUB
            sources.update(EXTRA_SOURCES)
            for relative, source in sources.items():
                output = root / 'src' / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(source)
            package = (root / 'src/io/github/voidnullvalue/snusnuroot'
                       '/persistence')
            package.mkdir(parents=True, exist_ok=True)
            for name in REAL_CLASSES:
                (package / name).write_bytes((V2_PKG / name).read_bytes())
            (root / 'src/HostReferenceSigner.java').write_bytes(
                (V2_TREE / 'host-reference/HostReferenceSigner.java')
                .read_bytes())

            classes = root / 'classes'
            signer_build = subprocess.run(
                [str(javac), '--release', '8', '-encoding', 'UTF-8',
                 '-d', str(classes),
                 str(root / 'src/HostReferenceSigner.java')],
                capture_output=True, text=True, timeout=40)
            self.assertEqual(signer_build.returncode, 0,
                             signer_build.stderr)
            keygen = subprocess.run(
                [str(java), '-cp', str(classes), 'HostReferenceSigner',
                 'keygen', str(root / 'pub.der'), str(root / 'priv.der')],
                capture_output=True, text=True, timeout=25)
            self.assertEqual(keygen.returncode, 0, keygen.stderr)

            pin = subprocess.run(
                ['python3', str(V2_TREE / 'gen_pinned_key.py'),
                 str(root / 'pub.der'),
                 'HOST TEST KEY - NOT THE DEVICE KEY',
                 str(package / 'Stage4PinnedProofKey.java')],
                capture_output=True, text=True, timeout=25)
            self.assertEqual(pin.returncode, 0, pin.stderr)

            (root / 'src/HostProofDropGateHarness.java').write_text(HARNESS)
            build = subprocess.run(
                [str(javac), '--release', '8', '-encoding', 'UTF-8',
                 '-d', str(classes),
                 *map(str, (root / 'src').rglob('*.java'))],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run(
                [str(java), '-cp', str(classes),
                 'HostProofDropGateHarness',
                 str(root), str(root / 'priv.der')],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stderr)
            lines = [line for line in run.stdout.splitlines() if line]
            passes = [line for line in lines
                      if line.startswith('PASS ')]
            self.assertEqual(len(passes), EXPECTED_PASS, run.stdout)
            self.assertEqual(lines[-1], f'TOTAL {EXPECTED_PASS}',
                             run.stdout)


if __name__ == '__main__':
    unittest.main()
