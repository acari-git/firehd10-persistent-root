"""Execute the v2 PersistenceService enablement closure on the host.

Regression coverage for the Step-0 persist-lifecycle finding of the
2026-11-02 enablement session (diagnostics/enablement-acceptance-
20261102/STEP0-PERSIST-LIFECYCLE-FINDING-20261102.md). As deployed
through boot 204, snusnu_persist_enabled was strictly one-shot:
report() disarms on every terminal attempt status (success included)
and nothing ever wrote the flag back to 1, so a standing enablement
would have lasted exactly one boot.

The closure under test (PersistenceService + two read-only journal
accessors):

  F. a verified routine completion (INFLIGHT -> READY via a signed
     stage4-root-v1 proof) re-arms the flag and reports
     rearmed_on_proof;
  G. a rejected proof does NOT re-arm and leaves the journal INFLIGHT;
  H. a genesis install does NOT re-arm (operator artifact semantics);
  I. a service run that completes a proof returns immediately -- it
     must not fall through into a fresh attempt on the completion
     boot;
  J. a later start on the already-proven boot is a quiet no-op (the
     journal READY binding guard): journal, flag and statuses are
     byte-identical afterwards -- in particular no journal_denied
     report may disarm the standing posture;
  K. the NEXT boot (new boot id, boot_count+1) is not blocked by the
     guard: beginOneShot proceeds to INFLIGHT bound to the new boot.

This proves host-side protocol behaviour only, like the module it is
modelled on.
"""

from pathlib import Path
import subprocess
import tempfile
import unittest

from test_execute_firehd10_journal_on_host_20261014 import JAVA_SOURCES, ROOT, JDK
from test_execute_firehd10_proofdrop_gate_host_20261102 import (
    EXTRA_SOURCES, BOOT_IDENTITY_STUB, V2_TREE, V2_PKG, REAL_CLASSES)


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

public class HostPersistRearmHarness {
    static final String B1 = "11111111-1111-1111-1111-111111111111";
    static final String B2 = "22222222-2222-2222-2222-222222222222";
    static final String B3 = "33333333-3333-3333-3333-333333333333";
    static int passed = 0;
    static Path priv;
    static Method processDrops;
    static Method runPersist;

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

    static boolean drops(PersistenceService svc) throws Exception {
        return (Boolean) processDrops.invoke(
            svc, svc.getContentResolver());
    }

    static void run(PersistenceService svc) throws Exception {
        runPersist.invoke(svc);
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

    static String get(String key) {
        return Settings.Global.VALUES.get(key);
    }

    static void place(File dir, String name, String[] msgSig)
            throws Exception {
        File dropDir = new File(dir, "proof-drop");
        dropDir.mkdirs();
        Files.write(new File(dropDir, name).toPath(),
            (msgSig[0] + "\n" + msgSig[1] + "\n")
                .getBytes(StandardCharsets.UTF_8));
    }

    // Genesis-install a fresh sandbox to READY:B1:190; returns nothing.
    static void bootstrap(File dir) throws Exception {
        PersistenceService svc = newService(dir);
        Stage4AttemptJournalV2 journal =
            new Stage4AttemptJournalV2(svc);
        setProc(B1);
        Settings.Global.VALUES.put("boot_count", "190");
        if (!"EMPTY".equals(journal.stateKind())) {
            throw new AssertionError("bootstrap: not EMPTY");
        }
        drops(svc);
        String c = read(challengeFile(dir)).trim();
        place(dir, "stage4-genesis.txt",
            HostReferenceSigner.signGenesis(priv, B1, c));
        drops(svc);
        if (!read(stateFile(dir)).trim().equals("READY:" + B1 + ":190")) {
            throw new AssertionError("bootstrap: genesis did not install");
        }
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 2, "sandbox and private key arguments");
        File sandbox = new File(args[0]);
        priv = Paths.get(args[1]);
        processDrops = PersistenceService.class.getDeclaredMethod(
            "processProofDrops", android.content.ContentResolver.class);
        processDrops.setAccessible(true);
        runPersist = PersistenceService.class.getDeclaredMethod(
            "runPersistence");
        runPersist.setAccessible(true);

        // --- F: verified routine completion re-arms.
        File f = new File(sandbox, "f");
        check(f.mkdirs(), "F dir");
        bootstrap(f);
        PersistenceService svcF = newService(f);
        Stage4AttemptJournalV2 jF = new Stage4AttemptJournalV2(svcF);
        setProc(B2);
        Settings.Global.VALUES.put("boot_count", "195");
        String chF = jF.beginOneShot(B2, 195);
        check(chF != null, "F begin to INFLIGHT");
        Settings.Global.VALUES.put("snusnu_persist_enabled", "0");
        Settings.Global.VALUES.put("snusnu_persist_status",
            "kernel_write_ok");
        place(f, "stage4-proof.txt",
            HostReferenceSigner.signRoot(priv, B2, chF));
        check(drops(svcF), "F completion run reports completion");
        check(read(stateFile(f)).trim().equals("READY:" + B2 + ":195"),
            "F journal READY bound to attempt boot");
        check("proof_completed_dps".equals(
                get("snusnu_proof_status")),
            "F proof status completed");
        check("1".equals(get("snusnu_persist_enabled")),
            "F flag re-armed on verified completion");
        check("rearmed_on_proof".equals(get("snusnu_rearm_status")),
            "F rearm status recorded");

        // --- G: rejected proof does not re-arm.
        File g = new File(sandbox, "g");
        check(g.mkdirs(), "G dir");
        bootstrap(g);
        PersistenceService svcG = newService(g);
        Stage4AttemptJournalV2 jG = new Stage4AttemptJournalV2(svcG);
        setProc(B2);
        Settings.Global.VALUES.put("boot_count", "195");
        String chG = jG.beginOneShot(B2, 195);
        check(chG != null, "G begin to INFLIGHT");
        Settings.Global.VALUES.put("snusnu_persist_enabled", "0");
        place(g, "stage4-proof.txt", HostReferenceSigner.signRoot(
            priv, B2,
            "0000000000000000000000000000000000000000000000000000000000000000"));
        check(!drops(svcG), "G rejected proof is not a completion");
        check("proof_rejected".equals(get("snusnu_proof_status")),
            "G proof status rejected");
        check("0".equals(get("snusnu_persist_enabled")),
            "G flag stays disarmed");
        check("INFLIGHT".equals(jG.stateKind()),
            "G journal stays INFLIGHT");

        // --- H: genesis install does not re-arm.
        File h = new File(sandbox, "h");
        check(h.mkdirs(), "H dir");
        PersistenceService svcH = newService(h);
        setProc(B1);
        Settings.Global.VALUES.put("boot_count", "190");
        Settings.Global.VALUES.put("snusnu_persist_enabled", "0");
        drops(svcH);
        String cH = read(challengeFile(h)).trim();
        place(h, "stage4-genesis.txt",
            HostReferenceSigner.signGenesis(priv, B1, cH));
        check(!drops(svcH), "H genesis install is not a completion");
        check(read(stateFile(h)).trim().equals("READY:" + B1 + ":190"),
            "H genesis installs");
        check("0".equals(get("snusnu_persist_enabled")),
            "H flag untouched by genesis");

        // --- I: the completion run does not fall through.
        File i = new File(sandbox, "i");
        check(i.mkdirs(), "I dir");
        bootstrap(i);
        PersistenceService svcI = newService(i);
        Stage4AttemptJournalV2 jI = new Stage4AttemptJournalV2(svcI);
        setProc(B2);
        Settings.Global.VALUES.put("boot_count", "195");
        String chI = jI.beginOneShot(B2, 195);
        check(chI != null, "I begin to INFLIGHT");
        place(i, "stage4-proof.txt",
            HostReferenceSigner.signRoot(priv, B2, chI));
        Settings.Global.VALUES.put("snusnu_persist_enabled", "1");
        Settings.Global.VALUES.put("snusnu_persist_status",
            "kernel_write_ok");
        Settings.Global.VALUES.put("snusnu_rearm_status",
            "disabled_one_shot");
        run(svcI);
        check(read(stateFile(i)).trim().equals("READY:" + B2 + ":195"),
            "I completion run ends READY, not re-begun");
        check("1".equals(get("snusnu_persist_enabled")),
            "I flag re-armed");
        check("kernel_write_ok".equals(get("snusnu_persist_status")),
            "I no new attempt report overwrote the status");
        check("rearmed_on_proof".equals(get("snusnu_rearm_status")),
            "I rearm recorded, no journal_denied teardown");

        // --- J: a later start on the proven boot is a quiet no-op.
        String stateBytesJ = read(stateFile(i));
        run(svcI);
        check(read(stateFile(i)).equals(stateBytesJ),
            "J journal byte-identical after proven-boot start");
        check("1".equals(get("snusnu_persist_enabled")),
            "J standing flag survives proven-boot start");
        check("kernel_write_ok".equals(get("snusnu_persist_status")),
            "J status untouched");
        check("rearmed_on_proof".equals(get("snusnu_rearm_status")),
            "J rearm status untouched (no journal_denied)");

        // --- K: the next boot is not blocked by the guard.
        setProc(B3);
        Settings.Global.VALUES.put("boot_count", "196");
        run(svcI);
        check(read(stateFile(i)).startsWith(
                "INFLIGHT:" + B3 + ":196:"),
            "K next boot begins a fresh attempt");

        System.out.println("TOTAL " + passed);
    }
}
'''

EXPECTED_PASS = 29


class PersistRearmHostTests(unittest.TestCase):
    def test_persist_rearm_closure(self):
        javac = JDK / 'javac'
        java = JDK / 'java'
        self.assertTrue(javac.is_file() and java.is_file(),
                        'JDK 17 is required')
        with tempfile.TemporaryDirectory(
                prefix='snu-persist-rearm-host-') as directory:
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

            (root / 'src/HostPersistRearmHarness.java').write_text(HARNESS)
            build = subprocess.run(
                [str(javac), '--release', '8', '-encoding', 'UTF-8',
                 '-d', str(classes),
                 *map(str, (root / 'src').rglob('*.java'))],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run(
                [str(java), '-cp', str(classes),
                 'HostPersistRearmHarness',
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
