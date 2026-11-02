"""Execute the PRODUCTION device proof signer on the host, cross-tested
against the real v2 journal classes.

Compiles build/journal-gated-implementation-20261101/device-signer/src/
Stage4DeviceSigner.java (the production signer, not the test-only host
reference signer) and drives it as a subprocess - one process per
invocation, exactly as the on-device launcher will run it. Every device
fact source (own uid/context, /sbin/su, getenforce, the enforcing marker,
the kernel boot id) is stubbed at the file/executable boundary via the
signer's -Dsnu.signer.* properties; the signer's own gate logic, ledger,
operator-token handling, message construction, ECDSA signing and drop
delivery all run for real. Drops produced by the signer are then fed to
the REAL Stage4AttemptJournalV2 / Stage4ProofVerifier /
Stage4GenesisVerifier / Stage4ProofDrop classes, pinned (through the real
gen_pinned_key.py) to the public half of the key the signer itself
generated in its sandbox custody directory.

This proves host-side protocol behaviour of the production signer code.
It does NOT prove the on-device exec context of app_process under the
magisk domain, SELinux label fixup on the real DPS, or Android storage
durability; those are genesis-session measurements (runbook Phase G-3).
"""

from pathlib import Path
import hashlib
import os
import secrets
import subprocess
import tempfile
import time
import unittest

from test_execute_firehd10_journal_on_host_20261014 import JAVA_SOURCES, ROOT, JDK


SIGNER_TREE = (ROOT / 'build/journal-gated-implementation-20261101'
               '/device-signer')
V2_TREE = ROOT / 'build/journal-gated-implementation-20261101/v2'
V2_PKG = (V2_TREE / 'stage4-persistent/app/src/io/github/voidnullvalue'
          '/snusnuroot/persistence')
V2_CLASSES = ('Stage4AttemptJournalV2.java', 'Stage4GenesisVerifier.java',
              'Stage4BootWitness.java', 'Stage4ProofDrop.java',
              'Stage4ProofVerifier.java')

BOOT_IDENTITY_STUB = r'''
package io.github.voidnullvalue.snusnuroot.persistence;
final class Stage4BootIdentity {
    static String readCurrentBootId() {
        String value = System.getProperty("snu.test.boot.id", "NONE");
        return "NONE".equals(value) ? null : value;
    }
}
'''

HARNESS = r'''
import io.github.voidnullvalue.snusnuroot.persistence.Stage4AttemptJournalV2;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4GenesisVerifier;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4PinnedProofKey;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4ProofDrop;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4ProofVerifier;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class HostSignerCrossHarness {
    static Stage4AttemptJournalV2 journal(File dir) {
        return new Stage4AttemptJournalV2(
                new android.content.Context(dir));
    }

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        if ("state".equals(mode)) {
            File dir = new File(args[1]);
            System.out.println("KIND " + journal(dir).stateKind());
            File state = new File(dir, "stage4-native-attempt-v2.state");
            System.out.println("RAW " + (state.isFile()
                    ? new String(Files.readAllBytes(state.toPath()),
                            StandardCharsets.UTF_8)
                    : "<absent>"));
            return;
        }
        if ("issue-challenge".equals(mode)) {
            String challenge = journal(new File(args[1]))
                    .issueGenesisChallenge();
            System.out.println("CHALLENGE " + challenge);
            return;
        }
        if ("install-genesis".equals(mode)) {
            Stage4ProofDrop.Drop drop = Stage4ProofDrop.readDrop(
                    new File(args[4]));
            if (drop == null) {
                System.out.println("RESULT nodrop");
                return;
            }
            boolean done = journal(new File(args[1])).installGenesis(
                    args[2], Long.parseLong(args[3]),
                    Stage4PinnedProofKey.publicKey(),
                    drop.message, drop.signatureHex);
            System.out.println("RESULT " + done);
            return;
        }
        if ("begin".equals(mode)) {
            String challenge = journal(new File(args[1])).beginOneShot(
                    args[2], Long.parseLong(args[3]));
            System.out.println(challenge == null ? "DENIED"
                    : "CHALLENGE " + challenge);
            return;
        }
        if ("complete".equals(mode)) {
            Stage4ProofDrop.Drop drop = Stage4ProofDrop.readDrop(
                    new File(args[4]));
            if (drop == null) {
                System.out.println("RESULT nodrop");
                return;
            }
            boolean done = journal(new File(args[1]))
                    .completeWithSignedProof(args[2],
                            Long.parseLong(args[3]),
                            Stage4PinnedProofKey.publicKey(),
                            drop.message, drop.signatureHex);
            System.out.println("RESULT " + done);
            return;
        }
        if ("verify-root".equals(mode)) {
            Stage4ProofDrop.Drop drop = Stage4ProofDrop.readDrop(
                    new File(args[3]));
            if (drop == null) {
                System.out.println("RESULT nodrop");
                return;
            }
            Stage4ProofVerifier verifier = new Stage4ProofVerifier(
                    Stage4PinnedProofKey.publicKey(), args[1], args[2]);
            System.out.println("RESULT " + verifier.verifyOnceForBoot(
                    args[1], drop.message, drop.signatureHex));
            return;
        }
        if ("verify-genesis".equals(mode)) {
            Stage4ProofDrop.Drop drop = Stage4ProofDrop.readDrop(
                    new File(args[3]));
            if (drop == null) {
                System.out.println("RESULT nodrop");
                return;
            }
            Stage4GenesisVerifier verifier = new Stage4GenesisVerifier(
                    Stage4PinnedProofKey.publicKey(), args[1], args[2]);
            System.out.println("RESULT " + verifier.verifyOnce(
                    drop.message, drop.signatureHex));
            return;
        }
        if ("parse".equals(mode)) {
            Stage4ProofDrop.Drop drop = Stage4ProofDrop.readDrop(
                    new File(args[1]));
            System.out.println(drop == null ? "PARSE NULL" : "PARSE OK");
            return;
        }
        System.err.println("unknown harness mode " + mode);
        System.exit(2);
    }
}
'''

BOOT_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
BOOT_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
BOOT_C = 'cccccccc-cccc-cccc-cccc-cccccccccccc'


def challenge():
    return secrets.token_hex(32)


class DeviceSandbox:
    """One fake device: stubbed fact sources + signer custody + app DPS."""

    def __init__(self, root):
        self.root = root
        self.custody = root / 'custody'
        self.custody.mkdir(parents=True)
        self.appfiles = root / 'appfiles'
        self.appfiles.mkdir()
        self.state_dir = root / 'state'
        self.state_dir.mkdir()
        self.su_mode = root / 'su_mode'
        self.su_mode.write_text('ok')
        self.enforce_mode = root / 'enforce_mode'
        self.enforce_mode.write_text('Enforcing')
        su = root / 'stub_su.sh'
        su.write_text(
            '#!/bin/sh\n'
            'mode=$(cat "$(dirname "$0")/su_mode")\n'
            'case "$mode" in\n'
            '  ok) echo "uid=0(root) gid=1000(system) '
            'groups=1000(system),2000(shell) context=u:r:magisk:s0" ;;\n'
            '  badctx) echo "uid=0(root) gid=0(root) groups=0(root) '
            'context=u:r:shell:s0" ;;\n'
            '  sleep) sleep 30 ;;\n'
            '  *) echo "su: permission denied" >&2; exit 1 ;;\n'
            'esac\n')
        su.chmod(0o755)
        enforce = root / 'stub_getenforce.sh'
        enforce.write_text(
            '#!/bin/sh\ncat "$(dirname "$0")/enforce_mode"\n')
        enforce.chmod(0o755)
        self.set_uid(0)
        self.set_context('u:r:magisk:s0')
        self.set_boot(BOOT_A)

    def set_uid(self, uid):
        (self.root / 'status').write_text(
            'Name:\tsigner\nUid:\t%d\t%d\t%d\t%d\n' % (uid, uid, uid, uid))

    def set_context(self, context):
        (self.root / 'attr_current').write_text(context)

    def set_boot(self, boot):
        (self.root / 'boot_id').write_text(boot + '\n')
        (self.root / 'marker.log').write_text(
            '2026-11-01T00:00:00Z boot=%s OK enforcing-restored '
            'owner=u:r:magisk:s0\n' % boot)

    def props(self, appfiles=None, fixup='print', su_timeout='20'):
        return {
            'snu.signer.custody': str(self.custody),
            'snu.signer.su': str(self.root / 'stub_su.sh'),
            'snu.signer.getenforce': str(self.root / 'stub_getenforce.sh'),
            'snu.signer.boot_id_path': str(self.root / 'boot_id'),
            'snu.signer.status_path': str(self.root / 'status'),
            'snu.signer.attr_path': str(self.root / 'attr_current'),
            'snu.signer.marker_path': str(self.root / 'marker.log'),
            'snu.signer.request_path': str(self.state_dir / 'proof_request'),
            'snu.signer.dps_files': str(appfiles or self.appfiles),
            'snu.signer.fixup': fixup,
            'snu.signer.su_timeout': su_timeout,
        }


class DeviceSignerHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.javac = JDK / 'javac'
        cls.java = JDK / 'java'
        if not (cls.javac.is_file() and cls.java.is_file()):
            raise unittest.SkipTest('JDK 17 is required')
        cls.tmp = tempfile.TemporaryDirectory(
            prefix='snu-device-signer-host-')
        root = Path(cls.tmp.name)
        cls.build = root / 'build'
        sources = dict(JAVA_SOURCES)
        sources.pop('HostJournalHarness.java')
        sources['io/github/voidnullvalue/snusnuroot/persistence/'
                'Stage4BootIdentity.java'] = BOOT_IDENTITY_STUB
        src = root / 'src'
        for relative, source in sources.items():
            output = src / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(source)
        package = (src / 'io/github/voidnullvalue/snusnuroot/persistence')
        package.mkdir(parents=True, exist_ok=True)
        for name in V2_CLASSES:
            (package / name).write_bytes((V2_PKG / name).read_bytes())
        (src / 'HostReferenceSigner.java').write_bytes(
            (V2_TREE / 'host-reference/HostReferenceSigner.java')
            .read_bytes())
        (src / 'Stage4DeviceSigner.java').write_bytes(
            (SIGNER_TREE / 'src/Stage4DeviceSigner.java').read_bytes())
        (src / 'HostSignerCrossHarness.java').write_text(HARNESS)

        # The primary sandbox provides the custody key that gets pinned
        # into the journal harness build, like the genesis session pins
        # the on-device key into the rebuilt APK.
        cls.primary = DeviceSandbox(root / 'primary')
        classes = cls.build / 'signer-classes'
        build = subprocess.run(
            [str(cls.javac), '--release', '8', '-encoding', 'UTF-8',
             '-d', str(classes), str(src / 'Stage4DeviceSigner.java')],
            capture_output=True, text=True, timeout=60)
        if build.returncode != 0:
            raise AssertionError(build.stderr)
        cls.signer_classes = classes
        keygen = cls.run_signer_raw(cls.primary,
                                    'keygen', str(root / 'primary.pub.der'))
        if keygen.returncode != 0:
            raise AssertionError(keygen.stdout + keygen.stderr)
        cls.primary_pub = root / 'primary.pub.der'

        pin = subprocess.run(
            ['python3', str(V2_TREE / 'gen_pinned_key.py'),
             str(cls.primary_pub),
             'HOST CROSS-TEST KEY - NOT THE DEVICE KEY',
             str(package / 'Stage4PinnedProofKey.java')],
            capture_output=True, text=True, timeout=25)
        if pin.returncode != 0:
            raise AssertionError(pin.stderr)
        cls.classes = cls.build / 'classes'
        build = subprocess.run(
            [str(cls.javac), '--release', '8', '-encoding', 'UTF-8',
             '-d', str(cls.classes), *map(str, src.rglob('*.java'))],
            capture_output=True, text=True, timeout=90)
        if build.returncode != 0:
            raise AssertionError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def run_signer_raw(cls, device, *args, appfiles=None, fixup='print',
                       su_timeout='20'):
        command = [str(cls.java)]
        for key, value in device.props(
                appfiles=appfiles, fixup=fixup,
                su_timeout=su_timeout).items():
            command.append('-D%s=%s' % (key, value))
        command += ['-cp', str(cls.signer_classes), 'Stage4DeviceSigner']
        command += list(args)
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=60)

    def run_signer(self, device, *args, **kwargs):
        return self.run_signer_raw(device, *args, **kwargs)

    def harness(self, *args, proc_boot=None):
        command = [str(self.java)]
        if proc_boot is not None:
            command.append('-Dsnu.test.boot.id=%s' % proc_boot)
        command += ['-cp', str(self.classes), 'HostSignerCrossHarness']
        command += [str(arg) for arg in args]
        run = subprocess.run(command, capture_output=True, text=True,
                             timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout

    def fresh_device(self, name):
        return DeviceSandbox(Path(self.tmp.name) / name)

    def do_genesis(self, device, appfiles, boot, count):
        """App issues a challenge; signer (token-gated) signs; journal
        installs READY. Returns the genesis drop path."""
        issued = self.harness('issue-challenge', appfiles)
        genesis_challenge = issued.split('CHALLENGE ')[1].strip()
        (device.custody / 'genesis-approved').write_text(boot + '\n')
        signed = self.run_signer(device, 'sign-genesis', genesis_challenge,
                                 appfiles=appfiles)
        self.assertEqual(signed.returncode, 0, signed.stdout)
        drop = appfiles / 'proof-drop' / 'stage4-genesis.txt'
        self.assertTrue(drop.is_file())
        installed = self.harness('install-genesis', appfiles, boot,
                                 count, drop)
        self.assertIn('RESULT true', installed)
        return drop

    # ---- scenarios ----

    def test_keygen_refuses_overwrite_and_pin_matches(self):
        device = self.fresh_device('keygen')
        pub = Path(self.tmp.name) / 'keygen.pub.der'
        first = self.run_signer(device, 'keygen', str(pub))
        self.assertEqual(first.returncode, 0, first.stdout)
        digest = hashlib.sha256(pub.read_bytes()).hexdigest()
        self.assertIn('pub_sha256=' + digest, first.stdout)
        second = self.run_signer(device, 'keygen', str(pub))
        self.assertEqual(second.returncode, 3, second.stdout)
        self.assertIn('key_already_exists', second.stdout)
        self.assertEqual(
            hashlib.sha256(pub.read_bytes()).hexdigest(), digest)

    def test_report_mode(self):
        good = self.run_signer(self.primary, 'report')
        self.assertEqual(good.returncode, 0, good.stdout)
        self.assertIn('FACT context=u:r:magisk:s0', good.stdout)
        self.primary.su_mode.write_text('fail')
        try:
            bad = self.run_signer(self.primary, 'report')
            self.assertEqual(bad.returncode, 3, bad.stdout)
        finally:
            self.primary.su_mode.write_text('ok')

    def test_pinned_key_accepts_signer_rejects_foreign(self):
        device = self.primary
        device.set_boot(BOOT_A)
        ch = challenge()
        signed = self.run_signer(device, 'sign-proof', BOOT_A, ch,
                                 appfiles=device.appfiles)
        self.assertEqual(signed.returncode, 0, signed.stdout)
        drop = device.appfiles / 'proof-drop' / 'stage4-proof.txt'
        verified = self.harness('verify-root', BOOT_A, ch, drop)
        self.assertIn('RESULT true', verified)
        # A signature over the same message from a different key (the
        # test-only host reference signer with its own key pair) must not
        # verify against the production signer's pin.
        foreign_dir = Path(self.tmp.name) / 'foreign'
        foreign_dir.mkdir(exist_ok=True)
        subprocess.run(
            [str(self.java), '-cp', str(self.classes),
             'HostReferenceSigner', 'keygen',
             str(foreign_dir / 'pub.der'), str(foreign_dir / 'priv.der')],
            check=True, capture_output=True, text=True, timeout=25)
        foreign = subprocess.run(
            [str(self.java), '-cp', str(self.classes),
             'HostReferenceSigner', 'sign-root',
             str(foreign_dir / 'priv.der'), BOOT_A, ch],
            check=True, capture_output=True, text=True, timeout=25)
        foreign_drop = foreign_dir / 'drop.txt'
        foreign_drop.write_text(foreign.stdout)
        rejected = self.harness('verify-root', BOOT_A, ch, foreign_drop)
        self.assertIn('RESULT false', rejected)

    def test_genesis_end_to_end(self):
        device = self.primary
        device.set_boot(BOOT_A)
        appfiles = Path(self.tmp.name) / 'genesis-app'
        appfiles.mkdir()
        drop = self.do_genesis(device, appfiles, BOOT_A, 191)
        state = self.harness('state', appfiles)
        self.assertIn('KIND READY', state)
        self.assertIn('RAW READY:%s:191' % BOOT_A, state)
        # The operator token was consumed and the pair ledgered.
        self.assertFalse((device.custody / 'genesis-approved').exists())
        ledger = (device.custody / 'used-challenges.log').read_text()
        issued = (appfiles / 'proof-drop' / 'stage4-genesis.txt')
        self.assertTrue(issued.is_file())
        parsed = self.harness('parse', drop)
        self.assertIn('PARSE OK', parsed)

    def test_genesis_token_gates(self):
        device = self.primary
        device.set_boot(BOOT_A)
        ch = challenge()
        no_token = self.run_signer(device, 'sign-genesis', ch)
        self.assertEqual(no_token.returncode, 3, no_token.stdout)
        self.assertIn('operator_token', no_token.stdout)
        (device.custody / 'genesis-approved').write_text(BOOT_B + '\n')
        wrong_boot = self.run_signer(device, 'sign-genesis', ch)
        self.assertEqual(wrong_boot.returncode, 3, wrong_boot.stdout)
        self.assertIn('operator_token', wrong_boot.stdout)
        (device.custody / 'genesis-approved').write_text(BOOT_A + '\n')
        ok = self.run_signer(device, 'sign-genesis', ch)
        self.assertEqual(ok.returncode, 0, ok.stdout)
        again = self.run_signer(device, 'sign-genesis', challenge())
        self.assertEqual(again.returncode, 3, again.stdout)
        self.assertIn('operator_token', again.stdout)

    def test_routine_completion_end_to_end_and_replay(self):
        device = self.primary
        device.set_boot(BOOT_A)
        appfiles = Path(self.tmp.name) / 'routine-app'
        appfiles.mkdir()
        self.do_genesis(device, appfiles, BOOT_A, 191)
        begun = self.harness('begin', appfiles, BOOT_B, 192,
                             proc_boot=BOOT_B)
        attempt_challenge = begun.split('CHALLENGE ')[1].strip()
        device.set_boot(BOOT_B)
        (device.state_dir / 'proof_request').write_text(
            '%s %s\n' % (BOOT_B, attempt_challenge))
        signed = self.run_signer(device, 'sign-proof-request',
                                 appfiles=appfiles)
        self.assertEqual(signed.returncode, 0, signed.stdout)
        drop = appfiles / 'proof-drop' / 'stage4-proof.txt'
        tampered = Path(self.tmp.name) / 'tampered.txt'
        lines = drop.read_text().splitlines()
        flipped = ('0' if lines[1][0] != '0' else '1') + lines[1][1:]
        tampered.write_text(lines[0] + '\n' + flipped + '\n')
        denied = self.harness('complete', appfiles, BOOT_B, 192,
                              tampered, proc_boot=BOOT_B)
        self.assertIn('RESULT false', denied)
        completed = self.harness('complete', appfiles, BOOT_B, 192,
                                 drop, proc_boot=BOOT_B)
        self.assertIn('RESULT true', completed)
        state = self.harness('state', appfiles)
        self.assertIn('RAW READY:%s:192' % BOOT_B, state)
        replay = self.harness('complete', appfiles, BOOT_B, 192,
                              drop, proc_boot=BOOT_B)
        self.assertIn('RESULT false', replay)

    def test_cross_domain_rejection(self):
        device = self.primary
        device.set_boot(BOOT_A)
        appfiles = Path(self.tmp.name) / 'xdomain-app'
        appfiles.mkdir()
        genesis_drop = self.do_genesis(device, appfiles, BOOT_A, 191)
        genesis_lines = genesis_drop.read_text().splitlines()
        genesis_challenge = genesis_lines[0].split('|')[2]
        # The genesis proof is not a routine proof.
        as_root = self.harness('verify-root', BOOT_A, genesis_challenge,
                               genesis_drop)
        self.assertIn('RESULT false', as_root)
        fed_to_genesis = self.harness(
            'install-genesis', appfiles, BOOT_A, 191, genesis_drop)
        self.assertIn('RESULT false', fed_to_genesis)
        # A routine proof is not a genesis proof.
        ch = challenge()
        signed = self.run_signer(device, 'sign-proof', BOOT_A, ch,
                                 appfiles=appfiles)
        self.assertEqual(signed.returncode, 0, signed.stdout)
        proof_drop = appfiles / 'proof-drop' / 'stage4-proof.txt'
        as_genesis = self.harness('verify-genesis', BOOT_A, ch, proof_drop)
        self.assertIn('RESULT false', as_genesis)
        other_app = Path(self.tmp.name) / 'xdomain-app2'
        other_app.mkdir()
        fed = self.harness('install-genesis', other_app, BOOT_A, 191,
                           proof_drop)
        self.assertIn('RESULT false', fed)

    def test_signer_gate_denials(self):
        device = self.primary
        device.set_boot(BOOT_C)
        ch = challenge()
        # caller boot mismatch against the signer's own measurement
        mismatch = self.run_signer(device, 'sign-proof', BOOT_A, ch)
        self.assertEqual(mismatch.returncode, 3, mismatch.stdout)
        self.assertIn('boot_mismatch', mismatch.stdout)
        ok = self.run_signer(device, 'sign-proof', BOOT_C, ch)
        self.assertEqual(ok.returncode, 0, ok.stdout)
        reuse = self.run_signer(device, 'sign-proof', BOOT_C, ch)
        self.assertEqual(reuse.returncode, 3, reuse.stdout)
        self.assertIn('challenge_reused', reuse.stdout)

        fresh = self.fresh_device('gates')
        keygen = self.run_signer(fresh, 'keygen',
                                 str(fresh.root / 'pub.der'))
        self.assertEqual(keygen.returncode, 0, keygen.stdout)
        ch2 = challenge()
        fresh.su_mode.write_text('badctx')
        bad_ctx = self.run_signer(fresh, 'sign-proof', BOOT_A, ch2)
        self.assertEqual(bad_ctx.returncode, 3, bad_ctx.stdout)
        self.assertIn('su_measurement', bad_ctx.stdout)
        fresh.su_mode.write_text('sleep')
        started = time.time()
        timed_out = self.run_signer(fresh, 'sign-proof', BOOT_A, ch2,
                                    su_timeout='3')
        self.assertLess(time.time() - started, 25)
        self.assertEqual(timed_out.returncode, 3, timed_out.stdout)
        fresh.su_mode.write_text('ok')
        fresh.enforce_mode.write_text('Permissive')
        permissive = self.run_signer(fresh, 'sign-proof', BOOT_A, ch2)
        self.assertEqual(permissive.returncode, 3, permissive.stdout)
        self.assertIn('enforcing_not_restored', permissive.stdout)
        fresh.enforce_mode.write_text('Enforcing')
        (fresh.root / 'marker.log').write_text('no marker for this boot\n')
        no_marker = self.run_signer(fresh, 'sign-proof', BOOT_A, ch2)
        self.assertEqual(no_marker.returncode, 3, no_marker.stdout)
        self.assertIn('enforcing_not_restored', no_marker.stdout)
        fresh.set_boot(BOOT_A)
        fresh.set_context('u:r:shell:s0')
        wrong_ctx = self.run_signer(fresh, 'sign-proof', BOOT_A, ch2)
        self.assertEqual(wrong_ctx.returncode, 3, wrong_ctx.stdout)
        self.assertIn('own_context', wrong_ctx.stdout)
        fresh.set_context('u:r:magisk:s0')
        fresh.set_uid(1000)
        wrong_uid = self.run_signer(fresh, 'sign-proof', BOOT_A, ch2)
        self.assertEqual(wrong_uid.returncode, 3, wrong_uid.stdout)
        self.assertIn('own_uid', wrong_uid.stdout)

    def test_fixup_plan_and_drop_shape(self):
        device = self.primary
        device.set_boot(BOOT_A)
        appfiles = Path(self.tmp.name) / 'fixup-app'
        appfiles.mkdir()
        issued = self.harness('issue-challenge', appfiles)
        ch = issued.split('CHALLENGE ')[1].strip()
        (device.custody / 'genesis-approved').write_text(BOOT_A + '\n')
        signed = self.run_signer(device, 'sign-genesis', ch,
                                 appfiles=appfiles)
        self.assertEqual(signed.returncode, 0, signed.stdout)
        self.assertIn('FIXUP_PLAN', signed.stdout)
        self.assertIn('chown', signed.stdout)
        self.assertIn('u0_a55', signed.stdout)
        self.assertIn('stage4-genesis-challenge.state', signed.stdout)
        drop = appfiles / 'proof-drop' / 'stage4-genesis.txt'
        parsed = self.harness('parse', drop)
        self.assertIn('PARSE OK', parsed)
        oversized = Path(self.tmp.name) / 'oversized.txt'
        oversized.write_text('x' * 2048)
        self.assertIn('PARSE NULL', self.harness('parse', oversized))


if __name__ == '__main__':
    unittest.main()
