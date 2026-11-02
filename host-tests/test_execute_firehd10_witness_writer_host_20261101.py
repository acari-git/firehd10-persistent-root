"""Execute the waiter-side boot-witness writer on the host.

Runs the REAL writer script (v2 stage4-persistent tree) under /bin/sh
against sandbox fixtures, and parses its output with the REAL
Stage4BootWitness.java compiled from the same tree -- so the byte
format the writer produces is judged by the exact parser the app
runs, including its freshness predicate. Device identity commands
the writer shells out to (getenforce, id) are stubbed through PATH,
the shell-level equivalent of the Android doubles used by the other
host modules; the writer's gates are exercised in both directions
through those stubs.

Scenarios: happy-path write with byte/mode checks, report mode
(writes nothing), refusal outside the Permissive window, skipping
on either disable sentinel, malformed boot-id / uptime sources,
stale-witness replacement, the read-back verification failure
branch, the parser's rejection of the genesis session's real
mangled write (2026-11-01 step 13: nested quoting turned the
newlines into literal 'n'), parser edge shapes, the design doc's
freshness table, and the waiter.sh hook position.

This proves host-side behaviour of the writer and the parser only.
It does NOT prove SELinux behaviour on the device, that the
waiter's Permissive poll and this writer interleave as designed on
real boots, or anything about enablement. Deployment and on-device
verification are a separate, separately approved session (genesis
runbook section 7).
"""

from pathlib import Path
import os
import stat
import subprocess
import tempfile
import unittest

from test_execute_firehd10_journal_on_host_20261014 import JDK, ROOT


TREE = (ROOT / 'build/journal-gated-implementation-20261101/v2'
        / 'stage4-persistent')
WRITER = TREE / 'snusnu-boot-witness.sh'
WAITER = TREE / 'waiter.sh'
WITNESS_JAVA = (TREE / 'app/src/io/github/voidnullvalue/snusnuroot'
                '/persistence/Stage4BootWitness.java')

BOOT_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
BOOT_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
BOOT_GENESIS = '01234567-89ab-cdef-0123-456789abcdef'
# Byte-exact copy of the malformed witness the genesis session's
# first step-13 write produced (45 bytes, newlines mangled to 'n').
MANGLED = BOOT_GENESIS + 'n8418.67n'

HARNESS = r'''
package io.github.voidnullvalue.snusnuroot.persistence;

import java.io.File;

public class WitnessWriterHostHarness {
    public static void main(String[] args) {
        Stage4BootWitness.Witness w =
                Stage4BootWitness.readWitnessFile(new File(args[0]));
        if (w == null) {
            System.out.println("WITNESS null");
            return;
        }
        boolean fresh = Stage4BootWitness.isFresh(
                w, Long.parseLong(args[1]));
        System.out.println("WITNESS boot=" + w.bootId
                + " uptime=" + w.uptimeSeconds + " fresh=" + fresh);
    }
}
'''


class WitnessWriterHostTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        javac = JDK / 'javac'
        cls.java = JDK / 'java'
        assert javac.is_file() and cls.java.is_file(), \
            'JDK 17 is required'
        assert WRITER.is_file(), 'writer script missing'
        assert WITNESS_JAVA.is_file(), 'Stage4BootWitness.java missing'
        cls._build = tempfile.TemporaryDirectory()
        build = Path(cls._build.name)
        src = build / 'WitnessWriterHostHarness.java'
        src.write_text(HARNESS)
        cls.classes = build / 'classes'
        cls.classes.mkdir()
        subprocess.run(
            [str(javac), '--release', '8', '-encoding', 'UTF-8',
             '-d', str(cls.classes), str(WITNESS_JAVA), str(src)],
            check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls._build.cleanup()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.sandbox = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    # -- helpers ----------------------------------------------------

    def parse_witness(self, path, elapsed_millis):
        out = subprocess.run(
            [str(self.java), '-cp', str(self.classes),
             'io.github.voidnullvalue.snusnuroot.persistence'
             '.WitnessWriterHostHarness',
             str(path), str(elapsed_millis)],
            check=True, capture_output=True, text=True)
        return out.stdout.strip()

    def run_writer(self, mode='write', enforce='Permissive', uid='0',
                   boot=BOOT_A, uptime='123.45 678.90',
                   sns_disable=False, cache_disable=False,
                   stub_getenforce=True):
        sb = self.sandbox
        state = sb / 'state'
        sns = sb / 'sns'
        proc = sb / 'proc'
        bin_dir = sb / 'bin'
        for d in (state, sns, proc, bin_dir):
            d.mkdir(exist_ok=True)
        (proc / 'boot_id').write_text(
            boot if boot.endswith('\n') or boot == '' else boot + '\n')
        (proc / 'uptime').write_text(uptime)
        if sns_disable:
            (sns / 'disable').write_text('stop\n')
        if cache_disable:
            (sb / 'cache_disable').write_text('stop\n')
        if stub_getenforce:
            (bin_dir / 'getenforce').write_text(
                '#!/bin/sh\necho "$FAKE_ENFORCE"\n')
            (bin_dir / 'getenforce').chmod(0o755)
        (bin_dir / 'id').write_text(
            '#!/bin/sh\nif [ "$1" = -u ]; then echo "$FAKE_UID"; '
            'else echo "uid=$FAKE_UID"; fi\n')
        (bin_dir / 'id').chmod(0o755)
        env = dict(os.environ)
        env.update({
            'PATH': str(bin_dir) + ':/usr/bin:/bin',
            'FAKE_ENFORCE': enforce,
            'FAKE_UID': uid,
            'SNU_WITNESS_SANDBOX': '1',
            'SNU_WITNESS_STATE_DIR': str(state),
            'SNU_WITNESS_BOOT_ID_FILE': str(proc / 'boot_id'),
            'SNU_WITNESS_UPTIME_FILE': str(proc / 'uptime'),
            'SNU_WITNESS_SNS_DISABLE': str(sns / 'disable'),
            'SNU_WITNESS_CACHE_DISABLE': str(sb / 'cache_disable'),
        })
        proc_run = subprocess.run(
            ['/bin/sh', str(WRITER), mode],
            capture_output=True, text=True, env=env)
        return proc_run, state / 'boot_witness', state

    # -- writer behaviour -------------------------------------------

    def test_write_happy_path_bytes_mode_and_cleanup(self):
        run, witness, state = self.run_writer()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('WITNESS_RESULT OK', run.stdout)
        data = witness.read_bytes()
        self.assertEqual(data, (BOOT_A + '\n123.45\n').encode())
        mode = stat.S_IMODE(os.stat(witness).st_mode)
        self.assertEqual(mode, 0o644)
        leftovers = [p.name for p in state.iterdir()
                     if p.name.startswith('.boot_witness.tmp')]
        self.assertEqual(leftovers, [])

    def test_written_witness_parses_and_freshness_window(self):
        run, witness, _ = self.run_writer()
        self.assertEqual(run.returncode, 0, run.stderr)
        # Same boot, read at the write instant and hours later:
        # always fresh (freshness has no max age by design).
        self.assertEqual(
            self.parse_witness(witness, 123450),
            'WITNESS boot=%s uptime=123.45 fresh=true' % BOOT_A)
        self.assertEqual(
            self.parse_witness(witness, 3600000),
            'WITNESS boot=%s uptime=123.45 fresh=true' % BOOT_A)
        # A later boot reading this file before its own uptime
        # reaches the recorded value (plus 5 s tolerance) sees it
        # as not fresh: the fail-closed direction.
        self.assertEqual(
            self.parse_witness(witness, 100000),
            'WITNESS boot=%s uptime=123.45 fresh=false' % BOOT_A)

    def test_report_mode_writes_nothing(self):
        run, witness, _ = self.run_writer(mode='report')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('WITNESS_RESULT REPORT', run.stdout)
        self.assertIn('FACT boot_id=' + BOOT_A, run.stdout)
        self.assertIn('FACT witness_present=no', run.stdout)
        self.assertFalse(witness.exists())

    def test_write_refused_when_enforcing(self):
        run, witness, _ = self.run_writer(enforce='Enforcing')
        self.assertEqual(run.returncode, 3)
        self.assertFalse(witness.exists())

    def test_write_refused_when_getenforce_unavailable(self):
        run, witness, _ = self.run_writer(stub_getenforce=False)
        self.assertEqual(run.returncode, 3)
        self.assertFalse(witness.exists())

    def test_write_refused_for_non_root_uid(self):
        run, witness, _ = self.run_writer(uid='10055')
        self.assertEqual(run.returncode, 3)
        self.assertFalse(witness.exists())

    def test_write_skipped_on_either_disable_sentinel(self):
        for kwargs in ({'sns_disable': True}, {'cache_disable': True}):
            with self.subTest(**kwargs):
                run, witness, _ = self.run_writer(**kwargs)
                self.assertEqual(run.returncode, 2)
                self.assertIn('WITNESS_RESULT SKIPPED', run.stdout)
                self.assertFalse(witness.exists())

    def test_write_rejects_malformed_boot_id(self):
        for bad in ('AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
                    'not-a-uuid', '', BOOT_A + ' ',
                    BOOT_A + '\n' + BOOT_A + '\n'):
            with self.subTest(bad=bad):
                run, witness, _ = self.run_writer(boot=bad)
                self.assertEqual(run.returncode, 4)
                self.assertFalse(witness.exists())

    def test_write_rejects_malformed_uptime(self):
        for bad in ('abc 1.0', '', '-5 3.0', '12.34.56 1.0'):
            with self.subTest(bad=bad):
                run, witness, _ = self.run_writer(uptime=bad)
                self.assertEqual(run.returncode, 4)
                self.assertFalse(witness.exists())

    def test_write_replaces_stale_previous_boot_witness(self):
        run, witness, state = self.run_writer()
        self.assertEqual(run.returncode, 0, run.stderr)
        witness.write_text(BOOT_B + '\n50.0\n')
        run2, witness2, _ = self.run_writer()
        self.assertEqual(run2.returncode, 0, run2.stderr)
        self.assertEqual(witness2.read_bytes(),
                         (BOOT_A + '\n123.45\n').encode())

    def test_write_verify_failure_branch_removes_target(self):
        # A directory squatting on the target path makes the rename
        # land inside it; the read-back then cannot match and the
        # writer must fail closed with exit 5.
        sb = self.sandbox
        state = sb / 'state'
        state.mkdir(exist_ok=True)
        (state / 'boot_witness').mkdir()
        run, witness, _ = self.run_writer()
        self.assertEqual(run.returncode, 5)

    def test_usage_error(self):
        run = subprocess.run(['/bin/sh', str(WRITER)],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 64)

    # -- real parser against adversarial files ----------------------

    def write_raw(self, name, data):
        path = self.sandbox / name
        if isinstance(data, str):
            data = data.encode()
        path.write_bytes(data)
        return path

    def test_parser_rejects_genesis_mangled_shape(self):
        for suffix in ('', '\n'):
            with self.subTest(suffix=repr(suffix)):
                path = self.write_raw('w', MANGLED + suffix)
                self.assertEqual(len((MANGLED + suffix).encode()),
                                 45 + len(suffix))
                self.assertEqual(self.parse_witness(path, 9000000),
                                 'WITNESS null')

    def test_parser_edge_shapes(self):
        cases = [
            # (content, elapsed, expected stdout)
            (BOOT_A + '\n', 1000,
             'WITNESS boot=%s uptime=-1.0 fresh=false' % BOOT_A),
            (BOOT_A + '\n8418.67n\n', 9000000,
             'WITNESS boot=%s uptime=-1.0 fresh=false' % BOOT_A),
            (BOOT_A + '\n-5\n', 9000000,
             'WITNESS boot=%s uptime=-1.0 fresh=false' % BOOT_A),
            (BOOT_A + '\n10.0\nextra\n', 9000000, 'WITNESS null'),
            ('', 9000000, 'WITNESS null'),
            (BOOT_A.upper() + '\n10.0\n', 9000000, 'WITNESS null'),
        ]
        for content, elapsed, expected in cases:
            with self.subTest(content=content):
                path = self.write_raw('w', content)
                self.assertEqual(self.parse_witness(path, elapsed),
                                 expected)

    def test_freshness_table_from_design(self):
        # (witness uptime, app elapsedRealtime ms, expected fresh)
        # Mirrors the design doc section 5 analysis, including the
        # genesis session's real write/read pair (8562.59 written,
        # device uptime 8563.03 at read-back).
        table = [
            (8562.59, 8563030, True),
            (120.0, 30000, False),    # next boot, read too early
            (120.0, 114999, False),   # just outside the 5 s tolerance
            (120.0, 115000, True),    # exactly at the tolerance edge
            (120.0, 125000, True),
            (300.0, 3600000, True),   # same boot, read an hour later
            (0.5, 0, True),
        ]
        for uptime, elapsed, fresh in table:
            with self.subTest(uptime=uptime, elapsed=elapsed):
                path = self.write_raw(
                    'w', '%s\n%s\n' % (BOOT_A, uptime))
                expected = ('WITNESS boot=%s uptime=%s fresh=%s'
                            % (BOOT_A, float(uptime),
                               str(fresh).lower()))
                self.assertEqual(self.parse_witness(path, elapsed),
                                 expected)

    # -- integration posture ----------------------------------------

    def test_waiter_hook_position_and_reference(self):
        text = WAITER.read_text()
        hook = text.index('snusnu-boot-witness.sh write')
        permissive = text.index('logmsg selinux_permissive')
        restore = text.index('magisk_restore_missing_refusing')
        self.assertLess(permissive, hook)
        self.assertLess(hook, restore)
        self.assertIn('FIREHD10_WAITER_BOOT_WITNESS_DESIGN', text)

    def test_writer_posture_by_construction(self):
        text = WRITER.read_text()
        # The writer neither reads nor writes the persist flag and
        # never touches Settings: gating on the flag is a design
        # decision (design doc section 7), enforced here by the
        # flag's total absence from the artifact.
        self.assertNotIn('snusnu_persist_enabled', text)
        self.assertNotIn('settings put', text)
        self.assertNotIn('settings get', text)
        # Atomic replace discipline and self-verification.
        self.assertIn('.boot_witness.tmp', text)
        self.assertIn('mv "$_tmp" "$WITNESS"', text)
        # The witness path matches Stage4BootWitness.WITNESS_PATH.
        self.assertIn('/data/cache/snusnu/state', text)
        java = WITNESS_JAVA.read_text()
        self.assertIn('"/data/cache/snusnu/state/boot_witness"',
                      java)


if __name__ == '__main__':
    unittest.main()
