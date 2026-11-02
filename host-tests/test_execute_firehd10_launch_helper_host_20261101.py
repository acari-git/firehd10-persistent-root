"""Execute the journal-gated on-demand waiter launcher on the host.

Runs the REAL helper script (v2 stage4-persistent tree) under /bin/sh
against sandbox fixtures: getprop/setprop/settings/id are stubbed
through PATH with a file-backed property store, so the helper's
protocol -- gate checks, transient arming, ctl.start, launch
confirmation via the service's still-running state, byte-exact
numeric restore, per-boot latch -- is exercised end to end,
including the TimeService race modelled from the 2026-11-01
measurements (a numeric write landing between the helper's arm and
the service's read makes the service perform its stock clock
restore and exit quickly; the helper must detect the miss from the
service state, not from hope, and retry once).

Also covered: report mode writes nothing, both disable sentinels,
the persist flag, slot-state refusals, the busy-service refusal,
static posture of the helper (it must not grow carrier/restore/
SELinux powers), the trigger constant's byte equality across the
helper, the preserved October watchdog and the app, the app-side
ordering (journal begin -> channel -> proof request -> launch ->
carrier, with the carrier gated on LAUNCH_RESULT OK), the
installer registration, and a javac compile of the patched
persistence package against the SDK android.jar.

This proves host-side behaviour only. It does NOT prove that this
firmware's init accepts ctl.start from the system context (the
static case is FIREHD10_TIME_UPDATE_ON_DEMAND_CTL_START_
CANDIDATE_20261015.md; on-device acceptance is the verification
session in genesis runbook section 8), nor SELinux behaviour of
the launch on a real boot. Enablement remains a separate,
separately approved decision.
"""

from pathlib import Path
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

from test_execute_firehd10_journal_on_host_20261014 import JDK, ROOT


IMPL = ROOT / 'build/journal-gated-implementation-20261101'
TREE = IMPL / 'v2/stage4-persistent'
HELPER = TREE / 'snusnu-launch.sh'
SERVICE = (TREE / 'app/src/io/github/voidnullvalue/snusnuroot'
           '/persistence/PersistenceService.java')
SNAPSHOT_WATCHDOG = (ROOT / 'build/firehd10-live-root-script-snapshot'
                     '-20261014/watchdog.sh')
INSTALLER = IMPL / 'stage4-persistent/install-hardened-4463-device.sh'
SDK_JAR_GLOB = '/opt/homebrew/share/android-commandlinetools/platforms/*/android.jar'

ORIG = '1793600000000'
RACE_NUMERIC = '1793600055555'
BOOT_COUNT = '195'
TRIGGER_RE = re.compile(r"^T='([^']*)'$", re.M)

GETPROP_STUB = """#!/bin/sh
cat "$SNU_STUB_DIR/prop.$1" 2>/dev/null
"""

SETPROP_STUB = """#!/bin/sh
echo "setprop $1 $2" >> "$SNU_STUB_DIR/ops.log"
case "$1" in
  persist.sys.saved_time)
    printf '%s' "$2" > "$SNU_STUB_DIR/prop.persist.sys.saved_time"
    ;;
  ctl.start)
    if [ "$2" = time_update ]; then
      n=0
      [ -f "$SNU_STUB_DIR/ctl_count" ] && n=$(cat "$SNU_STUB_DIR/ctl_count")
      n=$((n + 1))
      printf '%s' "$n" > "$SNU_STUB_DIR/ctl_count"
      mode=$(cat "$SNU_STUB_DIR/ctl_mode" 2>/dev/null)
      case "$mode" in
        accept)
          printf '%s\\n' "$(cat "$SNU_STUB_DIR/prop.persist.sys.saved_time")" \\
              >> "$SNU_STUB_DIR/reads.log"
          printf 'running' > "$SNU_STUB_DIR/prop.init.svc.time_update"
          ;;
        race_then_accept)
          if [ "$n" -eq 1 ]; then
            printf '%s' "$(cat "$SNU_STUB_DIR/race_numeric")" \\
                > "$SNU_STUB_DIR/prop.persist.sys.saved_time"
            printf '%s\\n' "$(cat "$SNU_STUB_DIR/race_numeric")" \\
                >> "$SNU_STUB_DIR/reads.log"
            printf 'running' > "$SNU_STUB_DIR/prop.init.svc.time_update"
            ( sleep 0.25; printf 'stopped' \\
                > "$SNU_STUB_DIR/prop.init.svc.time_update" ) &
          else
            printf '%s\\n' "$(cat "$SNU_STUB_DIR/prop.persist.sys.saved_time")" \\
                >> "$SNU_STUB_DIR/reads.log"
            printf 'running' > "$SNU_STUB_DIR/prop.init.svc.time_update"
          fi
          ;;
        *) : ;;
      esac
    fi
    ;;
esac
exit 0
"""

SETTINGS_STUB = """#!/bin/sh
if [ "$1" = get ] && [ "$2" = global ]; then
  if [ -f "$SNU_STUB_DIR/setting.$3" ]; then
    cat "$SNU_STUB_DIR/setting.$3"
  else
    echo null
  fi
fi
exit 0
"""

ID_STUB = """#!/bin/sh
if [ "$1" = -u ]; then cat "$SNU_STUB_DIR/uid"; fi
exit 0
"""


def trigger_of(path):
    match = TRIGGER_RE.search(path.read_text())
    assert match, f'no T= line in {path}'
    return match.group(1)


class LaunchFixture:
    def __init__(self, case):
        self.dir = Path(tempfile.mkdtemp(prefix='snusnu-launch-'))
        case.addCleanup(shutil.rmtree, self.dir, True)
        self.stub = self.dir / 'stub'
        self.stub.mkdir()
        self.state = self.dir / 'state'
        self.state.mkdir()
        for name, body in (('getprop', GETPROP_STUB),
                           ('setprop', SETPROP_STUB),
                           ('settings', SETTINGS_STUB),
                           ('id', ID_STUB)):
            path = self.stub / name
            path.write_text(body)
            path.chmod(0o755)
        self.write_prop('persist.sys.saved_time', ORIG)
        self.write_prop('init.svc.time_update', 'stopped')
        self.write_setting('snusnu_persist_enabled', '1')
        self.write_setting('boot_count', BOOT_COUNT)
        (self.stub / 'uid').write_text('1000')
        (self.stub / 'ctl_mode').write_text('accept')
        (self.stub / 'race_numeric').write_text(RACE_NUMERIC)
        (self.stub / 'ops.log').write_text('')
        (self.stub / 'reads.log').write_text('')

    def write_prop(self, name, value):
        (self.stub / f'prop.{name}').write_text(value)

    def read_prop(self, name):
        return (self.stub / f'prop.{name}').read_text()

    def write_setting(self, name, value):
        (self.stub / f'setting.{name}').write_text(value)

    def ops(self):
        return (self.stub / 'ops.log').read_text().splitlines()

    def reads(self):
        text = (self.stub / 'reads.log').read_text()
        return [line for line in text.splitlines() if line]

    def run(self, *args):
        env = dict(os.environ)
        env.update({
            'PATH': f"{self.stub}:/usr/bin:/bin",
            'SNU_STUB_DIR': str(self.stub),
            'SNU_LAUNCH_SANDBOX': '1',
            'SNU_LAUNCH_STATE_DIR': str(self.state),
            'SNU_LAUNCH_SNS_DISABLE': str(self.dir / 'sns_disable'),
            'SNU_LAUNCH_CACHE_DISABLE': str(self.dir / 'cache_disable'),
            'SNU_LAUNCH_POLL_SLEEP': '0.02',
            'SNU_LAUNCH_POLL_MAX': '100',
            'SNU_LAUNCH_CONFIRM_SLEEP': '0.6',
            'SNU_LAUNCH_BUSY_MAX': '50',
        })
        return subprocess.run(
            ['/bin/sh', str(HELPER), *args],
            capture_output=True, text=True, env=env, timeout=60)

    def tree_hashes(self):
        hashes = {}
        for path in sorted(self.dir.rglob('*')):
            if path.is_file():
                hashes[str(path.relative_to(self.dir))] = \
                    hashlib.sha256(path.read_bytes()).hexdigest()
        return hashes


class LaunchProtocolTest(unittest.TestCase):
    def test_happy_path_ordering_and_restore(self):
        fx = LaunchFixture(self)
        trigger = trigger_of(HELPER)
        result = fx.run('launch')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('LAUNCH_RESULT OK passes=1', result.stdout)
        ops = fx.ops()
        arm = ops.index(f'setprop persist.sys.saved_time {trigger}')
        start = ops.index('setprop ctl.start time_update')
        restore = len(ops) - 1 - ops[::-1].index(
            f'setprop persist.sys.saved_time {ORIG}')
        self.assertLess(arm, start)
        self.assertLess(start, restore)
        self.assertEqual(fx.read_prop('persist.sys.saved_time'), ORIG)
        self.assertEqual(fx.reads(), [trigger])
        record = (fx.state / 'launch_result').read_text()
        self.assertIn('result=OK', record)
        self.assertIn('restored=orig', record)
        self.assertIn('svc_confirmed=yes', record)
        latch = (fx.state / 'launch_attempts').read_text().splitlines()
        self.assertEqual(latch, [BOOT_COUNT, '1'])

    def test_second_pass_after_race_miss(self):
        fx = LaunchFixture(self)
        (fx.stub / 'ctl_mode').write_text('race_then_accept')
        trigger = trigger_of(HELPER)
        result = fx.run('launch')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('LAUNCH_RESULT OK passes=2', result.stdout)
        self.assertEqual(fx.reads(), [RACE_NUMERIC, trigger])
        self.assertEqual(fx.read_prop('persist.sys.saved_time'), ORIG)

    def test_cache_sentinel_skips(self):
        fx = LaunchFixture(self)
        (fx.dir / 'cache_disable').write_text('one-shot-test')
        result = fx.run('launch')
        self.assertEqual(result.returncode, 2)
        self.assertIn('LAUNCH_RESULT SKIPPED cache_disable', result.stdout)
        self.assertEqual(fx.ops(), [])

    def test_sns_sentinel_skips(self):
        fx = LaunchFixture(self)
        (fx.dir / 'sns_disable').write_text('x')
        result = fx.run('launch')
        self.assertEqual(result.returncode, 2)
        self.assertIn('LAUNCH_RESULT SKIPPED sns_disable', result.stdout)
        self.assertEqual(fx.ops(), [])

    def test_persist_disabled_refuses(self):
        fx = LaunchFixture(self)
        fx.write_setting('snusnu_persist_enabled', '0')
        result = fx.run('launch')
        self.assertEqual(result.returncode, 3)
        self.assertIn('persist_disabled', result.stderr)
        self.assertEqual(fx.ops(), [])

    def test_persist_missing_refuses(self):
        fx = LaunchFixture(self)
        (fx.stub / 'setting.snusnu_persist_enabled').unlink()
        result = fx.run('launch')
        self.assertEqual(result.returncode, 3)
        self.assertIn('persist_disabled', result.stderr)
        self.assertEqual(fx.ops(), [])

    def test_wrong_uid_refuses(self):
        for uid in ('0', '2000'):
            with self.subTest(uid=uid):
                fx = LaunchFixture(self)
                (fx.stub / 'uid').write_text(uid)
                result = fx.run('launch')
                self.assertEqual(result.returncode, 3)
                self.assertIn('not_uid1000', result.stderr)
                self.assertEqual(fx.ops(), [])

    def test_latch_exhaustion_and_next_boot(self):
        fx = LaunchFixture(self)
        self.assertEqual(fx.run('launch').returncode, 0)
        # The launched waiter eventually exits; the next invocation
        # again observes a stopped service.
        fx.write_prop('init.svc.time_update', 'stopped')
        self.assertEqual(fx.run('launch').returncode, 0)
        fx.write_prop('init.svc.time_update', 'stopped')
        trigger = trigger_of(HELPER)
        arms_before = sum(
            1 for op in fx.ops()
            if op == f'setprop persist.sys.saved_time {trigger}')
        third = fx.run('launch')
        self.assertEqual(third.returncode, 6)
        self.assertIn('latch_exhausted', third.stderr)
        arms_after = sum(
            1 for op in fx.ops()
            if op == f'setprop persist.sys.saved_time {trigger}')
        self.assertEqual(arms_before, arms_after)
        fx.write_setting('boot_count', str(int(BOOT_COUNT) + 1))
        self.assertEqual(fx.run('launch').returncode, 0)

    def test_latch_corrupt_refuses(self):
        fx = LaunchFixture(self)
        (fx.state / 'launch_attempts').write_text('garbage\n1\n')
        result = fx.run('launch')
        self.assertEqual(result.returncode, 6)
        self.assertIn('latch_unreadable', result.stderr)
        self.assertEqual(fx.ops(), [])

    def test_slot_already_armed_refuses(self):
        fx = LaunchFixture(self)
        trigger = trigger_of(HELPER)
        fx.write_prop('persist.sys.saved_time', trigger)
        result = fx.run('launch')
        self.assertEqual(result.returncode, 4)
        self.assertIn('slot_armed_foreign', result.stderr)
        self.assertEqual(fx.read_prop('persist.sys.saved_time'), trigger)
        self.assertFalse(any('ctl.start' in op for op in fx.ops()))

    def test_slot_garbage_refuses(self):
        fx = LaunchFixture(self)
        fx.write_prop('persist.sys.saved_time', 'not-a-time')
        result = fx.run('launch')
        self.assertEqual(result.returncode, 4)
        self.assertIn('slot_not_numeric', result.stderr)
        self.assertEqual(fx.ops(), [])

    def test_service_never_starts(self):
        fx = LaunchFixture(self)
        (fx.stub / 'ctl_mode').write_text('reject')
        result = fx.run('launch')
        self.assertEqual(result.returncode, 5)
        self.assertIn('no_launch_confirmed', result.stderr)
        self.assertEqual(fx.read_prop('persist.sys.saved_time'), ORIG)
        record = (fx.state / 'launch_result').read_text()
        self.assertIn('result=FAILED', record)
        latch = (fx.state / 'launch_attempts').read_text().splitlines()
        self.assertEqual(latch, [BOOT_COUNT, '1'])

    def test_service_busy_refuses(self):
        fx = LaunchFixture(self)
        fx.write_prop('init.svc.time_update', 'running')
        result = fx.run('launch')
        self.assertEqual(result.returncode, 5)
        self.assertIn('service_busy', result.stderr)
        trigger = trigger_of(HELPER)
        self.assertNotIn(
            f'setprop persist.sys.saved_time {trigger}', fx.ops())
        self.assertEqual(fx.read_prop('persist.sys.saved_time'), ORIG)

    def test_service_busy_then_starts(self):
        fx = LaunchFixture(self)
        fx.write_prop('init.svc.time_update', 'running')

        def release():
            time.sleep(0.3)
            fx.write_prop('init.svc.time_update', 'stopped')

        threading.Thread(target=release).start()
        result = fx.run('launch')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('LAUNCH_RESULT OK', result.stdout)

    def test_report_mode_writes_nothing(self):
        fx = LaunchFixture(self)
        before = fx.tree_hashes()
        result = fx.run('report')
        self.assertEqual(result.returncode, 0)
        self.assertIn('FACT saved_time_class=numeric', result.stdout)
        self.assertIn('FACT persist_enabled=1', result.stdout)
        self.assertIn('LAUNCH_RESULT REPORT', result.stdout)
        fx.write_prop('persist.sys.saved_time', trigger_of(HELPER))
        result = fx.run('report')
        self.assertIn('FACT saved_time_class=trigger', result.stdout)
        after = fx.tree_hashes()
        changed = {k for k in before
                   if before[k] != after.get(k)}
        self.assertEqual(changed, {'stub/prop.persist.sys.saved_time'})


class LaunchStaticTest(unittest.TestCase):
    def test_trigger_constant_matches_deployed(self):
        helper_t = trigger_of(HELPER)
        watchdog_t = trigger_of(SNAPSHOT_WATCHDOG)
        self.assertEqual(helper_t, watchdog_t)
        service_text = SERVICE.read_text()
        match = re.search(
            r'String TRIGGER =\s*"([^"]*)"', service_text)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), helper_t)

    def test_helper_static_posture(self):
        text = HELPER.read_text()
        # Posture is about what the helper can DO: scan executable
        # lines only (the header prose legitimately names the
        # components it must never invoke).
        code = '\n'.join(
            line for line in text.splitlines()
            if not line.lstrip().startswith('#'))
        for forbidden in ('magisk_restore', 'snusnu_hwbinder_root',
                          'setenforce', 'ctl.stop', 'watchdog',
                          'snusnu-boot-witness'):
            self.assertNotIn(forbidden, code)
        for required in ('/data/cache/snusnu/disable',
                         '/data/securedStorageLocation/snusnu/disable',
                         'snusnu_persist_enabled', 'ctl.start',
                         'init.svc.time_update'):
            self.assertIn(required, text)

    def test_app_ordering_and_carrier_gate(self):
        text = SERVICE.read_text()
        begin = text.index('beginOneShot')
        spawn = text.index('spawnSystemChannel())')
        proof = text.index('writeProofRequest(bootId')
        launch = text.index('LAUNCHER_PATH + " launch"')
        carrier = text.index('sys.boot_completed')
        self.assertLess(begin, spawn)
        self.assertLess(spawn, proof)
        self.assertLess(proof, launch)
        self.assertLess(launch, carrier)
        gate_block = text[launch:carrier]
        self.assertIn('LAUNCH_RESULT OK', gate_block)
        self.assertIn('waiter_launch_failed', gate_block)
        self.assertIn('return;', gate_block)

    def test_installer_registers_helper(self):
        text = INSTALLER.read_text()
        self.assertIn(
            'install_exec snusnu-launch.sh '
            '"$WATCHDOGDIR/snusnu-launch.sh" 0755 0 0 system_data_file',
            text)

    def test_result_record_written_directly(self):
        # Boot 195 (2026-11-01): the helper's LAUNCH_RESULT OK was
        # printed but never landed in launch_result -- the tmp+rename
        # write was denied by SELinux (avc denied { rename } from the
        # system_app domain onto cache_file), destroying the operator
        # record. write_result must create/write RESULT_FILE directly,
        # exactly as write_latch does.
        text = HELPER.read_text()
        start = text.index("write_result()")
        end = text.index("\n}", start)
        body = text[start:end]
        self.assertNotIn(".launch_result.tmp", body)
        self.assertNotIn("mv ", body)
        self.assertIn('> "$RESULT_FILE"', body)

    @unittest.skipUnless((JDK / 'javac').exists(), 'javac unavailable')
    def test_persistence_package_compiles(self):
        import glob as glob_module
        jars = sorted(glob_module.glob(SDK_JAR_GLOB))
        if not jars:
            self.skipTest('no SDK android.jar')
        package = SERVICE.parent
        sources = sorted(str(p) for p in package.glob('*.java'))
        out = Path(tempfile.mkdtemp(prefix='snusnu-launch-javac-'))
        self.addCleanup(shutil.rmtree, out, True)
        result = subprocess.run(
            [str(JDK / 'javac'), '-cp', jars[-1], '-d', str(out),
             *sources],
            capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr[-3000:])


if __name__ == '__main__':
    unittest.main()
