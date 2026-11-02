#!/usr/bin/env python3
"""Host tests for the unattended signer-completion worker
(snusnu-completion.sh), 2026-11-02.

Runs the REAL worker shell script under /bin/sh against sandbox
fixtures: every device path is redirected through the worker's
SNU_COMPLETION_SANDBOX=1 seam, and getenforce / settings / am / id
are PATH stubs with file-backed state. The signer is a stub at the
sandbox signer path that records invocations and can be told to
succeed (delivering a drop) or deny.

Design: FIREHD10_SIGNER_AUTO_COMPLETION_DESIGN_20261102.md.
"""

import os
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.join(
    HERE,
    "build/journal-gated-implementation-20261101/v2/stage4-persistent/"
    "snusnu-completion.sh",
)
LAUNCHER = os.path.join(
    HERE,
    "build/journal-gated-implementation-20261101/v2/stage4-persistent/"
    "snusnu-completion-service.sh",
)

BOOT = "11111111-2222-3333-4444-555555555555"
PREV_BOOT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CHALLENGE = "ab" * 32
COUNT = 207


def _write(path, content, mode=0o644):
    with open(path, "w") as fh:
        fh.write(content)
    os.chmod(path, mode)


class CompletionFixture(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="snusnu-completion-")
        self.bin = os.path.join(self.dir, "bin")
        os.makedirs(self.bin)
        os.makedirs(os.path.join(self.dir, "proof-drop"))
        # Fixture state files.
        _write(os.path.join(self.dir, "boot_id"), BOOT + "\n")
        _write(os.path.join(self.dir, "attr"), "u:r:magisk:s0")
        _write(os.path.join(self.dir, "enforcing.log"),
               "2026-11-02T00:00:00Z boot=%s OK enforcing-restored "
               "owner=u:r:magisk:s0\n" % BOOT)
        _write(os.path.join(self.dir, "boot_count"), str(COUNT))
        _write(os.path.join(self.dir, "proof_status"),
               "proof_completed_dps")
        _write(os.path.join(self.dir, "enforcing_state"), "Enforcing")
        _write(os.path.join(self.dir, "signer_mode"), "ok")
        _write(os.path.join(self.dir, "am_mode"), "complete")
        self.journal_path = os.path.join(self.dir, "journal.state")
        self.request_path = os.path.join(self.dir, "proof_request")
        self.result_log = os.path.join(self.dir, "result.log")
        self._stub_binaries()
        self._stub_signer()

    # -- fixture construction -------------------------------------

    def _stub_binaries(self):
        d = self.dir
        _write(os.path.join(self.bin, "id"),
               "#!/bin/sh\n"
               "if [ \"$1\" = \"-u\" ]; then cat \"%s/uid\"; "
               "else echo \"uid=$(cat \"%s/uid\")\"; fi\n" % (d, d),
               0o755)
        _write(os.path.join(self.dir, "uid"), "0")
        _write(os.path.join(self.bin, "getenforce"),
               "#!/bin/sh\ncat \"%s/enforcing_state\"\n" % d, 0o755)
        _write(os.path.join(self.bin, "settings"),
               "#!/bin/sh\n"
               "echo \"settings $*\" >> \"%s/settings_calls\"\n"
               "if [ \"$1 $2\" = \"get global\" ]; then\n"
               "  case \"$3\" in\n"
               "    boot_count) cat \"%s/boot_count\" ;;\n"
               "    snusnu_proof_status) cat \"%s/proof_status\" ;;\n"
               "  esac\n"
               "fi\n" % (d, d, d),
               0o755)
        _write(os.path.join(self.bin, "am"),
               "#!/bin/sh\n"
               "echo \"am $*\" >> \"%s/am_calls\"\n"
               "mode=$(cat \"%s/am_mode\")\n"
               "if [ \"$mode\" = \"fail\" ]; then\n"
               "  echo \"Error: not started\"; exit 1\n"
               "fi\n"
               "if [ \"$mode\" = \"complete\" ]; then\n"
               "  printf 'READY:%%s:%%s\\n' \"%s\" \"%s\" > \"%s\"\n"
               "fi\n"
               "echo \"Starting: $*\"\n" % (d, d, BOOT, COUNT,
                                          self.journal_path),
               0o755)

    def _stub_signer(self):
        d = self.dir
        drop = os.path.join(self.dir, "proof-drop", "stage4-proof.txt")
        _write(os.path.join(self.dir, "signer.sh"),
               "#!/bin/sh\n"
               "echo \"signer $*\" >> \"%s/signer_calls\"\n"
               "mode=$(cat \"%s/signer_mode\")\n"
               "if [ \"$1\" = \"report\" ]; then\n"
               "  echo \"FACT uid=0\"\n"
               "  echo \"SIGNER_RESULT OK mode=report\"\n"
               "  exit 0\n"
               "fi\n"
               "if [ \"$mode\" = \"deny\" ]; then\n"
               "  echo \"SIGNER_RESULT DENY mode=sign-proof "
               "reason=su_measurement\"\n"
               "  exit 3\n"
               "fi\n"
               "printf 'stage4-root-v1|%%s|%%s|uid=0\\n' \"%s\" \"%s\" "
               "> \"%s\"\n"
               "echo \"SIGNER DELIVERED %s\"\n"
               "echo \"SIGNER_RESULT OK mode=sign-proof boot=%s\"\n"
               % (d, d, BOOT, CHALLENGE, drop, drop, BOOT),
               0o755)

    # -- helpers ---------------------------------------------------

    def set_journal(self, content):
        _write(self.journal_path, content)

    def set_request(self, content):
        if content is None:
            if os.path.exists(self.request_path):
                os.remove(self.request_path)
        else:
            _write(self.request_path, content)

    def env(self, **extra):
        env = dict(os.environ)
        env["PATH"] = self.bin + ":" + env["PATH"]
        env["SNU_COMPLETION_SANDBOX"] = "1"
        env["SNU_COMPLETION_BOOT_ID_FILE"] = os.path.join(
            self.dir, "boot_id")
        env["SNU_COMPLETION_ATTR_FILE"] = os.path.join(self.dir, "attr")
        env["SNU_COMPLETION_ENFORCING_LOG"] = os.path.join(
            self.dir, "enforcing.log")
        env["SNU_COMPLETION_JOURNAL_FILE"] = self.journal_path
        env["SNU_COMPLETION_REQUEST_FILE"] = self.request_path
        env["SNU_COMPLETION_DROP_DIR"] = os.path.join(
            self.dir, "proof-drop")
        env["SNU_COMPLETION_SIGNER"] = os.path.join(
            self.dir, "signer.sh")
        env["SNU_COMPLETION_RESULT_LOG"] = self.result_log
        env["SNU_COMPLETION_LOCK_DIR"] = os.path.join(self.dir, "lock")
        env["SNU_COMPLETION_MARKER_BUDGET_S"] = "3"
        env["SNU_COMPLETION_MARKER_POLL_S"] = "1"
        env["SNU_COMPLETION_VERIFY_BUDGET_S"] = "3"
        env["SNU_COMPLETION_VERIFY_POLL_S"] = "1"
        env.update(extra)
        return env

    def run_worker(self, mode="run", **extra):
        return subprocess.run(
            ["/bin/sh", WORKER, mode],
            env=self.env(**extra), capture_output=True, text=True,
            timeout=60)

    def result_text(self):
        if not os.path.exists(self.result_log):
            return ""
        with open(self.result_log) as fh:
            return fh.read()

    def signer_calls(self):
        path = os.path.join(self.dir, "signer_calls")
        if not os.path.exists(path):
            return ""
        with open(path) as fh:
            return fh.read()

    def am_calls(self):
        path = os.path.join(self.dir, "am_calls")
        if not os.path.exists(path):
            return ""
        with open(path) as fh:
            return fh.read()

    def journal_bytes(self):
        with open(self.journal_path, "rb") as fh:
            return fh.read()

    def inflight(self, boot=BOOT, count=COUNT):
        return "INFLIGHT:%s:%d:%s:%s\n" % (boot, count, CHALLENGE,
                                           PREV_BOOT)


class TestCompletionWorker(CompletionFixture):

    def test_ready_is_noop(self):
        self.set_journal("READY:%s:%d\n" % (PREV_BOOT, COUNT - 1))
        before = self.journal_bytes()
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("NO_OP_READY", self.result_text())
        self.assertEqual(self.signer_calls(), "")
        self.assertEqual(self.journal_bytes(), before)

    def test_inflight_completes_end_to_end(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls = self.signer_calls()
        self.assertEqual(calls.count("sign-proof-request"), 1)
        self.assertIn("start-foreground-service", self.am_calls())
        results = self.result_text()
        self.assertIn("SIGNED", results)
        self.assertIn("COMPLETED", results)
        self.assertTrue(self.journal_bytes().startswith(
            ("READY:%s:" % BOOT).encode()))

    def test_stale_inflight_is_noop(self):
        self.set_journal(self.inflight(boot=PREV_BOOT, count=COUNT - 1))
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        before = self.journal_bytes()
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("NO_OP_STALE", self.result_text())
        self.assertEqual(self.signer_calls(), "")
        self.assertEqual(self.journal_bytes(), before)

    def test_no_marker_no_sign(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        _write(os.path.join(self.dir, "enforcing.log"),
               "2026-11-02T00:00:00Z unrelated line\n")
        proc = self.run_worker(SNU_COMPLETION_MARKER_BUDGET_S="0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("NO_MARKER", self.result_text())
        self.assertEqual(self.signer_calls(), "")

    def test_signer_denial_leaves_journal_untouched(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        _write(os.path.join(self.dir, "signer_mode"), "deny")
        before = self.journal_bytes()
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 5, proc.stderr)
        self.assertIn("SIGN_DENIED", self.result_text())
        # Exactly one signing attempt: the used-challenge ledger
        # makes blind retries useless, so the worker never retries.
        self.assertEqual(self.signer_calls().count(
            "sign-proof-request"), 1)
        self.assertEqual(self.am_calls(), "")
        self.assertEqual(self.journal_bytes(), before)

    def test_existing_drop_skips_signing(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        _write(os.path.join(self.dir, "proof-drop",
                            "stage4-proof.txt"),
               "stage4-root-v1|%s|%s|uid=0|ctx=u:r:magisk:s0|"
               "selinux=Enforcing\nc2ln\n" % (BOOT, CHALLENGE))
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("SIGN_SKIPPED", self.result_text())
        self.assertIn("COMPLETED", self.result_text())
        self.assertEqual(self.signer_calls(), "")
        self.assertIn("start-foreground-service", self.am_calls())

    def test_trigger_falls_back_to_broadcast_on_error(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        _write(os.path.join(self.dir, "am_mode"), "fail")
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 5, proc.stderr)
        calls = self.am_calls()
        self.assertIn("start-foreground-service", calls)
        self.assertIn("MY_PACKAGE_REPLACED", calls)
        self.assertIn("NOT_COMPLETED", self.result_text())

    def test_stale_drop_is_signed_over(self):
        # The app never deletes a processed drop, so an earlier
        # boot's proof file normally still sits in the drop dir.
        # It must not suppress signing for the new boot.
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        _write(os.path.join(self.dir, "proof-drop",
                            "stage4-proof.txt"),
               "stage4-root-v1|%s|%s|uid=0|ctx=u:r:magisk:s0|"
               "selinux=Enforcing\nc2ln\n" % (PREV_BOOT, "cd" * 32))
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        results = self.result_text()
        self.assertIn("DROP_STALE", results)
        self.assertIn("COMPLETED", results)
        self.assertEqual(self.signer_calls().count(
            "sign-proof-request"), 1)

    def test_degraded_inflight_completes(self):
        self.set_journal("INFLIGHT:?:%d:%s:%s\n" % (
            COUNT, CHALLENGE, PREV_BOOT))
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("COMPLETED", self.result_text())
        self.assertEqual(self.signer_calls().count(
            "sign-proof-request"), 1)

    def test_wrong_context_refused(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        _write(os.path.join(self.dir, "attr"), "u:r:time_update:s0")
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertIn("REFUSED_CTX", self.result_text())
        self.assertEqual(self.signer_calls(), "")

    def test_foreign_journal_untouched(self):
        self.set_journal("GARBAGE-RECORD\n")
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        before = self.journal_bytes()
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("NO_OP_JOURNAL", self.result_text())
        self.assertEqual(self.signer_calls(), "")
        self.assertEqual(self.journal_bytes(), before)

    def test_existing_lock_blocks_second_instance(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        lock = os.path.join(self.dir, "lock")
        os.makedirs(lock)
        _write(os.path.join(lock, "boot"), BOOT + "\n")
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("LOCKED", self.result_text())
        self.assertEqual(self.signer_calls(), "")

    def test_request_for_other_boot_is_noop(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (PREV_BOOT, CHALLENGE))
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("NO_OP_NO_REQUEST", self.result_text())
        self.assertEqual(self.signer_calls(), "")

    def test_verify_timeout_reports_not_completed(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        _write(os.path.join(self.dir, "am_mode"), "noop")
        proc = self.run_worker()
        self.assertEqual(proc.returncode, 5, proc.stderr)
        self.assertIn("NOT_COMPLETED", self.result_text())
        self.assertEqual(self.signer_calls().count(
            "sign-proof-request"), 1)

    def test_report_mode_writes_nothing(self):
        self.set_journal(self.inflight())
        self.set_request("%s %s\n" % (BOOT, CHALLENGE))
        before = self.journal_bytes()
        proc = self.run_worker(mode="report")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("FACT journal=INFLIGHT_OURS", proc.stdout)
        self.assertIn("FACT context=u:r:magisk:s0", proc.stdout)
        self.assertFalse(os.path.exists(self.result_log))
        self.assertEqual(self.journal_bytes(), before)
        self.assertEqual(self.signer_calls(), "")


class TestCompletionStatics(unittest.TestCase):

    def _worker_text(self):
        with open(WORKER) as fh:
            lines = fh.read().splitlines()
        # Static checks apply to code, not to the header comments
        # (which describe what the worker must never do).
        code = [l for l in lines if not l.lstrip().startswith("#")]
        return "\n".join(code)

    def test_worker_has_no_write_paths_to_authority_state(self):
        text = self._worker_text()
        # The worker must never write Settings, the journal, the
        # persist property, or either sentinel.
        self.assertNotIn("settings put", text)
        self.assertNotIn("persist.sys.saved_time", text)
        self.assertNotIn("snusnu_persist_enabled", text)
        self.assertNotIn("> \"$JOURNAL_FILE\"", text)
        self.assertNotIn(">$JOURNAL_FILE", text)

    def test_signer_invocation_is_production_launcher(self):
        text = self._worker_text()
        self.assertIn('"$SIGNER" sign-proof-request', text)
        self.assertIn(
            "/data/snusnu_root/signer/snusnu-proof-signer.sh", text)

    def test_launcher_detaches_and_targets_worker(self):
        with open(LAUNCHER) as fh:
            text = fh.read()
        self.assertIn(
            "/data/snusnu_root/bin/snusnu-completion.sh run", text)
        self.assertIn(") </dev/null >/dev/null 2>&1 &", text)
        self.assertTrue(text.rstrip().endswith("exit 0"))


if __name__ == "__main__":
    unittest.main()
