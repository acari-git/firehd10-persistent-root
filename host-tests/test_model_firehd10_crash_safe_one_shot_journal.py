import unittest

from model_firehd10_crash_safe_one_shot_journal import (
    Journal, plan_attempt, persist_attempt_lockout, launch_native,
    trusted_su_succeeded, commit_next_boot, crash_and_boot, audit,
)


class CrashSafeJournalTests(unittest.TestCase):
    def test_uncommitted_inflight_refuses_native(self):
        state = plan_attempt(Journal(), 'boot-A')
        with self.assertRaises(ValueError):launch_native(state)

    def test_failed_storage_commit_denies_native(self):
        with self.assertRaises(ValueError):
            persist_attempt_lockout(plan_attempt(Journal(), 'boot-A'), storage_commit_attested=False)

    def test_kernel_panic_leaves_retry_disabled(self):
        state = launch_native(persist_attempt_lockout(
            plan_attempt(Journal(), 'boot-A'), storage_commit_attested=True))
        self.assertTrue(crash_and_boot(state)['panic_after_unfinished_attempt_auto_retry_blocked'])

    def test_same_boot_second_native_attempt_is_denied(self):
        state = launch_native(persist_attempt_lockout(
            plan_attempt(Journal(), 'boot-A'), storage_commit_attested=True))
        with self.assertRaises(ValueError):launch_native(state)

    def test_reusing_previous_boot_id_is_denied(self):
        with self.assertRaises(ValueError):plan_attempt(Journal(), 'boot-previous')

    def test_missing_magisk_source_proof_cannot_rearm(self):
        state = launch_native(persist_attempt_lockout(
            plan_attempt(Journal(), 'boot-A'), storage_commit_attested=True))
        with self.assertRaises(ValueError):
            trusted_su_succeeded(state,same_boot=True,uid0=True,magisk_context=True,
                                 global_enforcing=True,magisk_origin_authenticated=False)

    def test_permissive_root_cannot_rearm(self):
        state = launch_native(persist_attempt_lockout(
            plan_attempt(Journal(), 'boot-A'), storage_commit_attested=True))
        with self.assertRaises(ValueError):
            trusted_su_succeeded(state,same_boot=True,uid0=True,magisk_context=True,
                                 global_enforcing=False,magisk_origin_authenticated=True)

    def test_uncommitted_root_rearm_refuses(self):
        state = launch_native(persist_attempt_lockout(
            plan_attempt(Journal(), 'boot-A'), storage_commit_attested=True))
        proved = trusted_su_succeeded(state,same_boot=True,uid0=True,
                                     magisk_context=True,global_enforcing=True,
                                     magisk_origin_authenticated=True)
        with self.assertRaises(ValueError):commit_next_boot(proved,storage_commit_attested=False)
        self.assertTrue(crash_and_boot(proved)['panic_after_unfinished_attempt_auto_retry_blocked'])

    def test_after_verified_success_arm_is_conditional(self):
        report = audit()
        self.assertTrue(report['crash_scenarios']['after_trusted_root_and_rearm_commit']
                        ['next_boot_native_auto_attempt_allowed_by_journal'])
        self.assertFalse(report['crash_scenarios']['during_kernel_attempt']
                         ['next_boot_native_auto_attempt_allowed_by_journal'])

    def test_model_never_claims_device_durability_or_brick_safety(self):
        report = audit()
        self.assertFalse(report['correct_pre_kernel_fsync_android_implementation_exists'])
        self.assertFalse(report['normal_boot_and_independent_unbrick_guaranteed'])
        self.assertFalse(report['goal_complete'])


if __name__ == '__main__':
    unittest.main()
