#!/usr/bin/env python3
"""HOST ONLY state-machine contract for crash-safe, one-shot root attempts.

The actor must durably mark INFLIGHT *before* touching the kernel. A later
panic then leaves a marker causing the next boot to refuse another native
attempt. This is a specification, not a tested Android implementation.
"""

from dataclasses import dataclass, replace
import argparse
import json
from pathlib import Path

STATES = ('DISABLED', 'READY', 'INFLIGHT', 'VERIFYING')


@dataclass(frozen=True)
class Journal:
    # Represents durable storage only when a commit is explicitly attested.
    durable: str = 'READY'
    boot_id: str = 'boot-previous'
    attempt_count: int = 0
    volatile_candidate: str | None = None
    device_native_attempted: bool = False
    magisk_proof_accepted: bool = False


def plan_attempt(state: Journal, boot_id: str) -> Journal:
    if state.durable != 'READY' or not boot_id or boot_id == state.boot_id:
        raise ValueError('not ready for a new boot-specific attempt')
    return replace(state, volatile_candidate='INFLIGHT', boot_id=boot_id)


def persist_attempt_lockout(state: Journal, *, storage_commit_attested: bool) -> Journal:
    if state.volatile_candidate != 'INFLIGHT' or not storage_commit_attested:
        raise ValueError('commit not proven: do not run kernel primitive')
    return replace(state, durable='INFLIGHT', volatile_candidate=None,
                   attempt_count=state.attempt_count + 1)


def launch_native(state: Journal) -> Journal:
    if state.durable != 'INFLIGHT' or state.volatile_candidate is not None:
        raise ValueError('INFLIGHT must have been durably recorded before launch')
    if state.device_native_attempted:
        raise ValueError('only one native operation per current boot')
    return replace(state, device_native_attempted=True)


def trusted_su_succeeded(state: Journal, *, same_boot: bool, uid0: bool,
                         magisk_context: bool, global_enforcing: bool,
                         magisk_origin_authenticated: bool) -> Journal:
    proven = (same_boot and uid0 and magisk_context and global_enforcing
              and magisk_origin_authenticated)
    if state.durable != 'INFLIGHT' or not state.device_native_attempted or not proven:
        raise ValueError('cannot rearm without a trusted, same-boot root proof')
    return replace(state, volatile_candidate='READY', magisk_proof_accepted=True)


def commit_next_boot(state: Journal, *, storage_commit_attested: bool) -> Journal:
    if not state.magisk_proof_accepted or state.volatile_candidate != 'READY':
        raise ValueError('no trusted root proof for rearm')
    if not storage_commit_attested:
        raise ValueError('next-boot arming not durably committed')
    return replace(state, durable='READY', volatile_candidate=None)


def crash_and_boot(state: Journal) -> dict:
    # Volatile candidate and running root do not survive panic.
    # A trustworthy commit is an assumption of this abstract contract.
    return {
        'durable_before_crash': state.durable,
        'native_was_attempted_before_crash': state.device_native_attempted,
        'next_boot_native_auto_attempt_allowed_by_journal': state.durable == 'READY',
        'panic_after_unfinished_attempt_auto_retry_blocked':
            state.durable == 'INFLIGHT',
        'normal_OS_boot_guaranteed': False,
        'android_storage_commit_durability_proven_on_device': False,
        'unsigned_bootchain_recovery_proven': False,
    }


def audit() -> dict:
    original = Journal()
    volatile = plan_attempt(original, 'boot-A')
    prelaunch = persist_attempt_lockout(volatile, storage_commit_attested=True)
    in_progress = launch_native(prelaunch)
    trusted = trusted_su_succeeded(
        in_progress, same_boot=True, uid0=True, magisk_context=True,
        global_enforcing=True, magisk_origin_authenticated=True)
    ready_after_success = commit_next_boot(trusted, storage_commit_attested=True)
    scenarios = {
        'before_lockout_commit': crash_and_boot(volatile),
        'after_lockout_before_native': crash_and_boot(prelaunch),
        'during_kernel_attempt': crash_and_boot(in_progress),
        'after_root_proof_before_rearm_commit': crash_and_boot(trusted),
        'after_trusted_root_and_rearm_commit': crash_and_boot(ready_after_success),
    }
    if scenarios['during_kernel_attempt']['next_boot_native_auto_attempt_allowed_by_journal']:
        raise ValueError('panic would automatically rerun the dangerous primitive')
    if scenarios['after_root_proof_before_rearm_commit']['next_boot_native_auto_attempt_allowed_by_journal']:
        raise ValueError('uncommitted permission would be wrongly honored')
    return {
        'scope': 'pure host state model, no root payload or device interaction',
        'model': 'KFTRWI/trona', 'build': 'PS7331.4463N',
        'source_of_privileged_proof': 'hypothetical authenticated Magisk context',
        'native_must_follow_durable_inflight_transition': True,
        'native_retried_after_panic': False,
        'watchdog_must_honor_journal_and_not_arm_while_inflight': True,
        'correct_pre_kernel_fsync_android_implementation_exists': False,
        'verified_system_app_persistence_storage_label_and_access': False,
        'authenticated_magisk_success_signal_implemented': False,
        'atomic_rearm_of_both_android_setting_and_time_property_proven': False,
        'real_device_root_reboot_tested_here': False,
        'normal_boot_and_independent_unbrick_guaranteed': False,
        'goal_complete': False,
        'crash_scenarios': scenarios,
        'verdict': ('HOST-ONLY SPECIFICATION: crash-safe one-shot retry control '
                    'requires a durable INFLIGHT journal before native work; '
                    'no such Android proof exists yet.'),
    }


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    if args.output.exists():
        p.error('refuse overwrite')
    d = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(d, ensure_ascii=False, indent=2) + '\n')
    print(d['verdict'])
