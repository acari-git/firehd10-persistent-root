# Host tests

Python `unittest` modules (interpreter: **python3.14**; JDK 17 for
the modules that compile the real Java). These are the tests as they
ran against the development tree — each module executes the *real*
device scripts under `/bin/sh` against sandbox fixtures (stubbed
`getprop`/`settings`/`id`/`getenforce` on PATH, file-backed property
stores) and compiles the *real* app/signer Java, rather than testing
re-implementations.

## Layout note (read before running)

The modules resolve the implementation tree by the development
project's relative paths:

```
build/journal-gated-implementation-20261101/v2/…
build/journal-gated-implementation-20261101/device-signer/…
build/firehd10-live-root-script-snapshot-20261014/…   (launch-helper static pin)
```

In this repository the same content lives at `app/`, `device/`, and
`signer/`. To run the suite, recreate the development layout from
this repo's files (a symlink shim is enough):

```
v2/stage4-persistent/app/            ← app/ (manifest, build.sh, src/)
v2/stage4-persistent/*.sh            ← device/*.sh
v2/{build-v2.sh, gen_pinned_key.py, manifest-v2.json,
    proof-key/, host-reference/}     ← app/ equivalents
device-signer/                       ← signer/ (+ src/)
snapshot dir                         ← device/ fielded copies of
                                       watchdog/magisk_restore/boot-entry
```

The verification recorded in the publication plan used exactly this
shim, assembled only from this repo's staged files.

## Suite accounting (against the canonical 127)

The development project's canonical host suite is **127 tests**,
grown in layers (59 v1 baseline + 1 v2 bootstrap + 9 device signer +
17 witness writer + 21 launch helper + 1 proof-drop gate + 18
completion worker + 1 persist rearm). The modules staged here are
the ones whose subjects ship in this repo:

| Module | Tests | Subject |
|---|---|---|
| `test_execute_firehd10_journal_v2_bootstrap_host_20261101` | 1 module / 19 scenarios | journal v2 + genesis bootstrap |
| `test_execute_firehd10_device_signer_host_20261101` | 9 | device signer gates, genesis + routine completion |
| `test_execute_firehd10_witness_writer_host_20261101` | 17 | witness writer + app parser |
| `test_execute_firehd10_launch_helper_host_20261101` | 21 | on-demand launch helper + app gating |
| `test_execute_firehd10_proofdrop_gate_host_20261102` | 1 | genesis-challenge gate on proof drops |
| `test_execute_firehd10_completion_worker_host_20261102` | 18 | signer auto-completion worker |
| `test_execute_firehd10_persist_rearm_host_20261102` | 1 | rearm-on-proof closure |
| **Staged canonical subtotal** | **68** | |

Not staged (59 tests): the v1-baseline modules
(`test_build_*`, `test_compile_*`, `test_review_*`, `test_goal_status`,
`test_stage4_two_phase_rearm_audit`, `test_stage4_watchdog_no_early_rearm`,
and the two v1-journal execute modules). Their subjects are the
superseded v1 journal build and October review artifacts that this
repository does not ship, so they cannot run from this tree; they
remain in the development project. The delta is therefore exactly
the v1 baseline: 127 − 68 = 59.

Also staged, outside the canonical 127 (run green alongside it
during development): `test_model_firehd10_crash_safe_one_shot_journal`
(+ its `model_firehd10_crash_safe_one_shot_journal` support module) —
a self-contained model of the crash-safe one-shot journal. Three
further journal-family modules from that extra set are not staged
because their subjects are the v1 review-tree classes.

## Publication scrub note

One fixture constant was scrubbed in this publication copy: the
witness-writer module used the development device's real genesis
boot id as its `BOOT_GENESIS` string. It is replaced here with the
synthetic UUID `01234567-89ab-cdef-0123-456789abcdef` (identical
format and length; the id is an opaque fixture string, no test logic
changed). All other UUID-shaped strings in these modules are
long-standing synthetic fixtures (`aaaaaaaa-…`, `11111111-…`, etc.).
No device serial, real boot id, address, or key material appears in
this directory.

## Verification record (clean room, 2026-11-03)

Verified from this repo's staged files only, assembled into the
development layout per the shim above (the launch-helper module also
reads the installer at the sibling `stage4-persistent/` path; the
staged installer is staged at both shim paths):

- The 7 canonical modules above: **68/68 OK** (bootstrap 1, device
  signer 9, witness writer 17, launch helper 21, proof-drop gate 1,
  completion worker 18, persist rearm 1) under python3.14.
- The crash-safe journal model: **10/10 OK**.
- **Total: 78/78 OK.**

One staged file is a harness, not a suite member:
`test_execute_firehd10_journal_on_host_20261014.py` is included
because the other modules import `ROOT`, `JDK`, and `JAVA_SOURCES`
(the Android test doubles) from it. Its *own* single test targets
the v1 journal classes in the development project's review tree
(`review/firehd10-actor-journal/`), which this repo does not ship;
run here it errors with `FileNotFoundError` for exactly that path.
That test belongs to the excluded v1 baseline (59) in the accounting
above.
