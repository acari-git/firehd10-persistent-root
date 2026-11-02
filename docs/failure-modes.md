# Failure modes

Everything below was observed on the real device and is part of why
the system is shaped the way it is.

## ENODATA: the probabilistic carrier miss

The Stage4 leak step reads back sprayed kernel objects. A miss shows
the `LIST_POISON2` signature (`node=0xdead000000000200`) — an RCU
grace-period / kmalloc-reuse race: the sprayed slot was not reused in
time. It is the historically most common miss type (7 of 10 recorded
misses) and it is a **per-boot draw**, not a deteriorating condition:

- Driver Phase B record across Oct–Nov 2026: **9/19 ≈ 47%**. At that
  rate, three consecutive misses (probability ≈0.21) are unremarkable
  — and indeed the longest historical streak (2026-10-11, and again
  2026-11-02) was 3, each resolving on a later fresh boot.
- No discriminating variable was found in the log comparison:
  saved_time delta, boot-count parity, and time of day all overlap
  completely between successes and misses. The only differing output
  is the leak step itself.
- A miss performs **no kernel write** (`ENODATA_LEAK_MISS_NO_WRITE`).
  The device returns to stock and can be retried on a fresh boot.

Operational rules that follow: retry only on this miss class, at
most 3 attempts per sequence, never change carrier parameters to
"improve the odds" (the hash-pinned 10 ms build is kept as-is).

## A missed armed boot disarms (by design)

Boot 209 (2026-11-02, first power-on after a 12.5 h power-off): the
app-side carrier missed on attempt 1 → `enodata_exhausted`,
`proof_status=proof_rejected`, and the app consumed the arming and
did **not** re-arm (persist 1→0). The journal stayed INFLIGHT. This
is the fail-closed contract working as designed — but it means a
missed boot is not self-healing: recovery needs the host-driven
flow in `genesis.md` (re-acquire root → sign-genesis lockout
recovery → restage → re-arm). App-side armed boots measured 9/10,
so this is an occasional, expected cost of the safety posture, not
an anomaly.

## Defects found by measurement, and their fixes

- **Channel reply deadlock.** The system-channel gate ends in an
  interactive shell that never exits; the app originally never
  half-closed, so command replies deadlocked into 120 s timeouts
  (boot 195: the launch had in fact succeeded on-device while the
  app timed out and disarmed). Fix: the app flushes and
  `shutdownOutput()`s after sending; the gate's shell sees EOF and
  the reply returns. Lesson recorded project-wide: verify every
  state-changing command by independent read-back — one "refused"
  lift in this project had in fact executed under an unknown-status
  result.
- **Helper result-write AVC denial.** The launch helper's tmp+rename
  result write was denied (rename, system_app→cache_file), losing
  the record. Fix: direct write.
- **Stale genesis drop re-evaluation.** The app never deletes
  processed drops; a consumed genesis drop was later re-scored as a
  lockout-recovery candidate against a new challenge and flipped
  `proof_status` to `genesis_rejected`. No journal or custody damage
  (a failed attempt writes nothing), and the fix gates the genesis
  branch on challenge equality, making consumed drops inert.
- **Completion-worker context read.** The firmware `tr` mangles the
  `\0` escape and ate the `r` of `u:r:magisk:s0`, which would have
  made the worker refuse its own context. Fix: command-substitution
  normalization instead of `tr`.
- **Stale-drop resume.** A naive "drop exists → skip signing" resume
  check would have suppressed signing on the next boot (the previous
  boot's drop is still in the directory). The worker requires the
  drop's signed message to bind *this* boot and the standing
  challenge (`drop_fresh`); stale drops are logged `DROP_STALE` and
  signed over.

## Platform quirks that shaped the design

- **TimeService eats cross-boot arming.** `persist.sys.saved_time`
  is overwritten numerically by NTP sync (~20 s and ~130 s into
  boot, plus an ungated daily timer), so any trigger armed for a
  *later* boot evaporates. The October poll-rearm watchdog countered
  this but is precisely the forbidden early-rearm pattern; the
  adopted answer is the in-boot, journal-gated on-demand launch.
- **No auto-boot on USB power** (measured): cold-boot testing needs
  a human at the power button.
- **`su -c "reboot -p"` rebooted instead of powering off** on one
  measured boot; the reliable power-off route is the non-root
  `adb shell reboot -p`.
- **The app cannot read the kernel boot id under stock Enforcing**
  (proc_random denial from the app domain): unattended journal
  begins therefore use the degraded identity form, with the waiter
  witness carrying the completion-time claim.

## What the logs cannot decide

Per-boot RCU/reuse micro-timing leaves no kernel-side record; the
app chain does not log HWBINDER values, so the driver-vs-app success
difference (7/17-era driver record vs 9/10 app cycles) cannot be
fully decomposed into chain vs timing effects from logs alone.
Suggested future instrumentation (not implemented): record the
`HWBINDER_STATEFUL` result in the app-side Settings markers.
