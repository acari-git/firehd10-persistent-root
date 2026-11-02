# Safety model

The design rule is **fail closed, and never make the device worse
than stock**. Every component was built and acceptance-tested under
that rule.

## Never written, never attempted

- No writes to boot / recovery / LK / preloader / system / vendor
  partitions. No flashing, no OTA manipulation, no downgrade.
- The bootloader stays locked and Verified Boot stays green. Root is
  a **per-boot, in-memory** chain (tmpfs Magisk); the ROM is never
  modified, so a plain reboot with the system disarmed returns the
  device to completely stock behaviour.
- The downgrade route to older, more exploitable firmware was
  evaluated and rejected at the outset: on this device it risks an
  unrecoverable RPMB brick with no low-level recovery path.

## Fail-closed semantics

- **Journal denials.** Missing, foreign-format, stale, or
  contradictory journal/witness/challenge state denies the attempt.
  A v1-format journal record is *foreign* to the v2 journal by
  design and is neither interpreted nor cleared.
- **One-shot arming.** Arming is consumed by the attempt. Success
  re-arms only through a verified proof completion; **any** failure —
  carrier miss, timeout, denial — leaves the persist flag at 0.
  Nothing retries silently across boots.
- **Signer gates.** The signer self-attests on every invocation
  (execution context, key custody, Enforcing state) and refuses to
  sign when a gate fails. Its used-challenge ledger consumes a
  challenge before signing, so a retry can only produce a
  `challenge_reused` denial; callers therefore never retry a denial.
  Exactly one signing attempt per boot.
- **Helper posture checks.** The launch helper re-verifies every
  stop condition itself (persist flag, both sentinels, launch latch,
  slot state) and refuses to hijack another actor's arming. The
  completion worker never writes the journal, any Settings value,
  the persist flag, or either sentinel — its only writes are its own
  log and a tmpfs lock.
- **Sentinels.** Two independent disable files
  (`/data/cache/snusnu/disable` and the secured-storage equivalent)
  each stop the whole system; components honour both.

## The root window and SELinux

Temporary root exists only inside the Stage4 window. The settled
state on every successful boot is **SELinux Enforcing with MagiskSU
live** (`u:r:magisk:s0`). The loaded policy in the settled state
measures 667,117 bytes against the stock 651,815 bytes; the delta is
the Magisk rule set, audited as part of the project's acceptance
gates. (Disclosed honestly: the Magisk domain's permissions are
broad by design — that is a property of Magisk itself, reviewed and
accepted in the gate audit, not hidden.)

A kernel panic or an unexpected transition to Recovery ends any
operating session immediately; the standing instruction is to leave
the device as-is in Recovery rather than improvise.

## Session discipline (how it was operated)

- Retry only on the known-safe `ENODATA` miss class, at most 3
  attempts per sequence; success is judged by actual SELinux state
  and a real `uid=0` check, never by a script's exit text alone.
- Every state-changing step is verified by an independent read-back,
  regardless of the tool's reported status.
- Components are installed hash-pinned: installers verify SHA-256
  before and after, set owner/mode/label explicitly, and fail closed
  on any mismatch.

## Honest limits

- The Stage4 carrier is **probabilistic** (see
  `failure-modes.md`). A missed boot is safe but disarmed; bringing
  it back requires the documented recovery flow on a rooted session,
  which itself needs a successful host-driven re-acquisition.
- The system is verified on exactly one firmware build. Nothing here
  should be read as implying other builds are safe to try: the
  driver's preflight refuses them, and that refusal is part of the
  safety model.
