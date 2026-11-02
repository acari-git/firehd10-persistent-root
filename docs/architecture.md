# Architecture

> 日本語版: [architecture.ja.md](architecture.ja.md)

The system turns upstream SnuSnuRoot's *temporary* root into
*unattended persistent* root on one exact firmware build, without
writing any partition. Every boot, the same in-memory chain runs:
the app arms an attempt, the waiter chain re-acquires temporary root,
Magisk is staged from tmpfs, Enforcing is restored, and a signed
proof closes the journal — which is the only thing allowed to arm the
next boot.

## The journal is the sole arming authority

`Stage4AttemptJournalV2` keeps a two-phase record
(`stage4-native-attempt-v2.state`, app-private storage):

```
EMPTY ──genesis proof──▶ READY ──begin(boot)──▶ INFLIGHT ──signed proof──▶ READY
```

- A boot may attempt root **only** by moving the journal
  READY → INFLIGHT (`beginOneShot`), bound to that boot's identity.
- An attempt completes **only** when the app verifies an ECDSA proof
  that binds the INFLIGHT record and the per-attempt 256-bit
  challenge. Anything else — missing, foreign, stale, contradictory —
  denies, and the boot stays stock.
- No other component may arm a boot. In particular the historical
  watchdog poll-rearm pattern is deliberately not used: it re-arms
  *before* success is known, which is exactly what the journal exists
  to prevent. A failed boot therefore leaves the system disarmed
  (fail-closed), never half-armed.

## Boot identity (three layers)

1. **Signer anchor** — the on-device signer reads
   `/proc/sys/kernel/random/boot_id` in its own root context.
2. **Waiter witness** — `snusnu-boot-witness.sh`, hooked into the
   waiter at Permissive detection, writes this boot's identity claim
   (boot UUID + `/proc/uptime`) into the cache state dir. The app
   parses it with `Stage4BootWitness` (strict parser, freshness
   rules). The witness is evidence only; it authorizes nothing.
3. **Boot-count latch** — anti-replay / same-boot guards.

Because the journal *begin* runs before any Permissive window exists,
unattended begins normally use the degraded `INFLIGHT:?` form; the
witness serves the completion-time claim and stale-witness cleanup.

## Proof and the on-device signer

- Proofs are ECDSA P-256 / SHA256withECDSA, domain-separated:
  routine proofs sign `stage4-root-v1|…`; genesis proofs sign
  `stage4-genesis-v1|…`. A proof binds the INFLIGHT record and the
  standing challenge; challenges are consumed on any verification
  attempt (replay-proof).
- The signer (`signer/Stage4DeviceSigner.java`, one dependency-free
  class compiled to a dex) runs via `app_process` from the root shell.
  The private key is generated **on the device** and lives at
  `/data/snusnu_root/signer/proof-key.der` (directory `root:root
  0700`, file `0400`). It never leaves the device.
- The signer self-attests on every invocation (identity, custody,
  Enforcing state) and refuses if any gate fails. Signed proofs are
  delivered through a file mailbox into the app's private
  `proof-drop/` directory, with the app's SELinux label copied onto
  the drop so the app can read it in its own domain.
- The app verifies against a **pinned public key** compiled into the
  APK (`Stage4PinnedProofKey`, regenerated at build time). The APK's
  own signing certificate plays no role in this trust chain.

## The boot cycle (armed boot, no operator)

1. App starts (direct-boot / package-replaced triggers), reads the
   journal. READY bound to an earlier boot → `beginOneShot` →
   INFLIGHT; a fresh challenge is issued.
2. The app writes a proof request and invokes the **on-demand launch
   helper** (`snusnu-launch.sh`) over the system channel. The helper
   re-verifies the posture itself (persist flag on, both disable
   sentinels absent, per-boot launch latch available, saved_time slot
   numeric), transiently arms the stock `time_update` trigger,
   starts the service with `ctl.start`, confirms the launch from the
   service's behaviour, and restores the slot byte-for-byte. Only on
   `LAUNCH_RESULT OK` does the app send the Stage4 carrier.
   (Cross-boot arming cannot work: TimeService overwrites the slot
   with NTP values seconds into every boot — see failure-modes.)
3. The waiter fires in the root window; the witness writer records
   the boot claim; `magisk_restore.sh` stages Magisk (tmpfs);
   `stage4-enforcing.sh` (reference-only) restores SELinux Enforcing
   with MagiskSU live (`uid=0`, `u:r:magisk:s0`).
4. The **auto-completion worker** (`snusnu-completion.sh`, launched
   from Magisk `service.d` in the magisk domain) syncs on this boot's
   Enforcing-restored marker, asks the production signer to sign the
   standing proof request (exactly one attempt), and re-triggers the
   app (`am start-foreground-service`; explicit broadcast fallback).
   If a drop that already binds this boot and challenge is present,
   it skips signing and only re-triggers.
5. The app verifies the proof, completes the journal
   (READY bound to this boot, `proof_status=proof_completed_dps`),
   and **re-arms** the persist flag (`rearmed_on_proof`). The
   completion run never falls through into a second attempt, and a
   same-boot READY record makes later triggers return quietly.

Measured end-to-end on the acceptance device: ≈90 seconds from boot
to a completed, re-armed journal.

## Genesis and lockout recovery

The first READY record cannot come from a routine proof (there is no
standing INFLIGHT to bind). Genesis installs it: on a rooted boot,
the signer — additionally gated by an operator token naming the
current boot id — signs a domain-separated genesis proof; the app
verifies it against the pinned key and writes `READY` +
`genesis_installed`. The same path is the **lockout recovery**: if a
journal is ever stuck INFLIGHT (e.g. after a failed boot), a rooted
session re-runs genesis and the system resumes. Genesis and recovery
completions deliberately do **not** re-arm; arming is earned only by
routine completions. See `genesis.md`.

## Components

| Layer | Pieces |
|---|---|
| App (`app/`) | journal, genesis/proof verifiers, proof-drop parser, boot identity/witness, forked `PersistenceService` orchestration |
| Signer (`signer/`) | on-device ECDSA signer + launcher + build |
| Device scripts (`device/`) | launch helper, witness writer, completion worker + launcher, system-channel gate, installers, and the fielded upstream-lineage waiter/watchdog/restore/boot-entry |
| Host (`host-tests/`) | Python unittest harnesses that execute the real scripts/Java against sandbox fixtures |
