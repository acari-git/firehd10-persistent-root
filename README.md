# firehd10-persistent-root

**Unattended persistent root for the Amazon Fire HD 10 (trona) on
Fire OS 7.3.3.1 — a journal-gated, fail-closed persistence layer built
on top of SnuSnuRoot.**

> 日本語版（全文）: [README.ja.md](README.ja.md)

## What this is

[SnuSnuRoot](https://github.com/voidnullvalue/SnuSnuRoot) by
voidnullvalue provides *temporary* root on this tablet: win a
probabilistic kernel race, get a root window, lose it at reboot.
This repository is the layer developed on top of it that makes root
**persistent and fully unattended**:

- Every armed boot re-acquires root by itself, stages Magisk,
  restores SELinux Enforcing with MagiskSU live, proves the cycle
  with an on-device ECDSA signature, and re-arms the next boot —
  in about 90 seconds, with no operator, no host, no cable.
- Arming is governed by a two-phase **journal**: a boot may attempt
  only from a READY record, and only a verified signed proof can
  complete an attempt and arm the next one. Any failure disarms the
  system (fail-closed) instead of leaving it half-armed.
- Verified end-to-end by a formal acceptance sequence: **5/5**
  (3 normal reboots + 2 power-off cold boots, all unattended),
  after a mid-sequence failure, a full recovery, and re-tests.

## What this is not

- **Not a new exploit.** The temporary-root chain is upstream's.
  This repo contains no Stage4 payload binaries (they are
  reference-only; see `UPSTREAM.md`).
- **Not a bootloader unlock.** There is no known legitimate unlock
  for trona, and this system deliberately works without one: the
  bootloader stays locked and Verified Boot stays green.
- **Not a ROM modification.** By design, nothing is ever written to
  boot / recovery / LK / preloader / system / vendor. Root is a
  per-boot, in-memory chain. Disarm the system and reboot, and the
  device is stock.

## Exact scope — read this first

Verified on **exactly one** device/build:

| | |
|---|---|
| Device | Amazon Fire HD 10 (trona, KFTRWI) |
| Fire OS | 7.3.3.1 |
| Fingerprint | `Amazon/trona/trona:9/PS7331.4463N/0031575863040` |
| Incremental | `0031575863172` |
| Kernel | 4.4.146+ · security patch 2024-08-01 |

The host driver's preflight enforces this build (`EXACT_4463`) and
refuses others. **Every other build is untested** — including
PS7331.4460N, which is upstream's documented target: the 4463
adaptation is part of this project's contribution, and it has only
ever run on 4463N. Do not extrapolate.

## Upstream prerequisite and attribution

You need SnuSnuRoot at the pinned commit
`d552f666ae05ffee1b9d4e4d6f8aa9da4bca0fb9` — the temp-root chain, the
original persistence actor this layer forks, the Stage4 payload, the
public debug keystore, and the Magisk artifacts all come from there.
GPL-3.0, as is this layer. Full per-file provenance, including the
reference-only material and its hashes, is in [`UPSTREAM.md`](UPSTREAM.md)
and [`NOTICE`](NOTICE).

## Architecture (summary)

- **Journal-gated arming** — `Stage4AttemptJournalV2`: EMPTY /
  INFLIGHT / READY; the journal is the *sole* arming authority. The
  historical poll-rearm watchdog pattern is explicitly not used.
- **On-device signer + proof completion** — an ECDSA P-256 key
  generated on the device (private half never leaves it) signs
  domain-separated proofs binding the INFLIGHT record and a
  per-attempt challenge; the app verifies against a public key
  pinned into the APK at build time.
- **Boot identity in three layers** — signer `/proc` anchor, a
  waiter-written boot witness, and a boot-count latch.
- **On-demand waiter launch** — arming happens inside the journal
  boot (stock `ctl.start`), because TimeService destroys any
  cross-boot arming within seconds.
- **Signer auto-completion** — a Magisk-domain worker syncs on the
  Enforcing-restored marker, has the signer sign the standing proof
  request (one attempt), and re-triggers the app.
- **Rearm-on-proof closure** — the persist flag is re-armed only by
  a verified routine completion; genesis and lockout-recovery
  completions never arm.

Details: [`docs/architecture.md`](docs/architecture.md) ·
safety: [`docs/safety-model.md`](docs/safety-model.md) ·
first-run/key ceremony: [`docs/genesis.md`](docs/genesis.md) ·
evidence: [`docs/acceptance.md`](docs/acceptance.md) ·
what goes wrong and why: [`docs/failure-modes.md`](docs/failure-modes.md)

## Measured reliability (development device, Oct–Nov 2026)

| Path | Rate |
|---|---|
| Host-driven re-acquisition, per fresh boot | 9/19 ≈ 47% |
| App-side unattended cycle, per armed boot | 9/10 |
| Formal acceptance sequence | **5/5** (3 warm reboots + 2 cold boots) |

A miss at the Stage4 leak step (`ENODATA`) performs no kernel write
and returns the device to stock — but a missed *armed* boot disarms
the system, and re-arming then requires the documented recovery
flow (rooted session + sign-genesis lockout recovery). That trade —
safety over self-healing — is deliberate.

## Repository layout

```
app/         persistence app (forked actor + journal/proof layer) and build tooling
device/      on-device scripts: launch, witness, completion, gate, installers,
             and the fielded upstream-lineage waiter/watchdog/restore/boot-entry
signer/      on-device ECDSA proof signer (source, launcher, build)
host-tests/  Python unittest harnesses (see its README for the 127-test accounting)
docs/        architecture, safety model, genesis, acceptance, failure modes
UPSTREAM.md  pinned upstream + per-file provenance and reference-only hashes
NOTICE       attribution
```

## Building

No Gradle. The build is POSIX `sh` plus an Android SDK command-line
tools install and JDK 17:

1. Fetch upstream at the pinned commit. `app/build.sh` resolves the
   signing keystore as `<app>/../../refs/SnuSnuRoot/poc/snusnu-persist-app/signing/snusnu-debug.keystore`
   — in this repository's layout that is a `refs/` directory in the
   repository's *parent* directory. Place or symlink the upstream
   checkout there as `refs/SnuSnuRoot` (in the development tree the
   same `refs/` sat at the build root, two levels above the app).
2. `app/build.sh` runs the plain build (javac `-source 8 -target 8`
   → jar → `d8 --min-api 28` → `aapt2 link` → `apksigner` v1+v2)
   with the checked-in pinned key. To pin your own public key first,
   run `python3 app/gen_pinned_key.py <your-public.der> "<label>"
   app/src/io/github/voidnullvalue/snusnuroot/persistence/Stage4PinnedProofKey.java`
   and then `app/build.sh` (see `docs/genesis.md`). `app/build-v2.sh`
   is the development-tree wrapper that chains these two steps; it
   assumes the development layout (a `stage4-persistent/` directory
   beside it) and is kept for provenance.
3. SDK discovery: `SNUSNU_SDK`, then `ANDROID_SDK_ROOT` /
   `ANDROID_HOME`.

**Signing disclosure.** The reference build signs with upstream's
**public debug keystore** so rebuilt APKs stay `pm install -r`
upgrade-compatible. That signature therefore carries **no issuer
authenticity whatsoever** — anyone can produce it. The system's
trust anchor is the per-device ECDSA proof key pinned at build time,
not the APK certificate. If you build this, build it from source
you have read.

**No release APK is provided** (v1 is source-only), for exactly the
reason above.

## License

- Code: **GNU GPL v3.0** (see `LICENSE`) — this layer is a derivative
  of GPL-3.0 upstream, and is licensed to match.
- Documentation in `docs/`: **CC BY 4.0** (see
  `docs/LICENSE-CC-BY-4.0.md`).

## Disclaimer

This is a hobbyist security-research project for a device you own.
It is provided **without any warranty**; modifying a device's
software can void its warranty and, if you deviate from the
documented procedures, could leave it unbootable. The author is not
affiliated with Amazon, voidnullvalue, or the Magisk project.
"Fire HD" and "Fire OS" are trademarks of Amazon.

