# app/ — provenance

The persistence app is a **fork of upstream SnuSnuRoot's persistence
actor** (`poc/snusnu-persist-app/` at the pinned commit, GPL-3.0). It
keeps upstream's package name
`io.github.voidnullvalue.snusnuroot.persistence` and upstream's public
debug-key signing so that rebuilt APKs upgrade in place
(`pm install -r`). `build.sh` itself carries the fork header.

Forked from upstream (see `../UPSTREAM.md` for hashes):

- `BootReceiver.java`, `BootstrapActivity.java` — upstream actor
  classes, carried with the fork.
- `PersistenceService.java` — upstream base, heavily extended in this
  project: journal-v2 state machine integration; the on-demand waiter
  launch step gated on `LAUNCH_RESULT OK`; the system-channel reply
  fix (flush + output half-close); the genesis-challenge gate that
  keeps consumed genesis drops inert; and the rearm-on-proof closure
  (re-arms only on a verified routine completion, never on genesis /
  lockout-recovery completions).
- `AndroidManifest.xml`, `build.sh` — upstream, carried with the fork.

Original to this project:

- `Stage4AttemptJournalV2.java` — the two-phase attempt journal
  (EMPTY / INFLIGHT / READY) that is the system's sole arming
  authority.
- `Stage4GenesisVerifier.java`, `Stage4ProofVerifier.java` —
  domain-separated ECDSA P-256 proof verification (`stage4-genesis-v1`
  and `stage4-root-v1` domains).
- `Stage4ProofDrop.java` — strict parser for signer drops delivered
  through the app-private proof-drop mailbox.
- `Stage4BootIdentity.java`, `Stage4BootWitness.java` — the three-layer
  boot identity (signer anchor, waiter witness, boot-count latch).
- `Stage4PinnedProofKey.java` — the pinned signer public key,
  regenerated at build time by `gen_pinned_key.py`. **The staged copy
  pins the labeled host test key** (`proof-key/test-public.der`); a
  real install rebuilds with the installer's own on-device key
  (see `../docs/genesis.md`).
- `NativeOutputSanitizer.java` — sanitizes native carrier output
  before it is recorded.
- `build-v2.sh`, `gen_pinned_key.py`, `manifest-v2.json`,
  `host-reference/HostReferenceSigner.java` (test-only; never install
  on a device).
