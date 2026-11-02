# Genesis: per-user keys and the first READY

> 日本語版: [genesis.ja.md](genesis.ja.md)

The system's trust anchor is a per-installation ECDSA keypair. There
is no shared "release" key: an APK built with somebody else's pinned
key can never complete a proof on your device, by construction.

## Why genesis exists

Routine completions bind a proof to an INFLIGHT journal record. The
very first READY record has nothing to bind to, so it is created by a
separate, domain-separated **genesis proof**
(`stage4-genesis-v1|…`), verified by `Stage4GenesisVerifier` against
the same pinned key. Genesis requires a live rooted session and an
operator token; it is deliberately not something the unattended
cycle can do for itself.

## The flow (as executed in the genesis session, 2026-11-01)

1. **Generate the keypair on the device**, inside a rooted session:
   the private key is written directly to its custody location,
   `/data/snusnu_root/signer/proof-key.der` (directory `root:root
   0700`, file `0400`). It is never copied off the device; only the
   public half leaves, as a DER file carried by the operator.
2. **Pin the public key by rebuilding the APK**:
   `app/build-v2.sh <device-public.der> "<device label>"` regenerates
   `Stage4PinnedProofKey.java` from the DER and rebuilds. The staged
   default pins the labeled **host test key**, whose private half
   was deleted in the session that created it — an APK built with
   the default pin signs nothing valid anywhere, intentionally.
3. **Run the signer's report mode** and require every self-attestation
   gate to pass (context, custody, Enforcing) before any signing.
4. **Place the operator token**: a root-owned `0400` token file whose
   content is the *current boot id*. A token naming any other boot,
   or a consumed token, denies.
5. **Sign genesis**: the signer produces the genesis proof for the
   journal's standing challenge and delivers it through the
   proof-drop mailbox, copying the app's SELinux label onto the drop.
6. **Re-trigger the app** (`pm install -r` of the rebuilt APK). The
   app verifies the genesis proof, writes `READY:<boot>:<count>`,
   and sets `proof_status=genesis_installed`.

After genesis, the next armed boot can run the unattended cycle, and
each verified routine completion re-arms the following one.

## Lockout recovery is the same path

If a boot fails after `beginOneShot`, the journal is stuck INFLIGHT
and the app correctly refuses to do anything further. Recovery:

1. Re-acquire temporary root with the host driver (probabilistic;
   see `failure-modes.md`).
2. Read the journal, guard, and standing challenge on-device.
3. Signer report → token (current boot id) → `sign-genesis
   <challenge>` → drop → `pm install -r`.
4. Journal returns to READY with `genesis_installed`; restage Magisk,
   restore Enforcing, run the hash sweep, reinstall the cache
   sentinel while disabled, then re-arm (sentinel to its held
   location, persist flag on, settle, read-back).

This exact flow recovered the acceptance device on 2026-11-02/03
after the boot-209 failure, and the system then completed its
remaining acceptance boots unattended.

## Custody rules (do not weaken these)

- Generate the private key **on the device**; never import a key
  generated elsewhere, and never export the device key.
- Exactly one custody location on the device. A stray second copy is
  a finding, not a convenience.
- Genesis/recovery completions never re-arm. Arming is earned only
  by routine, verified completions.
