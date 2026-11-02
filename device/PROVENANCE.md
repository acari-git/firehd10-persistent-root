# device/ — provenance

All scripts here run on the device inside the root/Stage4 chain. Two
groups: scripts **original** to this project, and **upstream-lineage**
scripts carried from SnuSnuRoot (GPL-3.0). For the lineage group, the
staged bytes are the *fielded* copies — the exact bytes whose hashes
were verified on the acceptance device — not intermediate working-tree
variants. Where a staged file differs from the hash-verified
2026-10-14 field snapshot
(`magisk_restore db70bac8…`, `stage4-enforcing 2e13b3ad…`,
`watchdog 119323bc…`, `waiter 32086d96…`, `boot-entry eea938e1…`),
the recorded change is summarized from the project's component
manifests.

| File | Origin | SHA-256 (staged) | Record |
|---|---|---|---|
| `snusnu-launch.sh` | original | `cb47ef1f2b039191cb00f7d3f933d51887fdee19801acc879552aaebf0940e25` | On-demand waiter launch helper (journal-gated). The staged copy is the 2026-11-02 fixed version: the launch-result write uses a direct write after the original tmp+rename form was AVC-denied on device. |
| `snusnu-boot-witness.sh` | original | `8fdf256a4b77b521976afb9a9759b672fb941c25f1b1f805ce1969d794064bcc` | Boot witness writer; called by the waiter hook during the Permissive window. |
| `snusnu-completion.sh` | original | `6b8232a990192ccab98d611207899b898c30d7c0af6b1727a5df5b32ace2e221` | Signer auto-completion worker (Magisk domain). Two on-device catches are baked in: no `tr`-based context normalization (the firmware `tr` mangles `\0`), and resume requires the standing drop to bind this boot + challenge (`drop_fresh`). |
| `snusnu-completion-service.sh` | original | `af696c048217994b072494e4607871c143540e73422006a80948bb99bb6bae46` | Magisk `service.d` launcher for the worker; detaches and exits 0. |
| `system-channel-gate.sh` | original | `33553a86f7725ebbb390dbd88e196bed5d29f584b7fd01835edca6de49c99065` | The UID1000 system-channel gate the app talks to (127.0.0.1:4321). Its trailing interactive shell is why the app half-closes after sending (see docs/failure-modes.md). |
| `install-hardened-4463-device.sh` | original | `b35f270c05b85d8b1b74b224bff383875524f791bd8eb8f179b4b0711f8ec9c1` | Hardened-tree installer (final form); registers every component above — including the witness writer and the launch helper, added by their component packages — with pinned hashes, owners, modes, and labels. An earlier working-tree variant (`a3bd1572…`, lacking the witness/launch registrations) exists in the development tree and is deliberately not published. |
| `install-completion-device.sh` | original | `7de94903e610d36fcc689a79bdcc67b3924550a2302eb8f27358f78148fac71e` | Standalone installer for the two completion files; verifies SHA-256 before/after install and fails closed. (Folding these into the hardened installer is a recorded follow-up.) |
| `waiter.sh` | upstream-lineage, **modified** | `6c086da42bbf75437519478402ec2b73dcb1153e9ba8e601aa4db71691617751` | Snapshot `32086d96…` → staged: adds a header divergence note and one best-effort callout to `snusnu-boot-witness.sh` immediately after Permissive detection, before the magisk_restore check (manifest-witness-writer.json). This hooked version is the fielded, acceptance-verified waiter. |
| `watchdog.sh` | upstream-lineage, unmodified fielded copy | `119323bcc41c7022c6e5ddffe5883013eba2e83c42a1b57e5dd238d1cf81e0c3` | Byte-identical to the 2026-10-14 snapshot. **No arming role** in this design: its historical poll-rearm behaviour is exactly the early-rearm pattern the journal-authority decision forbids; the journal is the sole arming authority. Staged so the fielded set is complete and hash-checkable. (A different working-tree variant exists in the development tree and was never fielded; it is deliberately not published.) |
| `magisk_restore.sh` | upstream-lineage, unmodified fielded copy | `db70bac8a92427689efdf525d6a3a8e5fea679959f48106bde5f5910757ade0f` | Byte-identical to the 2026-10-14 snapshot; the on-device resident restore script staged by the waiter during the root window. (As with watchdog.sh, an unfielded working-tree variant exists and is not published.) |
| `boot-entry.sh` | upstream-lineage, unmodified | `eea938e1ad624a1f612deea2d65a12c3082308160d5064dc4e279f82c909d7cd` | Byte-identical to the snapshot. |

Not staged here (reference-only, see `../UPSTREAM.md`):
`stage4-enforcing.sh` (fielded from the snapshot set) and the
`ps7331-standalone-4463.bin` payload.
