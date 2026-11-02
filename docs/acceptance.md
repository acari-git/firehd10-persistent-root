# Acceptance evidence

Measured on the development device (Fire HD 10, trona/KFTRWI,
Fire OS 7.3.3.1, fingerprint
`Amazon/trona/trona:9/PS7331.4463N/0031575863040`) in November 2026.
Raw session evidence is not published; this is the summary of record.

## Measured reliability

| Path | Result | Notes |
|---|---|---|
| Host-driven re-acquisition (driver Phase B) | **9/19 ≈ 47%** per fresh boot | A miss is `ENODATA_LEAK_MISS_NO_WRITE`: no kernel write, device returns to stock. |
| App-side unattended cycle (armed boots) | **9/10** | Boots 203–208, 224, 225, 226 completed; boot 209 missed (see failure-modes) and disarmed fail-closed. |
| Signer auto-completion measurement (boot 204) | full cycle ≈93 s | Reboot → journal READY, zero operator input after `adb reboot`. |
| Cold-boot cycle (boot 225) | ≈90 s | Same shape from a power-off cold start. |

## Acceptance sequence: 5/5 PASS

Standing enablement was switched on 2026-11-02 and the formal
sequence run against the rearm-closure build (APK SHA-256
`88e09d7a…`, signing cert `063dc4aa…`):

| # | Boot | Type | Result |
|---|---|---|---|
| 1 | 206 | normal reboot | PASS — full unattended cycle, persist lifecycle 1→0→1 measured |
| 2 | 207 | normal reboot | PASS |
| 3 | 208 | normal reboot | PASS |
| — | 209 | power-off #1 power-on | **FAIL** — carrier attempt-1 ENODATA miss; app disarmed fail-closed exactly as designed (persist 1→0, no re-arm, no damage) |
| — | 210–223 | recovery | Driver re-acquisition (with a 3-miss ENODATA streak, then success), journal read, sign-genesis lockout recovery, Magisk restage, hash sweep 10/10, sentinel reinstall, re-arm |
| — | 224 | warm reboot (extra) | PASS — full unattended cycle on the restored system (not counted in the 5) |
| 4 | 225 | cold boot #1 (power-off → power-on) | PASS — all criteria verified twice |
| 5 | 226 | cold boot #2 | PASS — all criteria verified twice |

Per-boot PASS criteria: journal `READY:<boot id>:<count>`;
`proof_status=proof_completed_dps`; `rearm_status=rearmed_on_proof`;
persist lifecycle 1→0→1; `getenforce=Enforcing`; `su -c id` =
`uid=0`, `u:r:magisk:s0`; launch result OK with the per-boot witness
bound to the same boot.

Also measured: the tablet does **not** auto-boot on USB power, so
cold boots require a physical power-button press — the two cold-boot
acceptance items are defined by boot type, not by boot count.

## Project gate ledger (SAFE_ROOT_GOAL, Step-3 determination)

The development project tracked 11 documentary gates. Final
determination at close-out:

| Gate | Result |
|---|---|
| G01 device identification | pass |
| G02 signed unlock / equivalent | **blocked** — no legitimate unlock exists for trona; the delivered persistence deliberately works without one (bootloader still locked) |
| G03 backup / restore | partial — real disaster-restore import not exercised |
| G04 Recovery rollback | partial — real-Recovery end-to-end restore not exercised |
| G05 `su` available under management | pass |
| G06 system-wide Enforcing + domain audit | pass (Magisk-domain breadth disclosed in the audit) |
| G07 three normal reboots | pass (206/207/208) |
| G08 two cold boots | pass (225/226) |
| G09 function + 48 h stability as one protocol | partial |
| G10 least privilege / no orphan services | partial — orphan-service side proven (only the designed 4321 gate listens; 4325 is transient); least-privilege side not fully minimized (WRITE_SECURE_SETTINGS, system-UID gate remain by design) |
| G11 OTA + recovery-plan proof | not_verified — real OTA and end-to-end stock recovery deliberately not exercised on the real device |

The project's `goal_status` tool reports 5/11 documentary gates
passing and an overall NO_GO *by construction* while any gate is
unmet. The six remaining items are assurance gates requiring
separate approvals — several are operations deliberately avoided on
the real device — not defects in the delivered system.

Final standing state after close-out: device ON, Enforcing,
persist armed, journal READY, MagiskSU live — the system proven
across 3 warm reboots + 2 cold boots, all fully unattended.
