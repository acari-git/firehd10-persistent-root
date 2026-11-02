#!/system/bin/sh
# snusnu-boot-witness.sh -- journal boot-witness writer (2026-11-01).
#
# Writes this boot's identity claim for the app-side journal
# (Stage4BootWitness) into /data/cache/snusnu/state/boot_witness:
# line 1 = this boot's kernel boot UUID, line 2 = /proc/uptime
# seconds at write time. The witness is EVIDENCE, never an
# authorization: the journal's READY transitions additionally require
# an ECDSA proof whose boot id the signer read from /proc itself, so
# a forged, stale or replayed witness can only fail closed (denial /
# degraded mode / lockout), never authorize. Design:
# FIREHD10_WAITER_BOOT_WITNESS_DESIGN_20261101.md (diagnostics
# project root). Governing identity design:
# FIREHD10_JOURNAL_BOOTSTRAP_AND_PROOF_CUSTODY_DESIGN_20261101.md
# section 3.2 (the uid0 waiter is layer 2 of the boot identity).
#
# Call site: waiter.sh invokes "write" immediately after its
# Permissive poll succeeds and before magisk_restore.sh runs. That is
# the earliest point in the boot chain where this process can
# lawfully read /proc/sys/kernel/random/boot_id: the time_update
# domain has no proc_random read and no cache_file write in the
# stock policy (measured 2026-11-01 against the live 4463N policy),
# so under Enforcing both operations are denied; in the Permissive
# window they are not enforced. The writer therefore re-checks
# getenforce itself and refuses to write outside the window.
#
# The boot id and uptime are always measured by this process from
# /proc at write time. Nothing is accepted from arguments, from the
# app, from Settings, or from any caller-writable file.
#
# Modes:
#   write   measure and atomically replace the witness
#           (temp file in the same directory + rename), then read
#           the target back and verify it byte-for-byte; a witness
#           that fails verification is removed (absence fails
#           closed, a malformed file must not linger either).
#   report  print FACT lines about this process, the sources and
#           the current witness; never writes anything.
#
# Exit codes (write): 0 = written and verified; 2 = skipped, a
# disable sentinel is present; 3 = refused (not uid 0, or SELinux
# not Permissive); 4 = source data unreadable or malformed;
# 5 = write or read-back verification failed (target removed).
# Exit codes (report): 0 = facts printed. 64 = usage error.
#
# Device install location: /data/snusnu_root/bin/snusnu-boot-witness.sh
# (root:root 0500), next to watchdog.sh and system-channel-gate.sh.
# Source of truth: build/journal-gated-implementation-20261101/v2/
# stage4-persistent/snusnu-boot-witness.sh (diagnostics project).
#
# Host-test seam: when SNU_WITNESS_SANDBOX=1, the five paths below
# may be overridden by SNU_WITNESS_STATE_DIR / _BOOT_ID_FILE /
# _UPTIME_FILE / _SNS_DISABLE / _CACHE_DISABLE so the host suite can
# run this exact file against fixtures. Nothing on a device sets
# these; with the variable unset or different, the compiled-in
# device paths are always used and the environment is ignored.

STATE_DIR=/data/cache/snusnu/state
BOOT_ID_FILE=/proc/sys/kernel/random/boot_id
UPTIME_FILE=/proc/uptime
SNS_DISABLE=/data/securedStorageLocation/snusnu/disable
CACHE_DISABLE=/data/cache/snusnu/disable
if [ "${SNU_WITNESS_SANDBOX:-0}" = 1 ]; then
    STATE_DIR=${SNU_WITNESS_STATE_DIR:-$STATE_DIR}
    BOOT_ID_FILE=${SNU_WITNESS_BOOT_ID_FILE:-$BOOT_ID_FILE}
    UPTIME_FILE=${SNU_WITNESS_UPTIME_FILE:-$UPTIME_FILE}
    SNS_DISABLE=${SNU_WITNESS_SNS_DISABLE:-$SNS_DISABLE}
    CACHE_DISABLE=${SNU_WITNESS_CACHE_DISABLE:-$CACHE_DISABLE}
fi
WITNESS=$STATE_DIR/boot_witness

logmsg() {
    if [ -x /system/bin/log ]; then
        /system/bin/log -t SNUSNU_WITNESS "$*" >/dev/null 2>&1
    else
        echo "SNUSNU_WITNESS $*" >&2
    fi
}

# Strict shapes, identical to the app-side parser
# (Stage4BootWitness.BOOT and the /proc/uptime first field).
# The newline guard matters: grep matches line-by-line, so without
# it a two-line source would pass on the strength of either line
# (caught by the host suite; the app parser would still have
# rejected the result, but the writer must be strict itself).
valid_boot_id() {
    case "$1" in
        *'
'*) return 1 ;;
    esac
    printf '%s' "$1" | grep -Eq '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
}
valid_uptime() {
    case "$1" in
        *'
'*) return 1 ;;
    esac
    printf '%s' "$1" | grep -Eq '^[0-9]+(\.[0-9]+)?$'
}

read_boot_id() {
    # Command substitution strips trailing newlines; a multi-line
    # or otherwise malformed source keeps its inner newline or bad
    # characters and is rejected by valid_boot_id.
    cat "$BOOT_ID_FILE" 2>/dev/null
}

read_uptime() {
    _up=$(cat "$UPTIME_FILE" 2>/dev/null)
    printf '%s' "${_up%% *}"
}

do_report() {
    echo "FACT uid=$(id -u 2>/dev/null)"
    _ctx=$(cat /proc/self/attr/current 2>/dev/null)
    echo "FACT context=${_ctx:-unreadable}"
    echo "FACT getenforce=$(getenforce 2>/dev/null || echo unavailable)"
    _boot=$(read_boot_id)
    if valid_boot_id "$_boot"; then
        echo "FACT boot_id=$_boot"
    else
        echo "FACT boot_id=unreadable_or_malformed"
    fi
    _up=$(read_uptime)
    if valid_uptime "$_up"; then
        echo "FACT uptime_now=$_up"
    else
        echo "FACT uptime_now=unreadable_or_malformed"
    fi
    [ -e "$SNS_DISABLE" ] && echo "FACT disable_sns=present" \
        || echo "FACT disable_sns=absent"
    [ -e "$CACHE_DISABLE" ] && echo "FACT disable_cache=present" \
        || echo "FACT disable_cache=absent"
    if [ -f "$WITNESS" ]; then
        echo "FACT witness_present=yes"
        _l1=$(sed -n '1p' "$WITNESS" 2>/dev/null)
        _l2=$(sed -n '2p' "$WITNESS" 2>/dev/null)
        _l3=$(sed -n '3p' "$WITNESS" 2>/dev/null)
        echo "FACT witness_line1=${_l1:-empty}"
        echo "FACT witness_line2=${_l2:-empty}"
        [ -n "$_l3" ] && echo "FACT witness_extra_lines=yes" \
            || echo "FACT witness_extra_lines=no"
    else
        echo "FACT witness_present=no"
    fi
    echo "WITNESS_RESULT REPORT"
    exit 0
}

do_write() {
    if [ "$(id -u 2>/dev/null)" != 0 ]; then
        logmsg "refuse_not_uid0"
        echo "WITNESS_RESULT REFUSED not_uid0" >&2
        exit 3
    fi
    _ef=$(getenforce 2>/dev/null)
    if [ "$_ef" != Permissive ]; then
        logmsg "refuse_enforce=${_ef:-unavailable}"
        echo "WITNESS_RESULT REFUSED enforce=${_ef:-unavailable}" >&2
        exit 3
    fi
    # The flow's own stop vocabulary (watchdog/journal authority
    # decision, 2026-11-01): either sentinel stops unattended
    # root-side activity for the boot. The persist flag is NOT
    # consulted: the witness is evidence the journal may ignore,
    # and genesis transitions require it even at persist=0
    # (design doc sections 1.2 and 3.2; see the design doc for
    # this task, section 7, for the full argument).
    if [ -e "$SNS_DISABLE" ]; then
        logmsg "skip_sns_disable"
        echo "WITNESS_RESULT SKIPPED sns_disable"
        exit 2
    fi
    if [ -e "$CACHE_DISABLE" ]; then
        logmsg "skip_cache_disable"
        echo "WITNESS_RESULT SKIPPED cache_disable"
        exit 2
    fi
    _boot=$(read_boot_id)
    if ! valid_boot_id "$_boot"; then
        logmsg "refuse_boot_id_malformed"
        echo "WITNESS_RESULT REFUSED boot_id_malformed" >&2
        exit 4
    fi
    _up=$(read_uptime)
    if ! valid_uptime "$_up"; then
        logmsg "refuse_uptime_malformed"
        echo "WITNESS_RESULT REFUSED uptime_malformed" >&2
        exit 4
    fi
    mkdir -p "$STATE_DIR" 2>/dev/null
    _tmp=$STATE_DIR/.boot_witness.tmp.$$
    rm -f "$_tmp" 2>/dev/null
    if ! printf '%s\n%s\n' "$_boot" "$_up" > "$_tmp" 2>/dev/null; then
        rm -f "$_tmp" 2>/dev/null
        logmsg "write_failed_tmp"
        echo "WITNESS_RESULT FAILED tmp_write" >&2
        exit 5
    fi
    chmod 0644 "$_tmp" 2>/dev/null
    # Genesis installed the witness as root:system 0644 with the
    # cache_file label inherited from the directory. Ownership is
    # reproduced best-effort; content correctness is decided by
    # the read-back comparison below, not by chown.
    chown 0:1000 "$_tmp" 2>/dev/null \
        || logmsg "chown_nonfatal_failed"
    sync >/dev/null 2>&1
    if ! mv "$_tmp" "$WITNESS" 2>/dev/null; then
        rm -f "$_tmp" 2>/dev/null
        logmsg "write_failed_rename"
        echo "WITNESS_RESULT FAILED rename" >&2
        exit 5
    fi
    sync >/dev/null 2>&1
    _rb=$(cat "$WITNESS" 2>/dev/null)
    _lines=$(wc -l < "$WITNESS" 2>/dev/null | tr -d ' ')
    if [ "$_lines" != 2 ] || [ "$_rb" != "$_boot
$_up" ]; then
        # Never leave a witness whose bytes were not verified.
        rm -f "$WITNESS" 2>/dev/null
        logmsg "verify_failed_removed"
        echo "WITNESS_RESULT FAILED readback_mismatch" >&2
        exit 5
    fi
    logmsg "written boot=$_boot uptime=$_up"
    echo "WITNESS_RESULT OK boot=$_boot uptime=$_up"
    exit 0
}

case "${1:-}" in
    write)  do_write ;;
    report) do_report ;;
    *)
        echo "usage: $0 {write|report}" >&2
        exit 64
        ;;
esac
