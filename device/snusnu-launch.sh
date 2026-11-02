#!/system/bin/sh
# snusnu-launch.sh -- journal-gated on-demand waiter launcher (2026-11-01).
#
# Starts the SNS waiter (waiter.sh, time_update context) on demand,
# in the SAME boot, at the moment the app-side journal has durably
# begun an attempt -- instead of relying on the trigger string
# surviving in persist.sys.saved_time from a previous boot.
#
# Why this exists: persist.sys.saved_time is a single slot with two
# writers. Amazon TimeService overwrites it with a numeric timestamp
# (measured at ~20 s and ~130 s after boot, plus a daily timer), so
# a trigger string armed during a previous boot is usually gone
# before the next boot's load_persist_props_action evaluates the
# property (2026-11-01 measurement boots 193/194: the SNS waiter
# never started; the project's witness writer therefore never fired
# unattended). October's recoveries worked because the arming actor
# (watchdog, 2-second poll) was alive in the preceding rooted boot
# and the interval to the evaluation was short. The journal
# authority decision (2026-11-01) forbids reviving that poll-arming:
# only the journal may arm, and never before its own gate. This
# helper is how the journal arms: transiently, inside one boot,
# after beginOneShot is durably INFLIGHT, through the existing
# authenticated UID1000 channel. Design:
# FIREHD10_WAITER_TRIGGER_ON_DEMAND_LAUNCH_DESIGN_20261101.md.
#
# Mechanism (stock behaviour only; no /system writes):
#   1. Re-validate every stop condition (below).
#   2. Capture the property's current value; it MUST be a clean
#      numeric timestamp. Anything else (including the trigger
#      string itself, armed by anyone else) is a refusal: this
#      helper never displaces a foreign arming and never guesses.
#   3. Write the deployed trigger string T (byte-identical to the
#      October watchdog's T; it evaluates /data/securedStorageLocation/w/b
#      = boot-entry.sh, which runs waiter.sh) and immediately issue
#      ctl.start for the disabled oneshot time_update service. Stock
#      Android 9 init resolves the legacy control name against
#      ctl_default_prop, which system_app/system may set on this
#      firmware (static case: FIREHD10_TIME_UPDATE_ON_DEMAND_CTL_START_
#      CANDIDATE_20261015.md, host audit 9/9; on-device acceptance is
#      a separate verification session -- if init refuses, this
#      helper fails closed and the app runs no carrier).
#   4. The service reads the property in its first lines, at fork.
#      Success is not "service ran" but "service is STILL running
#      after a confirmation delay": T's own command substitution
#      begins with sleep 30, so a service that consumed T stays in
#      the substitution for at least 30 s, while a service that read
#      a racing numeric value performs its stock clock restore and
#      exits in about a second. The confirmation delay (3 s) sits
#      far inside that margin.
#   5. Restore the captured numeric value byte-for-byte (fallback:
#      numeric 0, which the stock script never acts on). Nothing
#      executable may remain in the property when this helper exits:
#      the journal's arming authority is per-attempt and per-boot,
#      and an armed slot surviving into a later boot would be an
#      un-gated launch path.
#
# Ordering contract with the app (PersistenceService): this helper
# is invoked through the channel AFTER beginOneShot (INFLIGHT
# durable) and AFTER writeProofRequest, and the app MUST NOT send
# the carrier command unless this helper prints LAUNCH_RESULT OK.
# A Permissive window with no waiter would mean no restore and no
# Enforcing return for the rest of the boot.
#
# Stop conditions (all fail-closed; checked by this process itself,
# not trusted from the caller):
#   - caller uid must be 1000 (the channel's system shell);
#   - Settings.Global snusnu_persist_enabled must be exactly "1"
#     (the channel gate checks it too; defence in depth);
#   - /data/cache/snusnu/disable must be absent (authoritative for
#     this uid; it is the watchdog-side stop);
#   - /data/securedStorageLocation/snusnu/disable must be absent
#     AS FAR AS THIS UID CAN SEE. Stock policy may hide that tree
#     from uid 1000 (search denial is indistinguishable from
#     absence), so this check is best-effort here BY DESIGN:
#     boot-entry.sh and waiter.sh re-check it in the uid0
#     time_update context, where it is authoritative, before doing
#     any work. A launch that the sentinel then stops costs one
#     idle waiter timeout and authorizes nothing.
#   - a per-boot latch in the state dir caps launch invocations at
#     2 per boot_count (the app's flow invokes once; the budget
#     absorbs one full retry of the whole step, nothing more).
# Within one invocation, the set+start pair may be attempted twice
# (a TimeService write landing in the set-to-read gap makes the
# service perform its stock restore only -- a fail-closed miss that
# the second pass corrects).
#
# This helper never runs the carrier, never touches Stage4, never
# restores Magisk, never changes SELinux state, and installs
# nothing. On boots where the journal never begins (persist flag 0,
# journal denied, app disabled), it is never invoked at all: the
# no-attempt posture is a complete no-op.
#
# Modes:
#   launch  perform the protocol above; prints one LAUNCH_RESULT
#           line and records the outcome in $STATE_DIR/launch_result.
#   report  print FACT lines (identity, stops, property class,
#           service state, latch); never writes anything.
#
# Exit codes (launch): 0 = waiter launch confirmed, property
# restored; 2 = skipped, a disable sentinel is present;
# 3 = refused (uid, persist flag, or boot_count unreadable);
# 4 = refused (property not a clean numeric / foreign arming);
# 5 = failed (service busy, never started, read-miss on both
# passes, or the numeric restore did not verify);
# 6 = refused (per-boot latch exhausted or latch unreadable).
# Exit codes (report): 0 = facts printed. 64 = usage error.
#
# Device install location: /data/snusnu_root/bin/snusnu-launch.sh
# (root:root 0755, system_data_file -- the same placement class as
# watchdog.sh and system-channel-gate.sh, which the UID1000 actor
# executes). Source of truth:
# build/journal-gated-implementation-20261101/v2/stage4-persistent/
# snusnu-launch.sh (diagnostics project).
#
# Host-test seam: when SNU_LAUNCH_SANDBOX=1, the state/sentinel
# paths and the timing knobs may be overridden by the SNU_LAUNCH_*
# variables below, and getprop/setprop/settings/id resolve through
# PATH so the host suite can stub them against fixtures. Nothing on
# a device sets these; with the variable unset or different, the
# compiled-in device values are always used and the environment is
# ignored.

STATE_DIR=/data/cache/snusnu/state
SNS_DISABLE=/data/securedStorageLocation/snusnu/disable
CACHE_DISABLE=/data/cache/snusnu/disable
POLL_SLEEP=0.1
POLL_MAX=50
CONFIRM_SLEEP=3
BUSY_MAX=100
if [ "${SNU_LAUNCH_SANDBOX:-0}" = 1 ]; then
    STATE_DIR=${SNU_LAUNCH_STATE_DIR:-$STATE_DIR}
    SNS_DISABLE=${SNU_LAUNCH_SNS_DISABLE:-$SNS_DISABLE}
    CACHE_DISABLE=${SNU_LAUNCH_CACHE_DISABLE:-$CACHE_DISABLE}
    POLL_SLEEP=${SNU_LAUNCH_POLL_SLEEP:-$POLL_SLEEP}
    POLL_MAX=${SNU_LAUNCH_POLL_MAX:-$POLL_MAX}
    CONFIRM_SLEEP=${SNU_LAUNCH_CONFIRM_SLEEP:-$CONFIRM_SLEEP}
    BUSY_MAX=${SNU_LAUNCH_BUSY_MAX:-$BUSY_MAX}
fi
RESULT_FILE=$STATE_DIR/launch_result
LATCH_FILE=$STATE_DIR/launch_attempts
MAX_ATTEMPTS_PER_BOOT=2
MAX_PASSES=2

# The deployed trigger string, byte-identical to the October
# watchdog's T (preserved snapshot watchdog.sh, and re-verified by
# the host suite against it): after time_update.sh strips the
# trailing "000" (its ms-to-s conversion), the remaining array
# subscript is evaluated as shell arithmetic, whose command
# substitution runs boot-entry.sh (installed at
# /data/securedStorageLocation/w/b), which runs waiter.sh.
T='x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000'

logmsg() {
    if [ -x /system/bin/log ]; then
        /system/bin/log -t SNUSNU_LAUNCH "$*" >/dev/null 2>&1
    else
        echo "SNUSNU_LAUNCH $*" >&2
    fi
}

is_numeric() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

svc_state() {
    getprop init.svc.time_update 2>/dev/null
}

saved_time() {
    getprop persist.sys.saved_time 2>/dev/null
}

# Restore the captured numeric value and verify by read-back.
# Alternates the captured value with numeric 0 (never acted on by
# the stock script) so that no executable text can remain in the
# property even if an individual setprop is lost.
RESTORED_KIND=none
restore_numeric() {
    _orig=$1
    _try=0
    while [ "$_try" -lt 6 ]; do
        if [ $((_try % 2)) -eq 0 ]; then _v=$_orig; else _v=0; fi
        setprop persist.sys.saved_time "$_v" 2>/dev/null
        if [ "$(saved_time)" = "$_v" ]; then
            if [ "$_v" = "$_orig" ]; then
                RESTORED_KIND=orig
            else
                RESTORED_KIND=fallback0
            fi
            return 0
        fi
        _try=$((_try + 1))
    done
    RESTORED_KIND=failed
    return 1
}

write_result() {
    # Best-effort operator record; the stdout LAUNCH_RESULT line is
    # the app's authoritative signal. Written directly, NOT via a
    # tmp file + rename: this helper runs in the system_app context,
    # which the stock policy denies { rename } on cache_file
    # (measured avc denial on boot 195 -- the record was silently
    # lost even though the launch itself was confirmed). Direct
    # creation in the state dir is permitted; the latch file below
    # is written the same way and lands reliably.
    mkdir -p "$STATE_DIR" 2>/dev/null
    {
        printf 'result=%s\n' "$1"
        printf 'detail=%s\n' "${2:-}"
        printf 'boot_count=%s\n' "${3:-unknown}"
        printf 'passes=%s\n' "${4:-0}"
        printf 'svc_confirmed=%s\n' "${5:-no}"
        printf 'restored=%s\n' "${RESTORED_KIND:-none}"
    } > "$RESULT_FILE" 2>/dev/null
}

finish_skip() {
    write_result "SKIPPED" "$1" "${BOOT_COUNT:-unknown}" 0 no
    logmsg "skip_$1"
    echo "LAUNCH_RESULT SKIPPED $1"
    exit 2
}

finish_refused() {
    # $1 = detail, $2 = exit code
    write_result "REFUSED" "$1" "${BOOT_COUNT:-unknown}" 0 no
    logmsg "refuse_$1"
    echo "LAUNCH_RESULT REFUSED $1" >&2
    exit "$2"
}

finish_failed() {
    write_result "FAILED" "$1" "${BOOT_COUNT:-unknown}" "${PASSES_DONE:-0}" no
    logmsg "fail_$1"
    echo "LAUNCH_RESULT FAILED $1" >&2
    exit 5
}

wait_for_running() {
    _i=0
    while [ "$_i" -lt "$POLL_MAX" ]; do
        [ "$(svc_state)" = running ] && return 0
        sleep "$POLL_SLEEP" 2>/dev/null
        _i=$((_i + 1))
    done
    [ "$(svc_state)" = running ]
}

wait_for_stopped() {
    _i=0
    while [ "$_i" -lt "$BUSY_MAX" ]; do
        [ "$(svc_state)" != running ] && return 0
        sleep "$POLL_SLEEP" 2>/dev/null
        _i=$((_i + 1))
    done
    [ "$(svc_state)" != running ]
}

do_report() {
    echo "FACT uid=$(id -u 2>/dev/null)"
    _ctx=$(cat /proc/self/attr/current 2>/dev/null)
    echo "FACT context=${_ctx:-unreadable}"
    echo "FACT persist_enabled=$(settings get global snusnu_persist_enabled 2>/dev/null)"
    [ -e "$CACHE_DISABLE" ] && echo "FACT disable_cache=present" \
        || echo "FACT disable_cache=absent"
    [ -e "$SNS_DISABLE" ] && echo "FACT disable_sns=present" \
        || echo "FACT disable_sns=absent_or_unreadable"
    _cur=$(saved_time)
    if [ "$_cur" = "$T" ]; then
        echo "FACT saved_time_class=trigger"
    elif is_numeric "$_cur"; then
        echo "FACT saved_time_class=numeric"
    else
        echo "FACT saved_time_class=other"
    fi
    echo "FACT time_update_svc=$(svc_state)"
    echo "FACT boot_count=$(settings get global boot_count 2>/dev/null)"
    if [ -f "$LATCH_FILE" ]; then
        _lb=$(sed -n '1p' "$LATCH_FILE" 2>/dev/null)
        _la=$(sed -n '2p' "$LATCH_FILE" 2>/dev/null)
        echo "FACT latch_boot_count=${_lb:-malformed}"
        echo "FACT latch_attempts=${_la:-malformed}"
    else
        echo "FACT latch=absent"
    fi
    if [ -f "$RESULT_FILE" ]; then
        echo "FACT last_result=$(sed -n 's/^result=//p' "$RESULT_FILE" 2>/dev/null | head -1)"
    else
        echo "FACT last_result=none"
    fi
    echo "LAUNCH_RESULT REPORT"
    exit 0
}

do_launch() {
    BOOT_COUNT=unknown
    PASSES_DONE=0
    if [ "$(id -u 2>/dev/null)" != 1000 ]; then
        finish_refused not_uid1000 3
    fi
    if [ "$(settings get global snusnu_persist_enabled 2>/dev/null)" != 1 ]; then
        finish_refused persist_disabled 3
    fi
    if [ -e "$CACHE_DISABLE" ]; then
        finish_skip cache_disable
    fi
    if [ -e "$SNS_DISABLE" ]; then
        finish_skip sns_disable
    fi
    BOOT_COUNT=$(settings get global boot_count 2>/dev/null)
    if ! is_numeric "$BOOT_COUNT"; then
        BOOT_COUNT=unknown
        finish_refused boot_count_unreadable 3
    fi
    # Per-boot latch, spent BEFORE any arming: an invocation that
    # dies mid-protocol has still consumed its budget.
    _attempts=0
    if [ -f "$LATCH_FILE" ]; then
        _lb=$(sed -n '1p' "$LATCH_FILE" 2>/dev/null)
        _la=$(sed -n '2p' "$LATCH_FILE" 2>/dev/null)
        if ! is_numeric "$_lb"; then
            # A latch whose boot line is not a number is corrupt or
            # forged; never let it reset the budget by ambiguity.
            finish_refused latch_unreadable 6
        fi
        if [ "$_lb" = "$BOOT_COUNT" ]; then
            if ! is_numeric "$_la"; then
                finish_refused latch_unreadable 6
            fi
            _attempts=$_la
        fi
    fi
    if [ "$_attempts" -ge "$MAX_ATTEMPTS_PER_BOOT" ]; then
        finish_refused latch_exhausted 6
    fi
    _cur=$(saved_time)
    if [ "$_cur" = "$T" ]; then
        finish_refused slot_armed_foreign 4
    fi
    if ! is_numeric "$_cur"; then
        finish_refused slot_not_numeric 4
    fi
    _orig=$_cur
    # The start observation is only meaningful from a stopped
    # service: ctl.start on a running oneshot is a no-op, and a
    # service still running from the stock early-boot invocation
    # has already read the property. Wait briefly for it to finish;
    # if it does not, refuse rather than guess.
    if [ "$(svc_state)" = running ]; then
        if ! wait_for_stopped; then
            finish_failed service_busy
        fi
    fi
    mkdir -p "$STATE_DIR" 2>/dev/null
    printf '%s\n%s\n' "$BOOT_COUNT" "$((_attempts + 1))" \
        > "$LATCH_FILE" 2>/dev/null \
        || finish_refused latch_write_failed 6
    _pass=0
    while [ "$_pass" -lt "$MAX_PASSES" ]; do
        _pass=$((_pass + 1))
        PASSES_DONE=$_pass
        setprop persist.sys.saved_time "$T" 2>/dev/null
        if [ "$(saved_time)" != "$T" ]; then
            # A racing write replaced ours before the start; the
            # slot never held T at a service read. Restore the
            # captured value and use the next pass.
            restore_numeric "$_orig"
            continue
        fi
        setprop ctl.start time_update 2>/dev/null
        if ! wait_for_running; then
            restore_numeric "$_orig"
            continue
        fi
        sleep "$CONFIRM_SLEEP" 2>/dev/null
        if [ "$(svc_state)" = running ]; then
            # Still running past the confirmation delay: the
            # service is inside T's substitution (sleep 30 floor),
            # i.e. it consumed the trigger. The waiter is launched.
            restore_numeric "$_orig" \
                || finish_failed restore_failed
            write_result "OK" "launched" "$BOOT_COUNT" "$_pass" yes
            logmsg "launched pass=$_pass boot_count=$BOOT_COUNT"
            echo "LAUNCH_RESULT OK passes=$_pass"
            exit 0
        fi
        # The service ran and already exited: it read a racing
        # numeric value and performed its stock clock restore
        # only. Fail-closed miss; restore and retry once.
        restore_numeric "$_orig"
    done
    finish_failed no_launch_confirmed
}

case "${1:-}" in
    launch) do_launch ;;
    report) do_report ;;
    *)
        echo "usage: $0 {launch|report}" >&2
        exit 64
        ;;
esac
