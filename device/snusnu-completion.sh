#!/system/bin/sh
# snusnu-completion.sh -- unattended signer completion for the journal
# boot cycle (2026-11-02).
#
# After a journal-gated boot's restore chain has completed (Magisk
# restored, SELinux Enforcing restored), the journal sits INFLIGHT
# until a signed proof (stage4-root-v1) is delivered into the app's
# DPS proof-drop and the app processes it. Until this component
# existed, that took two operator hands: run the device signer
# (sign-proof-request) from a root shell, then re-trigger the app
# (pm install -r) -- measured on boot 203 (2026-11-02), the only
# manual steps in an otherwise fully unattended cycle. This worker
# performs exactly those two steps, and nothing else. Design:
# FIREHD10_SIGNER_AUTO_COMPLETION_DESIGN_20261102.md (diagnostics
# project root).
#
# What this worker is NOT:
#   - It never begins an attempt, never arms anything, and never
#     touches the persist flag, either disable sentinel, or
#     persist.sys.saved_time. Only the journal arms (2026-11-01
#     authority decision); this component is completion-side only.
#   - It never writes the journal, any Settings value, or any state
#     file. Its only writes are its own after-boot log and a tmpfs
#     lock. A failure anywhere leaves the journal INFLIGHT, which
#     is the designed fail-closed residual; the documented lockout
#     recovery (operator, genesis drop) remains the backstop.
#   - It supplies NO facts to the signer. The call is the
#     production custody launcher with argv unchanged
#     (sign-proof-request): the signer reads the request file and
#     re-measures every fact it signs (own uid/context, an
#     independent su measurement, Enforcing + the stage4-enforcing
#     marker for this boot, its own /proc boot id, the
#     used-challenge ledger). A replaced or forged caller can at
#     most cause a legitimate proof for a genuinely rooted boot
#     to be issued, or withhold it -- the custody design's caller
#     argument, applied to this caller.
#
# Synchronization: the stage4-enforcing completion marker for
# THIS boot is the scheduling hint that the restore chain is done
# (the signer additionally requires it as its own gate). The
# marker alone never authorizes anything here either: the worker
# re-checks getenforce, the journal binding, and the request
# binding itself, and the signer's gates remain the authority
# (e.g. a boot whose restore failed but Enforcing returned is
# denied by the signer's su measurement, and this worker records
# the denial and stops).
#
# Execution context: installed as a Magisk service.d companion;
# service.d processes run as uid 0 in u:r:magisk:s0 on this
# firmware (stage4-enforcing's own owner check + marker lines
# measure exactly that), which is the context the signer
# requires. The worker verifies its own uid/context before
# acting and refuses otherwise.
#
# Modes:
#   run      (default) the full completion procedure.
#   report   print FACT lines (own context, boot, marker,
#            journal classification, request, drop); never
#            writes anything.
#   probe    report's FACTs plus the signer's own report mode
#            transcribed into the worker log; never signs. Used
#            once at deployment to measure the real service.d
#            context on a plain boot.
#
# Result tags (after-boot log + logcat SNUSNU_COMPLETION):
#   COMPLETED, NO_OP_READY, NO_OP_STALE, NO_OP_JOURNAL,
#   NO_OP_NO_REQUEST, NO_MARKER, REFUSED_CTX, SIGN_DENIED,
#   SIGN_FAILED, NOT_COMPLETED, LOCKED.
#
# Exit codes (run): 0 = completed or a clean no-op / no-marker;
# 3 = refused (own uid/context); 4 = boot id unreadable;
# 5 = attempted but not completed (sign denied/failed, or the
# journal did not complete within the verify budget).
# 64 = usage error.
#
# Device install locations:
#   worker:  /data/snusnu_root/bin/snusnu-completion.sh
#            (root:root 0500, system_data_file)
#   launcher: /data/adb/service.d/snusnu-completion.sh
#            (root:root 0755; separate source file
#            snusnu-completion-service.sh)
# Source of truth: build/journal-gated-implementation-20261101/v2/
# stage4-persistent/snusnu-completion.sh (diagnostics project).
#
# Host-test seam: when SNU_COMPLETION_SANDBOX=1, the paths and
# budgets below may be overridden by SNU_COMPLETION_* variables
# so the host suite can run this exact file against fixtures.
# Nothing on a device sets these; with the variable unset or
# different, the compiled-in device paths are always used and
# the environment is ignored.

set -u

if [ "${SNU_COMPLETION_SANDBOX:-0}" = "1" ]; then
    BOOT_ID_FILE=${SNU_COMPLETION_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}
    ATTR_FILE=${SNU_COMPLETION_ATTR_FILE:-/proc/self/attr/current}
    ENFORCING_LOG=${SNU_COMPLETION_ENFORCING_LOG:-/data/adb/stage4-enforcing-after-boot.log}
    JOURNAL_FILE=${SNU_COMPLETION_JOURNAL_FILE:-/dev/null}
    REQUEST_FILE=${SNU_COMPLETION_REQUEST_FILE:-/data/cache/snusnu/state/proof_request}
    DROP_DIR=${SNU_COMPLETION_DROP_DIR:-/dev/null}
    SIGNER=${SNU_COMPLETION_SIGNER:-/data/snusnu_root/signer/snusnu-proof-signer.sh}
    RESULT_LOG=${SNU_COMPLETION_RESULT_LOG:-/data/adb/snusnu-completion-after-boot.log}
    LOCK_DIR=${SNU_COMPLETION_LOCK_DIR:-/dev/.snusnu-completion}
    MARKER_BUDGET_S=${SNU_COMPLETION_MARKER_BUDGET_S:-900}
    MARKER_POLL_S=${SNU_COMPLETION_MARKER_POLL_S:-5}
    VERIFY_BUDGET_S=${SNU_COMPLETION_VERIFY_BUDGET_S:-180}
    VERIFY_POLL_S=${SNU_COMPLETION_VERIFY_POLL_S:-3}
else
    BOOT_ID_FILE=/proc/sys/kernel/random/boot_id
    ATTR_FILE=/proc/self/attr/current
    ENFORCING_LOG=/data/adb/stage4-enforcing-after-boot.log
    JOURNAL_FILE=/data/user_de/0/io.github.voidnullvalue.snusnuroot.persistence/files/stage4-native-attempt-v2.state
    REQUEST_FILE=/data/cache/snusnu/state/proof_request
    DROP_DIR=/data/user_de/0/io.github.voidnullvalue.snusnuroot.persistence/files/proof-drop
    SIGNER=/data/snusnu_root/signer/snusnu-proof-signer.sh
    RESULT_LOG=/data/adb/snusnu-completion-after-boot.log
    LOCK_DIR=/dev/.snusnu-completion
    MARKER_BUDGET_S=900
    MARKER_POLL_S=5
    VERIFY_BUDGET_S=180
    VERIFY_POLL_S=3
fi

PKG=io.github.voidnullvalue.snusnuroot.persistence
SERVICE_COMPONENT="$PKG/.PersistenceService"
RECEIVER_COMPONENT="$PKG/.BootReceiver"
EXPECTED_CTX=u:r:magisk:s0
DROP_FILE="$DROP_DIR/stage4-proof.txt"

MODE=${1:-run}

boot_id() {
    # Command substitution strips trailing newlines (and, in
    # mksh, NUL bytes). No tr: this firmware's tr mangles the
    # '\0' escape in a delete set, measured 2026-11-02 (it ate
    # the 'r' out of u:r:magisk:s0).
    v=$(head -n 1 "$BOOT_ID_FILE" 2>/dev/null)
    printf '%s' "$v"
}

own_uid() { id -u 2>/dev/null; }

own_ctx() {
    v=$(cat "$ATTR_FILE" 2>/dev/null)
    printf '%s' "$v"
}

utc_now() {
    ts=$(date -u +%FT%TZ 2>/dev/null)
    [ -n "$ts" ] || ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
    printf '%s' "$ts"
}

logmsg() {
    if [ -x /system/bin/log ]; then
        /system/bin/log -t SNUSNU_COMPLETION "$*" >/dev/null 2>&1
    fi
}

# Append one result line to the after-boot log and mirror to logcat.
# Never called in report mode (report writes nothing).
result() {
    tag=$1; shift
    line="$(utc_now) boot=${BOOT:-unknown} $tag $*"
    printf '%s\n' "$line" >>"$RESULT_LOG" 2>/dev/null
    logmsg "$tag $*"
}

journal_line() {
    # The journal file is a single strict-grammar line.
    if [ -f "$JOURNAL_FILE" ]; then
        head -n 1 "$JOURNAL_FILE" 2>/dev/null
    fi
}

is_hex64() {
    [ "${#1}" = "64" ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    return 0
}

# Classify the journal relative to this boot. Prints one of:
# READY, INFLIGHT_OURS, INFLIGHT_DEGRADED, INFLIGHT_STALE,
# EMPTY, FOREIGN, UNREADABLE
classify_journal() {
    if [ ! -f "$JOURNAL_FILE" ]; then
        printf 'UNREADABLE'; return
    fi
    line=$(journal_line)
    if [ -z "$line" ]; then
        printf 'EMPTY'; return
    fi
    case "$line" in
        READY:*)
            printf 'READY'; return ;;
        INFLIGHT:*)
            rest=${line#INFLIGHT:}
            jboot=${rest%%:*}
            rest2=${rest#*:}
            jcount=${rest2%%:*}
            rest3=${rest2#*:}
            jchallenge=${rest3%%:*}
            if ! is_hex64 "$jchallenge"; then
                printf 'FOREIGN'; return
            fi
            if [ "$jboot" = "$BOOT" ]; then
                printf 'INFLIGHT_OURS'; return
            fi
            if [ "$jboot" = "?" ]; then
                cur_count=$(settings get global boot_count 2>/dev/null)
                if [ -n "$cur_count" ] && [ "$jcount" = "$cur_count" ]; then
                    printf 'INFLIGHT_DEGRADED'; return
                fi
            fi
            printf 'INFLIGHT_STALE'; return ;;
        *)
            printf 'FOREIGN'; return ;;
    esac
}

marker_ok() {
    [ -f "$ENFORCING_LOG" ] || return 1
    grep -F "boot=$BOOT OK enforcing-restored" "$ENFORCING_LOG" \
        >/dev/null 2>&1
}

request_boot() {
    if [ -f "$REQUEST_FILE" ]; then
        line=$(head -n 1 "$REQUEST_FILE" 2>/dev/null)
        # First whitespace-separated field.
        printf '%s' "$line" | awk '{print $1}'
    fi
}

drop_present() { [ -f "$DROP_FILE" ]; }

# A drop is only actionable for this boot if its signed message
# binds this boot id and the standing journal challenge. A stale
# drop from an earlier boot is never deleted by the app and must
# not suppress signing: the signer overwrites the same path.
# $1 = the standing challenge from the INFLIGHT journal line.
drop_fresh() {
    drop_present || return 1
    first=$(head -n 1 "$DROP_FILE" 2>/dev/null)
    case "$first" in
        "stage4-root-v1|$BOOT|$1|"*) return 0 ;;
        *) return 1 ;;
    esac
}

journal_ready_for_boot() {
    line=$(journal_line)
    case "$line" in
        "READY:$BOOT:"*) return 0 ;;
        *) return 1 ;;
    esac
}

facts() {
    printf 'FACT uid=%s\n' "$(own_uid)"
    printf 'FACT context=%s\n' "$(own_ctx)"
    printf 'FACT boot_id=%s\n' "$BOOT"
    if marker_ok; then printf 'FACT marker=present\n';
    else printf 'FACT marker=absent\n'; fi
    printf 'FACT journal=%s\n' "$(classify_journal)"
    printf 'FACT request_boot=%s\n' "$(request_boot)"
    if drop_present; then printf 'FACT drop=present\n';
    else printf 'FACT drop=absent\n'; fi
    printf 'FACT enforcing=%s\n' "$(getenforce 2>/dev/null)"
}

do_report() {
    facts
    return 0
}

do_probe() {
    result PROBE_BEGIN "uid=$(own_uid) ctx=$(own_ctx)"
    facts | while IFS= read -r l; do result PROBE_FACT "$l"; done
    out=$("$SIGNER" report 2>&1)
    rc=$?
    printf '%s\n' "$out" | while IFS= read -r l; do
        result PROBE_SIGNER "$l"
    done
    result PROBE "signer_report_rc=$rc"
    return 0
}

trigger_app() {
    # Primary: am start-foreground-service. PersistenceService is
    # a foreground service by design, and this is the vector that
    # works from root on this firmware -- measured on boot 203
    # (2026-11-02) with the app background-idle, the hardest
    # state: plain `am startservice` is refused by AMS
    # ("Background start not allowed ... from uid=0
    # pkg=com.android.shell"), while start-foreground-service
    # starts the process and delivers onStartCommand. Every
    # service start runs the drop processing first, including
    # while persistence is disabled. The journal verify poll in
    # do_run is the source of truth for success, not am's output.
    out=$(am start-foreground-service -n "$SERVICE_COMPONENT" 2>&1)
    rc=$?
    case "$out" in *Error:*) rc=1 ;; esac
    result TRIGGER "method=start-foreground-service rc=$rc out=$out"
    if [ $rc -ne 0 ]; then
        # Fallback: explicit-component MY_PACKAGE_REPLACED to the
        # boot receiver, which starts the same service (delivery
        # from root measured on boot 203 as well).
        out2=$(am broadcast -a android.intent.action.MY_PACKAGE_REPLACED \
            -n "$RECEIVER_COMPONENT" 2>&1)
        rc2=$?
        case "$out2" in *Error:*) rc2=1 ;; esac
        result TRIGGER "method=broadcast rc=$rc2 out=$out2"
    fi
    return 0
}

do_run() {
    # Single instance per boot (tmpfs lock; content = boot id).
    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        locked_boot=$(cat "$LOCK_DIR/boot" 2>/dev/null)
        if [ "$locked_boot" = "$BOOT" ]; then
            result LOCKED "existing instance for this boot"
            return 0
        fi
        rm -rf "$LOCK_DIR" 2>/dev/null
        mkdir "$LOCK_DIR" 2>/dev/null || return 0
    fi
    printf '%s\n' "$BOOT" >"$LOCK_DIR/boot" 2>/dev/null
    trap 'rm -rf "$LOCK_DIR"' 0

    if [ "$(own_uid)" != "0" ] || [ "$(own_ctx)" != "$EXPECTED_CTX" ]; then
        result REFUSED_CTX "uid=$(own_uid) ctx=$(own_ctx)"
        return 3
    fi

    # Wait for the restore chain's own completion signal for
    # this boot. The journal is classified only after the marker:
    # by then any begin for this boot has long happened, so a
    # READY read is unambiguous.
    waited=0
    while ! marker_ok; do
        if [ "$waited" -ge "$MARKER_BUDGET_S" ]; then
            result NO_MARKER "budget=${MARKER_BUDGET_S}s"
            return 0
        fi
        sleep "$MARKER_POLL_S"
        waited=$((waited + MARKER_POLL_S))
    done
    if [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
        result NO_MARKER "marker present but getenforce not Enforcing"
        return 0
    fi

    cls=$(classify_journal)
    case "$cls" in
        READY)
            result NO_OP_READY "journal already READY"
            return 0 ;;
        INFLIGHT_OURS|INFLIGHT_DEGRADED)
            : ;;
        INFLIGHT_STALE)
            result NO_OP_STALE "INFLIGHT belongs to another boot"
            return 0 ;;
        *)
            result NO_OP_JOURNAL "journal=$cls"
            return 0 ;;
    esac

    rb=$(request_boot)
    if [ "$rb" != "$BOOT" ]; then
        result NO_OP_NO_REQUEST "request_boot=$rb"
        return 0
    fi

    # The standing challenge, field 4 of the INFLIGHT line.
    jline=$(journal_line)
    jrest=${jline#INFLIGHT:}
    jrest=${jrest#*:}
    jrest=${jrest#*:}
    jchallenge=${jrest%%:*}

    if drop_fresh "$jchallenge"; then
        result SIGN_SKIPPED "fresh drop already present; re-trigger only"
    else
        if drop_present; then
            result DROP_STALE "earlier boot's drop present; signing over it"
        fi
        out=$("$SIGNER" sign-proof-request 2>&1)
        rc=$?
        printf '%s\n' "$out" | while IFS= read -r l; do
            result SIGNER_OUT "$l"
        done
        if [ $rc -ne 0 ]; then
            case "$out" in
                *SIGNER_RESULT\ DENY*) result SIGN_DENIED "rc=$rc" ;;
                *) result SIGN_FAILED "rc=$rc" ;;
            esac
            return 5
        fi
        case "$out" in
            *"SIGNER_RESULT OK"*) : ;;
            *)
                result SIGN_FAILED "rc=0 but no OK in output"
                return 5 ;;
        esac
        if ! drop_fresh "$jchallenge"; then
            result SIGN_FAILED "signer OK but no fresh drop for this boot"
            return 5
        fi
        result SIGNED "drop delivered"
    fi

    trigger_app

    waited=0
    while ! journal_ready_for_boot; do
        if [ "$waited" -ge "$VERIFY_BUDGET_S" ]; then
            result NOT_COMPLETED "budget=${VERIFY_BUDGET_S}s journal=$(journal_line)"
            return 5
        fi
        sleep "$VERIFY_POLL_S"
        waited=$((waited + VERIFY_POLL_S))
    done
    pstat=$(settings get global snusnu_proof_status 2>/dev/null)
    result COMPLETED "journal=$(journal_line) proof_status=$pstat"
    return 0
}

BOOT=$(boot_id)
if [ -z "$BOOT" ]; then
    printf 'snusnu-completion: boot id unreadable\n' >&2
    exit 4
fi

case "$MODE" in
    run) do_run; exit $? ;;
    report) do_report; exit 0 ;;
    probe) do_probe; exit 0 ;;
    *) printf 'usage: %s [run|report|probe]\n' "$0" >&2; exit 64 ;;
esac
