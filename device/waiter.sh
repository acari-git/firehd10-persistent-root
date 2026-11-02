# Adopted from SnuSnuRoot (GPL-3.0) -- scripts/snusnu_waiter.sh
# https://github.com/voidnullvalue/SnuSnuRoot
# Copied verbatim apart from line-ending normalisation and the state-directory
# fix described below. See NOTICE.
#
# PS7319 divergence: upstream prepares $STATE after the Permissive wait. That is
# an ordering deadlock here -- the actor's UID-1000 channel writes native_result
# into $STATE, and Permissive only appears once that write succeeded. Upstream
# never hit it because 4460N keeps saved_time armed across boots and its
# securedStorageLocation metadata survives; on this firmware a state directory
# whose mode is not re-asserted leaves the actor with EACCES, the kernel write
# never runs, and the waiter times out (measured: "system_native_failed" /
# "failed_no_reboot_1" with rm/create EACCES on $STATE). The preparation now
# runs at the top of the wait loop so it is re-asserted every second from the
# first moment of boot, before the actor's channel exists.
#
# 2026-11-01 divergence: once Permissive is confirmed, the waiter invokes
# the journal boot-witness writer (/data/snusnu_root/bin/
# snusnu-boot-witness.sh, source alongside this file) before
# magisk_restore, so this boot's identity claim exists before the
# restore flow and any later app-side journal processing. Upstream has
# no witness concept. Design: FIREHD10_WAITER_BOOT_WITNESS_DESIGN_
# 20261101.md (diagnostics project root). The call is best-effort:
# the witness authorizes nothing and its failure must never block
# the restore.
#!/system/bin/sh
# UID-0/time_update half of the persistent boot chain.  The installed direct-
# boot app performs the framework work, re-arms the trigger, and flips SELinux;
# this deliberately restricted process only waits and restores the root runtime.

SNS=/data/securedStorageLocation/snusnu
# Not under $SNS: that tree is assetstorage_data_file and this firmware denies
# system_app -- the actor's UID-1000 domain -- even `search` on it, so the actor
# cannot write its own state there (measured). /data/cache is cache_file, which
# system_app may search/create/unlink in. Root's mkdir here is best-effort; the
# actor also creates it itself.
STATE=/data/cache/snusnu/state
DISABLE="$SNS/disable"
ROOT_PORT=4325

logmsg() {
    /system/bin/log -t SNUSNU_WAITER "uid=$(id -u 2>/dev/null) $*" >/dev/null 2>&1
}

# A failure marker is only consumed when its boot ID matches this boot. It
# can suppress future root attempts but cannot authorize new privileges.
mark_restore_failure() {
    fail_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
    if [ -n "$fail_boot" ]; then
        printf '%s\n' "$fail_boot" >"$STATE/magisk_restore_failed_boot" 2>/dev/null
    fi
}

[ -e "$DISABLE" ] && { logmsg disabled; exit 0; }
logmsg "start saved_time=$(getprop persist.sys.saved_time 2>/dev/null)"

# getenforce is itself denied to time_update while enforcing.  Once the app's
# kernel write succeeds, the same command becomes readable and returns 0/Permissive.
permissive=0
# 300 s, not upstream's 180 s: the boot actor now retries the carrier in-boot
# (up to 5 attempts with 12 s spacing), so Permissive can arrive ~4 minutes into
# the window. A shorter wait would abandon a boot that is still making progress.
for i in $(seq 1 300); do
    # Re-asserted every second: the actor's channel must be able to write here
    # before its kernel write can succeed, and its kernel write is what makes
    # getenforce readable at all. Doing this after the loop (upstream) deadlocks.
    mkdir -p "$STATE" /data/local/tmp/rootsvc 2>/dev/null
    chmod 0777 "$STATE" /data/local/tmp/rootsvc 2>/dev/null
    [ "$(getenforce 2>/dev/null)" = Permissive ] && { permissive=1; break; }
    sleep 1
done
if [ "$permissive" != 1 ]; then
    logmsg timeout_waiting_for_permissive
    mark_restore_failure
    exit 1
fi
logmsg selinux_permissive

# Journal boot witness: this process is the first root-side actor to
# learn that Permissive landed, and Permissive is the first state in
# which it may read /proc/sys/kernel/random/boot_id at all (the
# time_update domain has no proc_random read under Enforcing;
# measured 2026-11-01). Write the witness now, before the restore
# consumes the window. Best-effort by design: see the header note.
/system/bin/sh /data/snusnu_root/bin/snusnu-boot-witness.sh write \
    >/dev/null 2>&1 || logmsg "boot_witness_writer rc=$?"

# Hardened 4463N boot: do not create the unauthenticated uid-0 TCP listener.
# This boot worker already has uid 0 (time_update). Restore Magisk directly
# and let MagiskSU mediate subsequent app and ADB-shell authorization.
if [ ! -x "$SNS/magisk_restore.sh" ]; then
    logmsg magisk_restore_missing_refusing_unauthenticated_listener
    mark_restore_failure
    exit 1
fi
restore_rc=0
out=$(/system/bin/sh "$SNS/magisk_restore.sh" start 2>&1) || restore_rc=$?
# A spoofed or partial marker from a failed subprocess is NOT success.
case "$restore_rc:$out" in
    0:*__SNU_MAGISK_OK__*)
        magisk=ok ;;
    *)
        printf '%s\n' "$out" >"$STATE/magisk_restore_failure" 2>/dev/null
        mark_restore_failure
        logmsg magisk_restore_failed_no_root_listener
        exit 1 ;;
esac
# Root's original listener is intentionally not started. No 4325 TCP port.
printf '%s\n' "ok magisk=$magisk listener=disabled" >"$STATE/last_result" 2>/dev/null
logmsg "ok Magisk=bootstrap_reported listener=disabled su_authorization=not_independently_attested"
exit 0
