#!/system/bin/sh
#
# snusnu_magisk_device_restore.sh - device-side live-Magisk reconstruction.
#
# Standalone version of the DEVICE_SCRIPT embedded in
# scripts/snusnu_magisk_bootstrap.sh, kept byte-for-byte behaviorally faithful
# but runnable entirely on-device through the uid-0 root listener at
# 127.0.0.1:4325 (no host adb, no host unzip needed once staged).
#
# Expected staged inputs (staged once at install time by runme.sh install):
#   /data/securedStorageLocation/snusnu/magisk/magisk
#   /data/securedStorageLocation/snusnu/magisk/magiskpolicy
#   /data/securedStorageLocation/snusnu/magisk/stub.apk   (optional)
#   /data/securedStorageLocation/snusnu/magisk/busybox    (optional)
#
# Actions:
#   start  - reconstruct /sbin Magisk tmpfs, live policy, magiskd, consume stub
#   status - report runtime/daemon state
#   stop   - roll back the runtime mounts (reversible)
#
# Success is reported by printing __SNU_MAGISK_OK__ so the uid-0 caller
# (snusnu_boot.sh) can verify completion without adb.
#
# Idempotency: start() already short-circuits when a healthy /sbin/./magisk
# runtime is present; rollback restores every mount it made. It never patches
# /boot or modifies the underlying /system.

set -eu

MAGISK_SRC=/data/securedStorageLocation/snusnu/magisk
STATE=/data/local/tmp/snusnu-magisk-state
ORIG=/data/local/tmp/snusnu-sbin-original
STAGE=/data/local/tmp/snusnu-magisk-stage
ENTRY_MOUNTS="$STATE/entry_mounts"
LOG="$STATE/bootstrap.log"

MAGISKTMP=/sbin
WORKER=/sbin/.magisk/worker

ACTION="${1:-status}"
IN_START=0

log() {
    mkdir -p "$STATE" 2>/dev/null
    msg="[snusnu-magisk-device] $*"
    echo "$msg"
    echo "$msg" >>"$LOG" 2>/dev/null
}

fail() {
    log "ERROR: $*"
    if [ "$IN_START" = "1" ]; then
        log "START failed; rolling back runtime mounts"
        rollback_runtime
    fi
    exit 1
}

mounted_at() {
    grep -q " $1 " /proc/mounts 2>/dev/null
}

sbin_is_magisk_tmpfs() {
    grep -q '^magisk /sbin tmpfs ' /proc/mounts 2>/dev/null
}

root_uid_ok() {
    [ "$(id -u 2>/dev/null)" = "0" ]
}

selinux_state() {
    getenforce 2>/dev/null || echo unknown
}

daemon_pid() {
    ps 2>/dev/null | grep '[m]agiskd' | awk 'NR==1 {print $2}'
}

verify_original_view() {
    [ -d "$ORIG" ] || return 1
    [ -e "$ORIG/charger" ] || return 1
    [ -e "$ORIG/crashreport" ] || return 1
    [ -L "$ORIG/ueventd" ] || return 1
    [ -L "$ORIG/watchdogd" ] || return 1
    return 0
}

record_bind() {
    echo "$1" >>"$ENTRY_MOUNTS"
}

restore_original_entries() {
    : >"$ENTRY_MOUNTS"
    restored=0

    for src in "$ORIG"/* "$ORIG"/.[!.]* "$ORIG"/..?*; do
        if [ ! -e "$src" ] && [ ! -L "$src" ]; then
            continue
        fi

        name=${src##*/}
        dst="/sbin/$name"
        restored=$((restored + 1))

        if [ -L "$src" ]; then
            target=$(readlink "$src") || return 31
            rm -f "$dst" 2>/dev/null
            ln -s "$target" "$dst" || return 32
            log "restored symlink: $dst -> $target"
        elif [ -f "$src" ]; then
            : >"$dst" || return 33
            mount --bind "$src" "$dst" || return 34
            record_bind "$dst"
            log "restored bind file: $dst"
        elif [ -d "$src" ]; then
            mkdir -p "$dst" || return 35
            mount --bind "$src" "$dst" || return 36
            record_bind "$dst"
            log "restored bind directory: $dst"
        else
            log "restore failed: unsupported entry type: $src"
            return 37
        fi
    done

    [ "$restored" -gt 0 ] || return 38
    [ -e /sbin/charger ] || return 41
    [ -e /sbin/crashreport ] || return 42
    [ -L /sbin/ueventd ] || return 43
    [ -L /sbin/watchdogd ] || return 44
    [ "$(readlink /sbin/ueventd)" = "../init" ] || return 45
    [ "$(readlink /sbin/watchdogd)" = "../init" ] || return 46

    log "restored $restored original /sbin entries"
    return 0
}

unmount_entry_binds() {
    [ -f "$ENTRY_MOUNTS" ] || return 0
    while IFS= read -r mnt; do
        [ -n "$mnt" ] || continue
        if mounted_at "$mnt"; then
            umount "$mnt" 2>/dev/null || true
        fi
    done <"$ENTRY_MOUNTS"
    while IFS= read -r mnt; do
        [ -n "$mnt" ] || continue
        if mounted_at "$mnt"; then
            umount "$mnt" 2>/dev/null || return 1
        fi
    done <"$ENTRY_MOUNTS"
    return 0
}

rollback_runtime() {
    IN_START=0
    if [ -x /sbin/magisk ] && sbin_is_magisk_tmpfs; then
        /sbin/magisk --stop >/dev/null 2>&1 || true
        sleep 1
    fi
    if mounted_at "$WORKER"; then
        umount "$WORKER" 2>/dev/null || true
    fi
    unmount_entry_binds || log "WARNING: preserved /sbin entry mounts busy"
    if sbin_is_magisk_tmpfs; then
        umount /sbin 2>/dev/null || {
            log "ERROR: could not unmount Magisk tmpfs from /sbin"
            return 1
        }
    fi
    if mounted_at "$ORIG"; then
        umount "$ORIG" 2>/dev/null || {
            log "ERROR: could not unmount original /sbin preservation bind"
            return 1
        }
    fi
    rm -rf "$ORIG" "$STAGE" 2>/dev/null
    rm -f "$ENTRY_MOUNTS" 2>/dev/null
    if [ ! -e /sbin/charger ] || [ ! -e /sbin/crashreport ]; then
        log "ERROR: original /sbin did not reappear correctly"
        return 1
    fi
    log "runtime rollback complete; persistent /data/adb state retained"
    return 0
}

status() {
    echo "uid=$(id -u 2>/dev/null)"
    echo "context=$(cat /proc/self/attr/current 2>/dev/null)"
    echo "selinux=$(selinux_state)"
    echo "--- /sbin mount ---"
    grep ' /sbin ' /proc/mounts 2>/dev/null || echo "rootfs-backed (no separate /sbin mount)"
    if [ -d /sbin/.magisk ]; then
        echo "magisk_runtime=present"
    else
        echo "magisk_runtime=absent"
    fi
    if [ -x /sbin/magisk ]; then
        printf 'local_version='
        /sbin/magisk -c 2>&1 || true
        printf 'magisk_path='
        /sbin/magisk --path 2>&1 || true
        printf 'daemon_version='
        /sbin/magisk -v 2>&1 || true
    else
        echo "local_version=unavailable"
    fi
    pid=$(daemon_pid)
    if [ -n "$pid" ]; then
        echo "magiskd_pid=$pid"
        printf 'magiskd_context='
        cat "/proc/$pid/attr/current" 2>/dev/null || echo unknown
    else
        echo "magiskd_pid=none"
    fi
    if [ -S /sbin/.magisk/device/socket ] || [ -e /sbin/.magisk/device/socket ]; then
        ls -l /sbin/.magisk/device/socket 2>/dev/null
    else
        echo "daemon_socket=absent"
    fi
}

start() {
    IN_START=1
    root_uid_ok || fail "helper is not running as uid 0"
    state=$(selinux_state)
    [ "$state" = "Permissive" ] || fail "SELinux is $state, expected Permissive"
    [ -d /sbin ] || fail "/sbin does not exist"

    # Stage from the persistent snusnu dir if this is the first reconstruction
    # of a boot (the host bootstrap script staged under /data/local/tmp/... the
    # autonomous path stages under /data/securedStorageLocation/snusnu/magisk).
    if [ ! -x "$STAGE/magisk" ]; then
        mkdir -p "$STAGE"
        cp "$MAGISK_SRC/magisk" "$STAGE/magisk" 2>/dev/null || true
        cp "$MAGISK_SRC/magiskpolicy" "$STAGE/magiskpolicy" 2>/dev/null || true
        cp "$MAGISK_SRC/stub.apk" "$STAGE/stub.apk" 2>/dev/null || true
        chmod 0755 "$STAGE/magisk" "$STAGE/magiskpolicy" 2>/dev/null || true
    fi
    [ -x "$STAGE/magisk" ] || fail "staged magisk binary missing"
    [ -x "$STAGE/magiskpolicy" ] || fail "staged magiskpolicy binary missing"

    if sbin_is_magisk_tmpfs; then
        if [ -x /sbin/magisk ] && [ -d /sbin/.magisk ]; then
            path=$(/sbin/magisk --path 2>/dev/null || true)
            if [ "$path" = "/sbin" ]; then
                log "Magisk /sbin runtime already present; treating start as idempotent"
                /sbin/magisk --daemon >/dev/null 2>&1 || true
                IN_START=0
                status
                echo "__SNU_MAGISK_OK__"
                return 0
            fi
        fi
        fail "/sbin is already tmpfs but does not look like a healthy Snu-Snu Magisk runtime"
    fi

    mkdir -p "$STATE" "$ORIG" || fail "cannot create state/preservation directories"
    : >"$LOG"

    log "preserving original /sbin via bind mount"
    if mounted_at "$ORIG"; then
        umount "$ORIG" 2>/dev/null || fail "stale preservation mount cannot be removed"
    fi
    mount --bind /sbin "$ORIG" || fail "cannot bind-preserve original /sbin"
    mount -t none -o private none "$ORIG" || fail "cannot make preserved /sbin mount private"
    verify_original_view || fail "original /sbin preservation verification failed"

    log "mounting Magisk tmpfs on /sbin"
    mount -t tmpfs -o mode=0755 magisk /sbin || fail "cannot mount tmpfs on /sbin"
    chcon u:object_r:rootfs:s0 /sbin 2>/dev/null || log "WARNING: could not chcon /sbin to rootfs context"

    log "re-exposing original /sbin entries"
    restore_original_entries || fail "failed to preserve all original /sbin entries"

    log "installing Magisk runtime binaries"
    cp "$STAGE/magisk" /sbin/magisk || fail "cannot copy magisk to /sbin"
    cp "$STAGE/magiskpolicy" /sbin/magiskpolicy || fail "cannot copy magiskpolicy to /sbin"
    chmod 0755 /sbin/magisk /sbin/magiskpolicy || fail "cannot chmod Magisk runtime binaries"
    ln -s ./magisk /sbin/su || fail "cannot create /sbin/su applet"
    ln -s ./magisk /sbin/resetprop || fail "cannot create /sbin/resetprop applet"

    mkdir -p /sbin/.magisk/device /sbin/.magisk/worker || fail "cannot create .magisk runtime directories"
    chmod 0755 /sbin/.magisk /sbin/.magisk/device || fail "cannot make Magisk daemon socket path traversable"
    : >/sbin/.magisk/config || fail "cannot create runtime config"
    : >/sbin/.magisk/live || fail "cannot create live marker"

    if [ ! -d /data/adb ]; then
        mkdir -p /data/adb || fail "cannot create /data/adb"
        chmod 0700 /data/adb 2>/dev/null || true
    fi
    mkdir -p /data/adb/magisk /data/adb/modules /data/adb/post-fs-data.d /data/adb/service.d \
        || fail "cannot create /data/adb Magisk directories"

    mount -t tmpfs -o mode=0755 magisk /sbin/.magisk/worker || fail "cannot mount Magisk worker tmpfs"
    mount -t none -o private none /sbin/.magisk/worker || fail "cannot make Magisk worker mount private"

    path=$(/sbin/magisk --path 2>&1) || fail "magisk --path failed: $path"
    [ "$path" = "/sbin" ] || fail "magisk --path returned '$path', expected /sbin"

    /sbin/magisk -c >/dev/null 2>&1 || fail "runtime magisk binary no longer executes"
    applets=$(/sbin/magisk --list 2>&1) || fail "magisk --list failed"
    echo "$applets" | grep -q '^su$' || fail "Magisk su applet is unavailable"
    echo "$applets" | grep -q '^resetprop$' || fail "Magisk resetprop applet is unavailable"

    log "applying Magisk live SELinux policy"
    if [ -f /vendor/etc/selinux/precompiled_sepolicy ]; then
        policy_out=$(/sbin/magiskpolicy --load /vendor/etc/selinux/precompiled_sepolicy --live --magisk 2>&1)
        policy_rc=$?
        policy_source="/vendor/etc/selinux/precompiled_sepolicy"
    elif [ -f /sepolicy ]; then
        policy_out=$(/sbin/magiskpolicy --load /sepolicy --live --magisk 2>&1)
        policy_rc=$?
        policy_source="/sepolicy"
    else
        policy_out=$(/sbin/magiskpolicy --live --magisk 2>&1)
        policy_rc=$?
        policy_source="live kernel policy"
    fi
    [ "$policy_rc" = "0" ] ||
        fail "magiskpolicy failed rc=$policy_rc source=$policy_source: $policy_out"
    log "Magisk policy applied from: $policy_source"
    [ "$(selinux_state)" = "Permissive" ] || fail "SELinux unexpectedly left Permissive mode"

    log "starting magiskd"
    daemon_out=$(/sbin/magisk --daemon 2>&1)
    daemon_rc=$?
    [ "$daemon_rc" = "0" ] || fail "magisk --daemon failed rc=$daemon_rc: $daemon_out"
    sleep 1
    dver=$(/sbin/magisk -v 2>&1)
    dver_rc=$?
    [ "$dver_rc" = "0" ] || fail "client cannot talk to magiskd: $dver"
    [ -e /sbin/.magisk/device/socket ] || fail "magiskd socket was not created"
    pid=$(daemon_pid)
    [ -n "$pid" ] || fail "magiskd process is not present"
    log "magiskd version: $dver"
    log "magiskd pid: $pid"
    log "magiskd context: $(cat "/proc/$pid/attr/current" 2>/dev/null || echo unknown)"

    # Bind trusted Manager cert before any su request (cold-daemon safety).
    if [ -f "$STAGE/stub.apk" ]; then
        log "staging stub.apk for trusted Manager certificate"
        cp "$STAGE/stub.apk" /sbin/stub.apk || fail "cannot stage /sbin/stub.apk"
        chmod 0644 /sbin/stub.apk
        log "running magisk post-fs-data to consume stub (sets trusted_cert)"
        pfs_out=$(/sbin/magisk --post-fs-data 2>&1)
        pfs_rc=$?
        log "post-fs-data rc=$pfs_rc"
        if [ -e /sbin/stub.apk ]; then
            fail "stub.apk was not consumed; trusted Manager certificate not bound"
        else
            toybox sha256sum "$STAGE/stub.apk" | awk '{print $1}' \
                > /data/adb/magisk/.snusnu-trusted-stub.sha256 \
                || fail "cannot record trusted stub digest"
            chmod 0600 /data/adb/magisk/.snusnu-trusted-stub.sha256
            log "stub.apk consumed: trusted Manager certificate bound"
        fi
        /sbin/magisk --sqlite "INSERT OR REPLACE INTO settings (key,value) VALUES('bootloop',0)" >/dev/null 2>&1 || true
        log "testing Magisk su applet from existing uid-0 context"
        su_out=$(/sbin/su -c id 2>&1)
        su_rc=$?
        [ "$su_rc" = "0" ] || fail "root-context Magisk su test failed rc=$su_rc: $su_out"
        echo "$su_out" | grep -q 'uid=0' || fail "Magisk su test did not return uid=0: $su_out"
        log "root-context su result: $su_out"
    else
        log "WARNING: no stub.apk staged; skipping root-context su test to avoid a cold-daemon Manager uninstall"
    fi

    IN_START=0
    log "Phase 1 runtime bootstrap succeeded"
    status
    # The original bootless restore does not issue Magisk's late_start
    # service phase. Trigger it from the established Magisk daemon, not from
    # the time_update context. service.d scripts must defer enforcement
    # until this init worker has fully stopped.
    if /sbin/magisk --service >/dev/null 2>&1; then
        log "Magisk late_start service requested"
    else
        log "WARNING: Magisk late_start service request failed"
    fi
    echo "__SNU_MAGISK_OK__"
}

stop() {
    root_uid_ok || {
        log "ERROR: stop must run as uid 0"
        exit 1
    }
    rollback_runtime || exit 1
    status
}

case "$ACTION" in
    start) start ;;
    status) status ;;
    stop) stop ;;
    *) echo "usage: $0 {start|status|stop}" >&2; exit 2 ;;
esac
