#!/system/bin/sh
# Stage 4 re-arm watchdog.
#
# Why this exists: on this firmware persist.sys.saved_time is NOT durable.
# Amazon's TimeService NTP-syncs ~20 s and ~130 s into boot and writes the synced
# millisecond clock into that property, overwriting the armed trigger. The
# consequence is a silent alternating-boot failure -- the trigger is armed for
# the current boot, NTP makes it numeric, and the NEXT boot's
# load_persist_props_action finds nothing to evaluate, so no uid-0 waiter runs
# while the actor still reports success. Measured on device:
#   TimeService.clockWrapper: broadcastTimeUpdate ... newTimeMillis = 1791389093870
# which is byte-for-byte the value left in the property.
#
# Polling every 2 s rather than restoring once is deliberate: a single restore
# would race an NTP write at an unknown moment, whereas polling keeps the value
# armed at every instant, so whichever moment the device reboots, the next boot
# fires. Cost is one getprop per 2 s.
#
# INSTALLED BY ROOT, EXECUTED BY THE UID-1000 ACTOR. It deliberately does not
# live in the actor's scratch directory: that directory is 0777 (the actor has to
# write native_result into it) and executing a script from a world-writable
# directory would let any local app replace it and run code as uid 1000 -- which
# is a straight path back to re-arming root. This file is root-owned 0755 in a
# root-owned 0755 directory, so the actor can run it but not modify it.
#
# "Armed at every instant" is the design intent, not a measured guarantee: the
# loop has a gap between the check and the sleep, and an NTP write landing in
# that gap is only corrected on the next tick. That is exactly why the boot actor
# retries the carrier in-boot (see PersistenceService.java) instead of assuming
# the trigger survived.

T='x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000'
D=/data/cache/snusnu/disable
P=/data/cache/snusnu/state/watchdog.pid

# One guard per boot. A second guard would double the property traffic and could
# exit between reads without ever re-arming.
#
# The pidfile records the BOOT ID on the first line and the PID on the second.
# A PID alone is not safe here: this file lives on /data and survives reboots, so
# a PID recycled by an unrelated process in the next boot would make `kill -0`
# succeed and the real guard would exit without ever arming -- a dead watchdog
# that looks alive. Requiring the boot id to match as well removes that
# coincidence entirely.
BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
if [ -s "$P" ]; then
    prev_boot=$(sed -n '1p' "$P" 2>/dev/null)
    prev_pid=$(sed -n '2p' "$P" 2>/dev/null)
    if [ -n "$BOOT" ] && [ "$prev_boot" = "$BOOT" ] \
        && [ -n "$prev_pid" ] && kill -0 "$prev_pid" 2>/dev/null; then
        exit 0
    fi
fi
printf '%s\n%s\n' "$BOOT" "$$" > "$P" 2>/dev/null

# The disable sentinel is what makes `install-persistence.sh --remove` actually
# work. Without it this loop re-armed the trigger every 2 s forever, so removal
# reported success while the property still pointed at a payload it had just
# deleted. Checked every tick so the loop stops within one interval.
# The Android setting is an independent emergency stop. Do not continue
# re-arming when the user has explicitly disabled persistence.
while [ ! -e "$D" ] && [ "$(settings get global snusnu_persist_enabled 2>/dev/null)" = 1 ]; do
    [ "$(getprop persist.sys.saved_time)" = "$T" ] || setprop persist.sys.saved_time "$T"
    sleep 2
done

# Disarm only our exact trigger, and only if an original numeric value was
# retained by the installer. Never overwrite an unrelated time-service value.
ORIG=/data/cache/snusnu/saved_time.orig
if [ "$(getprop persist.sys.saved_time)" = "$T" ] && [ -r "$ORIG" ]; then
    previous=$(cat "$ORIG" 2>/dev/null)
    case "$previous" in
        ''|*[!0-9]*) : ;;
        *) setprop persist.sys.saved_time "$previous" || true ;;
    esac
fi
rm -f "$P" 2>/dev/null
