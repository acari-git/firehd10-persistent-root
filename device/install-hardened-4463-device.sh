#!/system/bin/sh
# Hardened Fire HD 10 4463N Stage4 installer. Run only via authorized MagiskSU.
# Does NOT enable persistence or arm any property; host does that only after tests.
set -eu
umask 077
SRC=/data/local/tmp/snu4463-stage
PKG=io.github.voidnullvalue.snusnuroot.persistence
ACTOR_UID=10055
SNS=/data/securedStorageLocation/snusnu
CARRIER=/data/snusnu_hwbinder_root
STATE=/data/cache/snusnu/state
GUARD=/data/cache/snusnu/expected-build
PRIV=/data/user_de/0/$PKG
WATCHDOGDIR=/data/snusnu_root/bin
AUTH=/data/cache/snusnu/channel-auth
EXPECTED_CARRIER=604725775c9a9121b7c36fd63c077d0f8fab5511101dae78ef4f5265c2f25841

fail() { echo "INSTALL_ABORT: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "not root"
[ "$(getenforce)" = Permissive ] || fail "SELinux state"
[ "$(getprop ro.product.device)" = trona ] || fail "device mismatch"
[ "$(getprop ro.build.id)" = PS7331.4463N ] || fail "build mismatch"
[ "$(getprop ro.build.version.incremental)" = 0031575863172 ] || fail "incremental mismatch"
[ "$(settings get global snusnu_persist_enabled)" != 1 ] || fail "persistence already enabled"
[ -d "$PRIV" ] || fail "actor app data missing"
[ "$(stat -c %u "$PRIV")" = "$ACTOR_UID" ] || fail "actor UID mismatch"
[ -x /sbin/magisk ] || fail "Magisk currently absent"
for f in carrier boot-entry.sh waiter.sh watchdog.sh system-channel-gate.sh magisk_restore.sh snusnu-boot-witness.sh magisk magiskpolicy stub.apk; do
  [ -s "$SRC/$f" ] || fail "stage file missing: $f"
done
[ "$(toybox sha256sum "$SRC/carrier" | cut -d' ' -f1)" = "$EXPECTED_CARRIER" ] || fail "carrier hash mismatch"

# Root-owned executable paths; the actor (uid 1000) can traverse but not alter.
mkdir -p /data/snusnu_root "$WATCHDOGDIR" /data/cache/snusnu "$STATE" "$SNS" "$SNS/magisk" /data/securedStorageLocation/w "$PRIV/files"
chown 0:0 /data/snusnu_root "$WATCHDOGDIR" "$SNS" "$SNS/magisk" /data/securedStorageLocation/w
chmod 0700 "$SNS" "$SNS/magisk" /data/securedStorageLocation/w
chmod 0755 /data/snusnu_root "$WATCHDOGDIR"
chown 1000:1000 /data/cache/snusnu
chmod 0700 /data/cache/snusnu
chown 0:0 "$STATE"
chmod 0777 "$STATE"
chown "$ACTOR_UID:$ACTOR_UID" "$PRIV/files"
chmod 0700 "$PRIV/files"

# Generate a 256-bit secret on-device; NEVER copy it through an adb readback or log.
dd if=/dev/urandom bs=32 count=1 2>/dev/null | toybox od -An -tx1 | tr -d ' \n' > "$AUTH"
[ "$(wc -c < "$AUTH" | tr -d ' ')" = 64 ] || fail "random token failed"
chown 0:1000 "$AUTH"
chmod 0640 "$AUTH"
cp "$AUTH" "$PRIV/files/channel-auth"
chown "$ACTOR_UID:$ACTOR_UID" "$PRIV/files/channel-auth"
chmod 0600 "$PRIV/files/channel-auth"
chcon u:object_r:cache_file:s0 "$AUTH" || fail "token label"
restorecon -R "$PRIV/files" >/dev/null 2>&1 || fail "app token relabel"
APP_CTX=$(ls -ldZ "$PRIV" | awk '{print $5}')
case "$APP_CTX" in u:object_r:app_data_file:s0:*) :;; *) fail "app security context not recognized";; esac
chcon "$APP_CTX" "$PRIV/files" "$PRIV/files/channel-auth" || fail "app token MCS categories"

# Replace only /data files. Never flash boot/system/vendor/recovery.
install_exec() {
  src="$1"; dst="$2"; mode="$3"; owner="$4"; group="$5"; label="$6"
  cp "$SRC/$src" "$dst.new" || fail "copy $src"
  chown "$owner:$group" "$dst.new" || fail "ownership $dst"
  chmod "$mode" "$dst.new" || fail "mode $dst"
  chcon "u:object_r:$label:s0" "$dst.new" || fail "label $dst"
  mv -f "$dst.new" "$dst" || fail "atomic rename $dst"
}
install_exec carrier "$CARRIER" 0750 0 1000 system_data_file
install_exec watchdog.sh "$WATCHDOGDIR/watchdog.sh" 0755 0 0 system_data_file
install_exec system-channel-gate.sh "$WATCHDOGDIR/system-channel-gate.sh" 0755 0 0 system_data_file
install_exec snusnu-boot-witness.sh "$WATCHDOGDIR/snusnu-boot-witness.sh" 0500 0 0 system_data_file
install_exec snusnu-launch.sh "$WATCHDOGDIR/snusnu-launch.sh" 0755 0 0 system_data_file
install_exec boot-entry.sh /data/securedStorageLocation/w/b 0644 0 0 shell_exec
install_exec waiter.sh "$SNS/waiter.sh" 0755 0 0 shell_exec
install_exec magisk_restore.sh "$SNS/magisk_restore.sh" 0755 0 0 assetstorage_data_file
install_exec magisk "$SNS/magisk/magisk" 0755 0 0 assetstorage_data_file
install_exec magiskpolicy "$SNS/magisk/magiskpolicy" 0755 0 0 assetstorage_data_file
install_exec stub.apk "$SNS/magisk/stub.apk" 0644 0 0 assetstorage_data_file
# Disable stray old artifacts left by previous proof of concept, if any.
rm -f "$SNS/disable" /data/cache/snusnu/disable "$STATE/watchdog.sh"

# Gate prevents OTA/kernel drift from launching a stale write payload.
printf 'ps=PS7331.4463N\nincremental=0031575863172\ncarrier_sha=%s\n' "$EXPECTED_CARRIER" > "$GUARD"
chown 0:1000 "$GUARD"
chmod 0640 "$GUARD"
chcon u:object_r:cache_file:s0 "$GUARD"
[ "$(toybox sha256sum "$CARRIER" | cut -d' ' -f1)" = "$EXPECTED_CARRIER" ] || fail "installed carrier mismatch"
# Ensure expected gate and modes are visible. Never print the token.
[ -x "$WATCHDOGDIR/system-channel-gate.sh" ] || fail "auth wrapper non-executable"
[ -x "$SNS/magisk_restore.sh" ] || fail "restore script non-executable"
[ "$(stat -c %a "$AUTH")" = 640 ] || fail "system token mode"
[ "$(stat -c %a "$PRIV/files/channel-auth")" = 600 ] || fail "actor token mode"
[ "$(stat -c %u "$PRIV/files/channel-auth")" = "$ACTOR_UID" ] || fail "app token owner"
[ "$(stat -c %a /data/cache/snusnu)" = 700 ] || fail "token parent mode"
# Do not arm! Only the host executes that final step after validation.
sync
echo 'STAGED_4463_HARDENED_OK (persistence still disabled)'
