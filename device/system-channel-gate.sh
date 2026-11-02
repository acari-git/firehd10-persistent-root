#!/system/bin/sh
# Authenticate localhost:4321 before executing anything with system uid.
# /data/cache/snusnu/channel-auth: mode 0640, root:system, parent 0700 system.
# The Android actor reads its own matching device-protected private copy.
# Other apps cannot read either copy under normal DAC rules.
AUTH=/data/cache/snusnu/channel-auth
# Fail closed on a missing/disabled persistence setting, even with a valid
# token. A system-UID listener left alive after fail-safe disarm must not
# continue accepting privileged shells. Check again immediately before exec:
# persistence can be disabled while the client is authenticating.
persistence_enabled() {
    [ "$(settings get global snusnu_persist_enabled 2>/dev/null)" = 1 ]
}
persistence_enabled || exit 1
[ -r "$AUTH" ] || exit 1
IFS= read -r supplied || exit 1
expected=$(cat "$AUTH" 2>/dev/null) || exit 1
[ -n "$expected" ] && [ "$supplied" = "$expected" ] || exit 1
unset supplied expected
persistence_enabled || exit 1
exec /system/bin/sh
