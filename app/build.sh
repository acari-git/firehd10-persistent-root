#!/bin/sh
# Build the patched SnuSnuRoot persistence APK.
#
# Forked from SnuSnuRoot (GPL-3.0) poc/snusnu-persist-app/build.sh. See NOTICE.
# The only source change is STATE_DIR in PersistenceService.java; its comment
# records the measurement that motivates it.
#
#   sh build.sh
#
# Output: app/build/snusnu-persistence.apk, signed with upstream's public debug
# keystore so it stays upgrade-compatible with the checked-in APK (pm install -r
# succeeds without an uninstall).
set -eu

app_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$app_dir/../.." && pwd)

# SDK discovery: SNUSNU_SDK wins, then the usual environment variables, then the
# two locations this repo has been built from.
sdk="${SNUSNU_SDK:-${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}}"
if [ -z "$sdk" ] || [ ! -d "$sdk" ]; then
    for candidate in "$HOME/Android/Sdk" "$HOME/android-sdk"; do
        [ -d "$candidate" ] && { sdk="$candidate"; break; }
    done
fi
[ -d "$sdk" ] || { echo "no Android SDK; set SNUSNU_SDK" >&2; exit 1; }

build_tools=$(ls -d "$sdk"/build-tools/* 2>/dev/null | sort -V | tail -1)
android_jar=$(ls -d "$sdk"/platforms/*/android.jar 2>/dev/null | sort -V | tail -1)
[ -n "$build_tools" ] && [ -n "$android_jar" ] || {
    echo "SDK at $sdk has no build-tools or platform android.jar" >&2; exit 1; }

# Windows SDK ships these as .bat/.exe; POSIX SDKs ship bare names.
tool() {
    for candidate in "$build_tools/$1" "$build_tools/$1.bat" "$build_tools/$1.exe"; do
        [ -f "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
    done
    echo "missing SDK tool: $1" >&2
    return 1
}
d8=$(tool d8)
aapt2=$(tool aapt2)
apksigner=$(tool apksigner)

keystore="$repo_dir/refs/SnuSnuRoot/poc/snusnu-persist-app/signing/snusnu-debug.keystore"
[ -f "$keystore" ] || { echo "missing signing keystore: $keystore" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/classes" "$work/dex"

javac -source 8 -target 8 -nowarn -classpath "$android_jar" -d "$work/classes" \
    "$app_dir"/src/io/github/voidnullvalue/snusnuroot/persistence/*.java 2>"$work/javac.log" \
    || { cat "$work/javac.log" >&2; exit 1; }
jar cf "$work/classes.jar" -C "$work/classes" .

"$d8" --min-api 28 --output "$work/dex" "$work/classes.jar"
"$aapt2" link -o "$work/unsigned.apk" -I "$android_jar" \
    --manifest "$app_dir/AndroidManifest.xml" --min-sdk-version 28 --target-sdk-version 28
jar uf "$work/unsigned.apk" -C "$work/dex" classes.dex

mkdir -p "$app_dir/build"
"$apksigner" sign --min-sdk-version 28 --v1-signing-enabled true \
    --v2-signing-enabled true --v3-signing-enabled false \
    --ks "$keystore" --ks-pass pass:android --key-pass pass:android \
    --out "$app_dir/build/snusnu-persistence.apk" "$work/unsigned.apk"
"$apksigner" verify --print-certs "$app_dir/build/snusnu-persistence.apk"
echo "built: $app_dir/build/snusnu-persistence.apk"
echo "run 'python stage4-persistent/preflight.py' to confirm the STATE_DIR patch is in the dex"
