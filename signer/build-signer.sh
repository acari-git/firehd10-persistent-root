#!/bin/sh
# Build the production device proof signer (design doc section 2).
#
# Outputs, under device-signer/build/:
#   stage4-device-signer-host.jar  - host JVM build (used by host tests)
#   stage4-device-signer.dex       - the on-device artifact run through
#                                    snusnu-proof-signer.sh / app_process
# The signer source uses only Java SE APIs available on Android 9
# (API 28), so one source produces both artifacts.
set -eu
cd "$(dirname "$0")"
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@17}"
export PATH="$JAVA_HOME/bin:$PATH"
sdk="${SNUSNU_SDK:-/opt/homebrew/share/android-commandlinetools}"
build_tools=$(ls -d "$sdk"/build-tools/* 2>/dev/null | sort -V | tail -1)
[ -n "$build_tools" ] || { echo "no Android build-tools under $sdk" >&2; exit 1; }

mkdir -p build/classes
javac --release 8 -nowarn -encoding UTF-8 -d build/classes \
    src/Stage4DeviceSigner.java
jar cf build/stage4-device-signer-host.jar -C build/classes .
mkdir -p build/dex-tmp
"$build_tools/d8" --min-api 28 --output build/dex-tmp \
    build/stage4-device-signer-host.jar
mv build/dex-tmp/classes.dex build/stage4-device-signer.dex
rmdir build/dex-tmp

# Smoke check: a bare invocation must print usage and exit 2.
if java -cp build/classes Stage4DeviceSigner >/dev/null 2>&1; then
    echo "smoke check failed: usage exit code expected" >&2
    exit 1
fi
shasum -a 256 build/stage4-device-signer.dex \
    build/stage4-device-signer-host.jar src/Stage4DeviceSigner.java
echo "built: build/stage4-device-signer.dex"
