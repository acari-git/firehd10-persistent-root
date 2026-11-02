#!/bin/sh
# Build the v2 (genesis/bootstrap-capable) journal-gated persistence APK.
#
# Usage: sh build-v2.sh [public.der] [key-label]
#
# Defaults pin the labeled HOST TEST key in proof-key/. A genesis session
# passes the device-generated public key DER and a device label instead
# (see FIREHD10_ROOT_REACQUISITION_RUNBOOK_ADDENDUM_20261101.md, Phase G).
# The build itself is October's stage4-persistent/app/build.sh, unchanged;
# this wrapper only regenerates Stage4PinnedProofKey.java first.
set -eu
cd "$(dirname "$0")"
der="${1:-proof-key/test-public.der}"
label="${2:-HOST TEST KEY - NOT THE DEVICE KEY}"
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@17}"
export PATH="$JAVA_HOME/bin:$PATH"
python3 gen_pinned_key.py "$der" "$label" \
  stage4-persistent/app/src/io/github/voidnullvalue/snusnuroot/persistence/Stage4PinnedProofKey.java
cd stage4-persistent/app
SNUSNU_SDK="${SNUSNU_SDK:-/opt/homebrew/share/android-commandlinetools}" \
  sh build.sh
