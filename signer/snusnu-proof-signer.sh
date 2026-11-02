#!/system/bin/sh
# Production proof-signer launcher (design doc
# FIREHD10_JOURNAL_BOOTSTRAP_AND_PROOF_CUSTODY_DESIGN_20261101.md section 2).
#
# Installed, together with stage4-device-signer.dex, at
#   /data/snusnu_root/signer/snusnu-proof-signer.sh   (root:root 0500)
# inside the root-owned 0700 custody directory. Never install this under
# /data/securedStorageLocation: its UID1000-owned ancestors allow the whole
# tree to be swapped out (design section 2.2).
#
# The signer measures every fact it signs about itself (design section
# 2.4), so this launcher only has to put the dex on the classpath and hand
# over argv unchanged. Modes:
#   keygen <pubOut.der> | report | sign-proof <bootId> <challengeHex> |
#   sign-proof-request | sign-genesis <challengeHex>
set -u
DIR=${0%/*}
[ "$DIR" = "$0" ] && DIR=.
DEX="$DIR/stage4-device-signer.dex"
if [ ! -f "$DEX" ]; then
    echo "signer dex missing: $DEX" >&2
    exit 2
fi
CLASSPATH="$DEX" exec /system/bin/app_process "$DIR" Stage4DeviceSigner "$@"
