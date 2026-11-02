#!/system/bin/sh
# install-completion-device.sh -- device-side installer for the
# unattended signer-completion feature (2026-11-02).
#
# Run as root (magisk context) on the device, with the two build
# artifacts staged in $1 (default /data/local/tmp/snu-completion):
#   snusnu-completion.sh          (worker)
#   snusnu-completion-service.sh  (service.d launcher)
#
# Verifies the sha256 of each staged file against the values
# pinned at build time, installs to:
#   /data/snusnu_root/bin/snusnu-completion.sh   root:root 0500
#   /data/adb/service.d/snusnu-completion.sh     root:root 0755
# labels copied from the established siblings (witness writer in
# bin/, stage4-enforcing in service.d/), then reads back and
# re-verifies hashes. Fails closed: any mismatch aborts before
# the next step. Installs files only; starts nothing; the worker
# first runs at the next boot via service.d.
#
# Design: FIREHD10_SIGNER_AUTO_COMPLETION_DESIGN_20261102.md.
# Manifest: signer-autocompletion/manifest-signer-autocompletion.json

set -u

STAGE=${1:-/data/local/tmp/snu-completion}
WORKER_SHA=6b8232a990192ccab98d611207899b898c30d7c0af6b1727a5df5b32ace2e221
LAUNCHER_SHA=af696c048217994b072494e4607871c143540e73422006a80948bb99bb6bae46
BIN_DIR=/data/snusnu_root/bin
SVC_DIR=/data/adb/service.d

die() { echo "INSTALL_COMPLETION ABORT: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "must run as root"
[ -d "$STAGE" ] || die "stage dir missing: $STAGE"
[ -d "$BIN_DIR" ] || die "bin dir missing: $BIN_DIR"
[ -d "$SVC_DIR" ] || die "service.d dir missing: $SVC_DIR"

sha_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
label_of() { ls -Z "$1" 2>/dev/null | awk '{print $1}'; }

install_one() {
    src=$1; want=$2; dst=$3; mode=$4; sibling=$5
    [ -f "$src" ] || die "staged file missing: $src"
    got=$(sha_of "$src")
    [ "$got" = "$want" ] || die "staged hash mismatch for $src: $got"
    cp "$src" "$dst" || die "copy failed: $dst"
    chown root:root "$dst" || die "chown failed: $dst"
    chmod "$mode" "$dst" || die "chmod failed: $dst"
    lbl=$(label_of "$sibling")
    case "$lbl" in
        u:object_r:*) chcon "$lbl" "$dst" || die "chcon failed: $dst" ;;
        *) die "sibling label unreadable: $sibling" ;;
    esac
    got=$(sha_of "$dst")
    [ "$got" = "$want" ] || die "installed hash mismatch for $dst: $got"
    echo "INSTALLED $dst sha256=$got mode=$mode label=$(label_of "$dst")"
}

install_one "$STAGE/snusnu-completion.sh" "$WORKER_SHA" \
    "$BIN_DIR/snusnu-completion.sh" 0500 "$BIN_DIR/snusnu-boot-witness.sh"
install_one "$STAGE/snusnu-completion-service.sh" "$LAUNCHER_SHA" \
    "$SVC_DIR/snusnu-completion.sh" 0755 "$SVC_DIR/stage4-enforcing.sh"

echo "INSTALL_COMPLETION OK"
exit 0
