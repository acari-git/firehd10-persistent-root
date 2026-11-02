#!/system/bin/sh
# Magisk service.d launcher for the unattended signer completion
# worker (2026-11-02). Run only from a Magisk-owned root process.
# Starts the worker detached and exits immediately; the worker
# itself waits for the restore chain's completion marker for
# this boot before doing anything. Design:
# FIREHD10_SIGNER_AUTO_COMPLETION_DESIGN_20261102.md.
#
# Installed at /data/adb/service.d/snusnu-completion.sh
# (root:root 0755). Worker source of truth:
# build/journal-gated-implementation-20261101/v2/stage4-persistent/
# snusnu-completion-service.sh (diagnostics project).

(
    umask 077
    /system/bin/sh /data/snusnu_root/bin/snusnu-completion.sh run
) </dev/null >/dev/null 2>&1 &
exit 0
