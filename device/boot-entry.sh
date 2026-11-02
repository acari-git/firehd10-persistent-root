# Adopted from SnuSnuRoot (GPL-3.0) -- scripts/snusnu_boot_entry.sh
# https://github.com/voidnullvalue/SnuSnuRoot
# Copied verbatim apart from line-ending normalisation. See NOTICE.
#!/system/bin/sh

SNS=/data/securedStorageLocation/snusnu
DISABLE_SENTINEL="$SNS/disable"

log -t REROOTWAIT "started uid=$(id -u) ctx=$(cat /proc/self/attr/current)"
if [ -e "$DISABLE_SENTINEL" ]; then
    log -t REROOTWAIT "disabled by sentinel"
    exit 0
fi

/system/bin/sh "$SNS/waiter.sh"
rc=$?
log -t REROOTWAIT "waiter.sh rc=$rc"
exit "$rc"
