#!/system/bin/sh
# inotifyd callback: $1 = event (n created, d deleted), $2 = dir, $3 = file
[ "$3" = disable ] || exit 0
case "$1" in
n) /data/adb/modules/android-sshd/system/bin/sshd.service stop ;;
d) /data/adb/modules/android-sshd/system/bin/sshd.service start ;;
esac
