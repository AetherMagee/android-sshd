#!/system/bin/sh
# inotifyd callback: $1 = event (n created, d deleted), $2 = dir, $3 = file
# disable / remove: stop now; undoing either starts again unless the other still applies.
MOD=/data/adb/modules/android-sshd
case "$3" in disable | remove) ;; *) exit 0 ;; esac
case "$1" in
n) "$MOD/system/bin/sshd.service" stop ;;
d) [ -e "$MOD/disable" ] || [ -e "$MOD/remove" ] || "$MOD/system/bin/sshd.service" start ;;
esac
