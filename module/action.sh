#!/system/bin/sh
# Root manager "Action" button: restart the daemon and show the log.
/data/adb/modules/android-sshd/system/bin/sshd.service restart
echo
tail -n 20 /data/adb/sshd/sshd.log
