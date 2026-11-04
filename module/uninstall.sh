#!/system/bin/sh
# Keeps /data/adb/sshd (keys, settings, host key). To wipe it: rm -rf /data/adb/sshd
/data/adb/modules/android-sshd/system/bin/sshd.service stop
pm uninstall io.github.aethermagee.sshd >/dev/null 2>&1
