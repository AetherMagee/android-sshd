#!/system/bin/sh
# Keeps /data/adb/sshd (keys, settings, host key). To wipe it: rm -rf /data/adb/sshd
/data/adb/modules/android-sshd/system/bin/sshd.service stop
# Root managers run this early in boot, before the package manager is up.
(
	until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 1; done
	pm uninstall io.github.aethermagee.sshd >/dev/null 2>&1
) &
