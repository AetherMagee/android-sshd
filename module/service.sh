#!/system/bin/sh
MODDIR=${0%/*}

until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 1; done

"$MODDIR/system/bin/sshd.service" start

# Stop/start live when the module is toggled in the root manager.
# (Managers skip service.sh for modules disabled at boot, so re-enabling those needs a reboot.)
inotifyd "$MODDIR/scripts/on-toggle.sh" "$MODDIR:nd" >/dev/null 2>&1 &
