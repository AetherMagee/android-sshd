#!/system/bin/sh
# shellcheck disable=SC2034
SKIPUNZIP=0

DATA=/data/adb/sshd
PKG=io.github.aethermagee.sshd

[ "$ARCH" = arm64 ] || abort "! Only arm64 is supported (got $ARCH)"
[ "$BOOTMODE" = true ] || abort "! Install from Magisk, KernelSU or APatch, not recovery"

set_perm_recursive "$MODPATH/system/bin" 0 0 0755 0755
set_perm_recursive "$MODPATH/scripts" 0 0 0755 0755
set_perm "$MODPATH/action.sh" 0 0 0755

mkdir -p "$DATA"
chmod 700 "$DATA"
for f in sshd.conf authorized_keys; do
	if [ -f "$DATA/$f" ]; then
		ui_print "- Keeping existing $DATA/$f"
	else
		mv "$MODPATH/$f" "$DATA/$f"
		chmod 600 "$DATA/$f"
	fi
	rm -f "$MODPATH/$f"
done

ui_print "- Installing the approval app"
TMP=/data/local/tmp/android-sshd.apk
cp "$MODPATH/app.apk" "$TMP" && chmod 644 "$TMP"
# Each build has its own signing key; reinstall when the signature changed.
if ! pm install -r "$TMP" >/dev/null 2>&1; then
	pm uninstall "$PKG" >/dev/null 2>&1
	pm install "$TMP" >/dev/null 2>&1 || ui_print "! App install failed: logins that need approval will be denied"
fi
rm -f "$TMP" "$MODPATH/app.apk"
pm grant "$PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null

# (Re)start from the staged module so it works before the first reboot.
ui_print "- Starting android-sshd"
"$MODPATH/system/bin/sshd.service" restart 2>&1 | while read -r l; do ui_print "  $l"; done

ui_print ""
ui_print "- Add your public key to $DATA/authorized_keys"
ui_print "- Service:  su -c 'sshd.service {start|stop|restart|status|log}'"
ui_print "- Settings: $DATA/sshd.conf"
