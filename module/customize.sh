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
# Streamed from the module dir: no world-writable staging file to tamper with.
APK="$MODPATH/app.apk"
install_app() { pm install -r -S "$(stat -c %s "$APK")" <"$APK" 2>&1 | grep -q Success; }
if ! install_app; then
	# Signing key changed (e.g. a local build replacing a release): reinstall.
	pm uninstall "$PKG" >/dev/null 2>&1
	install_app || ui_print "! App install failed: logins that need approval will be denied"
fi
rm -f "$APK"
pm grant "$PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null

# (Re)start from the staged module so it works before the first reboot.
ui_print "- Starting android-sshd"
"$MODPATH/system/bin/sshd.service" restart 2>&1 | while read -r l; do ui_print "  $l"; done

ui_print ""
ui_print "- Add your public key to $DATA/authorized_keys"
ui_print "- Service:  su -c 'sshd.service {start|stop|restart|status|log}'"
ui_print "- Settings: $DATA/sshd.conf"
