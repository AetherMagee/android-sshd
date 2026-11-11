#!/usr/bin/env bash
# Builds the module zip: sshd/ (Go) + app/ (companion APK) + module/ -> dist/android-sshd-v<VERSION>.zip
#
# Needs Go, a JDK and the Android SDK (build-tools, a platform, the NDK; $ANDROID_HOME or ~/Android/Sdk).
# Env: SKIP_TESTS=1 to skip the Go tests
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
WORK="$ROOT/.work"
DIST="$ROOT/dist"
VERSION="v$(cat "$ROOT/VERSION")"
# 0.1.2 -> 102
IFS=. read -r MAJ MIN PAT <"$ROOT/VERSION"
VERSION_CODE=$((MAJ * 10000 + MIN * 100 + PAT))

SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
# Newest build-tools and platform.
BT=$(printf '%s\n' "$SDK"/build-tools/* | sort -V | tail -n 1)
JAR=$(printf '%s\n' "$SDK"/platforms/android-* | sort -V | tail -n 1)/android.jar
NDK="${ANDROID_NDK_HOME:-$(printf '%s\n' "$SDK"/ndk/* | sort -V | tail -n 1)}"

echo "==> android-sshd $VERSION ($VERSION_CODE)"
rm -rf "$WORK" && mkdir -p "$WORK" "$DIST"

cd "$ROOT/sshd"
if [ -z "${SKIP_TESTS:-}" ]; then
	echo "==> testing sshd"
	go test ./...
fi
echo "==> building sshd android/arm64"
# cgo against bionic: DNS lookups (ssh -L to a hostname) go through Android's resolver;
# Go's own resolver needs /etc/resolv.conf, which Android doesn't have.
CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang" \
	go build -trimpath -ldflags="-s -w" -o "$WORK/android-sshd" .

echo "==> building app ($(basename "$BT"), $(basename "$(dirname "$JAR")"))"
APP="$WORK/app"
mkdir -p "$APP/classes" "$APP/dex"
"$BT/aapt2" link -I "$JAR" --manifest "$ROOT/app/AndroidManifest.xml" \
	--version-code "$VERSION_CODE" --version-name "$VERSION" -o "$APP/unsigned.apk"
find "$ROOT/app/src" -name '*.java' -exec javac -Xlint:-options --release 17 -classpath "$JAR" -d "$APP/classes" {} +
find "$APP/classes" -name '*.class' -exec "$BT/d8" --release --min-api 26 --lib "$JAR" --output "$APP/dex" {} +
(cd "$APP/dex" && zip -qj "$APP/unsigned.apk" classes.dex)
"$BT/zipalign" -f 4 "$APP/unsigned.apk" "$APP/aligned.apk"
# Releases are signed with a stable secret key (CI: APP_KEYSTORE, base64 PKCS12 with
# password APP_KEYSTORE_PASS) so updates keep the app and its notification settings.
# Local builds get a throwaway key; customize.sh reinstalls when the key changes.
# The key must stay secret: it grants the permission that guards prompts.
if [ -n "${APP_KEYSTORE:-}" ]; then
	base64 -d <<<"$APP_KEYSTORE" >"$APP/key.p12"
	KS_PASS="env:APP_KEYSTORE_PASS"
else
	APP_KEYSTORE_PASS=$(head -c 18 /dev/urandom | base64)
	export APP_KEYSTORE_PASS
	keytool -genkeypair -keystore "$APP/key.p12" -storetype PKCS12 -storepass:env APP_KEYSTORE_PASS \
		-alias app -keyalg EC -dname CN=android-sshd -validity 10000 >/dev/null 2>&1
	KS_PASS="env:APP_KEYSTORE_PASS"
fi
"$BT/apksigner" sign --ks "$APP/key.p12" --ks-pass "$KS_PASS" --out "$APP/app.apk" "$APP/aligned.apk"
rm -f "$APP/key.p12"

echo "==> packaging"
STAGE="$WORK/module"
cp -r "$ROOT/module" "$STAGE"
mkdir -p "$STAGE/system/bin"
cp "$WORK/android-sshd" "$STAGE/system/bin/android-sshd"
cp "$APP/app.apk" "$STAGE/app.apk"
sed -i -e "s/^version=.*/version=$VERSION/" -e "s/^versionCode=.*/versionCode=$VERSION_CODE/" "$STAGE/module.prop"

ZIP="$DIST/android-sshd-$VERSION.zip"
rm -f "$ZIP"
(cd "$STAGE" && zip -qr9 "$ZIP" .)

# Consumed by CI.
cat >"$DIST/build.env" <<EOT
VERSION=$VERSION
VERSION_CODE=$VERSION_CODE
ZIP=$ZIP
EOT
echo "==> $ZIP"
