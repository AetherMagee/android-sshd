#!/usr/bin/env bash
# Builds the module zip: sshd/ (Go) + app/ (companion APK) + module/ -> dist/android-sshd-v<VERSION>.zip
#
# Needs Go, a JDK and the Android SDK (build-tools + a platform; $ANDROID_HOME or ~/Android/Sdk).
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

echo "==> android-sshd $VERSION ($VERSION_CODE)"
rm -rf "$WORK" && mkdir -p "$WORK" "$DIST"

cd "$ROOT/sshd"
if [ -z "${SKIP_TESTS:-}" ]; then
	echo "==> testing sshd"
	go test ./...
fi
echo "==> building sshd linux/arm64"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "$WORK/android-sshd" .

echo "==> building app ($(basename "$BT"), $(basename "$(dirname "$JAR")"))"
APP="$WORK/app"
mkdir -p "$APP/classes" "$APP/dex"
"$BT/aapt2" link -I "$JAR" --manifest "$ROOT/app/AndroidManifest.xml" \
	--version-code "$VERSION_CODE" --version-name "$VERSION" -o "$APP/unsigned.apk"
find "$ROOT/app/src" -name '*.java' -exec javac -Xlint:-options --release 17 -classpath "$JAR" -d "$APP/classes" {} +
find "$APP/classes" -name '*.class' -exec "$BT/d8" --release --min-api 26 --lib "$JAR" --output "$APP/dex" {} +
(cd "$APP/dex" && zip -qj "$APP/unsigned.apk" classes.dex)
"$BT/zipalign" -f 4 "$APP/unsigned.apk" "$APP/aligned.apk"
# Throwaway key per build: the app is stateless, and customize.sh reinstalls
# it when the signature changes. Nothing to keep secret.
keytool -genkeypair -keystore "$APP/key.jks" -storepass android -alias app -keyalg EC \
	-dname CN=android-sshd -validity 10000 >/dev/null 2>&1
"$BT/apksigner" sign --ks "$APP/key.jks" --ks-pass pass:android --out "$APP/app.apk" "$APP/aligned.apk"

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
