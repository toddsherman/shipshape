#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/native/work/build"
PLIST="$ROOT/native/Resources/Info.plist"
NAME="$(plutil -extract CFBundleName raw -o - "$PLIST")"
EXECUTABLE="$(plutil -extract CFBundleExecutable raw -o - "$PLIST")"
APP="$ROOT/dist/$NAME.app"
# A release must carry the public half of the update signing key, or installed copies couldn't verify updates.
if [ -n "${SIGN_IDENTITY:-}" ] && ! plutil -extract SUPublicEDKey raw -o - "$PLIST" >/dev/null 2>&1; then
  printf '%s\n' 'Info.plist has no SUPublicEDKey. Run native/setup-update-key.command first.' >&2
  exit 1
fi
SPARKLE="$(bash "$ROOT/native/sparkle.sh")"
mkdir -p "$BUILD" "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Frameworks"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
for ARCH in arm64 x86_64; do
  xcrun swiftc -swift-version 5 -O -parse-as-library -target "$ARCH-apple-macos13.0" -sdk "$SDK" \
    -F "$SPARKLE" -framework Sparkle -Xlinker -rpath -Xlinker @executable_path/../Frameworks \
    "$ROOT"/native/Sources/{Models,Catalog,Lockfiles,Inventory,Advisories,Commands,Feeds,Updates,Lookout,App}.swift \
    -o "$BUILD/$EXECUTABLE-$ARCH"
done
xcrun lipo -create "$BUILD/$EXECUTABLE-arm64" "$BUILD/$EXECUTABLE-x86_64" -output "$APP/Contents/MacOS/$EXECUTABLE"
cp "$PLIST" "$APP/Contents/Info.plist"
if [ -f "$ROOT/native/Resources/AppIcon.icns" ]; then cp "$ROOT/native/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"; fi
# Sparkle installs Shipshape's own updates. Shipshape isn't sandboxed, so Sparkle's XPC services are never used.
FRAMEWORK="$APP/Contents/Frameworks/Sparkle.framework"
rm -rf "$FRAMEWORK"
ditto "$SPARKLE/Sparkle.framework" "$FRAMEWORK"
rm -rf "$FRAMEWORK/XPCServices" "$FRAMEWORK/Versions/B/XPCServices"
# Sparkle's helpers are signed inside out, without --deep, as its documentation describes.
if [ -n "${SIGN_IDENTITY:-}" ]; then
  SIGN=(codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY")
else
  SIGN=(codesign --force --sign -)
fi
"${SIGN[@]}" "$FRAMEWORK/Versions/B/Autoupdate"
"${SIGN[@]}" "$FRAMEWORK/Versions/B/Updater.app"
"${SIGN[@]}" "$FRAMEWORK"
"${SIGN[@]}" "$APP"
codesign --verify --strict --verbose=2 "$APP"
printf '%s\n' "$APP"
