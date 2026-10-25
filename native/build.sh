#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/native/work/build"
PLIST="$ROOT/native/Resources/Info.plist"
NAME="$(plutil -extract CFBundleName raw -o - "$PLIST")"
EXECUTABLE="$(plutil -extract CFBundleExecutable raw -o - "$PLIST")"
APP="$ROOT/dist/$NAME.app"
mkdir -p "$BUILD" "$APP/Contents/MacOS" "$APP/Contents/Resources"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
for ARCH in arm64 x86_64; do
  xcrun swiftc -swift-version 5 -O -parse-as-library -target "$ARCH-apple-macos13.0" -sdk "$SDK" \
    "$ROOT"/native/Sources/{Models,Catalog,Lockfiles,Inventory,Advisories,Commands,Feeds,App}.swift \
    -o "$BUILD/$EXECUTABLE-$ARCH"
done
xcrun lipo -create "$BUILD/$EXECUTABLE-arm64" "$BUILD/$EXECUTABLE-x86_64" -output "$APP/Contents/MacOS/$EXECUTABLE"
cp "$PLIST" "$APP/Contents/Info.plist"
if [ -f "$ROOT/native/Resources/AppIcon.icns" ]; then cp "$ROOT/native/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"; fi
if [ -n "${SIGN_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP"
else
  codesign --force --sign - "$APP"
fi
codesign --verify --strict --verbose=2 "$APP"
printf '%s\n' "$APP"
