#!/bin/bash
# Opens a copy of Shipshape on made-up findings, to see how the interface looks in different situations.
#   bash native/scenario.sh           lists the scenarios
#   bash native/scenario.sh malware   opens one; run it again with another name to switch
# The copy is "Shipshape Dev" (its own bundle ID, settings and data folder) with checks turned off, so it never
# scans this Mac or replaces the scenario's findings. Each run starts from the scenario's original data.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCES="$ROOT/native/Sources"
WORK="$ROOT/native/work/scenarios"
APP="$WORK/Shipshape Dev.app"
mkdir -p "$WORK"

xcrun swiftc -swift-version 5 -O -parse-as-library "$SOURCES"/{Models,Catalog,Lockfiles,Inventory,Advisories,Commands,Feeds}.swift "$ROOT/native/Tests/Scenarios.swift" -o "$WORK/scenarios"
LIST="$("$WORK/scenarios" "$WORK/states")"
if [ "$#" -eq 0 ]; then
  printf '%s\n\n%s\n' "$LIST" 'Open one with: bash native/scenario.sh NAME'
  exit 0
fi
NAME="$1"
if [ ! -f "$WORK/states/$NAME/state.json" ]; then
  printf 'No scenario named %s. These exist:\n%s\n' "$NAME" "$LIST" >&2
  exit 2
fi

# Rebuild the app only when a source file is newer than it. One architecture, signed ad hoc, for this Mac only.
BINARY="$APP/Contents/MacOS/Shipshape"
if [ ! -x "$BINARY" ] || [ -n "$(find "$SOURCES" "$ROOT/native/Resources" -newer "$BINARY" -print -quit)" ]; then
  SPARKLE="$(bash "$ROOT/native/sparkle.sh")"
  rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Frameworks"
  xcrun swiftc -swift-version 5 -O -parse-as-library -target "$(uname -m)-apple-macos13.0" \
    -F "$SPARKLE" -framework Sparkle -Xlinker -rpath -Xlinker @executable_path/../Frameworks \
    "$SOURCES"/{Models,Catalog,Lockfiles,Inventory,Advisories,Commands,Feeds,Updates,App}.swift -o "$BINARY"
  cp "$ROOT/native/Resources/Info.plist" "$APP/Contents/Info.plist"
  cp "$ROOT/native/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
  plutil -replace CFBundleIdentifier -string sh.todd.security-monitor.dev "$APP/Contents/Info.plist"
  plutil -remove SUFeedURL "$APP/Contents/Info.plist"
  FRAMEWORK="$APP/Contents/Frameworks/Sparkle.framework"
  ditto "$SPARKLE/Sparkle.framework" "$FRAMEWORK"
  rm -rf "$FRAMEWORK/XPCServices" "$FRAMEWORK/Versions/B/XPCServices"
  for item in "$FRAMEWORK/Versions/B/Autoupdate" "$FRAMEWORK/Versions/B/Updater.app" "$FRAMEWORK" "$APP"; do codesign --force --sign - "$item" 2>/dev/null; done
fi

STATE="$WORK/run/$NAME"
rm -rf "$STATE"; mkdir -p "$STATE"
cp "$WORK/states/$NAME/state.json" "$STATE/state.json"
pkill -f "$APP/Contents/MacOS/Shipshape" 2>/dev/null && sleep 1 || true
open -n --env SHIPSHAPE_STATE_DIR="$STATE" --env SHIPSHAPE_NO_CHECKS=1 "$APP"
printf 'Opened the %s scenario in Shipshape Dev.\n' "$NAME"
