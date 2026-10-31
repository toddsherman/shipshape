#!/bin/bash
# Opens a copy of Shipshape on made-up findings, to see how the interface looks in different situations.
#   bash native/scenario.sh           lists the scenarios
#   bash native/scenario.sh malware         opens one; run it again with another name to switch
#   bash native/scenario.sh malware light   opens it in light mode, whatever this Mac's appearance; without "light"
#                                           it follows the Mac
# The copy is "Shipshape Dev", with an orange icon and its own bundle ID, settings and data folder, and checks turned
# off, so it never scans this Mac or replaces the scenario's findings. Each run starts from the scenario's original
# data; its Scenarios menu (and the menu bar panel) switches between scenarios without relaunching.
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
if [ ! -x "$BINARY" ] || [ -n "$(find "$SOURCES" "$ROOT/native/Resources" "$ROOT/native/make-icon.swift" -newer "$BINARY" -print -quit)" ]; then
  SPARKLE="$(bash "$ROOT/native/sparkle.sh")"
  rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Frameworks"
  xcrun swiftc -swift-version 5 -O -parse-as-library -target "$(uname -m)-apple-macos13.0" \
    -F "$SPARKLE" -framework Sparkle -Xlinker -rpath -Xlinker @executable_path/../Frameworks \
    "$SOURCES"/{Models,Catalog,Lockfiles,Inventory,Advisories,Commands,Feeds,Updates,Lookout,App}.swift -o "$BINARY"
  cp "$ROOT/native/Resources/Info.plist" "$APP/Contents/Info.plist"
  xcrun swift "$ROOT/native/make-icon.swift" "$ROOT" dev
  iconutil -c icns "$ROOT/native/work/AppIcon-Dev.iconset" -o "$APP/Contents/Resources/AppIcon.icns"
  plutil -replace CFBundleIdentifier -string sh.todd.security-monitor.dev "$APP/Contents/Info.plist"
  plutil -replace CFBundleName -string "Shipshape Dev" "$APP/Contents/Info.plist"
  plutil -replace CFBundleDisplayName -string "Shipshape Dev" "$APP/Contents/Info.plist"
  plutil -remove SUFeedURL "$APP/Contents/Info.plist"
  FRAMEWORK="$APP/Contents/Frameworks/Sparkle.framework"
  ditto "$SPARKLE/Sparkle.framework" "$FRAMEWORK"
  rm -rf "$FRAMEWORK/XPCServices" "$FRAMEWORK/Versions/B/XPCServices"
  for item in "$FRAMEWORK/Versions/B/Autoupdate" "$FRAMEWORK/Versions/B/Updater.app" "$FRAMEWORK" "$APP"; do codesign --force --sign - "$item" 2>/dev/null; done
fi

STATE="$WORK/run/$NAME"
rm -rf "$STATE"; mkdir -p "$STATE"
cp "$WORK/states/$NAME/state.json" "$STATE/state.json"
# Quit a running copy the normal way first; a copy killed outright may come back without its window.
if pgrep -f "$APP/Contents/MacOS/Shipshape" >/dev/null; then
  osascript -e 'tell application id "sh.todd.security-monitor.dev" to quit' >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -f "$APP/Contents/MacOS/Shipshape" >/dev/null || break; sleep 0.5; done
  pkill -f "$APP/Contents/MacOS/Shipshape" 2>/dev/null && sleep 1 || true
fi
# The dev copy's own setting (its bundle ID's defaults), the same one apps use to opt out of dark mode.
if [ "${2:-}" = light ]; then defaults write sh.todd.security-monitor.dev NSRequiresAquaSystemAppearance -bool true
else defaults delete sh.todd.security-monitor.dev NSRequiresAquaSystemAppearance 2>/dev/null || true; fi
open -n --env SHIPSHAPE_STATE_DIR="$STATE" --env SHIPSHAPE_NO_CHECKS=1 --env SHIPSHAPE_SCENARIOS="$WORK/states" --env SHIPSHAPE_SCENARIO="$NAME" "$APP"
# Opening it again once it's running brings its window forward, in case it came up without one.
sleep 2; open "$APP"
printf 'Opened the %s scenario in Shipshape Dev%s.\n' "$NAME" "$([ "${2:-}" = light ] && echo ' in light mode')"
