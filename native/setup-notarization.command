#!/bin/bash
set -euo pipefail

# Maintainers: set DEVELOPER_TEAM to your Apple Developer team ID, or enter it when asked.
NOTARY_PROFILE="${NOTARY_PROFILE:-security-monitor-notary}"
DEVELOPER_TEAM="${DEVELOPER_TEAM:-}"

printf '%s\n' \
  'Shipshape — Apple notarization setup' \
  '' \
  '1. Open https://account.apple.com and sign in to your developer Apple Account.' \
  '2. Under Sign-In and Security > App-Specific Passwords, generate a password' \
  '   named Shipshape notarization.' \
  '3. Enter that same Apple Account email below.' \
  '' \
  'Apple will ask for the app-specific password in a hidden prompt.' \
  'Use the generated app-specific password, not your usual account password.' \
  'The password is stored by Apple in Keychain; this script does not read it.' \
  ''

if [ ! -t 0 ]; then
  printf '%s\n' 'Run this setup interactively in Terminal.' >&2
  exit 2
fi

if [ -z "$DEVELOPER_TEAM" ]; then IFS= read -r -p 'Apple Developer team ID: ' DEVELOPER_TEAM; fi
if [ -z "$DEVELOPER_TEAM" ]; then
  printf '%s\n' 'No team ID entered. Nothing was changed.'
  exit 2
fi

IFS= read -r -p 'Developer Apple Account email: ' NOTARY_APPLE_ACCOUNT
if [ -z "$NOTARY_APPLE_ACCOUNT" ]; then
  printf '%s\n' 'No email entered. Nothing was changed.'
  exit 2
fi

/usr/bin/xcrun notarytool store-credentials "$NOTARY_PROFILE" \
  --apple-id "$NOTARY_APPLE_ACCOUNT" \
  --team-id "$DEVELOPER_TEAM"

printf '\n%s\n' \
  'Credentials validated and saved in Keychain.' \
  "Next, run: bash native/notarize.sh $NOTARY_PROFILE" \
  'Never paste the password into chats, scripts or shell history.'
IFS= read -r -p 'Press Return to finish. ' NOTARY_FINISH
