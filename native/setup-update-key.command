#!/bin/bash
set -euo pipefail

# Creates the key that signs Shipshape's updates, or reuses it if this Mac already has one, and puts its public
# half in Info.plist. The private key stays in your login Keychain under the account below.
ACCOUNT="${SPARKLE_KEY_ACCOUNT:-shipshape}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLIST="$ROOT/native/Resources/Info.plist"

printf '%s\n' \
  'Shipshape — update signing key setup' \
  '' \
  'Each release is signed with a private key kept in your login Keychain.' \
  'Installed copies of Shipshape only install updates signed with that key.' \
  'If macOS asks whether generate_keys may use your Keychain, allow it.' \
  ''

if [ ! -t 0 ]; then
  printf '%s\n' 'Run this setup interactively in Terminal.' >&2
  exit 2
fi

SPARKLE="$(bash "$ROOT/native/sparkle.sh")"
"$SPARKLE/bin/generate_keys" --account "$ACCOUNT" >/dev/null
KEY="$("$SPARKLE/bin/generate_keys" --account "$ACCOUNT" -p)"
if [ "$(printf '%s' "$KEY" | base64 -D 2>/dev/null | wc -c | tr -d ' ')" != 32 ]; then
  printf '%s\n' 'generate_keys did not return a public key. Nothing was changed.' >&2
  exit 1
fi

CURRENT="$(plutil -extract SUPublicEDKey raw -o - "$PLIST" 2>/dev/null || true)"
if [ -n "$CURRENT" ] && [ "$CURRENT" != "$KEY" ]; then
  printf '%s\n' \
    'Info.plist already holds a different public key, and released copies only trust that one.' \
    'Import its private key with generate_keys -f instead of replacing it. Nothing was changed.' >&2
  exit 1
fi
plutil -replace SUPublicEDKey -string "$KEY" "$PLIST"
printf '\n%s\n%s\n\n' "Public key: $KEY" 'Saved as SUPublicEDKey in native/Resources/Info.plist; commit that change.'

printf '%s\n' \
  'Back up the private key now. If it is lost, installed copies can never be updated again' \
  'and everyone would have to download the next release by hand.' \
  'The backup file holds the key itself: put its contents in your password manager, then delete the file.'
IFS= read -r -p 'Write a backup to your Desktop now? [y/N] ' ANSWER
if [ "$ANSWER" = y ] || [ "$ANSWER" = Y ]; then
  BACKUP="$HOME/Desktop/shipshape-update-key.txt"
  ( umask 077; "$SPARKLE/bin/generate_keys" --account "$ACCOUNT" -x "$BACKUP" )
  printf '%s\n' "Wrote $BACKUP. Store it in your password manager, then delete it."
fi
IFS= read -r -p 'Press Return to finish. ' FINISH
