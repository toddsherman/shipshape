# Contributing to Shipshape

Thanks for helping. The most useful contributions are:

- **Coverage:** software people install to build apps with AI coding tools that Shipshape doesn't recognize yet, new lockfile formats, and new install locations.
- **Accuracy:** findings that are wrong (false positives) and known fixes it misses (false negatives). Include the product, installed version, advisory ID and how it was installed.
- **Update routes:** better commands or links for installing a fix, for each way software can be installed.

Open an issue before starting anything large, so we can agree on the approach.

## Build and test

You need macOS 13 or later and Xcode (or a matching Swift toolchain and macOS SDK). The one third-party package is Sparkle, which installs Shipshape's own updates; the build downloads its pinned release once and checks the checksum.

```sh
bash native/test.sh                  # rule, parser, command and history tests
bash native/build.sh                 # ad-hoc signed dist/Shipshape.app, for local use only
```

To see how the interface looks in different situations without touching your Mac's results, open a scenario of made-up findings:

```sh
bash native/scenario.sh              # lists them: first-run, all-clear, waiting-only, typical, malware, exploited, everything, crowded, check-issues
bash native/scenario.sh malware      # opens one; run it again with another name to switch
```

It builds a copy called Shipshape Dev, with its own settings and data, and opens it with checks turned off, so it never scans your Mac or replaces the made-up findings. The scenarios are defined in `native/Tests/Scenarios.swift`.

Run your build with its own data folder, so it doesn't share saved results with an installed copy:

```sh
open -n --env SHIPSHAPE_STATE_DIR=/tmp/shipshape-dev dist/Shipshape.app
```

To scan from the command line with the same engine, pass an output file and any project folders:

```sh
xcrun swiftc -swift-version 5 -O -parse-as-library native/Sources/{Models,Catalog,Lockfiles,Inventory,Advisories,Commands,Feeds}.swift native/Tests/Check.swift -o native/work/check
native/work/check native/work/scan.json ~/Projects
```

## Adding software to the catalog

Add an entry to `native/Sources/Catalog.swift` with its bundle IDs, Homebrew formulae or casks, and one advisory source:
- an NVD CPE (`vendor:product`);
- an OSV package (`{major}` in a name follows the installed major version);
- the project's GitHub security advisories.

Check that the source actually has data for the product before adding it. Shipshape reports nothing for a CPE or package that doesn't exist, which looks like "safe." The [native README](native/README.md) explains how each source is matched.

If the app updates itself with Sparkle but sets its update feed in code instead of in its Info.plist (`SUFeedURL`), add its public appcast as `feed`, as Codex's entry does. Use an https feed anyone can read, never one that needs a per-install ID or account, and check that its newest item matches the newest release.

## Ground rules

These keep Shipshape trustworthy, so pull requests that break them won't be merged:

- **Never run anything.** The app shows commands for people to review and run. It doesn't execute them, install, remove or change software, or pipe downloads into a shell.
- **Quote and validate.** Every package name, version or path that appears in a command goes through the existing name checks and `Shell.quote`.
- **Fail closed.** If a source is missing or its format is unfamiliar, the check fails and says so. It never reports software as safe.
- **No secrets, no telemetry.** Don't read environment variables, keys or tokens (MCP settings are read for commands and arguments only), and don't add analytics or send inventory anywhere new. If a change sends new data to a service, document it in the README.
- **Tests with every rule change.** Add a case to `native/Tests/RulesTests.swift` for each parser, version rule or command change.
- **Match the surrounding code:** Swift 5 language mode, Foundation, SwiftUI and AppKit only, and the same naming and comment style.

## Privacy in issues and pull requests

Scan output lists your installed software, project folders and package names, which can include private project names. Before pasting it, remove anything you don't want public, and never include API keys, tokens or `.env` contents.

## Releases

Maintainers build, sign, notarize and publish releases; see the [native README](native/README.md#development). Contributors don't need an Apple Developer account.

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
