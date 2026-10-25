# Shipshape for macOS — 0.3.0 preview

Shipshape was called Security Monitor before 0.3.0.

A native SwiftUI menu bar app for macOS 13 or later, built for Apple silicon and Intel. It watches the developer stack people install to build apps with AI coding tools such as Claude Code and Codex, and shows the easiest way to install each fix. No Python, Node, Homebrew, account or API key is needed to run it.

## Install and use

Copy **Shipshape.app** from the disk image into Applications and open it. Add the folders that hold your projects, run the first check, then enable notifications. Optionally turn on **Start Shipshape when I log in** in Settings. Each Mac builds its own inventory.

**Upgrading from Security Monitor:** quit Security Monitor, move it from Applications to the Trash, then install Shipshape. Both use the bundle identifier `sh.todd.security-monitor`, so notification permission carries over, and on first launch Shipshape moves the saved results and History from `Application Support/Security Monitor` to `Application Support/Shipshape`. If the old app is still in Applications, Shipshape says so. If Start at login was on, check that it still is in Settings, since the app's file name changed.

Release builds are Developer ID signed and notarized by Apple, with tickets stapled to the disk image and the app. Each release on GitHub includes `SHA256SUMS.txt` with the disk image's checksum. Never disable Gatekeeper to install or distribute a build.

A fresh check runs every time the app opens, including at login, once the network is up (after 30 seconds it checks anyway). Checks also run daily at 9 a.m. America/Los_Angeles while the app is open, and catch up after waking. **Check now** always runs a full check. A first check takes a few minutes because NVD limits requests without an API key; NVD results are reused for 20 hours. Quitting the app stops monitoring.

While the app is open it also refreshes every minute, so the lists change within a minute of updating, removing or adding software. A refresh reads this Mac and the project folders again but reuses advisory data it fetched recently: vendor pages, GitHub advisories, Homebrew metadata, CISA's catalog and Apple Software Update for an hour, OSV answers for each package version for six hours and OSV advisories for twelve. Newly installed versions are looked up straight away. Refreshes are quiet (no progress display), save only when something changed, and pause while a check is running, the Mac is offline or Low Power Mode is on. On this Mac a refresh of about 6,000 installations took under two seconds. Turn it off in Settings.

**History** logs every recommendation: when it was first found and, once a check no longer reports it, when it was resolved and how. "Updated to 9.0.2" means the same software is now at another version; "Removed" means an older Homebrew copy was cleaned up; "Removed from this Mac" or "from the project" means the software is gone; "Project folder no longer checked" means its folder was taken out of Settings; and "No longer reported" means the software is unchanged but the advisory no longer matches. A finding that comes back, or is still reported after a version change, starts a new entry. Findings kept as unverified after a failed check stay open. History is stored with the latest result in Application Support, keeps the newest 10,000 entries (dropping the oldest resolved ones first), and exports as CSV. The first launch of a version with History starts it from the last saved result.

Notifications are deduplicated by installation, version, fix version, advisory identifiers and known-exploitation status. Malicious packages get their own alert title. Failed source checks produce a separate alert and keep earlier findings visible as unverified.

## What it checks

| Area | Found from | Security source |
| --- | --- | --- |
| Project dependencies | package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, uv.lock, poetry.lock, pinned requirements.txt, Cargo.lock, Gemfile.lock and go.mod in chosen folders, up to five levels deep | OSV (npm, PyPI, crates.io, Go, RubyGems), including OpenSSF malicious-package reports |
| Global packages | npm (Homebrew, standard, nvm, fnm), Bun and pnpm globals, python.org/Homebrew/uv/pyenv site-packages, pipx and uv tools, the npx cache | OSV |
| MCP servers | Claude Code, Claude, Codex, Cursor, Windsurf, VS Code and Gemini CLI settings, plus project `.mcp.json` | OSV for pinned servers and npx-cached versions |
| AI coding tools | Claude Code (native, local or cask), Codex CLI, Gemini CLI, GitHub Copilot CLI (cask or native), OpenCode (Homebrew, desktop or native); Claude, Codex, ChatGPT, Cursor, Windsurf, VS Code, Zed, Ollama and LM Studio apps | OSV for the Claude Code, Codex, Gemini and Copilot npm packages; OpenCode's own GitHub advisories; NVD where a CPE exists |
| Runtimes | Node (standard, Homebrew, nvm, Volta, fnm), Bun, Deno, uv, Go (go.dev or Homebrew), python.org, Homebrew, uv and pyenv Pythons; Node, Python, Go, Ruby, Bun and Deno installed with mise; Rust, Ruby, PHP and OpenJDK from Homebrew | Vendor rules for Node and Bun; OSV for Go's standard library and uv; NVD for the rest |
| Homebrew | Every installed formula and cask, including retained older copies | Vendor rules for PostgreSQL (including the libpq client library) and OpenSSL; OSV for Docker Compose's Go module; NVD for catalog tools and libraries (curl, git, sqlite, libxml2, libpng and others) |
| Developer apps | Catalog apps in /Applications and ~/Applications: browsers, terminals, Docker, JetBrains IDEs, Postman, Tailscale and others | NVD where a CPE exists |
| Apple | Software Update, including Command Line Tools | Update eligibility only |

**Excluded by design:** Google Chrome, whether installed directly or with Homebrew, and every app installed from the Mac App Store. They update through Chrome's own updater and the App Store, and are skipped entirely: not listed, checked or counted as findings.

Versions are read by their first number, so an app that reports `Build 4215` compares as 4215. As a final check on every scan, an update is never offered when its version is the installed release written differently. Homebrew rebuilds such as 15.0.0 → 15.0.0_1 still count, and anything skipped is noted under Coverage.

CISA's Known Exploited Vulnerabilities catalog raises the priority of any finding whose CVE is listed. Homebrew's public metadata marks ordinary newer releases as updates, not security fixes. RustSec "unmaintained" notices are not reported as vulnerabilities.

NVD matching uses only explicit version ranges or exact versions on macOS-applicable configurations. Pre-release and unbounded "all versions" entries are ignored. NVD can lag vendor advisories, and Homebrew sometimes ships patches without changing a version, so NVD findings say so.

**No fix released yet.** Sometimes NVD lists no fixed version and the installed Homebrew copy is already Homebrew's newest release, so updating can't help. Those findings appear in their own group with no update command, and they don't count toward items needing attention or trigger alerts. They show the fix version when an advisory's text names one ("before 1.22.3"). When Homebrew ships a newer release, the finding becomes an ordinary one with its command, and the alert says **Fix now available**.

Vendor rules fail closed: a missing page or an unfamiliar format marks the check as failed instead of reporting software as safe. The one exception is a new OpenSSL release branch with no vulnerability page yet. It counts as having no published vulnerabilities, but only when OpenSSL's vulnerabilities index loads, links other branches and doesn't list that one.

To cover more software, add an entry to `native/Sources/Catalog.swift` with its bundle IDs, Homebrew formulae or casks, and one advisory source: an NVD CPE (`vendor:product`), an OSV package (`{major}` in a name follows the installed major version, as in Go's `/v5` module paths), or the project's GitHub repository advisories. Check that the source has data before adding it; the app reports nothing for a CPE or package it doesn't know, and a product whose versions don't match its package's versions needs its repository advisories instead.

**Coverage is partial.** Editor extensions, container images, Java and other ecosystems, unpinned MCP servers that npx hasn't cached, software outside the catalog and arbitrary install paths aren't checked. A newer version alone is not a vulnerability. This is an update monitor, not a malware scanner or an assurance that a Mac is secure.

## Installing updates

Each finding lists the ways to install its fix, best first, with the others under **Other ways to update**. The app checks how the software was installed and what this Mac has (Homebrew, mise, npm, pnpm, Yarn, Bun, corepack, uv, Poetry, Cargo, Bundler, Go, nvm, Volta, fnm), and uses Homebrew's data on whether each app updates itself. Options come in four kinds:

- **Terminal command**, matched to the install method: `brew upgrade curl`, `cd ~/Projects/app && npm install next@16.4.1`, `npm audit fix` for transitive dependencies, `uv lock --upgrade-package`, `mise upgrade node`, `claude update`, `opencode upgrade` or the owning interpreter's `pip`. **Copy**, to the right of the command, puts it on the clipboard to paste into any terminal.
- **Website**: the vendor's download page, nodejs.org, python.org or go.dev. Only https pages are offered.
- **App**: opens an app that updates itself so its updater can install the release.
- **File**: opens requirements.txt, package.json or an MCP configuration where a pin has to change.

For a directly downloaded app, one that updates itself leads with opening it, then a Homebrew command if Homebrew is installed, then the download page. An app without a self-updater leads with Homebrew or the download page. Homebrew apps that update themselves get `--greedy` so Homebrew includes them. When a project's package manager isn't installed, the command first installs it (`corepack enable pnpm`, `npm install -g yarn`, `brew install uv`), or the first option is its install page. Older Homebrew copies get `brew upgrade X && brew cleanup X`, because Homebrew deletes them only once its newest build is installed; removing just that copy from Homebrew's Cellar is offered as an alternative. Pinned formulae are unpinned before upgrading, and a pinned formula's old copy is removed without upgrading. Homebrew rebuilds, such as 26.12.1 → 26.12.1_1, appear as updates. Apple updates open Software Update. Installers downloaded from nodejs.org or python.org are checked with Apple's notarization assessment before `sudo installer` runs. 

Findings whose recommended command is the same, or differs only in what it acts on, appear as one card with one combined command (`brew upgrade a b c`, `rm -rf dir1 dir2`, `npm install next@16.4.1 ai@5.0.52`), followed by each finding's version, reason, location, advisories and any alternatives of its own. All older Homebrew copies share one card, and so do a project's indirect dependencies under its `npm audit fix`. **All commands…** on the Security and Updates tabs lists every recommended Terminal command combined the same way, with each project's commands kept together, to review and copy one at a time or all at once. Commands that can't take several targets, such as `cargo update --precise`, stay one per line. On the developer's Mac, 187 security findings became 44 cards and 28 commands, and 52 updates became 4 cards and 3 commands.

Package names and versions are checked against each ecosystem's naming rules and shell-quoted before they appear in a command, and nothing is ever run by the app. Review a command before running it; dependency updates can change behavior.

## Data and privacy

State lives in `~/Library/Application Support/Shipshape/state.json` (folder 0700, file 0600). It contains local paths, project folders, package names, versions, results and notification fingerprints. There is no analytics, account, remote inventory or AI service.

Package names and versions are sent to OSV, product names and versions to NVD, and release and advisory lookups to Homebrew, GitHub, Node, PostgreSQL and OpenSSL. **Private package names in your lockfiles are included in OSV queries.** MCP settings are read for each server's command and arguments only; environment variables, headers and keys are never kept. Lockfiles are read as text and nothing in a project is run. Exported reports contain local paths and package names, so review them before sharing.

To uninstall, turn off Start at login, quit the app and move it to Trash. Remove the Application Support folder separately if you no longer need saved results.

## Development

Requires Xcode or a matching Swift compiler and macOS SDK. No third-party packages are used.

```sh
bash native/test.sh
SIGN_IDENTITY="Developer ID Application: YOUR NAME (TEAMID)" bash native/build.sh
SIGN_IDENTITY="Developer ID Application: YOUR NAME (TEAMID)" bash native/package.sh
bash native/notarize.sh security-monitor-notary
```

To try a development build without touching the installed app's saved results, launch it with `SHIPSHAPE_STATE_DIR` set to another folder, for example `open -n --env SHIPSHAPE_STATE_DIR=/tmp/shipshape-state dist/Shipshape.app`. Without it, a development build moves a leftover `Security Monitor` folder like a real upgrade would. The name and version come from `native/Resources/Info.plist`; the build, packaging and notarization scripts read them from there, and `appName` in `Feeds.swift` is the name shown in the app. The notary keychain profile keeps its original name. Without `SIGN_IDENTITY`, the build uses an ad-hoc signature for local development only. Tests cover version ordering, vendor range rules, each lockfile format, MCP command parsing, OSV alias handling and fix selection, NVD range and platform evaluation, command quoting and routing, failed-check retention, notification fingerprints and Pacific-time scheduling.

For a command-line scan with the same engine (pass an output file and any project folders):

```sh
xcrun swiftc -swift-version 5 -O -parse-as-library native/Sources/{Models,Catalog,Lockfiles,Inventory,Advisories,Commands,Feeds}.swift native/Tests/Check.swift -o native/work/check
native/work/check native/work/live-scan.json ~/Projects
```

Every rebuilt DMG needs its own notarization before sharing. `native/notarize.sh` submits the DMG with a saved notarytool keychain profile, waits for **Accepted**, staples the DMG and app, verifies Gatekeeper acceptance and rewrites the checksum. Run `native/setup-notarization.command` once in Terminal to save the `security-monitor-notary` profile. Never put Apple passwords in source files or shell history. This preview does not update itself; a signed update channel such as Sparkle remains future work.

Primary documentation: [OSV API](https://google.github.io/osv.dev/api/), [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities), [MenuBarExtra](https://developer.apple.com/documentation/swiftui/menubarextra), [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice), [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).
