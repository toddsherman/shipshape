# Shipshape

Keep the tools you build with patched.

Shipshape is a free, open-source Mac app, in the menu bar and the Dock, for people who build software on a Mac, especially with AI coding tools like Claude Code and Codex. Those tools install a lot quickly: runtimes, package managers, CLIs, MCP servers, Homebrew libraries and thousands of project dependencies. Shipshape keeps track of all of it and tells you when something has a published security fix or a malicious release. For each one it shows the installed and fixed versions, the evidence, and the easiest way to install the fix for how it got onto your Mac: a Terminal command to copy, a download page, or the app's own updater.

![Shipshape's Security page: an Act now badge, 13 items need attention, 88% of the inventory needs no action, and tiles for malicious packages and known exploitation in red, then security fixes and end of support in orange, waiting for a fix in gray and updates in blue](docs/shipshape-security.webp)

## What it checks

- **Project dependencies** from the lockfiles in folders you choose: npm, pnpm, Yarn, Bun, uv, Poetry, pip requirements, Cargo, Bundler, Go modules, Swift Package Manager (including Xcode projects), Composer, Dart and Flutter, .NET, Elixir and Gradle.
- **GitHub Actions** used by your projects' workflows, including moving tags like `@v4`.
- **Global packages:** npm, Bun and pnpm globals, Python environments, pipx and uv tools, `cargo install`, `go install` and Ruby gems, and the npx cache.
- **Editor extensions** in VS Code, Cursor and Windsurf, against Microsoft's list of extensions it removed as malware or impersonation.
- **Self-updating apps** that use Sparkle, whether or not they're on the built-in list: newer releases from each app's own update feed, and the Sparkle version bundled inside, against Sparkle's advisories.
- **MCP servers** configured for Claude Code, Claude, Codex, Cursor, Windsurf, VS Code and Gemini CLI.
- **AI coding tools and runtimes:** Claude Code, Codex CLI, Gemini CLI, Copilot CLI, OpenCode, Node, Bun, Deno, Python, Go and more, however they were installed. Apple's Python in Xcode is flagged once its branch is out of support, and waits on Apple.
- **Playwright's browsers:** the Chromium, Firefox and WebKit builds Playwright downloads, which never update themselves. Builds nothing uses any more are listed to delete; ones in use are checked against Chrome's and Firefox's advisories, and against what Playwright's newest release ships.
- **Apps built on Electron**, which carry their own Chromium: the Electron inside each app, against Electron's own advisories, whether that Electron still gets security fixes, and the Chrome vulnerabilities published since its release.
- **Browsers test tools download:** Puppeteer's and Selenium's Chrome for Testing and Firefox builds, and each cached Cypress app, which never update themselves either.
- **Homebrew** formulae and casks, including old copies left on disk, and common developer apps.
- **App signatures**, for your information: Inventory lists which apps are ad-hoc signed, unsigned or without the Hardened Runtime, and Coverage names them. They aren't findings, since apps built on your Mac and some Homebrew casks are ad-hoc signed by design.

Advisories come from [OSV](https://osv.dev) (including OpenSSF malicious-package reports), [NVD](https://nvd.nist.gov), vendor security pages and GitHub security advisories, with [CISA's Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) raising priority. Google Chrome and Mac App Store apps are left out, since they update themselves; the Chromium inside Playwright and Electron apps doesn't, so it's checked. The full coverage table and its limits are in [native/README.md](native/README.md).

The **Security** page opens with an overview: a status badge set by the most urgent finding (**Act now** for malware or known exploitation, **Fix soon** for security fixes or end of support, otherwise **Nothing urgent** or **All clear**), how many items need attention, and a bar of your inventory by each item's most urgent finding, with a count for each kind. Below it are tiles for malicious packages, known exploitation, security fixes, end of support, waiting for a fix and updates, in their bar colors; malware and known exploitation fill red. Each tile lists its findings, and the menu bar shows the same counts. The **Hide** button on a card hides a finding that doesn't apply to you until something changes: its version, whether a fix can be installed, known exploitation or a malware report. A finding waits for a fix when no release fixes it yet, or when a tool you run with npx still requires the affected version: its card names the tool and what's holding the package back, rather than offering a command that wouldn't last, and you're alerted when a release allows the fix. A Playwright browser waits the same way until a Playwright release ships one with the fixes, and its card suggests running Playwright on Google Chrome meanwhile. An Electron app waits for its developer to ship a release on a newer Electron, unless an exploited Chrome flaw puts it under known exploitation. When the app's newest release comes as a zip, Shipshape reads the Electron or Sparkle inside it from a few hundred kilobytes of the download, and the card changes to **Fix available as of** its date once a release has the fix, with an alert.

Shipshape checks when it opens, daily at 9 a.m. Pacific and whenever you click **Check now**; the footer shows when the last check ran and how long ago. During a check, the window lists each step, what it found and what's still to come. **History** keeps a log of every recommendation and when it was resolved. If a finding looks wrong, the bug button (**Report a problem**) on its card opens a GitHub issue with its details filled in, for you to review and submit; a card that combines several findings under one command has one for the whole card as well. Text in a card can be selected and copied. Each finding says when its advisory came out; hover over an advisory ID for its own date, or over the location for buttons to copy the path and show it in Finder. **Quit** in the Dock leaves Shipshape watching from the menu bar; **Quit** in the menu bar panel stops it.

## Principles

- **It never changes your software.** Shipshape shows commands for you to review and run; it doesn't run them. It only offers commands your account can run, and never suggests `sudo` for package managers. The one thing it installs is its own update, when you click Install Update.
- **No account, API key, analytics or cloud inventory.** Your inventory stays on your Mac. Package names and versions are sent to OSV, product versions to NVD, and release lookups to Homebrew, vendors and self-updating apps' own update feeds. That includes private package names in your lockfiles. npm receives the name of a tool you run with npx, only when that tool holds back a flagged package, and npm and GitHub receive Playwright's name and newest version when a browser build it uses has advisories. Electron's public release list is downloaded when an app built on Electron is installed; nothing about your Mac is sent. For an app with a vulnerable Sparkle or Electron inside, a few hundred kilobytes of its newest update download are fetched from its developer, as its own updater would. Project paths in Claude Code's and Codex's settings are read only to suggest project folders. Shipshape's own update check reads its release feed on GitHub.
- **Coverage is partial, and it says so.** A check that can't complete is shown as failed, never as "safe." This is an update monitor, not antivirus.

## Install

Download the latest `Shipshape-<version>.dmg` from [Releases](https://github.com/toddsherman/shipshape/releases), drag Shipshape into Applications and open it. Builds are signed with Developer ID and notarized by Apple. Requires macOS 13 or later on Apple silicon or Intel.

Add the folders that hold your projects (Shipshape suggests the ones Claude Code and Codex have worked in), run the first check and turn on notifications. The first check takes a few minutes, because NVD limits requests made without an API key.

From 0.3.14, Shipshape updates itself. When a new version is out, it shows the release notes; **Install Update** downloads it, checks that it's signed by Shipshape's developer, then quits, replaces and reopens the app. You can turn off the daily check in Settings. Copies older than 0.3.14 need one manual download to get there.

## Build from source

```sh
bash native/test.sh
bash native/build.sh
open dist/Shipshape.app
```

The one third-party dependency is [Sparkle](https://sparkle-project.org), which installs Shipshape's own updates; `native/sparkle.sh` downloads its pinned release and checks the checksum. See [CONTRIBUTING.md](CONTRIBUTING.md) to get involved, [SECURITY.md](SECURITY.md) to report a vulnerability privately, [CHANGELOG.md](CHANGELOG.md) for what changed and [ROADMAP.md](ROADMAP.md) for what's planned.

## License

[MIT](LICENSE)
