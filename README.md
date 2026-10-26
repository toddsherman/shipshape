# Shipshape

Keep the tools you build with patched.

Shipshape is a free, open-source macOS menu bar app for people who build software on a Mac, especially with AI coding tools like Claude Code and Codex. Those tools install a lot quickly: runtimes, package managers, CLIs, MCP servers, Homebrew libraries and thousands of project dependencies. Shipshape keeps track of all of it and tells you when something has a published security fix or a malicious release. For each one it shows the installed and fixed versions, the evidence, and the easiest way to install the fix for how it got onto your Mac: a Terminal command to copy, a download page, or the app's own updater.

## What it checks

- **Project dependencies** from the lockfiles in folders you choose: npm, pnpm, Yarn, Bun, uv, Poetry, pip requirements, Cargo, Bundler, Go modules, Swift Package Manager (including Xcode projects), Composer, Dart and Flutter, .NET, Elixir and Gradle.
- **GitHub Actions** used by your projects' workflows, including moving tags like `@v4`.
- **Global packages:** npm, Bun and pnpm globals, Python environments, pipx and uv tools, `cargo install`, `go install` and Ruby gems, and the npx cache.
- **Editor extensions** in VS Code, Cursor and Windsurf, against Microsoft's list of extensions it removed as malware or impersonation.
- **Self-updating apps** that use Sparkle, whether or not they're on the built-in list: newer releases from each app's own update feed, and the Sparkle version bundled inside, against Sparkle's advisories.
- **MCP servers** configured for Claude Code, Claude, Codex, Cursor, Windsurf, VS Code and Gemini CLI.
- **AI coding tools and runtimes:** Claude Code, Codex CLI, Gemini CLI, Copilot CLI, OpenCode, Node, Bun, Deno, Python, Go and more, however they were installed.
- **Homebrew** formulae and casks, including old copies left on disk, and common developer apps.

Advisories come from [OSV](https://osv.dev) (including OpenSSF malicious-package reports), [NVD](https://nvd.nist.gov), vendor security pages and GitHub security advisories, with [CISA's Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) raising priority. Google Chrome and Mac App Store apps are left out, since they update themselves. The full coverage table and its limits are in [native/README.md](native/README.md).

Shipshape checks when it opens, daily at 9 a.m. Pacific and whenever you click **Check now**; the footer shows when the last check ran and how long ago. The **History** tab keeps a log of every recommendation and when it was resolved.

## Principles

- **It never changes your Mac.** Shipshape shows commands for you to review and run; it doesn't run them. It only offers commands your account can run, and never suggests `sudo` for package managers.
- **No account, API key, analytics or cloud inventory.** Your inventory stays on your Mac. Package names and versions are sent to OSV, product versions to NVD, and release lookups to Homebrew, vendors and self-updating apps' own update feeds. That includes private package names in your lockfiles.
- **Coverage is partial, and it says so.** A check that can't complete is shown as failed, never as "safe." This is an update monitor, not antivirus.

## Install

Download the latest `Shipshape-<version>.dmg` from [Releases](https://github.com/toddsherman/shipshape/releases), drag Shipshape into Applications and open it. Builds are signed with Developer ID and notarized by Apple. Requires macOS 13 or later on Apple silicon or Intel.

Add the folders that hold your projects, run the first check and turn on notifications. The first check takes a few minutes, because NVD limits requests made without an API key.

## Build from source

```sh
bash native/test.sh
bash native/build.sh
open dist/Shipshape.app
```

There are no third-party dependencies. See [CONTRIBUTING.md](CONTRIBUTING.md) to get involved, [SECURITY.md](SECURITY.md) to report a vulnerability privately, and [CHANGELOG.md](CHANGELOG.md) for what changed.

## License

[MIT](LICENSE)
