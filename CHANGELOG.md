# Changelog

Every release is a universal (Apple silicon and Intel) build for macOS 13 or later, signed with Developer ID and notarized by Apple.

## 0.3.10 — October 27, 2026

- **Python fixes stay in your Python's branch.** NVD lists some fixes only as a release in a newer branch ("before 3.13.14"), and Shipshape used to recommend that for every older Python. Now the fix is the release in the installed branch when NVD lists one, such as 3.12.14 for 3.12.13, and a fix listed only in a newer branch is mentioned on the card.
- **uv Pythons** are upgraded with `uv python upgrade 3.12`, which installs the newest patch release and moves uv's virtual environments to it, in one command for every branch. The old command reinstalled a release that was already there. uv keeps the previous patch release after an upgrade; it's now listed under Updates as an older copy with `uv python uninstall`, and only the newest patch of each branch is checked.
- **Packages inside a Python uv manages**, such as its bundled setuptools, get pip's `--break-system-packages` override. uv marks its Pythons as externally managed, so the plain pip command failed. Removing a package from Homebrew's Python gets the same override.

## 0.3.9 — October 25, 2026

- **Report a problem** on any finding opens a new GitHub issue with the finding's details filled in: what's wrong, room for Terminal output, how it was installed and the command shown. **Send feedback…** in the menu and in Settings does the same for ideas, problems and software Shipshape should check. You review the issue on GitHub and submit it with your own account; Shipshape never posts anything, and your home folder is shown as `~`.
- The issue templates are now GitHub issue forms.
- Settings lists every lockfile format Shipshape reads.

## 0.3.8 — October 25, 2026

- **A ship instead of a shield:** a new sailboat app icon, and a sailboat in the menu bar (filled, with the count, when something needs attention) and in the app's headers.

## 0.3.7 — October 25, 2026

- **Ruby gems:** only the newest copy of each gem is checked, since that's the one Ruby loads. A default gem that ships with Ruby, such as json 2.18.0 in Ruby 4.0, is no longer flagged once a newer version is installed; `gem update` reported nothing to update, and the gem can't be removed.

## 0.3.6 — October 25, 2026

- **Codex** is checked against its own update feed, which it sets in code rather than in its Info.plist. When it's current, its bundled Sparkle waits in **No fix released yet** instead of asking you to update.
- When Shipshape can't tell whether an app with a vulnerable Sparkle is current, because its update feed can't be found or read, the card says so instead of implying an update is out.

## 0.3.5 — October 25, 2026

- **The alert for a bundled Sparkle** names the app and says its new release *may* include a newer Sparkle ("New iTerm2 release"), instead of "Fix now available" with Sparkle's repository name.
- That alert now arrives for findings you'd already been alerted about before they started waiting, including everything carried over from 0.3.3.
- A finding waiting in No fix released yet keeps waiting when its app's update feed or Homebrew's data can't be read, instead of briefly turning into an alert.

## 0.3.4 — October 25, 2026

- **Bundled Sparkle in apps that are already current** moves to **No fix released yet**: updating can't help until the developer ships a newer Sparkle, so there's no "Open app" button and it doesn't count as needing attention. Shipshape alerts you when a newer release of the app appears.
- **Modified Sparkle builds,** such as iTerm2's (Sparkle 1.22.0 plus 1,354 changes), are noted on their card, since the version may not show fixes made since.
- Advisory summaries read correctly when some advisories have no published fix ("…Signing Checks Bypass. 1 has no published fix.").

## 0.3.3 — October 25, 2026

- **Self-updating apps (Sparkle):** any app with a Sparkle update feed, on the built-in list or not, is checked against its own feed for newer releases.
- **Bundled Sparkle:** the Sparkle framework inside each app is checked against Sparkle's published advisories, such as the signing-check bypass fixed in 2.6.4. The fix is updating the app.

## 0.3.2 — October 25, 2026

- Removed a notice that only appeared on Macs that had run pre-release builds.
- **More project languages:** Swift Package Manager (including Xcode projects), Composer (PHP), Dart and Flutter, .NET, Elixir and Gradle lockfiles, each checked against OSV.
- **GitHub Actions** in project workflows, including moving tags such as `@v4` and commits pinned with a version comment.
- **More global tools:** `cargo install` crates, `go install` programs and Ruby gems.
- **Editor extensions** in VS Code, Cursor and Windsurf are checked against Microsoft's list of extensions removed as malware, impersonation or untrustworthy.
- **13 more catalog products,** each verified against NVD: Vault, Consul, Podman, QEMU, Composer, Gradle, Maven, rsync, Nmap, mitmproxy, Bruno, Sourcetree and 1Password.

## 0.3.1 — October 25, 2026

- **Commands only for what your account can change.** On a Mac with several accounts, or with folders left owned by root after a `sudo` install, package managers failed with "Permission denied". Shipshape now checks that your account can write where each command acts. If it can't, the finding stays listed with a notice naming the folder's owner and what to do, instead of a command that would fail. That covers another person's projects, a Homebrew installed by another account, and root-owned `node_modules` or global package folders.
- **No package-manager internals as projects.** Project scans skip app bundles, Homebrew's own folders, `/usr`, `/System`, `/Library`, `~/Library` and Go's module cache, so a broad project folder no longer lists Homebrew's own tools as projects.
- **Warnings for project folders** that belong to another account or include system folders, when you add them and in Settings.
- **No more minute refresh.** Checks run at launch, daily and when you click Check now; nothing runs in between. The footer and menu show the last check's time and how long ago it was.
- **Security fixes** from an independent review, each with a regression test:
  - "Open file" opens only plain, non-executable text files inside your project folders or known MCP settings, in your text editor. A repo could previously make it run a script.
  - Commands are withheld when a name contains invisible control characters that could change what a pasted command does.
  - A crafted `requirements.txt` can no longer stall checks. Project files aren't read through links or above 64 MB, and project parsing has a time limit.
  - Homebrew is read from its folders instead of running `brew`. Other programs run only if this account or root owns them, with a minimal environment.
  - Package names are always quoted. MCP options can't be mistaken for package names, so keys aren't saved. Oversized version numbers are rejected. Downloads stop at their size limit.
- **Lighter checks:** a full check on a Mac with about 6,000 packages now takes about 1.9 CPU-seconds instead of 6.5, and peaks at 182 MB instead of 301 MB.

## 0.3.0 — October 24, 2026

- **Refresh every minute** while the app is open (removed in 0.3.1).
- **History tab:** a log of every recommendation, when it was found, and when and how it was resolved ("Updated to 9.0.2", "Removed", "Project folder no longer checked" and others). It has search, filters and CSV export.
- **No more same-version updates:** versions are read by their first number, so `Build 4215` compares as 4215. After every scan, an update is dropped if its version is the installed release written differently.

## 0.2.7

- Commands that can act on several targets combine into one line (`brew upgrade a b c`), and **All commands…** lists every recommended command, kept together by project.

## 0.2.6

- Findings that share a command are grouped into one card.

## 0.2.5

- A fresh check at every launch. The Copy button sits beside its command, evidence is shown inline, and the "View source" link became "Open website".

## 0.2.4

- Old Homebrew copies get a cleanup command that works, and Homebrew rebuilds (such as 26.12.1_1) are handled.

## 0.2.3

- Google Chrome and Mac App Store apps are excluded.
- A new OpenSSL branch with no vulnerability page counts as having no published vulnerabilities, but only when OpenSSL's index loads and doesn't list it.
- Findings with no released fix get their own "No fix released yet" group.

## 0.2.2

- Each finding lists its update options, best first: a Terminal command for the tool that installed it, the app's own updater, or the vendor's download page.

## 0.2.1

- Coverage for OpenCode, GitHub Copilot CLI, more Claude Code and Ollama install names, libpq, Docker Compose and runtimes installed with mise.

## 0.2.0

- Rebuilt around the developer stack: runtimes, package managers, AI coding tools, MCP servers, Homebrew and project lockfiles, checked against OSV, NVD and vendor advisories.

## 0.1.0

- First preview.
