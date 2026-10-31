# Changelog

Every release is a universal (Apple silicon and Intel) build for macOS 13 or later, signed with Developer ID and notarized by Apple.

## Unreleased

- **Packages a tool holds back no longer offer a fix that can't work.** npx cache cards now name the tool npx installed. When that tool requires an affected version of a package and its newest release still does, deleting the cache would only bring the package back, so the finding moves to **Waiting for a fix**, says what's holding it back and offers no command. Shipshape alerts you when a release allows the fix. It reads this from the cached install's own files and asks npm for the tool's newest release, which receives the tool's name only. Malicious packages are still flagged for removal, whatever needs them.
- **The lookout stays at his post.** He now stands beside Check now all the time, smaller and paler, and moves only during a check: he eases into his watch and settles back when it ends. The rest of the time he's a still picture that uses no processor time.
- **A check's steps fade in and out smoothly,** and the page moves out of their way instead of jumping. Folding the list is animated too.

## 0.3.25 — October 31, 2026

- **A check shows what it's doing, step by step.** While it runs, the window lists its whole route: what each finished step found, the step under way and what's still to come, with a count of findings so far. A line under the current step says what it's reading, why it takes the time it does or what leaves your Mac, and NVD's step says about how long is left. Apple Software Update and CISA's list have their own steps now, so a slow one no longer looks like Homebrew. Fold the list away with the arrow at its corner, and it stays folded. The menu bar panel shows the current step and the count.
- **A lookout replaces the spinner.** While a check runs, a sailor in a crow's nest watches the horizon through his telescope, to the left and then to the right, on a gently rocking mast. With Reduce Motion on, he stays still and faces the other way every few seconds.

## 0.3.24 — October 28, 2026

- **Text in a card can be selected and copied,** as in a document: drag across an explanation, a version or a note, or double-click a word, then copy it. Each piece of text is selected on its own.
- **A card that combines several findings under one command has its own bug button,** beside its badge. It reports the whole card: the command they share, then each finding. Each finding in it keeps its own button too.

## 0.3.23 — October 28, 2026

- **Findings say when their advisory came out.** Each card's explanation ends with the date its advisory was published, or the newest one's when there are several, plus how long ago for anything in the last 30 days. Malicious-package reports say when they were reported, and known exploitation says when CISA listed it. Hover over an advisory ID for its own date; a CVE that's the same issue as a GitHub advisory says so. Dates come from OSV, NVD, GitHub and CISA data Shipshape already downloads, and they never change the order of findings, their urgency or alerts.
- **Finding cards no longer have an Open website link.** Each advisory ID already links to its own page.
- **Copy and Show in Finder appear when you hover over a finding's location,** so the line stays uncluttered.

## 0.3.22 — October 27, 2026

- **Inventory shows how each app is signed.** A new **Signatures** list reads the code signature of every app in Applications and your own Applications folder, and says whether it's signed by a developer (with the team ID), signed by Apple, ad-hoc signed or unsigned, and whether it has the Hardened Runtime. Apps that are ad-hoc signed, unsigned or without the Hardened Runtime come first and have their own filters, the **Apps** list notes them beside the version, and **Coverage** names them. This is for your information, not a finding: apps built on your Mac and some Homebrew casks are ad-hoc signed by design. Signatures are read with macOS's Security framework, in milliseconds per app, without opening the apps or sending anything anywhere; App Store apps and Google Chrome are skipped, as everywhere else. Requested in [#1](https://github.com/toddsherman/shipshape/issues/1).

## 0.3.21 — October 27, 2026

- **Quit in the Dock keeps Shipshape in the menu bar.** It closes the dashboard and removes the Dock icon, and checks carry on; opening the dashboard from the menu bar brings the icon back. The same goes for quitting from the Command-Tab switcher. Quit in the menu bar panel, Command-Q, logging out and restarting still quit.

## 0.3.20 — October 27, 2026

- **The Security summary leads with a status badge instead of the gauge,** set by the most urgent finding: **Act now** for malicious packages or known exploitation, **Fix soon** for security fixes or end of support, **Nothing urgent** when only findings waiting for a fix or updates remain, and **All clear**. A high percentage could look healthy with a malicious package present; the badge can't. The share of your inventory that needs no action is now a caption in the corner, the bar's legend shows each kind's count, and tiles with findings take their bar color: orange for security fixes and end of support, gray for waiting for a fix and blue for updates. Malicious packages and known exploitation are still filled red.
- **For contributors: `native/scenario.sh` opens Shipshape on made-up findings,** to see the interface in situations such as malicious packages, known exploitation, a clean Mac, failed checks or two hundred findings, without scanning your Mac. The copy is called Shipshape Dev and has an orange icon; its Scenarios menu and menu bar panel switch between scenarios without relaunching. Development builds with their own data folder can turn checks off with `SHIPSHAPE_NO_CHECKS=1`.

## 0.3.19 — October 27, 2026

- **The Security summary shows a gauge** instead of a full ring: an arc open at the bottom that fills green to teal with the share of your inventory that needs no action, with the percentage in the middle.

## 0.3.18 — October 27, 2026

- **A bundled Sparkle no longer needs attention just because its app's feed lists a brand-new release.** Self-updating apps check about daily, may install on quit, and roll releases out in phases, so a feed can list a release the app doesn't offer yet; Codex listed one an hour old. The bundled Sparkle now waits until a newer app release has been out a week (or through its phased rollout), and the card says when it came out. It also waits, instead of needing attention, when Shipshape can't read the app's feed. Releases for Apple silicon only no longer count as newer on an Intel Mac.

## 0.3.17 — October 27, 2026

- **Install Update is one click.** After it downloads and checks the update, Shipshape quits, replaces itself and reopens, instead of stopping at Ready to Install for a second click. This applies to updates from 0.3.17 on; updating to 0.3.17 itself still asks twice.

## 0.3.16 — October 27, 2026

- **The menu bar panel's Check now is a refresh button** in its top-right corner, with a spinner while a check runs, and **Open Shipshape** and **Quit** share one row.

## 0.3.15 — October 27, 2026

- **Report a problem is a bug button** on each finding, beside Open website. It opens the same filled-in GitHub issue.
- **Each finding's location has Copy and Show in Finder buttons.** Copy puts the full path on the clipboard. Show in Finder opens a folder in its own window, or selects a file or app in its folder without opening it.
- **The menu bar panel no longer has Send feedback;** it's in Settings. Malicious packages now use a microbe icon, so the bug only means Report a problem.

## 0.3.14 — October 27, 2026

- **Shipshape updates itself.** When a new version is out, it shows the release notes; **Install Update** downloads it, checks that it's signed by Shipshape's developer, then quits, replaces and reopens the app, with no dragging into Applications. It checks once a day (turn that off in Settings) and whenever you choose **Check for Updates…** in the app menu or Settings. Updates use [Sparkle](https://sparkle-project.org) with signed disk images and a signed feed attached to each GitHub release. This version still needs one manual download; later ones arrive this way.

## 0.3.13 — October 27, 2026

- **Claude is no longer reported as out of date when its own updater says it's current.** Claude picks its release channel per device and organization, and some channels follow a version line apart from the public one Homebrew lists (3.6556.2 while Homebrew had 4.29.0). Shipshape now leaves Claude's updates to Claude, and Coverage says so.

## 0.3.12 — October 27, 2026

- **The Security page starts with an overview.** A summary card shows how many items need attention, a ring with the share of your inventory that needs no action (items only waiting for a fixed release count as done, so 100% means there's nothing left you can do), and a bar of every item by its most urgent finding. Below it, six tiles sort findings into malicious packages, known exploitation, security fixes, end of support, waiting for a fix and updates. Malicious packages and known exploitation turn red when present. Clicking a tile lists just those findings. Updates are now a tile, so the separate Updates page is gone.
- **The menu bar panel lists the same kinds of finding,** each with its count. Clicking one opens the Security page at that list, and the panel closes when it opens the window.
- **A known-exploited flaw with no fix released yet counts as needing attention,** in the overview, the sidebar and the menu bar count, instead of waiting quietly with other unfixed advisories.

## 0.3.11 — October 27, 2026

- **Shipshape has a Dock icon** and a regular app menu, alongside its menu bar icon. Clicking the Dock icon opens its window again after you close it.
- **Links that open a web page show the pointing-hand cursor:** each advisory ID, Open website, the Download buttons and Open in GitHub. Advisory IDs are now separate links, with Copy on their right-click menu.

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
