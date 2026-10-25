# Changelog

Shipshape was called Security Monitor before 0.3.0. Every release is a universal (Apple silicon and Intel) build for macOS 13 or later, signed with Developer ID and notarized by Apple.

## 0.3.0 — October 24, 2026

- **New name: Shipshape.** On first launch the app moves its saved results from `Application Support/Security Monitor` to `Application Support/Shipshape`. The bundle identifier is unchanged, so notification permission carries over. If the old app is still in Applications, Shipshape asks you to remove it.
- **Refresh every minute** while the app is open. Each refresh reads this Mac and your project folders again, reusing recent advisory data, so software you update, remove or add shows up within a minute. Refreshes pause while offline or in Low Power Mode, and can be turned off in Settings.
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
