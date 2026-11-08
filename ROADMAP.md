# Roadmap

What's planned for Shipshape, roughly in order. Plans change as reports come in. To ask for something, open a [coverage request](https://github.com/toddsherman/shipshape/issues/new?template=coverage-request.yml) or [feedback](https://github.com/toddsherman/shipshape/issues/new?template=feedback.yml) issue. What has shipped is in [CHANGELOG.md](CHANGELOG.md).

## Now: accuracy

Shipshape added a lot of coverage in October and November 2026: apps built on Electron, the browsers Playwright, Puppeteer, Selenium and Cypress download, and the Sparkle or Electron inside an app's newest release. The next releases favor getting those right over adding more, because a wrong finding costs more trust than a gap that's documented.

- **Every reported wrong finding becomes a test,** built from what the report showed, so it can't come back.
- **The newest checks are tried on more Macs.** The Electron card's count of Chrome flaws is an estimate from publication dates, and reading an app's newest release from part of its zip depends on how each developer packages it. Reports from real Macs are the fastest way to find where they're off: the bug button on each card files a [wrong or missing finding](https://github.com/toddsherman/shipshape/issues/new?template=wrong-or-missing-finding.yml) issue, filled in for you to check.
- **Releases about once a week,** with urgent fixes sooner, so installed copies don't ask to update every day.

## Next: coverage gaps

Of what the [native README](native/README.md) lists as not checked, these are closest to what Shipshape already does:

- **GitHub Actions pinned to a bare commit.** A commit pin with a version comment beside it is checked already; one without is listed as not checkable. Shipshape would work out which release the commit belongs to, which sends the action's name and the commit to GitHub.
- **MCP servers run with npx and no version,** before npx has cached them. Shipshape would check the version npx would install today, by asking npm for the newest release, which receives the package name only.
- **A Homebrew cask for Shipshape itself,** so `brew install --cask shipshape` works, with Shipshape still installing its own updates. Until it qualifies for Homebrew's main list, from a tap.

## 1.0

Shipshape reaches 1.0 when no report of a wrong finding has stayed open for more than a week, the newest checks have gone four weeks without one, and it installs with Homebrew.

## Not planned

- **Running fixes for you.** Shipshape shows commands for you to review and run, and never runs them.
- **An account, API key, analytics or cloud inventory.** That includes an optional NVD API key, even though it would make the first check faster: Shipshape works the same for everyone without one.
- **Container images.** Scanning them is a different kind of tool, and Docker Scout and Trivy already do it.
- **CocoaPods, and vulnerabilities in editor extensions.** No public advisory database covers them, so there's nothing to compare them with. Editor extensions are checked against Microsoft's list of extensions it removed as malware.
- **Google Chrome and Mac App Store apps,** which update themselves.
- **Antivirus.** Shipshape flags malicious packages from published reports, but it doesn't scan files for malware or say a Mac is secure.
