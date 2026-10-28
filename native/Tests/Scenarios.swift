import Foundation
// Made-up saved states for seeing how the interface looks in different situations: scenarios <output folder>.
// Writes <folder>/<name>/state.json for each scenario, and index.tsv (name, title, description), which the app's
// Scenarios menu reads; prints "name: description" lines. native/scenario.sh opens one in a copy of the app with
// checks turned off, so the made-up findings stay as they are.
@main struct Scenarios {
    static let home = NSHomeDirectory()
    static let projects = home + "/Projects"
    static let now = Date()

    // MARK: Installations
    static func npm(_ project: String, _ name: String, _ version: String, dependency: String = "direct") -> Installation {
        let folder = projects + "/" + project, lock = folder + "/package-lock.json"
        return Installation(product: "npm:" + name, name: name, version: version, path: lock + "#" + name + "@" + version, domain: "projects",
                            ecosystem: "npm", packageName: name, manager: "npm", location: folder, dependency: dependency, file: lock)
    }
    static func pypi(_ project: String, _ name: String, _ version: String) -> Installation {
        let folder = projects + "/" + project, file = folder + "/requirements.txt"
        return Installation(product: "pypi:" + name, name: name, version: version, path: file + "#" + name + "@" + version, domain: "projects",
                            ecosystem: "PyPI", packageName: name, manager: "pip-req", location: folder, dependency: "direct", file: file)
    }
    static func brew(_ formula: String, _ version: String, product: String? = nil) -> Installation {
        Installation(product: product ?? formula, name: formula, version: version, path: "/opt/homebrew/Cellar/\(formula)/\(version)", domain: "brew", package: formula, manager: "brew")
    }
    static func app(_ name: String, _ version: String, id: String) -> Installation {
        Installation(product: "app:" + id, name: name, version: version, path: "/Applications/\(name).app", domain: "apps", manager: "app")
    }
    static func sparkle(in app: String, _ version: String) -> Installation {
        Installation(product: "swifturl:github.com/sparkle-project/Sparkle", name: "Sparkle in \(app)", version: version, path: "/Applications/\(app).app/Contents/Frameworks/Sparkle.framework",
                     domain: "apps", note: "The update framework bundled inside \(app). It is updated with the app.", ecosystem: "SwiftURL",
                     packageName: "github.com/sparkle-project/Sparkle", manager: "sparkle-framework", location: "/Applications/\(app).app")
    }
    static func mcp(_ package: String, _ version: String, config: String) -> Installation {
        Installation(product: "npm:" + package, name: package, version: version, path: config + "#" + package, domain: "mcp", ecosystem: "npm",
                     packageName: package, manager: "mcp", location: config, file: config)
    }
    static func globalNPM(_ name: String, _ version: String) -> Installation {
        let prefix = "/opt/homebrew/lib/node_modules"
        return Installation(product: "npm:" + name, name: name, version: version, path: prefix + "/" + name, domain: "packages", ecosystem: "npm", packageName: name, manager: "npm-global", location: prefix)
    }
    // Packages with nothing found, so the gauge and Inventory have a realistic share of clean items.
    static func clean(_ count: Int) -> [Installation] {
        let names = ["react", "react-dom", "typescript", "zod", "eslint", "prettier", "vitest", "tailwindcss", "postcss", "date-fns", "uuid", "chalk", "commander", "dotenv",
                     "undici", "esbuild", "rollup", "sharp", "prisma", "drizzle-orm", "hono", "zustand", "clsx", "lucide-react", "framer-motion", "openai", "@anthropic-ai/sdk"]
        return (0..<count).map { index in
            let project = ["shop", "agent-tools", "docs-site"][index % 3]
            return npm(project, index < names.count ? names[index] : "\(names[index % names.count])-plugin-\(index)", "\(1 + index % 9).\(index % 13).\(index % 7)", dependency: index % 4 == 0 ? "direct" : "transitive")
        }
    }

    // MARK: Findings
    static func finish(_ finding: Finding) -> Finding { var finding = finding; finding.commands = Commands.commands(for: finding); return finding }
    static func security(_ item: Installation, fixed: String, severity: String, ids: [String], titles: [String], exploited: Bool = false) -> Finding {
        finish(Finding(source: "osv", installation: item, kind: .security, fixed: fixed,
                       reason: "\(titles.count) published advisor\(titles.count == 1 ? "y" : "ies"): " + titles.joined(separator: "; ") + ".",
                       action: Commands.action(for: item, malicious: false, fixed: fixed), links: ids.map { "https://osv.dev/vulnerability/" + $0 }, advisories: ids, exploited: exploited, severity: severity))
    }
    static func malware(_ item: Installation, id: String) -> Finding {
        finish(Finding(source: "osv", installation: item, kind: .security, fixed: "Remove this version",
                       reason: "OpenSSF's malicious-package database lists this exact version. Assume anything it could reach is exposed.",
                       action: Commands.action(for: item, malicious: true, fixed: nil), links: ["https://osv.dev/vulnerability/" + id], advisories: [id], severity: "CRITICAL", malicious: true))
    }
    static func waiting(_ item: Installation, severity: String, ids: [String], titles: [String], fixed: String = "No fix released yet", action: String? = nil) -> Finding {
        var finding = security(item, fixed: fixed, severity: severity, ids: ids, titles: titles)
        finding.awaitingFix = true
        finding.action = action ?? "You have the newest \(item.name), and no release fixes these yet. Shipshape alerts you when a fixed release is available."
        return finish(finding)
    }
    static func update(_ item: Installation, to version: String, source: String = "homebrew-formula") -> Finding {
        finish(Finding(source: source, installation: item, kind: .update, fixed: version, reason: "Newer release metadata is available. This alone does not establish a security vulnerability.",
                       action: item.manager == "app" ? "Install the new release with one of the options below." : "Review the release notes, then update with Homebrew.", links: []))
    }
    static func endOfSupport(_ item: Installation, what: String, fixed: String, link: String) -> Finding {
        finish(Finding(source: "endoflife", installation: item, kind: .unsupported, fixed: fixed, reason: "This \(what) branch is past its published end-of-life date.",
                       action: "Move what uses it to a supported release, or remove this copy after checking what uses it.", links: [link], advisories: ["\(what) end of life"]))
    }
    static func blocked(_ finding: Finding, owner: String) -> Finding {
        var finding = finding
        finding.blocked = "\(Inventory.display(finding.installation.location ?? finding.installation.path)) belongs to \(owner), so this account can't change it. Make the fix from \(owner)'s account, or ask them to."
        finding.commands = []
        return finding
    }
    static func stale(_ finding: Finding) -> Finding { var finding = finding; finding.stale = true; return finding }

    // MARK: A few findings used by several scenarios
    static let flatmap = malware(npm("shop", "flatmap-stream", "0.1.1", dependency: "transitive"), id: "MAL-2025-20690")
    static let vite = security(npm("shop", "vite", "5.0.0", dependency: "dev"), fixed: "6.4.4", severity: "HIGH", ids: ["GHSA-vg6x-rcgg-rjx6", "CVE-2025-30208"],
                               titles: ["Vite bypasses server.fs.deny for raw and import queries", "Vite dev server exposes files outside the project root"], exploited: true)
    static let lodash = security(npm("shop", "lodash", "4.17.20"), fixed: "4.17.21", severity: "HIGH", ids: ["GHSA-35jh-r3h4-6jhm"], titles: ["Command injection in lodash template"])
    static let axios = security(npm("shop", "axios", "0.21.1"), fixed: "0.30.0", severity: "HIGH", ids: ["GHSA-jr5f-v2jv-69x6", "GHSA-wf5p-g6vw-rhxx"],
                                titles: ["axios can leak credentials to absolute URLs", "Cross-site request forgery in axios"])
    static let requests = security(pypi("api-server", "requests", "2.25.0"), fixed: "2.32.4", severity: "MODERATE", ids: ["GHSA-9wx4-h78v-vm56"], titles: ["Requests leaks .netrc credentials to third parties"])
    static let openssl = security(brew("openssl@3", "3.5.1", product: "openssl"), fixed: "3.5.4", severity: "HIGH", ids: ["CVE-2025-9230", "CVE-2025-9231"],
                                  titles: ["Out-of-bounds read and write in RFC 3211 KEK unwrap", "Timing side channel in SM2 on 64-bit ARM"])
    static let ffmpeg = waiting(brew("ffmpeg", "9.0.2"), severity: "HIGH", ids: ["CVE-2026-107675", "CVE-2026-107676"], titles: ["Heap overflow in the HEVC decoder", "Use after free in the MOV demuxer"],
                                action: "You have Homebrew's newest ffmpeg (9.0.2), and no release fixes these yet. Shipshape alerts you when a fixed release is available.")
    static let folxSparkle = waiting(sparkle(in: "Folx", "1.20.0"), severity: "HIGH", ids: ["GHSA-g3hp-f6mg-559v"], titles: ["Sparkle's installer XPC listener accepts unvalidated connections"],
                                     fixed: "2.9.2, not in Folx yet", action: "You have the newest Folx, and it still bundles Sparkle 1.20.0. Only its developer can update Sparkle, so let them know. Shipshape alerts you when a newer Folx is released.")
    static let gitUpdate = update(brew("git", "2.51.0"), to: "2.51.1")
    static let zedUpdate = update(app("Zed", "0.210.4", id: "dev.zed.Zed"), to: "0.211.2", source: "homebrew-cask")
    static let nodeUpdate = update(brew("node", "25.8.0"), to: "25.9.0")

    static func checks(failed: Int = 0, partial: Int = 0) -> [SourceCheck] {
        var list = [SourceCheck(id: "inventory-projects", name: "Project lockfiles", status: "checked", detail: "Read 3 project folders: 6 lockfiles, 412 packages."),
                    SourceCheck(id: "osv", name: "OSV advisories", status: "checked", detail: "Package versions checked against OSV, including OpenSSF malicious-package reports.", url: "https://osv.dev"),
                    SourceCheck(id: "nvd:openssl", name: "OpenSSL (NVD)", status: "checked", detail: "Checked against NVD."),
                    SourceCheck(id: "homebrew-formula", name: "Homebrew formula metadata", status: "checked", detail: "48 installations compared with Homebrew's current releases.", url: "https://formulae.brew.sh/"),
                    SourceCheck(id: "sparkle-feeds", name: "Sparkle update feeds", status: "checked", detail: "9 self-updating apps' own update feeds checked for newer releases.")]
        let failures = [SourceCheck(id: "kev", name: "CISA known exploited vulnerabilities", status: "failed", detail: "The catalog couldn't be downloaded (timed out). Known exploitation isn't marked this time.", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                        SourceCheck(id: "github-actions", name: "GitHub Actions (OSV)", status: "failed", detail: "OSV didn't answer for GitHub Actions. Workflow actions weren't checked."),
                        SourceCheck(id: "nvd:node", name: "Node (NVD)", status: "failed", detail: "NVD rate-limited this request. Earlier findings are kept as unverified.")]
        let partials = [SourceCheck(id: "inventory-apps", name: "Developer apps", status: "partial", detail: "2 apps couldn't be read: their Info.plist is damaged."),
                        SourceCheck(id: "extensions", name: "Editor extensions", status: "partial", detail: "Cursor's extension list couldn't be read. VS Code and Windsurf were checked.")]
        list += failures.prefix(failed) + partials.prefix(partial)
        return list
    }

    // MARK: Scenarios
    // history: findings an earlier check made that today's no longer does; current: what those installations are now.
    struct Scenario {
        let name: String; let description: String; let findings: [Finding]
        var clean = 220; var checks = Scenarios.checks(); var history: [Finding] = []; var current: [Installation] = []; var noReport = false
        var title: String { Scenarios.titles[name] ?? name }
    }
    // Menu titles, in menu order.
    static let titles = ["first-run": "First Run", "all-clear": "All Clear", "waiting-only": "Waiting Only", "typical": "Typical Day", "malware": "Malware",
                         "exploited": "Known Exploitation", "everything": "Everything", "crowded": "Crowded (200 Findings)", "check-issues": "Check Issues"]

    static var all: [Scenario] {
        let manyProjects = ["shop", "agent-tools", "docs-site", "api-server", "mobile", "admin"]
        let crowded = (0..<200).map { index -> Finding in
            let project = manyProjects[index % manyProjects.count]
            switch index % 10 {
            case 0: return malware(npm(project, "evil-pkg-\(index)", "1.0.\(index % 9)", dependency: "transitive"), id: "MAL-2026-\(1000 + index)")
            case 1: return security(npm(project, "lib-\(index)", "2.\(index % 7).0"), fixed: "2.\(index % 7 + 1).0", severity: "CRITICAL", ids: ["GHSA-c\(index)"], titles: ["Remote code execution in lib-\(index)"], exploited: index % 20 == 1)
            case 2, 3, 4: return security(npm(project, "pkg-\(index)", "1.\(index % 5).0", dependency: "transitive"), fixed: "1.\(index % 5).3", severity: ["HIGH", "MODERATE", "LOW"][index % 3], ids: ["GHSA-p\(index)"], titles: ["Prototype pollution in pkg-\(index)"])
            case 5: return endOfSupport(brew("python@3.\(index % 6 + 4)", "3.\(index % 6 + 4).\(index)", product: "python"), what: "Python", fixed: "Python 3.12 or later", link: "https://devguide.python.org/versions/")
            case 6: return waiting(npm(project, "slow-fix-\(index)", "3.0.\(index % 9)"), severity: "MODERATE", ids: ["GHSA-w\(index)"], titles: ["Denial of service in slow-fix-\(index)"])
            default: return update(brew("tool-\(index)", "1.\(index % 9).0"), to: "1.\(index % 9 + 1).0")
            }
        }
        return [
            Scenario(name: "first-run", description: "No check yet: the welcome screen.", findings: [], noReport: true),
            Scenario(name: "all-clear", description: "Nothing found: every tile empty and the gauge at 100%.", findings: []),
            Scenario(name: "waiting-only", description: "Nothing to install: only findings waiting for a fix, plus updates.",
                     findings: [ffmpeg, folxSparkle, waiting(sparkle(in: "Ice", "2.8.0"), severity: "MODERATE", ids: ["GHSA-hg88-v3cw-3qrh"], titles: ["Binary delta symlink traversal in Sparkle"],
                                                                  fixed: "2.9.2, not in Ice yet", action: "Ice 0.11.13 came out on Oct 27, and it may bundle a newer Sparkle. Ice installs its own updates, usually within days. If it hasn't after a week, this moves to Needs attention. Only Ice's developer can update the Sparkle it bundles."),
                                gitUpdate, zedUpdate]),
            Scenario(name: "typical", description: "A normal day: a couple of security fixes, updates and waiting items.",
                     findings: [lodash, requests, ffmpeg, folxSparkle, gitUpdate, nodeUpdate, zedUpdate], clean: 260),
            Scenario(name: "malware", description: "Malicious packages in two projects and an MCP server, with a few ordinary fixes.",
                     findings: [flatmap, malware(pypi("api-server", "requessts", "2.31.0"), id: "MAL-2025-41022"),
                                malware(mcp("@mcp-tools/filesystem-plus", "1.4.2", config: home + "/.cursor/mcp.json"), id: "MAL-2026-1187"),
                                lodash, axios, gitUpdate]),
            Scenario(name: "exploited", description: "Known exploitation, with and without a released fix.",
                     findings: [vite, security(brew("curl", "8.10.1"), fixed: "8.11.1", severity: "CRITICAL", ids: ["CVE-2026-0001"], titles: ["curl heap overflow in SOCKS5 proxy handshake"], exploited: true),
                                { var f = waiting(app("Raycast", "1.104.2", id: "com.raycast.macos"), severity: "CRITICAL", ids: ["CVE-2026-31337"], titles: ["Raycast extension sandbox escape"]); f.exploited = true; return f }(),
                                openssl, requests, nodeUpdate]),
            Scenario(name: "everything", description: "Every kind of finding, including blocked and unverified ones, failed checks, and History.",
                     findings: [flatmap, vite, openssl, lodash, axios, requests,
                                security(globalNPM("@anthropic-ai/claude-code", "2.0.10"), fixed: "2.0.31", severity: "HIGH", ids: ["GHSA-x5gv-jw7f-j6xj"], titles: ["Claude Code permission prompt bypass"]),
                                blocked(security(npm("legacy-portal", "minimist", "1.2.5"), fixed: "1.2.6", severity: "CRITICAL", ids: ["GHSA-xvch-5gv4-984h"], titles: ["Prototype pollution in minimist"]), owner: "sam"),
                                stale(security(brew("node@20", "20.11.0", product: "node"), fixed: "20.19.5", severity: "HIGH", ids: ["CVE-2025-23166"], titles: ["Node.js crypto error handling crash"])),
                                endOfSupport(brew("node@18", "18.20.4", product: "node"), what: "Node", fixed: "Supported LTS branch", link: "https://nodejs.org/en/about/previous-releases"),
                                endOfSupport(brew("python@3.9", "3.9.23", product: "python"), what: "Python", fixed: "Python 3.12 or later", link: "https://devguide.python.org/versions/"),
                                ffmpeg, folxSparkle, gitUpdate, nodeUpdate, zedUpdate, update(brew("gh", "2.80.0"), to: "2.81.0"), update(brew("jq", "1.7.1"), to: "1.8.0")],
                     clean: 150, checks: checks(failed: 1, partial: 1),
                     history: [security(npm("shop", "next", "14.0.0"), fixed: "14.2.25", severity: "CRITICAL", ids: ["GHSA-f82v-jwr5-mffw"], titles: ["Authorization bypass in Next.js middleware"]),
                               security(pypi("api-server", "gunicorn", "20.0.4"), fixed: "22.0.0", severity: "HIGH", ids: ["GHSA-w3h3-4rj7-4ph4"], titles: ["Request smuggling in gunicorn"]),
                               update(brew("wget", "1.24.5"), to: "1.25.0")],
                     current: [npm("shop", "next", "14.2.25"), brew("wget", "1.25.0")]),
            Scenario(name: "crowded", description: "Two hundred findings across six projects, to test long lists and scrolling.", findings: crowded, clean: 300),
            Scenario(name: "check-issues", description: "Three failed and two partial checks, with earlier findings kept as unverified.",
                     findings: [stale(lodash), stale(openssl), requests, gitUpdate], checks: checks(failed: 3, partial: 2)),
        ]
    }

    static func state(for scenario: Scenario) -> SavedState {
        var state = SavedState()
        state.projectFolders = [projects]
        state.lastScheduledDay = Schedule.day(now)
        guard !scenario.noReport else { return state }
        let findings = scenario.findings.sorted(by: Scanner.mostUrgentFirst)
        var installations = clean(scenario.clean) + scenario.current
        for item in findings.map(\.installation) where !installations.contains(where: { $0.path == item.path }) { installations.append(item) }
        var report = ScanReport(date: now.addingTimeInterval(-4 * 60), installations: installations, findings: findings, checks: scenario.checks)
        report.domains = ["projects": true, "packages": true, "mcp": true, "tools": true, "brew": true, "apps": true]
        // History: an earlier check three days ago found these, and today's check no longer does.
        var history: [HistoryEntry] = []
        if !scenario.history.isEmpty {
            let earlier = ScanReport(date: now.addingTimeInterval(-3 * 86_400), installations: installations + scenario.history.map(\.installation), findings: findings + scenario.history)
            History.update(&history, with: earlier, projectFolders: [projects], at: earlier.date)
        }
        History.update(&history, with: report, projectFolders: [projects], at: report.date)
        report.date = now.addingTimeInterval(-4 * 60)
        state.report = report
        state.history = history
        state.lastAttempt = report.date
        return state
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            FileHandle.standardError.write(Data("Usage: scenarios <output folder>\n".utf8)); exit(2)
        }
        let folder = CommandLine.arguments[1]
        var index = ""
        for scenario in all {
            let directory = folder + "/" + scenario.name
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            try JSONEncoder().encode(state(for: scenario)).write(to: URL(fileURLWithPath: directory + "/state.json"), options: .atomic)
            index += [scenario.name, scenario.title, scenario.description].joined(separator: "\t") + "\n"
            print("\(scenario.name): \(scenario.description)")
        }
        try index.write(toFile: folder + "/index.tsv", atomically: true, encoding: .utf8)
    }
}
