import Foundation
import Compression

// OSV covers package ecosystems (npm, PyPI, crates.io, Go, RubyGems) and OpenSSF's malicious-package
// reports. OSV decides applicability with each ecosystem's own version rules; this code only collapses
// duplicate advisories and picks the lowest published fix above the installed version.
enum OSV {
    struct Vuln: Sendable {
        let id: String
        let summary: String
        let aliases: [String]
        let severity: String?
        let fixed: [String: [String]]  // "ecosystem|name" → fixed versions
        var informational = false      // RustSec "unmaintained" or "notice": not a vulnerability
        var published: Date? = nil
    }
    static func normalized(_ name: String, _ ecosystem: String) -> String {
        ecosystem == "PyPI" ? name.lowercased().replacingOccurrences(of: "[-_.]+", with: "-", options: .regularExpression) : name
    }
    static func key(_ item: Installation) -> String? {
        guard let ecosystem = item.ecosystem, let name = item.packageName, item.version.first?.isNumber == true else { return nil }
        return ecosystem + "|" + normalized(name, ecosystem) + "|" + item.version
    }

    static func query(_ items: [Installation]) async throws -> [String: [String]] {
        let keys = Array(Set(items.compactMap(key))).sorted()
        var matches: [String: [String]] = [:]
        for start in stride(from: 0, to: keys.count, by: 1000) {
            let batch = Array(keys[start..<min(start + 1000, keys.count)])
            let queries = batch.map { key -> [String: Any] in
                let part = key.components(separatedBy: "|")
                return ["package": ["ecosystem": part[0], "name": part[1]], "version": part[2]]
            }
            let body = try JSONSerialization.data(withJSONObject: ["queries": queries])
            guard let obj = try await Fetch.json("https://api.osv.dev/v1/querybatch", limit: 60_000_000, body: body) as? [String: Any],
                  let results = obj["results"] as? [[String: Any]], results.count == batch.count else { throw MonitorError(message: "OSV returned an unexpected response") }
            for (key, result) in zip(batch, results) {
                let ids = ((result["vulns"] as? [[String: Any]]) ?? []).compactMap { $0["id"] as? String }
                if !ids.isEmpty { matches[key] = ids }
            }
        }
        return matches
    }

    static func details(_ ids: Set<String>) async throws -> [String: Vuln] {
        var vulns: [String: Vuln] = [:]
        let list = ids.sorted()
        for start in stride(from: 0, to: list.count, by: 8) {
            let batch = list[start..<min(start + 8, list.count)]
            try await withThrowingTaskGroup(of: Vuln.self) { group in
                for id in batch { group.addTask { try await vuln(id) } }
                for try await vuln in group { vulns[vuln.id] = vuln }
            }
        }
        return vulns
    }
    static func vuln(_ id: String) async throws -> Vuln {
        guard id.range(of: "^[A-Za-z0-9._:-]+$", options: .regularExpression) != nil,
              let obj = try await Fetch.json("https://api.osv.dev/v1/vulns/" + id) as? [String: Any] else { throw MonitorError(message: "OSV advisory \(id) could not be read") }
        var fixed: [String: [String]] = [:], informational = false
        for affected in (obj["affected"] as? [[String: Any]]) ?? [] {
            if let note = (affected["database_specific"] as? [String: Any])?["informational"] as? String, ["unmaintained", "notice"].contains(note) { informational = true }
            guard let package = affected["package"] as? [String: Any], let ecosystem = package["ecosystem"] as? String, let name = package["name"] as? String else { continue }
            for range in (affected["ranges"] as? [[String: Any]]) ?? [] {
                for event in (range["events"] as? [[String: Any]]) ?? [] {
                    if let version = event["fixed"] as? String { fixed[ecosystem + "|" + normalized(name, ecosystem), default: []].append(version) }
                }
            }
        }
        let summary = obj["summary"] as? String ?? (obj["details"] as? String).map { String($0.prefix(160)) } ?? id
        let severity = id.hasPrefix("MAL-") ? "CRITICAL" : ((obj["database_specific"] as? [String: Any])?["severity"] as? String)?.uppercased()
        return Vuln(id: id, summary: summary, aliases: obj["aliases"] as? [String] ?? [], severity: severity, fixed: fixed, informational: informational,
                    published: advisoryDate(obj["published"] as? String))
    }

    // npm holds the name of a package it took down, or one at risk of malicious use, with an empty placeholder version such
    // as 0.0.1-security. OSV's malware report for the name covers every version, but the placeholder holds no code, so
    // it's listed to remove rather than as malware.
    static let placeholderFix = "Remove placeholder"
    static func placeholder(_ item: Installation) -> Bool {
        item.ecosystem == "npm" && item.version.range(of: "^[0-9]+\\.[0-9]+\\.[0-9]+-security(\\.[0-9]+)?$", options: .regularExpression) != nil
    }
    static func findings(for items: [Installation], matches: [String: [String]], vulns: [String: Vuln]) -> [Finding] {
        func order(_ id: String) -> Int { id.hasPrefix("MAL-") ? 0 : id.hasPrefix("GHSA-") ? 1 : 2 }
        var findings: [Finding] = []
        for item in items {
            guard let key = key(item), let ids = matches[key], let ecosystem = item.ecosystem, let name = item.packageName else { continue }
            // A GHSA and its PYSEC or CVE twin describe one issue; count it once.
            var seen = Set<String>(), chosen: [Vuln] = []
            for id in ids.sorted(by: { (order($0), $0) < (order($1), $1) }) where !seen.contains(id) {
                let vuln = vulns[id] ?? Vuln(id: id, summary: id, aliases: [], severity: nil, fixed: [:])
                seen.insert(id); seen.formUnion(vuln.aliases)
                if !vuln.informational { chosen.append(vuln) }
            }
            guard !chosen.isEmpty else { continue }
            if placeholder(item), chosen.allSatisfy({ $0.id.hasPrefix("MAL-") }) {
                var finding = Finding(source: "osv", installation: item, kind: .update, fixed: placeholderFix,
                                      reason: "This is npm's empty placeholder for \(name), \(item.version), which holds the name so no one can publish malicious code under it. It contains no code. "
                                          + "OSV's malware report for the name covers every version, so it lists the placeholder too.",
                                      action: "Remove it: it does nothing. A project that lists \(name) usually meant something else, such as a module built into Node.",
                                      links: chosen.prefix(2).map { "https://osv.dev/vulnerability/" + $0.id } + ["https://www.npmjs.com/package/" + name],
                                      advisories: chosen.map(\.id).sorted())
                dates(&finding, chosen.map { ($0.id, $0.aliases, $0.published) })
                findings.append(finding)
                continue
            }
            let target = ecosystem + "|" + normalized(name, ecosystem)
            var fixes: [String] = [], unfixed = 0, severity: String? = nil
            for vuln in chosen {
                if let fix = (vuln.fixed[target] ?? []).filter({ looseLess(item.version, $0) }).min(by: looseLess) { fixes.append(fix) } else { unfixed += 1 }
                severity = worse(severity, vuln.severity)
            }
            let malicious = chosen.contains { $0.id.hasPrefix("MAL-") }
            let count = chosen.count == 1 ? "1 published advisory" : "\(chosen.count) published advisories"
            var titles = chosen.prefix(3).map(\.summary).joined(separator: "; ") + (chosen.count > 3 ? "; …" : "")
            if !titles.hasSuffix(".") && !titles.hasSuffix("…") { titles += "." }
            let unpublished = unfixed > 0 && !fixes.isEmpty ? " \(unfixed) \(unfixed == 1 ? "has" : "have") no published fix." : ""
            let reason = malicious
                ? "OpenSSF's malicious-package database lists this exact version. Assume anything it could reach is exposed."
                : count + ": " + titles + unpublished
            let advisories = Set(chosen.flatMap { [$0.id] + $0.aliases.filter { $0.hasPrefix("CVE-") } })
            var finding = Finding(source: "osv", installation: item, kind: .security,
                                  fixed: malicious ? "Remove this version" : fixes.max(by: looseLess) ?? "No fixed version published",
                                  reason: reason, action: Commands.action(for: item, malicious: malicious, fixed: fixes.max(by: looseLess)),
                                  links: chosen.prefix(4).map { "https://osv.dev/vulnerability/" + $0.id }, advisories: advisories.sorted(),
                                  severity: malicious ? "CRITICAL" : severity, malicious: malicious ? true : nil)
            dates(&finding, chosen.map { ($0.id, $0.aliases, $0.published) })
            findings.append(finding)
        }
        return findings
    }
    // Each advisory's date, and its CVE aliases on the card pointed at it, so a date shows once per issue.
    static func dates(_ finding: inout Finding, _ advisories: [(id: String, aliases: [String], published: Date?)]) {
        var published: [String: Date] = [:], same: [String: String] = [:]
        for advisory in advisories {
            if let date = advisory.published { published[advisory.id] = date }
            for alias in advisory.aliases where finding.advisories.contains(alias) && alias != advisory.id && same[alias] == nil && published[alias] == nil { same[alias] = advisory.id }
        }
        same = same.filter { published[$0.key] == nil }
        finding.published = published.isEmpty ? nil : published
        finding.sameIssue = same.isEmpty ? nil : same
    }
}

// GitHub Actions advisories come from OSV, whose own lookup doesn't compare versions for this ecosystem, so
// each action's advisories are fetched by name and its affected ranges compared here. A moving tag such as
// v45 points at the newest 45.x release, so it is affected only if no 45.x release fixes the problem.
enum GitHubActions {
    struct Range { let introduced: String?; let fixed: String?; let lastAffected: String? }
    struct Advisory { let id: String; let summary: String; let severity: String?; let aliases: [String]; let ranges: [Range]; var published: Date? = nil }

    // The version a workflow reference stands for, or nil when it can't be told (a branch or a bare commit).
    static func comparable(_ ref: String) -> (version: String, moving: Bool)? {
        guard let match = captures("^v?([0-9]+(?:\\.[0-9]+)*)", ref).first else { return nil }
        let parts = match[1].split(separator: ".").map(String.init)
        return parts.count >= 3 ? (parts.prefix(3).joined(separator: "."), false) : ((parts + ["999999", "999999"]).prefix(3).joined(separator: "."), true)
    }
    static func before(_ a: String, _ b: String) -> Bool {
        if let x = Version(a), let y = Version(b) { return x < y }
        return looseLess(a, b)
    }
    static func affected(_ version: String, _ range: Range) -> Bool {
        if let introduced = range.introduced, introduced != "0", before(version, introduced) { return false }
        if let fixed = range.fixed { return before(version, fixed) }
        if let last = range.lastAffected { return !before(last, version) }
        return true
    }
    static func advisories(_ obj: [String: Any], name: String) -> [Advisory] {
        ((obj["vulns"] as? [[String: Any]]) ?? []).compactMap { vuln in
            guard let id = vuln["id"] as? String else { return nil }
            var ranges: [Range] = []
            for affected in (vuln["affected"] as? [[String: Any]]) ?? [] {
                guard ((affected["package"] as? [String: Any])?["name"] as? String)?.lowercased() == name.lowercased() else { continue }
                for range in (affected["ranges"] as? [[String: Any]]) ?? [] where ["ECOSYSTEM", "SEMVER"].contains(range["type"] as? String ?? "") {
                    var introduced: String?, fixed: String?, last: String?
                    for event in (range["events"] as? [[String: Any]]) ?? [] {
                        if let v = event["introduced"] as? String { if introduced != nil || fixed != nil || last != nil { ranges.append(Range(introduced: introduced, fixed: fixed, lastAffected: last)); fixed = nil; last = nil }; introduced = v }
                        if let v = event["fixed"] as? String { fixed = v }
                        if let v = event["last_affected"] as? String { last = v }
                    }
                    if introduced != nil || fixed != nil || last != nil { ranges.append(Range(introduced: introduced, fixed: fixed, lastAffected: last)) }
                }
            }
            let summary = vuln["summary"] as? String ?? id
            let severity = ((vuln["database_specific"] as? [String: Any])?["severity"] as? String)?.uppercased()
            return ranges.isEmpty ? nil : Advisory(id: id, summary: summary, severity: severity, aliases: vuln["aliases"] as? [String] ?? [], ranges: ranges,
                                                   published: advisoryDate(vuln["published"] as? String))
        }
    }
    static func finding(_ item: Installation, advisories: [Advisory]) -> Finding? {
        guard let (version, moving) = comparable(item.version) else { return nil }
        let hits = advisories.filter { advisory in advisory.ranges.contains { affected(version, $0) } }
        guard !hits.isEmpty else { return nil }
        let fixes = hits.compactMap { advisory in advisory.ranges.compactMap(\.fixed).filter { before(version, $0) }.min(by: before) }
        let fixed = fixes.max(by: before)
        let count = hits.count == 1 ? "1 published advisory" : "\(hits.count) published advisories"
        var reason = count + ": " + hits.prefix(3).map(\.summary).joined(separator: "; ") + (hits.count > 3 ? "; …" : "")
        if moving, let fixed { reason += " @\(item.version) is a moving tag, and no release in that major version fixes this, so the fix means moving to \(fixed) or later." }
        var finding = Finding(source: "osv-actions", installation: item, kind: .security, fixed: fixed ?? "No fixed version published", reason: reason,
                              action: Commands.action(for: item, malicious: false, fixed: fixed), links: hits.prefix(4).map { "https://osv.dev/vulnerability/" + $0.id },
                              advisories: Array(Set(hits.flatMap { [$0.id] + $0.aliases.filter { $0.hasPrefix("CVE-") } })).sorted(), severity: hits.compactMap(\.severity).reduce(nil, worse))
        OSV.dates(&finding, hits.map { ($0.id, $0.aliases, $0.published) })
        return finding
    }
    static func findings(_ items: [Installation]) async throws -> (findings: [Finding], checked: Int, unknown: Int) {
        let actions = items.filter { $0.ecosystem == "GitHub Actions" }
        var byName: [String: [Advisory]] = [:]
        for name in Set(actions.compactMap { $0.packageName?.lowercased() }).sorted() {
            let body = try JSONSerialization.data(withJSONObject: ["package": ["ecosystem": "GitHub Actions", "name": name]])
            guard let obj = try await Fetch.json("https://api.osv.dev/v1/query", body: body) as? [String: Any] else { throw MonitorError(message: "OSV returned an unexpected response") }
            byName[name] = advisories(obj, name: name)
        }
        let checkable = actions.filter { comparable($0.version) != nil }
        let findings = checkable.compactMap { item in finding(item, advisories: byName[item.packageName?.lowercased() ?? ""] ?? []) }
        return (findings, checkable.count, actions.count - checkable.count)
    }
}

// Microsoft publishes every extension it removes from the Visual Studio Marketplace, with the reason. Extensions
// removed as malware, impersonation or untrustworthy are flagged; spam, copyright and owner requests aren't.
// Cursor, Windsurf and VSCodium install from Open VSX, where the same identifier may belong to someone else.
// An npx cache folder records what it was asked to run and why each package is there: package.json's dependencies name
// the tool and package-lock.json has every package's dependency ranges. Together they say whether deleting the folder can
// help, since the next npx run installs the tool again with only what its dependencies allow. Nothing here is executed.
enum NpxCache {
    struct Hold: Equatable {
        let package: String
        let tool: String, version: String      // the tool and its version in this cache
        let dependency: String, range: String  // the tool's own dependency that leads here, and the range it asks for
        let holder: String, holderVersion: String, allows: String  // the package whose range rules out the fix
    }
    struct Release: Equatable { let version: String; let dependencies: [String: String] }
    static func tools(in folder: String) -> [String] {
        ((Inventory.json(folder + "/package.json")?["dependencies"] as? [String: Any]) ?? [:]).keys.sorted()
    }
    // Whether an npm range allows a version. Nil for what isn't a numeric range, such as a tag or a prerelease: unknown is never a hold.
    static func allows(_ range: String, _ version: String) -> Bool? {
        guard let version = Version(version) else { return nil }
        var alternatives: [String] = []
        for alternative in range.components(separatedBy: "||") {
            var clauses: [String] = []
            for word in alternative.split(whereSeparator: \.isWhitespace) {
                guard let clause = comparisons(String(word)) else { return nil }
                clauses.append(clause)
            }
            alternatives.append(clauses.isEmpty ? ">=0" : clauses.joined(separator: ","))
        }
        return version.matches(alternatives.joined(separator: "||"))
    }
    // One word of a range, as the comparisons Version.matches reads: ^1.2.3 is >=1.2.3,<2.0.0.
    private static func comparisons(_ word: String) -> String? {
        if word == "*" || word.lowercased() == "x" { return ">=0" }
        if word.range(of: "^(>=|<=|>|<)v?[0-9]+(\\.[0-9]+)*$", options: .regularExpression) != nil { return word }
        guard let m = captures("^([\\^~=]?)v?([0-9]+)(?:\\.([0-9]+|[xX*]))?(?:\\.([0-9]+|[xX*]))?$", word).first, let major = Int(m[2]) else { return nil }
        let minor = Int(m[3]), patch = Int(m[4])
        let lower = ">=\(major).\(minor ?? 0).\(patch ?? 0)"
        let nextMinor = minor.map { "<\(major).\($0 + 1).0" } ?? "<\(major + 1).0.0"
        switch m[1] {
        case "^":
            if major > 0 || minor == nil { return lower + ",<\(major + 1).0.0" }
            if minor! > 0 || patch == nil { return lower + "," + nextMinor }
            return lower + ",<0.0.\(patch! + 1)"
        case "~": return lower + "," + nextMinor
        default: return minor != nil && patch != nil ? "=\(major).\(minor!).\(patch!)" : lower + "," + nextMinor
        }
    }
    static func exact(_ range: String) -> Bool { Version(range.hasPrefix("=") ? String(range.dropFirst()) : range)?.parts.count == 3 }
    // What rules out `fix`, if anything does for certain: a package whose range excludes it, when that package is the tool
    // or is pinned to one version all the way down from the tool. A range that merely allows an older copy could resolve
    // differently next time, so it isn't a hold.
    static func hold(_ package: String, fix: String, tools: [String], lock: [String: Any]) -> Hold? {
        guard Version(fix) != nil, let packages = lock["packages"] as? [String: [String: Any]] else { return nil }
        struct Entry { let name: String, version: String, dependencies: [String: String] }
        let entries: [Entry] = packages.keys.sorted().compactMap { key in
            guard let name = key.components(separatedBy: "node_modules/").last, !name.isEmpty, let version = packages[key]?["version"] as? String else { return nil }
            var dependencies: [String: String] = [:]
            for field in ["peerDependencies", "optionalDependencies", "dependencies"] { dependencies.merge(packages[key]?[field] as? [String: String] ?? [:]) { $1 } }
            return Entry(name: name, version: version, dependencies: dependencies)
        }
        // The tool and its dependency that pin `name`, following exact versions up from it.
        func anchor(_ name: String, seen: Set<String>) -> (tool: Entry, head: String)? {
            for parent in entries where !seen.contains(parent.name) && parent.dependencies[name].map(exact) == true {
                if tools.contains(parent.name) { return (parent, name) }
                if let found = anchor(parent.name, seen: seen.union([parent.name])) { return found }
            }
            return nil
        }
        for holder in entries.sorted(by: { tools.contains($0.name) && !tools.contains($1.name) }) {
            guard let range = holder.dependencies[package], allows(range, fix) == false else { continue }
            if tools.contains(holder.name) {
                return Hold(package: package, tool: holder.name, version: holder.version, dependency: package, range: range, holder: holder.name, holderVersion: holder.version, allows: range)
            }
            if let (tool, head) = anchor(holder.name, seen: [holder.name]) {
                return Hold(package: package, tool: tool.name, version: tool.version, dependency: head, range: tool.dependencies[head]!, holder: holder.name, holderVersion: holder.version, allows: range)
            }
        }
        return nil
    }
    // The holds among these findings, by finding. Malicious packages are left out: they're removed whatever needs them.
    static func holds(in findings: [Finding]) -> [String: Hold] {
        var holds: [String: Hold] = [:], folders: [String: (tools: [String], lock: [String: Any])] = [:]
        for finding in findings where finding.installation.manager == "npx-cache" && finding.kind == .security && finding.malicious != true {
            guard let folder = finding.installation.location, let package = finding.installation.packageName else { continue }
            if folders[folder] == nil { folders[folder] = (tools(in: folder), Inventory.json(folder + "/package-lock.json") ?? [:]) }
            holds[finding.id] = hold(package, fix: finding.fixed, tools: folders[folder]!.tools, lock: folders[folder]!.lock)
        }
        return holds
    }
    // The tool's newest release, from npm's public registry, which receives its name only.
    static func newest(_ tool: String) async throws -> Release {
        guard let name = Commands.safe(tool, Commands.namePatterns["npm"]!),
              let manifest = try await Fetch.json("https://registry.npmjs.org/" + name.replacingOccurrences(of: "/", with: "%2f") + "/latest") as? [String: Any],
              let version = manifest["version"] as? String else { throw MonitorError(message: "npm's record of \(tool) could not be read") }
        return Release(version: version, dependencies: manifest["dependencies"] as? [String: String] ?? [:])
    }
    // A held package waits for a fix when the tool's newest release asks for the same as the cached one. A newer release
    // that asks for something else may take the fix, so the finding stays an ordinary one whose command makes npx fetch it.
    // Without npm's answer nothing shows a newer release, so one that was waiting keeps waiting.
    static func mark(_ findings: inout [Finding], holds: [String: Hold], newest: [String: Release], waiting: [String: Finding] = [:]) {
        for index in findings.indices {
            let id = findings[index].id
            guard let hold = holds[id] else { continue }
            guard let release = newest[hold.tool] else {
                if let old = waiting[id], old.heldBack != nil, old.installation.version == findings[index].installation.version {
                    findings[index].awaitingFix = true; findings[index].heldBack = old.heldBack; findings[index].action = old.action
                }
                continue
            }
            guard release.version == hold.version || release.dependencies[hold.dependency] == hold.range else { continue }
            let requirement = hold.holder == hold.tool ? "\(hold.tool) \(hold.version) requires \(hold.package) \(hold.allows)"
                : "\(hold.holder) \(hold.holderVersion), pinned by \(hold.tool) \(hold.version), requires \(hold.package) \(hold.allows)"
            let outlook = (release.version == hold.version ? "\(hold.tool) \(hold.version) is its newest release" : "\(hold.tool)'s newest release, \(release.version), asks for the same")
                + ", so deleting the npx cache would only bring this back. \(appName) alerts you when a release allows the fix."
            findings[index].awaitingFix = true
            findings[index].heldBack = HeldBack(tool: hold.tool, requirement: requirement, outlook: outlook)
            findings[index].action = requirement + ", which rules out the fix. " + outlook
        }
    }
}

// Playwright downloads its own Chromium, Firefox and WebKit builds into one cache and never updates them: each release
// names the builds it uses in its browsers.json. Every install that runs `playwright install` leaves a file in the
// cache's .links folder naming its package folder, and the next install by any of them deletes the builds no linked
// package uses. So a build only a newer Playwright can replace waits until a Playwright release ships the fix.
enum Playwright {
    struct Release: Equatable { let version: String; let browsers: [String: String] }  // build kind → browser version
    static let cache = Inventory.home + "/Library/Caches/ms-playwright"
    // "chromium_headless_shell-1243" is kind chromium_headless_shell, revision 1243. ffmpeg and other helpers aren't browsers.
    static func kind(_ folder: String) -> String? {
        captures("^((?:chromium|firefox|webkit)[a-z0-9_]*)-[0-9]+$", folder).first?[1]
    }
    static func product(_ kind: String) -> String { kind.hasPrefix("chromium") ? "playwright-chromium" : kind.hasPrefix("firefox") ? "playwright-firefox" : "playwright-webkit" }
    static func name(_ kind: String) -> String {
        (kind.hasPrefix("chromium") ? "Chromium" : kind.hasPrefix("firefox") ? "Firefox" : "WebKit") + (kind.contains("tip_of_tree") ? " tip-of-tree" : "")
            + (kind.contains("headless_shell") ? " headless shell" : "") + (kind.hasSuffix("_beta") ? " beta" : "")
    }
    // The cache folders a browsers.json names, with the version each is. A revision kept for an older macOS gets a folder of
    // its own, such as webkit_mac14_arm64_special-2251; every one counts as used, so no build is called unused because of it.
    static func folders(_ browsers: [[String: Any]]) -> [(folder: String, version: String?)] {
        browsers.flatMap { browser -> [(folder: String, version: String?)] in
            guard let name = browser["name"] as? String, let revision = browser["revision"] as? String else { return [] }
            let overrides = (browser["revisionOverrides"] as? [String: String] ?? [:]).sorted { $0.key < $1.key }
                .map { (folder: "\(name)_\($0.key)_special".replacingOccurrences(of: "-", with: "_") + "-" + $0.value, version: nil as String?) }
            return [(name.replacingOccurrences(of: "-", with: "_") + "-" + revision, browser["browserVersion"] as? String)] + overrides
        }
    }
    // A build's version from its own files: its app's Info.plist, or for Chromium's headless shell, which has no app, the
    // reading-mode manifest it carries. WebKit's app is numbered 1.0, so WebKit builds go by revision instead.
    static func version(_ path: String) -> String? {
        for child in Inventory.children(path) {
            let folder = path + "/" + child
            for app in [folder] + Inventory.children(folder).map({ folder + "/" + $0 }) where app.hasSuffix(".app") {
                guard let data = Inventory.read(app + "/Contents/Info.plist", limit: 1_000_000),
                      let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
                      let version = info["CFBundleShortVersionString"] as? String, Version(version) != nil else { continue }
                return version
            }
            if let version = Inventory.json(folder + "/resources/accessibility/reading_mode_gdocs_helper_manifest.json", limit: 100_000)?["version"] as? String,
               Version(version)?.parts.count == 4 { return version }
        }
        return nil
    }
    // Where a Playwright package is installed: an npx cache folder, a project (the folder holding its node_modules), or
    // somewhere else, such as global packages.
    static func owner(_ package: String) -> (kind: String, folder: String) {
        if let npx = captures("^(.*/\\.npm/_npx/[^/]+)/", package).first?[1] { return ("npx", npx) }
        let global = ["/lib/node_modules/", "/.bun/install/global/", "/Library/pnpm/global/"].contains { package.contains($0) }
        if !global, let range = package.range(of: "/node_modules/"), Inventory.fm.fileExists(atPath: package[..<range.lowerBound] + "/package.json") {
            return ("project", String(package[..<range.lowerBound]))
        }
        return ("other", package)
    }
    // How a project depends on Playwright, for the command that updates it: the package it lists, whether as a development
    // dependency, and its package manager, from its lockfile.
    static func dependency(in project: String) -> (package: String, dev: Bool, tool: String)? {
        guard let manifest = Inventory.json(project + "/package.json", limit: 4_000_000) else { return nil }
        let dev = manifest["devDependencies"] as? [String: Any] ?? [:], direct = manifest["dependencies"] as? [String: Any] ?? [:]
        guard let package = ["@playwright/test", "playwright", "playwright-core"].first(where: { dev[$0] != nil || direct[$0] != nil }) else { return nil }
        let tool = [("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"), ("bun.lock", "bun"), ("bun.lockb", "bun")].first { Inventory.fm.fileExists(atPath: project + "/" + $0.0) }?.1 ?? "npm"
        return (package, dev[package] != nil, tool)
    }
    // The newest Playwright, from npm's public registry, and the browsers its release ships, from the browsers.json at its
    // tag on GitHub. Both receive Playwright's name and version only.
    static func newest() async throws -> Release {
        guard let manifest = try await Fetch.json("https://registry.npmjs.org/playwright-core/latest") as? [String: Any],
              let version = Commands.safe(manifest["version"] as? String, "^[0-9]+\\.[0-9]+\\.[0-9]+$"),
              let browsers = (try await Fetch.json("https://raw.githubusercontent.com/microsoft/playwright/v\(version)/packages/playwright-core/browsers.json") as? [String: Any])?["browsers"] as? [[String: Any]]
        else { throw MonitorError(message: "Playwright's newest release couldn't be read") }
        var shipped: [String: String] = [:]
        for (folder, browserVersion) in folders(browsers) { if let kind = kind(folder), let browserVersion { shipped[kind] = browserVersion } }
        return Release(version: version, browsers: shipped)
    }
    // A build a Playwright still uses is fixed by updating that Playwright, but only as far as its newest release goes. When
    // that release has none of the fixes, the finding waits; without its answer, one that was waiting keeps waiting.
    static func mark(_ findings: inout [Finding], newest: Release?, hits: (Installation) -> [NVDHit], waiting: [String: Finding] = [:]) {
        for index in findings.indices {
            let finding = findings[index], item = finding.installation
            guard finding.source.hasPrefix("nvd:playwright-"), let kind = kind((item.path as NSString).lastPathComponent) else { continue }
            let next = item.manager == "playwright-npx" ? "Delete the npx install that uses it; its next run fetches the newest release."
                : item.manager == "playwright" ? "Update each Playwright that uses it, then install their browsers. Playwright then deletes this build."
                : "Update Playwright in this project, then install its browsers. Playwright then deletes this build."
            guard let newest else {
                if let old = waiting[finding.id], old.installation.version == item.version {
                    findings[index].awaitingFix = true; findings[index].fixed = old.fixed; findings[index].action = old.action
                } else { findings[index].action = "\(appName) couldn't read which browsers Playwright's newest release ships, so updating may not bring every fix. " + next }
                continue
            }
            let shipped = newest.browsers[kind], all = hits(item)
            let open = all.filter { hit in shipped.flatMap { version in hit.fixed.map { looseLess(version, $0) } } ?? true }
            if open.count == all.count {
                // Google Chrome gets Chromium's fixes first and updates itself, and Playwright can run on it instead.
                let chrome = kind.hasPrefix("chromium") ? " Meanwhile, Playwright can run on Google Chrome, which updates itself, if it's installed: choose the chrome channel (channel: 'chrome' in Playwright's config)." : ""
                findings[index].awaitingFix = true
                findings[index].fixed = finding.fixed == NVD.noFixListed ? "No fix released yet" : "\(finding.fixed), not in Playwright yet"
                findings[index].action = (shipped.map { "Playwright's newest release, \(newest.version), ships \(name(kind)) \($0), which doesn't have these fixes yet." }
                    ?? "Playwright's newest release, \(newest.version), doesn't ship this browser.") + " \(appName) alerts you when a Playwright release has them." + chrome
            } else {
                // The card's target is the build the update installs, which may still lack the newest fixes.
                findings[index].fixed = shipped!
                findings[index].action = "Playwright \(newest.version) ships \(name(kind)) \(shipped!), which has " + (open.isEmpty ? "these fixes. " : "\(all.count - open.count) of these fixes; the other \(open.count) wait for a later release. ") + next
            }
        }
    }
    // A build no Playwright on this Mac uses any more, listed to delete like an older Homebrew copy. It isn't checked for
    // vulnerabilities, since nothing runs it.
    static func unused(_ item: Installation) -> Finding {
        Finding(source: "inventory-playwright", installation: item, kind: .update, fixed: "Delete unused build",
                reason: item.note + " Playwright never updates its browsers, and deletes ones nothing uses only the next time a Playwright here installs browsers.",
                action: "Delete it. A Playwright that needs it again downloads it.", links: ["https://playwright.dev/docs/browsers#managing-browser-binaries"])
    }
}

// An app built on Electron carries its own Chromium, which changes only when the app ships a release on a newer Electron.
// Electron supports its three newest major versions and copies Chrome's security fixes into them, usually within days,
// without changing the Chromium version a release names. So a Chrome vulnerability NVD lists for that Chromium counts
// against an Electron release only if NVD published it more than a week after the release came out: one published
// earlier may have been fixed in it, and NVD can take a week to publish what Chrome has already fixed.
enum Electron {
    struct Release: Equatable { let version: String; let date: Date; let chromium: String }
    struct Releases: Equatable {
        var all: [String: Release] = [:]   // stable releases by version
        var newest: [Int: Release] = [:]   // each major's newest release
        var started: [Int: Date] = [:]     // when each major's first release came out
        var supported: [Int] = []          // the three newest majors, newest first
        // A major stops getting fixes when the major three above it comes out.
        func ended(_ major: Int) -> Date? {
            supported.contains(major) ? nil : started[major + 3] ?? supported.last.flatMap { started[$0] }
        }
    }
    static let source = "https://releases.electronjs.org/releases.json"
    static let timelines = "https://www.electronjs.org/docs/latest/tutorial/electron-timelines"
    static let grace: TimeInterval = 7 * 86_400
    static func major(_ version: String) -> Int? { Int(version.prefix { $0 != "." }) }
    // Electron's release list: every release with its date and Chromium. Alpha, beta and nightly releases are left out.
    static func parse(_ rows: [[String: Any]]) -> Releases {
        var releases = Releases()
        for row in rows {
            guard let version = Commands.safe(row["version"] as? String, "^[0-9]+\\.[0-9]+\\.[0-9]+$"), let major = major(version),
                  let chromium = row["chrome"] as? String, Version(chromium) != nil,
                  let date = advisoryDate(row["fullDate"] as? String) ?? advisoryDate(row["date"] as? String) else { continue }
            let release = Release(version: version, date: date, chromium: chromium)
            releases.all[version] = release
            if releases.newest[major].map({ looseLess($0.version, version) }) ?? true { releases.newest[major] = release }
            if releases.started[major].map({ date < $0 }) ?? true { releases.started[major] = date }
        }
        releases.supported = Array(releases.newest.keys.sorted(by: >).prefix(3))
        return releases
    }
    // Electron's public release list. Nothing about this Mac is sent.
    static func releases() async throws -> Releases {
        guard let rows = try await Fetch.json(source, limit: 40_000_000) as? [[String: Any]] else { throw MonitorError(message: "Electron's release list couldn't be read") }
        let releases = parse(rows)
        guard releases.supported.count == 3 else { throw MonitorError(message: "Electron's release list names too few releases") }
        return releases
    }
    // How many of a finding's advisories an Electron release has the fixes for, by the rule the finding was made with: one
    // published no more than a week after the release came out counts as fixed in it. Complete means every fix, in a
    // major that still gets fixes. An Electron that isn't a public release can't be judged.
    static func fixes(_ finding: Finding, in version: String, releases: Releases) -> (fixes: Int, total: Int, complete: Bool)? {
        guard let release = releases.all[version], let major = major(version) else { return nil }
        let dates = Array((finding.published ?? [:]).values)
        guard version != finding.installation.version else { return (0, dates.count, false) }
        let fixed = dates.filter { $0 <= release.date.addingTimeInterval(grace) }.count
        return (fixed, dates.count, fixed == dates.count && releases.ended(major) == nil)
    }
    // An app's Electron: the Chrome vulnerabilities its Chromium still has, and whether its Electron still gets fixes. The
    // fix is the newest release of its major, or of the oldest major still supported once its own has stopped. An Electron
    // that isn't a public release has no known Chromium, so it gets no finding.
    static func finding(_ item: Installation, releases: Releases, hits: [NVDHit]) -> Finding? {
        guard let release = releases.all[item.version], let major = major(item.version), let oldest = releases.supported.last else { return nil }
        let app = item.bundledApp ?? item.name, cypress = item.manager == "cypress-cache"
        let open = hits.filter { ($0.published ?? .distantFuture) > release.date.addingTimeInterval(grace) }
        let ended = releases.ended(major)
        guard !open.isEmpty || ended != nil else { return nil }
        guard let target = releases.newest[ended == nil ? major : oldest] else { return nil }
        func day(_ date: Date) -> String { date.formatted(date: .abbreviated, time: .omitted) }
        var reason = "\(app) is built on Electron \(item.version), released \(day(release.date)), with Chromium \(release.chromium)."
        if !open.isEmpty {
            let count = open.count == 1 ? "1 Chrome vulnerability" : "\(open.count.formatted()) Chrome vulnerabilities"
            reason += " NVD published \(count) affecting that Chromium more than a week after this release came out, so it doesn't have their fixes."
        }
        if let ended {
            reason += " Electron \(major) stopped getting security fixes on \(day(ended)), when Electron \(major + 3) came out, so this Chromium gets no more of them until \(app) moves to a newer Electron."
        } else {
            reason += target.version == item.version ? " Electron \(major) still gets Chrome's fixes, but no Electron \(major) release has these yet." : " Electron \(major) still gets Chrome's fixes; its newest release is \(target.version)."
        }
        // A cached Cypress app is replaced by updating Cypress, whose newer releases are built on newer Electron.
        let fixed = cypress ? "Newer Cypress" : target.version == item.version ? NVD.noFixListed : target.version
        let action = cypress ? "Update Cypress in the projects that use it (npm install --save-dev cypress@latest), and it downloads a newer app; then delete this one."
            : fixed == NVD.noFixListed ? "No Electron \(major) release has these fixes yet. A newer \(app) may be built on a newer Electron that does." : Commands.action(for: item, malicious: false, fixed: fixed)
        var finding = Finding(source: "nvd:electron", installation: item, kind: open.isEmpty ? .unsupported : .security, fixed: fixed, reason: reason,
                              action: action,
                              links: open.prefix(3).map { "https://nvd.nist.gov/vuln/detail/" + $0.id } + [timelines], advisories: open.map(\.id).sorted(),
                              severity: open.reduce(nil) { worse($0, $1.severity) })
        OSV.dates(&finding, open.map { ($0.id, [], $0.published) })
        return finding
    }
    // Each app's Electron gets one card: Electron's own advisories, from OSV, join the finding about its Chromium, whose
    // fix, a supported Electron release, covers them too. Without that finding they keep a card of their own.
    static func combine(_ findings: inout [Finding]) {
        var merged = Set<String>()
        for own in findings where own.source == "osv" && ["electron-framework", "cypress-cache"].contains(own.installation.manager ?? "") && own.malicious != true {
            guard let index = findings.firstIndex(where: { $0.source == "nvd:electron" && $0.installation.path == own.installation.path }) else { continue }
            // OSV's reason reads "45 published advisories: Electron: <title>; …"; its titles all start with Electron's name.
            let parts = own.reason.components(separatedBy: ": ")
            let count = parts[0].replacingOccurrences(of: "published ", with: "")
            let titles = parts.dropFirst().joined(separator: ": ").replacingOccurrences(of: "Electron: ", with: "")
            var finding = findings[index]
            finding.kind = .security
            finding.reason += " Electron has also published \(count) that affect this release: \(titles)"
            finding.advisories = Array(Set(finding.advisories + own.advisories)).sorted()
            finding.severity = worse(finding.severity, own.severity)
            finding.links += own.links
            finding.published = (finding.published ?? [:]).merging(own.published ?? [:]) { first, _ in first }
            finding.sameIssue = own.sameIssue.map { (finding.sameIssue ?? [:]).merging($0) { first, _ in first } } ?? finding.sameIssue
            findings[index] = finding
            merged.insert(own.id)
        }
        findings.removeAll { merged.contains($0.id) }
    }
}

// What's inside an app's newest release, read from its update zip without downloading it. A zip ends with a directory of
// its files, so four small ranges are enough: the download's size, its end with the directory's place, the directory, and
// the one file wanted, the bundled framework's Info.plist. That's about 200 KB of a 150 MB update. Disk images and
// installer packages can't be read in parts, so their contents stay unknown.
enum ReleasePeek {
    struct Result: Codable, Equatable { var bundles: String?; var modified: Date? }
    struct Entry: Equatable { let offset: Int; let compressed: Int; let size: Int; let method: Int }
    static func readable(_ address: String) -> Bool { URL(string: address).map { $0.scheme == "https" && $0.path.lowercased().hasSuffix(".zip") } ?? false }
    // framework is the bundle's name: "Electron Framework" or "Sparkle".
    static func bundled(_ framework: String, in address: String) async throws -> Result {
        let probe = try await Fetch.range(address, from: 0, to: 0, limit: 1024)
        guard let total = probe.response.value(forHTTPHeaderField: "Content-Range")?.split(separator: "/").last.flatMap({ Int($0) }), total > 22 else {
            throw MonitorError(message: "The download didn't say its size")
        }
        let modified = probe.response.value(forHTTPHeaderField: "Last-Modified").flatMap(httpDate)
        let tail = try await Fetch.range(address, from: max(0, total - 65_558), to: total - 1, limit: 70_000).data
        guard let place = directory(tail, size: total), place.length <= 16_000_000 else { throw MonitorError(message: "The download isn't a zip Shipshape can read") }
        let listing = try await Fetch.range(address, from: place.offset, to: place.offset + place.length - 1, limit: place.length + 1024).data
        guard let entry = entry(framework, in: listing) else { return Result(bundles: nil, modified: modified) }
        guard entry.compressed <= 4_000_000, entry.size <= 4_000_000 else { throw MonitorError(message: "The framework's Info.plist is too large") }
        let local = try await Fetch.range(address, from: entry.offset, to: entry.offset + 30 + 4_096 + entry.compressed - 1, limit: entry.compressed + 8_192).data
        guard let plist = contents(local, entry: entry) else { throw MonitorError(message: "The framework's Info.plist couldn't be read") }
        return Result(bundles: version(framework, plist: plist), modified: modified)
    }
    // Where the zip's directory is, from the end-of-directory record in the download's last bytes (and its zip64 record,
    // when a large zip uses one and it's among those bytes).
    static func directory(_ tail: Data, size: Int) -> (offset: Int, length: Int)? {
        let bytes = [UInt8](tail)
        guard bytes.count >= 22 else { return nil }
        guard let end = stride(from: bytes.count - 22, through: 0, by: -1).first(where: { u32(bytes, $0) == 0x06054b50 }) else { return nil }
        let length = Int(u32(bytes, end + 12)), offset = Int(u32(bytes, end + 16))
        guard length == 0xFFFF_FFFF || offset == 0xFFFF_FFFF else { return (offset, length) }
        guard end >= 20, u32(bytes, end - 20) == 0x07064b50 else { return nil }
        let record = Int(u64(bytes, end - 12)) - (size - bytes.count)
        guard record >= 0, record + 56 <= bytes.count, u32(bytes, record) == 0x06064b50 else { return nil }
        return (Int(u64(bytes, record + 48)), Int(u64(bytes, record + 40)))
    }
    // The framework's Info.plist in the app at the zip's top level, or in one folder: Versions/A or a flattened framework.
    static func entry(_ framework: String, in listing: Data) -> Entry? {
        let bytes = [UInt8](listing)
        let pattern = "^(?:[^/]+/)?[^/]+\\.app/Contents/Frameworks/" + NSRegularExpression.escapedPattern(for: framework) + "\\.framework/(?:Versions/[^/]+/)?Resources/Info\\.plist$"
        var p = 0
        while p + 46 <= bytes.count, u32(bytes, p) == 0x02014b50 {
            let method = Int(u16(bytes, p + 10)), compressed = Int(u32(bytes, p + 20)), size = Int(u32(bytes, p + 24)), offset = Int(u32(bytes, p + 42))
            let nameLength = Int(u16(bytes, p + 28)), extra = Int(u16(bytes, p + 30)), comment = Int(u16(bytes, p + 32))
            guard p + 46 + nameLength <= bytes.count else { return nil }
            let name = String(decoding: bytes[(p + 46)..<(p + 46 + nameLength)], as: UTF8.self)
            if name.range(of: pattern, options: .regularExpression) != nil, method == 0 || method == 8, compressed != 0xFFFF_FFFF, offset != 0xFFFF_FFFF {
                return Entry(offset: offset, compressed: compressed, size: size, method: method)
            }
            p += 46 + nameLength + extra + comment
        }
        return nil
    }
    // A file's bytes from its local header onward: stored as is, or deflated.
    static func contents(_ local: Data, entry: Entry) -> Data? {
        let bytes = [UInt8](local)
        guard bytes.count >= 30, u32(bytes, 0) == 0x04034b50 else { return nil }
        let start = 30 + Int(u16(bytes, 26)) + Int(u16(bytes, 28))
        guard start + entry.compressed <= bytes.count, entry.size > 0 else { return nil }
        let packed = Array(bytes[start..<(start + entry.compressed)])
        if entry.method == 0 { return Data(packed) }
        var output = [UInt8](repeating: 0, count: entry.size)
        let written = compression_decode_buffer(&output, entry.size, packed, packed.count, nil, COMPRESSION_ZLIB)
        return written == entry.size ? Data(output) : nil
    }
    static func version(_ framework: String, plist: Data) -> String? {
        guard let info = (try? PropertyListSerialization.propertyList(from: plist, format: nil)) as? [String: Any] else { return nil }
        if framework == "Sparkle" { return ((info["CFBundleShortVersionString"] ?? info["CFBundleVersion"]) as? String).flatMap(Inventory.trimmedSparkleVersion) }
        return Commands.safe((info["CFBundleVersion"] ?? info["CFBundleShortVersionString"]) as? String, "^[0-9]+\\.[0-9]+\\.[0-9]+(?:-(?:alpha|beta|nightly)\\.[0-9]+)?$")
    }
    static func httpDate(_ text: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return formatter.date(from: text)
    }
    private static func u16(_ b: [UInt8], _ i: Int) -> UInt16 { UInt16(b[i]) | UInt16(b[i + 1]) << 8 }
    private static func u32(_ b: [UInt8], _ i: Int) -> UInt32 { (0..<4).reduce(0) { $0 | UInt32(b[i + $1]) << (8 * UInt32($1)) } }
    private static func u64(_ b: [UInt8], _ i: Int) -> UInt64 { (0..<8).reduce(0) { $0 | UInt64(b[i + $1]) << (8 * UInt64($1)) } }
}

// Apps built with electron-builder's updater name their update feed in Contents/Resources/app-update.yml: a GitHub
// repository's releases or a plain URL. Its latest-mac.yml names the newest release, when it came out and its downloads,
// including the zip the updater installs from, which ReleasePeek can read.
enum ElectronUpdater {
    struct Release: Equatable { let version: String; let date: Date?; let download: String? }
    static func feed(app: String) -> (feed: String, base: String)? {
        guard let data = Inventory.read(app + "/Contents/Resources/app-update.yml", limit: 100_000) else { return nil }
        return feed(String(decoding: data, as: UTF8.self))
    }
    static func feed(_ settings: String) -> (feed: String, base: String)? {
        switch field("provider", settings) {
        case "github":
            guard let owner = Commands.safe(field("owner", settings), "^[A-Za-z0-9_.-]+$"), let repo = Commands.safe(field("repo", settings), "^[A-Za-z0-9_.-]+$") else { return nil }
            let base = "https://github.com/\(owner)/\(repo)/releases/latest/download/"
            return (base + "latest-mac.yml", base)
        case "generic":
            guard let url = field("url", settings), url.hasPrefix("https://"), !url.contains("${") else { return nil }
            let base = url.hasSuffix("/") ? url : url + "/"
            return (base + "latest-mac.yml", base)
        default: return nil
        }
    }
    // The newest release in a latest-mac.yml, with the zip for this Mac's processor: arm64 or x64 in its name, a universal
    // one, or one that names no processor.
    static func release(_ text: String, base: String, machine: String = SparkleFeeds.machine) -> Release? {
        guard let version = field("version", text) else { return nil }
        let zips = captures("(?m)^\\s*-\\s*url:\\s*['\"]?([^'\"\\n]+?)['\"]?\\s*$", text).map { $0[1] }.filter { $0.lowercased().hasSuffix(".zip") }
        let own = machine == "arm64" ? zips.first { $0.contains("arm64") } : zips.first { $0.contains("x64") || $0.contains("x86_64") }
        let pick = own ?? zips.first { $0.contains("universal") } ?? zips.first { !$0.contains("arm64") && !$0.contains("x64") }
        let download = pick.map { $0.hasPrefix("https://") ? $0 : base + ($0.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? $0) }
        return Release(version: version, date: field("releaseDate", text).flatMap(advisoryDate), download: download)
    }
    private static func field(_ key: String, _ text: String) -> String? {
        captures("(?m)^" + key + ":[ \\t]*['\"]?([^'\"\\n]+?)['\"]?[ \\t]*$", text).first?[1]
    }
}

enum EditorExtensions {
    static let source = "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md"
    static let page = "https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md"
    static func removed(_ markdown: String) throws -> [String: (date: String, reason: String)] {
        var list: [String: (date: String, reason: String)] = [:]
        for row in captures("(?m)^\\|\\s*([A-Za-z0-9][A-Za-z0-9-]*\\.[A-Za-z0-9][A-Za-z0-9._-]*)\\s*\\|\\s*([0-9/]+)\\s*\\|\\s*([^|\\r\\n]+?)\\s*\\|", markdown) {
            list[row[1].lowercased()] = (row[2], row[3])
        }
        // Fail closed: a page that no longer looks like the list must not read as "nothing removed".
        guard list.count >= 100 else { throw MonitorError(message: "Microsoft's list of removed extensions wasn't in the expected format") }
        return list
    }
    static func findings(_ items: [Installation], removed: [String: (date: String, reason: String)]) -> [Finding] {
        items.filter { $0.manager == "extension" }.compactMap { item in
            guard let entry = removed[item.name.lowercased()] else { return nil }
            let reason = entry.reason.lowercased()
            let malware = reason.contains("malware")
            guard malware || reason.contains("impersonation") || reason.contains("untrustworthy") else { return nil }
            let editor = item.package ?? "the editor"
            let openVSX = editor != "VS Code" && editor != "VS Code Insiders"
            return Finding(source: "vs-marketplace", installation: item, kind: .security, fixed: "Remove this extension",
                           reason: "Microsoft removed \(item.name) from the Visual Studio Marketplace on \(entry.date) (\(entry.reason))."
                               + (openVSX ? " \(editor) installs extensions from Open VSX, where this identifier may belong to a different publisher; check who published yours." : ""),
                           action: "Uninstall it" + (malware ? ", then assume anything it could reach is exposed: tokens, SSH keys and files in your projects." : ", then reinstall the genuine extension if you need it."),
                           links: [page], severity: malware ? "CRITICAL" : "HIGH", malicious: malware && !openVSX ? true : nil)
        }
    }
}

// Self-updating apps name their Sparkle update feed (an RSS "appcast") in SUFeedURL. Each item names a
// release by build number (sparkle:version, compared with the app's CFBundleVersion as Sparkle does) and
// usually a readable version. Beta channels, other platforms and releases needing a newer macOS are skipped.
enum SparkleFeeds {
    struct Release: Equatable {
        var build: String; var version: String?; var minimumSystem: String?
        var date: Date? = nil              // pubDate
        var rollout: TimeInterval? = nil   // sparkle:phasedRolloutInterval: copies get the release in seven groups this far apart
        var hardware: [String]? = nil      // sparkle:hardwareRequirements, such as arm64
        var url: String? = nil             // the enclosure's download
    }
    final class Reader: NSObject, XMLParserDelegate {
        var releases: [Release] = []
        private var inItem = false, current = Release(build: ""), element = "", text = "", skip = false
        private static func local(_ name: String) -> String { name.split(separator: ":").last.map(String.init) ?? name }
        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String] = [:]) {
            if name == "item" { inItem = true; current = Release(build: ""); skip = false }
            guard inItem else { return }
            element = name; text = ""
            if name == "enclosure" {
                current.url = attributes["url"]
                for (key, value) in attributes where key.contains(":") {
                    switch Self.local(key) {
                    case "version": current.build = value
                    case "shortVersionString": current.version = value
                    case "os": if value.lowercased() != "macos" { skip = true }
                    default: break
                    }
                }
            }
        }
        func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }
        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            guard inItem else { return }
            let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if name.contains(":") {
                switch Self.local(name) {
                case "version": if !value.isEmpty { current.build = value }
                case "shortVersionString": if !value.isEmpty { current.version = value }
                case "minimumSystemVersion": current.minimumSystem = value
                case "phasedRolloutInterval": current.rollout = TimeInterval(value)
                case "hardwareRequirements": current.hardware = value.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init)
                case "channel": skip = true
                default: break
                }
            }
            if name == "pubDate" { current.date = SparkleFeeds.date(value) }
            if name == "item" {
                inItem = false
                if !skip && !current.build.isEmpty { releases.append(current) }
            }
            text = ""
        }
    }
    static func releases(_ data: Data) -> [Release] {
        let parser = XMLParser(data: data), reader = Reader()
        parser.shouldResolveExternalEntities = false
        parser.delegate = reader
        return parser.parse() ? reader.releases : []
    }
    static func older(_ a: String, _ b: String) -> Bool {
        if let x = Version(a), let y = Version(b) { return x < y }
        return looseLess(a, b)
    }
    static func date(_ text: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        for format in ["EEE, dd MMM yyyy HH:mm:ss Z", "EEE, dd MMM yyyy HH:mm:ss zzz", "dd MMM yyyy HH:mm:ss Z", "EEE, d MMM yyyy HH:mm:ss Z"] {
            formatter.dateFormat = format
            if let date = formatter.date(from: text) { return date }
        }
        return nil
    }
    static let machine: String = {
        #if arch(arm64)
        return "arm64"
        #else
        return "x86_64"
        #endif
    }()
    // Releases this Mac can install: its macOS is new enough and its processor is one the release lists, if any.
    static func installable(_ releases: [Release], system: String, machine: String = machine) -> [Release] {
        let macOS = captures("([0-9]+(?:\\.[0-9]+)*)", system).first?[1] ?? "99"
        return releases.filter { ($0.minimumSystem.map { !older(macOS, $0) } ?? true) && ($0.hardware.map { $0.contains(machine) } ?? true) }
    }
    // The newest release this Mac can install, if any.
    static func newest(_ releases: [Release], system: String = ProcessInfo.processInfo.operatingSystemVersionString, machine: String = machine) -> Release? {
        installable(releases, system: system, machine: machine).max { older($0.build, $1.build) }
    }
    // A self-updating app installs a new release itself, but not the moment its feed lists it: Sparkle checks about
    // daily, may wait to install until the app quits, and phased rollouts reach copies in seven groups. So a newer
    // release counts as something to install once it has been out a week, or through its whole rollout.
    static let grace: TimeInterval = 7 * 86_400
    static func settled(_ release: Release, now: Date = Date()) -> Bool {
        guard let date = release.date else { return true }
        return now.timeIntervalSince(date) >= max(grace, 7 * (release.rollout ?? 0))
    }
    // The newest of the app's newer releases when all of them are too recent to count yet; nil when the app is
    // current or a newer release has been out long enough.
    static func fresh(_ item: Installation, releases: [Release], system: String = ProcessInfo.processInfo.operatingSystemVersionString,
                      machine: String = machine, now: Date = Date()) -> Release? {
        guard let installed = item.build ?? Optional(item.version) else { return nil }
        let newer = installable(releases, system: system, machine: machine).filter { older(installed, $0.build) }
        guard !newer.isEmpty, !newer.contains(where: { settled($0, now: now) }) else { return nil }
        return newer.max { older($0.build, $1.build) }
    }
    static func finding(_ item: Installation, releases: [Release], system: String = ProcessInfo.processInfo.operatingSystemVersionString) -> Finding? {
        guard let installed = item.build ?? Optional(item.version), let release = newest(releases, system: system), older(installed, release.build) else { return nil }
        let version = release.version ?? release.build
        return Finding(source: "sparkle-feed", installation: item, kind: .update, fixed: version,
                       reason: "\(item.name)'s own update feed lists \(version)\(release.version != nil && release.version != release.build ? " (build \(release.build))" : "") as its newest release. This alone does not establish a security vulnerability.",
                       action: "Open \(item.name) and check for updates, or download the release from its developer.", links: [])
    }
    // Whether the app already has the newest release its feed offers this Mac.
    // Whether a Sparkle version has a finding's fix: at least the fixed version OSV names. All or none, since OSV's fixes
    // aren't kept per advisory.
    static func fixes(_ finding: Finding, in version: String) -> (fixes: Int, total: Int, complete: Bool) {
        let total = max((finding.published ?? [:]).count, 1)
        guard let fix = Commands.safe(finding.fixed, "^[0-9][a-z0-9.+_-]*$"), !looseLess(version, fix) else { return (0, total, false) }
        return (total, total, true)
    }
    static func current(_ item: Installation, releases: [Release], system: String = ProcessInfo.processInfo.operatingSystemVersionString) -> Bool {
        guard let installed = item.build ?? Optional(item.version), let release = newest(releases, system: system) else { return false }
        return !older(installed, release.build)
    }
    static func findings(_ items: [Installation], skipping paths: Set<String>) async
        -> (findings: [Finding], current: Set<String>, fresh: [String: Release], newest: [String: Release], read: Int, unreadable: Int) {
        let apps = items.filter { $0.feed != nil && !paths.contains($0.path) }
        var findings: [Finding] = [], current = Set<String>(), fresh: [String: Release] = [:], newest: [String: Release] = [:], read = 0, unreadable = 0
        await withTaskGroup(of: (Installation, Data?).self) { group in
            for app in apps { group.addTask { (app, try? await Fetch.data(app.feed!, limit: 5_000_000)) } }
            for await (app, data) in group {
                guard let data else { unreadable += 1; continue }
                let releases = Self.releases(data)
                if releases.isEmpty { unreadable += 1; continue }
                read += 1
                if let release = Self.newest(releases) { newest[app.path] = release }
                if let finding = finding(app, releases: releases) {
                    findings.append(finding)
                    if let release = Self.fresh(app, releases: releases) { fresh[app.path] = release }
                } else if Self.current(app, releases: releases) { current.insert(app.path) }
            }
        }
        return (findings, current, fresh, newest, read, unreadable)
    }
}

// NVD CVE configurations for catalog products identified by CPE. Matches need explicit version bounds
// or an exact version; unbounded "all versions" entries and other-platform configurations are ignored.
enum NVD {
    static func hits(cpe: String, version: String) async throws -> [NVDHit] {
        guard let installed = Version(version) else { throw MonitorError(message: "Version format needs manual review") }
        var hits: [NVDHit] = [], start = 0, total = 1
        while start < total {
            let url = "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:\(cpe)&versionStart=\(version)&versionStartType=including&versionEnd=\(version)&versionEndType=including&noRejected&resultsPerPage=2000&startIndex=\(start)"
            let obj: [String: Any]
            do { obj = try await Fetch.json(url, limit: 80_000_000) as? [String: Any] ?? [:] }
            catch { try await Task.sleep(nanoseconds: 12_000_000_000); obj = try await Fetch.json(url, limit: 80_000_000) as? [String: Any] ?? [:] }
            guard let rows = obj["vulnerabilities"] as? [[String: Any]], let count = obj["totalResults"] as? Int else { throw MonitorError(message: "NVD returned an unexpected response") }
            total = count
            hits += rows.compactMap { ($0["cve"] as? [String: Any]).flatMap { evaluate($0, cpe: cpe, version: installed) } }
            start += 2000
            if start < total { try await Task.sleep(nanoseconds: 6_500_000_000) }
        }
        return hits
    }
    static func evaluate(_ cve: [String: Any], cpe: String, version: Version) -> NVDHit? {
        guard let id = cve["id"] as? String else { return nil }
        for configuration in (cve["configurations"] as? [[String: Any]]) ?? [] {
            var hit = false, fixed: String? = nil, platforms: [String] = []
            for node in (configuration["nodes"] as? [[String: Any]]) ?? [] where node["negate"] as? Bool != true {
                for match in (node["cpeMatch"] as? [[String: Any]]) ?? [] {
                    guard let criteria = match["criteria"] as? String else { continue }
                    if criteria.hasPrefix("cpe:2.3:o:") { platforms.append(criteria) }
                    guard criteria.hasPrefix("cpe:2.3:a:" + cpe + ":"), match["vulnerable"] as? Bool == true,
                          let result = affects(match, criteria: criteria, version: version), result.hit else { continue }
                    hit = true
                    fixed = result.fixed ?? fixed
                }
            }
            guard hit else { continue }
            if configuration["operator"] as? String == "AND", !platforms.isEmpty, !platforms.contains(where: { $0.contains(":apple:") }) { continue }
            return NVDHit(id: id, fixed: fixed, severity: severity(cve), expected: fixed == nil ? expectedFix(cve, version: version) : nil, published: advisoryDate(cve["published"] as? String))
        }
        return nil
    }
    static func affects(_ match: [String: Any], criteria: String, version: Version) -> (hit: Bool, fixed: String?)? {
        let fields = criteria.components(separatedBy: ":")
        let exact = fields.count > 5 ? fields[5] : "*", update = fields.count > 6 ? fields[6] : "*"
        guard update == "*" || update == "-" else { return nil }  // pre-release CPEs such as 3.15.0:alpha1
        if exact != "*" && exact != "-" { return Version(exact).map { ($0 == version, nil) } }
        let endExcluding = match["versionEndExcluding"] as? String
        let bounds = ["versionStartIncluding", "versionStartExcluding", "versionEndExcluding", "versionEndIncluding"].compactMap { key in (match[key] as? String).map { (key, $0) } }
        guard !bounds.isEmpty else { return nil }
        for (key, value) in bounds {
            guard let bound = Version(value) else { return nil }
            let inside: Bool
            switch key {
            case "versionStartIncluding": inside = version >= bound
            case "versionStartExcluding": inside = version > bound
            case "versionEndExcluding": inside = version < bound
            default: inside = version <= bound
            }
            if !inside { return (false, nil) }
        }
        return (true, endExcluding)
    }
    static func severity(_ cve: [String: Any]) -> String? {
        let metrics = cve["metrics"] as? [String: Any] ?? [:]
        for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"] {
            if let value = ((metrics[key] as? [[String: Any]])?.first?["cvssData"] as? [String: Any])?["baseSeverity"] as? String { return value }
        }
        return (metrics["cvssMetricV2"] as? [[String: Any]])?.first?["baseSeverity"] as? String
    }
    // Descriptions often name the fix ("before 1.22.3") when the configuration only says "through 1.22.2".
    // The lowest such version above the installed one is the expected fix.
    static func expectedFix(_ cve: [String: Any], version: Version) -> String? {
        let text = ((cve["descriptions"] as? [[String: Any]]) ?? []).first { $0["lang"] as? String == "en" }?["value"] as? String ?? ""
        return captures("\\bbefore (?:version )?v?([0-9]+(?:\\.[0-9]+)+)", text).map { $0[1] }
            .filter { Version($0).map { version < $0 } ?? false }.min(by: looseLess)
    }
    static let noFixListed = "No fixed version listed"
    static func branch(_ version: String) -> String { version.split(separator: ".").prefix(2).joined(separator: ".") }
    // A project's CVE records, and so NVD's, can give one range for every branch ("before 3.13.14") though each branch
    // got the fix in a release of its own. OSV works out the affected releases from the fix commits, and a maintenance
    // branch's releases are listed only when a fix landed after them. So a release past all of those in its branch has
    // the fix, and otherwise the release after them does. A branch with none listed tells us nothing, so the hit stands.
    static func inBranch(_ hit: NVDHit, version: String, affected: [String]) -> NVDHit? {
        let branch = Self.branch(version)
        let releases = affected.map { $0.hasPrefix("v") ? String($0.dropFirst()) : $0 }
            .filter { Self.branch($0) == branch && $0.range(of: "^[0-9]+\\.[0-9]+\\.[0-9]+$", options: .regularExpression) != nil }
        guard let newest = releases.max(by: looseLess) else { return hit }
        if looseLess(newest, version) { return nil }
        if let fixed = hit.fixed, Self.branch(fixed) == branch { return hit }
        let parts = newest.split(separator: ".").map(String.init)
        return NVDHit(id: hit.id, fixed: "\(parts[0]).\(parts[1]).\((Int(parts[2]) ?? 0) + 1)", severity: hit.severity, expected: hit.expected, published: hit.published)
    }
    static func affectedReleases(_ id: String, repository: String) async -> [String] {
        guard id.range(of: "^CVE-[0-9]+-[0-9]+$", options: .regularExpression) != nil,
              let obj = (try? await Fetch.json("https://api.osv.dev/v1/vulns/" + id)) as? [String: Any] else { return [] }
        return ((obj["affected"] as? [[String: Any]]) ?? []).filter { entry in
            ((entry["ranges"] as? [[String: Any]]) ?? []).contains { $0["repo"] as? String == repository }
        }.flatMap { $0["versions"] as? [String] ?? [] }
    }
    // Answers from OSV are kept for the check, since every Python on a Mac shares most of its CVEs.
    static func branchHits(_ hits: [NVDHit], version: String, repository: String, releases: inout [String: [String]]) async -> NVDCacheEntry {
        var kept: [NVDHit] = [], backported: [String] = []
        for hit in hits {
            if releases[hit.id] == nil { releases[hit.id] = await affectedReleases(hit.id, repository: repository) }
            if let result = inBranch(hit, version: version, affected: releases[hit.id]!) { kept.append(result) } else { backported.append(hit.id) }
        }
        return NVDCacheEntry(date: Date(), hits: kept, backported: backported)
    }
    // For a product with several supported branches, the fix is the one in the installed branch, such as 3.12.14
    // for Python 3.12.13. NVD sometimes lists a fix only as a release in a newer branch ("before 3.13.14"); that
    // becomes the fix only when nothing in the installed branch is listed, and is mentioned otherwise.
    static func finding(_ item: Installation, product: Product, hits: [NVDHit]) -> Finding? {
        guard !hits.isEmpty else { return nil }
        let unknown = hits.filter { $0.fixed == nil }.count
        let branch = product.branches ? Self.branch(item.version) : nil
        let fixes = hits.compactMap(\.fixed), inBranch = fixes.filter { branch == nil || Self.branch($0) == branch }
        let elsewhere = inBranch.isEmpty ? [] : fixes.filter { branch != nil && Self.branch($0) != branch }
        let listed = (inBranch.isEmpty ? fixes : inBranch).max(by: looseLess), expected = listed == nil ? hits.compactMap(\.expected).max(by: looseLess) : nil
        let count = hits.count == 1 ? "1 NVD-listed vulnerability affects" : "\(hits.count.formatted()) NVD-listed vulnerabilities affect"
        let reason = count + " this version" + (unknown > 0 ? "; \(unknown) list no fixed version" : "")
            + (elsewhere.isEmpty ? "" : "; \(elsewhere.count) list\(elsewhere.count == 1 ? "s" : "") a fix only in a newer \(product.name) (\(elsewhere.max(by: looseLess)!))") + ". NVD can lag vendor advisories"
            + (item.domain == "brew" ? ", and Homebrew sometimes ships patches without changing the version." : ".")
            + (expected.map { " The advisory text names \($0) as the fix." } ?? "")
        let onlyNewer = listed.flatMap { fix in branch.map { Self.branch(fix) != $0 } } == true
        var finding = Finding(source: "nvd:" + product.id, installation: item, kind: .security, fixed: listed ?? expected ?? noFixListed,
                              reason: reason, action: onlyNewer ? "No \(product.name) \(branch!) release has every fix, so the way out is a newer \(product.name)." : "Install the update below, then restart programs that use it.",
                              links: hits.prefix(3).map { "https://nvd.nist.gov/vuln/detail/" + $0.id }, advisories: hits.map(\.id).sorted(),
                              severity: hits.reduce(nil) { worse($0, $1.severity) }, expectedFix: expected)
        OSV.dates(&finding, hits.map { ($0.id, [], $0.published) })
        return finding
    }
}
