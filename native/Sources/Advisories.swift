import Foundation

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
    static func current(_ item: Installation, releases: [Release], system: String = ProcessInfo.processInfo.operatingSystemVersionString) -> Bool {
        guard let installed = item.build ?? Optional(item.version), let release = newest(releases, system: system) else { return false }
        return !older(installed, release.build)
    }
    static func findings(_ items: [Installation], skipping paths: Set<String>) async
        -> (findings: [Finding], current: Set<String>, fresh: [String: Release], read: Int, unreadable: Int) {
        let apps = items.filter { $0.feed != nil && !paths.contains($0.path) }
        var findings: [Finding] = [], current = Set<String>(), fresh: [String: Release] = [:], read = 0, unreadable = 0
        await withTaskGroup(of: (Installation, Data?).self) { group in
            for app in apps { group.addTask { (app, try? await Fetch.data(app.feed!, limit: 5_000_000)) } }
            for await (app, data) in group {
                guard let data else { unreadable += 1; continue }
                let releases = Self.releases(data)
                if releases.isEmpty { unreadable += 1; continue }
                read += 1
                if let finding = finding(app, releases: releases) {
                    findings.append(finding)
                    if let release = Self.fresh(app, releases: releases) { fresh[app.path] = release }
                } else if Self.current(app, releases: releases) { current.insert(app.path) }
            }
        }
        return (findings, current, fresh, read, unreadable)
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
        let count = hits.count == 1 ? "1 NVD-listed vulnerability affects" : "\(hits.count) NVD-listed vulnerabilities affect"
        let reason = count + " this version" + (unknown > 0 ? "; \(unknown) list no fixed version" : "")
            + (elsewhere.isEmpty ? "" : "; \(elsewhere.count) list\(elsewhere.count == 1 ? "s" : "") a fix only in a newer \(product.name) (\(elsewhere.max(by: looseLess)!))") + ". NVD can lag vendor advisories"
            + (item.domain == "brew" ? ", and Homebrew sometimes ships patches without changing the version." : ".")
            + (expected.map { " The advisory text names \($0) as the fix." } ?? "")
        var finding = Finding(source: "nvd:" + product.id, installation: item, kind: .security, fixed: listed ?? expected ?? noFixListed,
                              reason: reason, action: "Install the update below, then restart programs that use it.",
                              links: hits.prefix(3).map { "https://nvd.nist.gov/vuln/detail/" + $0.id }, advisories: hits.map(\.id).sorted(),
                              severity: hits.reduce(nil) { worse($0, $1.severity) }, expectedFix: expected)
        OSV.dates(&finding, hits.map { ($0.id, [], $0.published) })
        return finding
    }
}
