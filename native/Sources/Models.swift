import Foundation

struct Version: Comparable, Equatable {
    let parts: [Int]
    init?(_ value: String) {
        let clean = value.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "^v", with: "", options: .regularExpression)
        guard clean.range(of: "^[0-9]+(\\.[0-9]+)*$", options: .regularExpression) != nil else { return nil }
        let parsed = clean.split(separator: ".").map { Int($0) }
        guard !parsed.contains(nil) else { return nil }  // a component too large for Int would otherwise vanish
        parts = parsed.compactMap { $0 }
    }
    static func < (a: Version, b: Version) -> Bool {
        for i in 0..<max(a.parts.count, b.parts.count) {
            let x = i < a.parts.count ? a.parts[i] : 0, y = i < b.parts.count ? b.parts[i] : 0
            if x != y { return x < y }
        }
        return false
    }
    static func == (a: Version, b: Version) -> Bool { !(a < b) && !(b < a) }
    var major: Int { parts[0] }
    var branch: String { parts.prefix(2).map(String.init).joined(separator: ".") }
    // Only accept explicit numeric ranges. Unsupported syntax is unknown, never safe.
    func matches(_ expression: String) -> Bool? {
        let alternatives = expression.components(separatedBy: "||")
        var any = false
        for alternative in alternatives {
            let clauses = alternative.split(separator: ",", omittingEmptySubsequences: false)
            guard !clauses.isEmpty else { return nil }
            var all = true
            for clause in clauses {
                let text = clause.trimmingCharacters(in: .whitespacesAndNewlines)
                guard let m = captures("^(>=|<=|>|<|=)?\\s*(v?[0-9]+(?:\\.[0-9]+)*)$", text).first,
                      let other = Version(m[2]) else { return nil }
                switch m[1] {
                case ">=": all = all && self >= other
                case "<=": all = all && self <= other
                case ">": all = all && self > other
                case "<": all = all && self < other
                default: all = all && self == other
                }
            }
            any = any || all
        }
        return any
    }
}

func captures(_ pattern: String, _ text: String) -> [[String]] {
    guard let re = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators, .caseInsensitive]) else { return [] }
    return re.matches(in: text, range: NSRange(text.startIndex..., in: text)).map { match in
        (0..<match.numberOfRanges).map { index in
            Range(match.range(at: index), in: text).map { String(text[$0]) } ?? ""
        }
    }
}
func plain(_ html: String) -> String {
    html.replacingOccurrences(of: "<[^>]+>", with: " ", options: .regularExpression)
        .replacingOccurrences(of: "&nbsp;", with: " ").replacingOccurrences(of: "&amp;", with: "&")
        .replacingOccurrences(of: "&#39;", with: "'").replacingOccurrences(of: "&quot;", with: "\"")
        .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression).trimmingCharacters(in: .whitespacesAndNewlines)
}
func higher(_ a: String, _ b: String) -> String {
    guard let av = Version(a), let bv = Version(b) else { return b }
    return av > bv ? a : b
}
// Package ecosystems use pre-release and date suffixes. This ordering only picks fix targets and update
// candidates; advisory applicability comes from OSV, NVD or vendor ranges, never from this comparison.
// The first dotted number anywhere in the text is the version, so "Build 4215", "r3222" and "v1.2" compare
// by 4215, 3222 and 1.2; whatever follows it (a pre-release or date suffix) only breaks ties.
func looseLess(_ a: String, _ b: String) -> Bool {
    func split(_ value: String) -> ([Int], String) {
        guard let range = value.range(of: "[0-9]+(\\.[0-9]+)*", options: .regularExpression) else { return ([], value) }
        return (value[range].split(separator: ".").compactMap { Int($0) }, String(value[range.upperBound...]))
    }
    let (x, xs) = split(a), (y, ys) = split(b)
    for i in 0..<max(x.count, y.count) {
        let p = i < x.count ? x[i] : 0, q = i < y.count ? y[i] : 0
        if p != q { return p < q }
    }
    if xs.isEmpty != ys.isEmpty { return !xs.isEmpty }
    return xs.localizedStandardCompare(ys) == .orderedAscending
}
// Homebrew versions end with a rebuild number (26.12.1_1). A rebuild of the same version counts as newer.
func homebrewOlder(_ installed: String, _ newest: String) -> Bool {
    func split(_ value: String) -> (String, Int) { let parts = value.components(separatedBy: "_"); return (parts[0], parts.count > 1 ? Int(parts[1]) ?? 0 : 0) }
    let (version, rebuild) = split(installed), (target, targetRebuild) = split(newest)
    return looseLess(version, target) || (!looseLess(target, version) && rebuild < targetRebuild)
}
// The same release written two ways ("Build 4215" and "4215", "1.2" and "1.2.0"). A Homebrew rebuild
// (15.0.0_1 against 15.0.0) is a different release. Text without any number never matches.
func sameRelease(_ a: String, _ b: String) -> Bool {
    guard a.contains(where: \.isNumber), b.contains(where: \.isNumber) else { return false }
    return !homebrewOlder(a, b) && !homebrewOlder(b, a)
}
let severityRank = ["LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4]
func worse(_ a: String?, _ b: String?) -> String? { (severityRank[a ?? ""] ?? 0) >= (severityRank[b ?? ""] ?? 0) ? a : b }

struct Installation: Codable, Identifiable, Hashable {
    var id: String { path }
    let product: String
    let name: String
    let version: String
    let path: String
    let domain: String
    var package: String? = nil
    var note: String = ""
    var ecosystem: String? = nil   // OSV ecosystem for package-level advisories
    var packageName: String? = nil
    var manager: String? = nil     // update route; see Commands
    var location: String? = nil    // project folder, interpreter, prefix or config the manager acts on
    var dependency: String? = nil  // project packages: direct, dev or transitive
    var pinned: Bool? = nil        // pinned in Homebrew, which refuses to upgrade it
    var file: String? = nil        // the lockfile or settings file a project package or MCP server was read from
    var build: String? = nil       // an app's CFBundleVersion, which its Sparkle feed is compared with
    var feed: String? = nil        // an app's https Sparkle update feed (SUFeedURL)
    // Reports saved before `file` existed joined the file and package with "#", which a folder name can contain.
    var sourceFile: String { file ?? String(path.prefix { $0 != "#" }) }
    // The app a bundled Sparkle belongs to; its entry is named "Sparkle in <app>".
    var sparkleApp: String? { manager == "sparkle-framework" ? String(name.dropFirst("Sparkle in ".count)) : nil }
}
enum FindingKind: String, Codable { case security, unsupported, update }
// One way to install an update. A Terminal command is copied for the user to run; a link, app or file is
// opened when the user clicks it. `text` is the command itself or the button's label.
struct UpdateCommand: Codable, Hashable {
    let text: String
    let note: String
    var kind: String? = nil    // nil: Terminal command; "link", "app" or "file"
    var target: String? = nil  // URL, application path or file path for the other kinds
    var template: [String]? = nil  // for combining: text is template.joined(separator: argument)
    var argument: String? = nil
}
struct Finding: Codable, Identifiable {
    var id: String { source + "|" + installation.path }
    let source: String
    let installation: Installation
    var kind: FindingKind
    var fixed: String
    var reason: String
    var action: String
    var links: [String]
    var advisories: [String] = []
    var exploited: Bool = false
    var stale: Bool = false
    var severity: String? = nil
    var malicious: Bool? = nil
    var commands: [UpdateCommand]? = nil
    var expectedFix: String? = nil    // fix version named only in an advisory's description
    var awaitingFix: Bool? = nil      // newest release installed and no fixed release yet: nothing to install
    var blocked: String? = nil        // why this account can't make the change; its commands are left out (see Ownership)
    var fingerprint: String { [id, installation.version, kind.rawValue, fixed, advisories.sorted().joined(separator: ","), String(exploited)].joined(separator: "|") }
}
// Findings whose recommended Terminal command is the same, or built from the same template (brew upgrade a,
// brew upgrade b), are shown as one card with one combined command. Groups keep the list's order, so a group
// sits where its most urgent member would.
struct FindingGroup: Identifiable {
    let id: String
    let findings: [Finding]
    var command: UpdateCommand? {
        guard findings.count > 1, findings[0].blocked == nil, let first = findings[0].commands?.first else { return nil }
        guard let template = first.template else { return first }
        var arguments: [String] = []
        for finding in findings { if let argument = finding.commands?.first?.argument, !arguments.contains(argument) { arguments.append(argument) } }
        return UpdateCommand(text: template.joined(separator: arguments.joined(separator: " ")), note: first.note, template: template)
    }
}
// Findings this account can't fix share a card per place and reason, such as one project owned by someone
// else; others group by their Terminal command or its template; the rest stand alone.
func groupKey(_ finding: Finding) -> String {
    if let blocked = finding.blocked { return "blocked|" + (finding.installation.location ?? "") + "|" + blocked }
    guard let command = finding.commands?.first, command.kind == nil else { return "finding|" + finding.id }
    if let template = command.template { return "template|" + template.joined(separator: "\u{1}") }
    return "command|" + command.text
}
func groupByCommand(_ findings: [Finding]) -> [FindingGroup] {
    var order: [String] = [], members: [String: [Finding]] = [:]
    for finding in findings {
        let key = groupKey(finding)
        if members[key] == nil { order.append(key) }
        members[key, default: []].append(finding)
    }
    return order.map { FindingGroup(id: $0, findings: members[$0]!) }
}
// The kinds of action a finding needs, most urgent first. Each finding belongs to exactly one; the Security page
// shows a tile for each.
enum FindingCategory: Int, CaseIterable, Identifiable, Comparable {
    case malicious, exploited, security, unsupported, waiting, updates
    var id: Int { rawValue }
    static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    init(of finding: Finding) {
        if finding.malicious == true { self = .malicious }
        else if finding.exploited && finding.kind != .update { self = .exploited }
        else if finding.awaitingFix == true { self = .waiting }
        else {
            switch finding.kind {
            case .security: self = .security
            case .unsupported: self = .unsupported
            case .update: self = .updates
            }
        }
    }
    var title: String {
        switch self {
        case .malicious: return "Malicious packages"
        case .exploited: return "Known exploitation"
        case .security: return "Security fixes"
        case .unsupported: return "End of support"
        case .waiting: return "Waiting for a fix"
        case .updates: return "Updates"
        }
    }
    var detail: String {
        switch self {
        case .malicious: return "Reported as malware. Remove them, then rotate secrets they could reach."
        case .exploited: return "Attackers are using these flaws now. Fix these first."
        case .security: return "A released version fixes a published advisory."
        case .unsupported: return "These versions no longer get security fixes."
        case .waiting: return "You have the newest release. \(appName) alerts you when a fix ships."
        case .updates: return "Newer releases with no confirmed security fix."
        }
    }
    var symbol: String {
        switch self {
        case .malicious: return "ladybug"
        case .exploited: return "flame"
        case .security: return "exclamationmark.shield"
        case .unsupported: return "calendar.badge.exclamationmark"
        case .waiting: return "hourglass"
        case .updates: return "arrow.down.circle"
        }
    }
    var urgent: Bool { self == .malicious || self == .exploited }
    // Everything to act on now; waiting findings and plain updates are left out.
    var needsAttention: Bool { self < .waiting }
    static func counts(in report: ScanReport) -> [FindingCategory: Int] {
        report.findings.reduce(into: [:]) { $0[FindingCategory(of: $1), default: 0] += 1 }
    }
    static func attentionTitle(_ count: Int) -> String {
        count == 0 ? "Nothing needs attention" : count == 1 ? "1 item needs attention" : "\(count) items need attention"
    }
    // Inventory items by the category of their most urgent finding. An item counts as waiting only when all its
    // findings are, since anything else on it is still something to do. Items without findings aren't counted.
    static func items(in report: ScanReport) -> [FindingCategory: Int] {
        func rank(_ category: FindingCategory) -> Int { category == .waiting ? Int.max : category.rawValue }
        var worst: [String: FindingCategory] = [:]
        for finding in report.findings {
            let category = FindingCategory(of: finding), current = worst[finding.installation.id] ?? category
            worst[finding.installation.id] = rank(category) < rank(current) ? category : current
        }
        return worst.values.reduce(into: [:]) { $0[$1, default: 0] += 1 }
    }
    // Inventory items with nothing left to do: no findings, or only findings waiting for a fixed release.
    static func settled(in report: ScanReport) -> Int {
        max(0, report.installations.count - items(in: report).filter { $0.key != .waiting }.values.reduce(0, +))
    }
}
struct NVDHit: Codable, Hashable {
    let id: String
    let fixed: String?
    let severity: String?
    var expected: String? = nil  // "before X" from the description when no fixed version is listed
}
struct NVDCacheEntry: Codable {
    let date: Date
    let hits: [NVDHit]
}
struct SourceCheck: Codable, Identifiable {
    var id: String
    var name: String
    var status: String // checked, partial, failed, not installed
    var detail: String
    var date: Date = Date()
    var url: String? = nil
}
struct ScanReport: Codable {
    var date: Date = Date()
    var installations: [Installation] = []
    var findings: [Finding] = []
    var checks: [SourceCheck] = []
    var domains: [String: Bool] = [:]
    var nvdCache: [String: NVDCacheEntry]? = nil
    var errors: [String] { checks.filter { $0.status == "failed" || $0.status == "partial" }.map { "\($0.name): \($0.detail)" } }
    // Findings with something to install. Those waiting for a fixed release are listed separately.
    var security: [Finding] { findings.filter { $0.kind != .update && $0.awaitingFix != true } }
    var awaiting: [Finding] { findings.filter { $0.kind != .update && $0.awaitingFix == true } }
    var updates: [Finding] { findings.filter { $0.kind == .update } }
    // What the Security page lists first: everything to act on now, including known exploitation with no fix yet.
    var attention: [Finding] { findings.filter { FindingCategory(of: $0).needsAttention } }

    // Failed discovery or advisory requests cannot erase previously confirmed evidence. Findings from a
    // source this version no longer runs are dropped rather than kept as permanently unverified.
    mutating func retainUnverified(from old: ScanReport?) {
        guard let old else { return }
        let currentIDs = Set(findings.map(\.id))
        let installed = Set(installations.map(\.path))
        for var finding in old.findings where !currentIDs.contains(finding.id) {
            let stillInstalled = installed.contains(finding.installation.path)
            if !stillInstalled && domains[finding.installation.domain] == true { continue }
            guard let check = checks.first(where: { $0.id == finding.source }) else { continue }
            let healthy = check.status == "checked"
            if !healthy || domains[finding.installation.domain] != true {
                finding.stale = true
                findings.append(finding)
            }
        }
    }
}
struct SavedState: Codable {
    var report: ScanReport? = nil
    var delivered: [String: String] = [:]
    var lastFailure: String? = nil
    var lastAttempt: Date? = nil
    var lastScheduledDay: String? = nil
    var projectFolders: [String]? = nil
    var history: [HistoryEntry]? = nil
}
// What the alert about new or changed findings says. `released` holds the findings that were waiting for a fix.
// A bundled Sparkle that stops waiting isn't known to be fixed: its app has a new release, which may or may not
// bundle a newer Sparkle, so the alert names the app and says only that.
enum Alerts {
    static func findings(_ changed: [Finding], released: Set<String>) -> (title: String, body: String) {
        let newRelease = { (finding: Finding) in released.contains(finding.id) && finding.installation.sparkleApp != nil }
        let others = changed.filter { !newRelease($0) }
        let apps = Array(Set(changed.filter(newRelease).compactMap(\.installation.sparkleApp))).sorted()
        let title = changed.contains { $0.malicious == true } ? "Malicious package found"
            : others.contains { released.contains($0.id) } ? "Fix now available"
            : !others.isEmpty ? "Security updates to review"
            : apps.count == 1 ? "New \(apps[0]) release" : "New app releases"
        var body: [String] = []
        if !others.isEmpty {
            let names = Array(Set(others.map { $0.installation.sparkleApp != nil ? $0.installation.name : $0.installation.packageName ?? $0.installation.name })).sorted()
            body.append(names.prefix(4).joined(separator: ", ") + (names.count > 4 ? " and \(names.count - 4) more" : "") + ".")
        }
        if !apps.isEmpty {
            body.append(apps.count == 1 ? "The new release of \(apps[0]) may include a newer Sparkle than the vulnerable version it bundles now."
                                        : "New releases of \(list(apps)) may include a newer Sparkle than the vulnerable versions they bundle now.")
        }
        body.append(others.isEmpty ? "Open \(appName) for details." : "Open \(appName) for versions and update commands.")
        return (title, body.joined(separator: " "))
    }
    static func list(_ names: [String]) -> String {
        let shown = names.count > 4 ? Array(names.prefix(4)) + ["\(names.count - 4) more"] : names
        return shown.count < 2 ? shown.joined() : shown.dropLast().joined(separator: ", ") + " and " + shown.last!
    }
    // Delivered alerts are kept only for findings still listed and not waiting for a fix. A waiting finding loses
    // its record, so it alerts again when a fix or a new release appears, even if it was alerted before it waited.
    static func pruned(_ delivered: [String: String], report: ScanReport) -> [String: String] {
        let ids = Set(report.findings.filter { $0.awaitingFix != true }.map(\.id))
        return delivered.filter { ids.contains($0.key) }
    }
}

// "Oct 25, 2026 at 10:36 AM (5 minutes ago)"; under a minute reads "(just now)".
func lastCheckText(_ date: Date, now: Date = Date()) -> String {
    let ago = now.timeIntervalSince(date) < 60 ? "just now" : RelativeDateTimeFormatter().localizedString(for: date, relativeTo: now)
    return date.formatted(date: .abbreviated, time: .shortened) + " (" + ago + ")"
}

// One recommendation's life on this Mac: when it was first found and when and how it went away. A finding
// that comes back after being resolved, or that is still reported after the software changed version,
// starts a new entry, so the history reads as a log.
struct HistoryEntry: Codable, Identifiable, Hashable {
    var id = UUID()
    let findingID: String
    let name: String
    let domain: String
    let product: String
    let location: String?  // project folder, interpreter or prefix, as on the installation
    let package: String?   // Homebrew formula or cask
    let place: String      // install path, or the lockfile or settings file it was found in
    let version: String
    var fixed: String
    var kind: FindingKind
    var severity: String?
    var malicious: Bool?
    var awaiting: Bool?
    var advisories: [String]
    var command: String?
    let firstSeen: Date
    var lastSeen: Date
    var resolved: Date? = nil
    var resolution: String? = nil

    init(_ finding: Finding, at date: Date) {
        let item = finding.installation
        findingID = finding.id
        name = item.name
        domain = item.domain
        product = item.product
        location = item.location
        package = item.domain == "brew" ? item.package : nil
        place = item.sourceFile
        version = item.version
        fixed = finding.fixed
        kind = finding.kind
        firstSeen = date
        lastSeen = date
        advisories = []
        refresh(finding)
    }

    mutating func refresh(_ finding: Finding) {
        fixed = finding.fixed
        kind = finding.kind
        severity = finding.severity
        malicious = finding.malicious
        awaiting = finding.awaitingFix
        advisories = finding.advisories
        command = finding.commands?.first.flatMap { $0.kind == nil ? $0.text : nil }
    }
}

enum History {
    static let limit = 10_000

    // Brings the log up to date with a finished check: new findings open entries, findings still present
    // refresh theirs, and open entries whose finding is gone are resolved with what happened to the software.
    // Findings kept as unverified after a failed check are still present, so they stay open.
    static func update(_ history: inout [HistoryEntry], with report: ScanReport, projectFolders: [String], at date: Date, limit: Int = limit) {
        var open: [String: Int] = [:]
        for (index, entry) in history.enumerated() where entry.resolved == nil { open[entry.findingID] = index }
        var present = Set<String>()
        for finding in report.findings {
            present.insert(finding.id)
            if let index = open[finding.id], history[index].version == finding.installation.version {
                history[index].lastSeen = date
                history[index].refresh(finding)
                continue
            }
            if let index = open[finding.id] {
                history[index].resolved = date
                history[index].resolution = changed(from: history[index].version, to: finding.installation.version)
            }
            history.append(HistoryEntry(finding, at: date))
            open[finding.id] = history.count - 1
        }
        for (id, index) in open where !present.contains(id) {
            history[index].resolved = date
            history[index].resolution = resolution(of: history[index], in: report, projectFolders: projectFolders)
        }
        if history.count > limit {
            let resolved = history.indices.filter { history[$0].resolved != nil }.sorted { history[$0].resolved! < history[$1].resolved! }
            let drop = Set(resolved.prefix(history.count - limit))
            history = history.enumerated().filter { !drop.contains($0.offset) }.map(\.element)
        }
    }

    // What happened to the software behind a resolved entry, judged from the latest inventory.
    static func resolution(of entry: HistoryEntry, in report: ScanReport, projectFolders: [String]) -> String {
        if entry.kind == .update && entry.fixed.lowercased().hasPrefix("remove") { return "Removed" }
        let candidates = report.installations.filter { item in
            item.domain == entry.domain && item.product == entry.product && item.location == entry.location
                && (entry.package == nil || item.package == entry.package)
                && (entry.domain != "projects" || item.sourceFile == entry.place)
        }
        if let current = candidates.map(\.version).filter({ $0 != entry.version }).max(by: looseLess) { return changed(from: entry.version, to: current) }
        if !candidates.isEmpty { return "No longer reported" }
        if entry.domain == "projects", !projectFolders.contains(where: { entry.place.hasPrefix($0 + "/") }) { return "Project folder no longer checked" }
        return entry.domain == "projects" ? "Removed from the project" : "Removed from this Mac"
    }

    // Oldest first, as a log. Cells that a spreadsheet would read as a formula (=, +, -, @) start with an
    // apostrophe, since names like @scope/package come from lockfiles.
    static func csv(_ history: [HistoryEntry]) -> String {
        let dates = ISO8601DateFormatter()
        func cell(_ value: String) -> String {
            let safe = value.first.map { "=+-@\t\r".contains($0) } == true ? "'" + value : value
            return "\"" + safe.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        let header = ["Status", "Name", "Kind", "Severity", "Installed version", "Fixed version", "Found", "Last seen", "Resolved", "Resolution", "Location", "Advisories", "Recommended command"]
        let rows = history.sorted { $0.firstSeen < $1.firstSeen }.map { entry in
            [entry.resolved == nil ? "Open" : "Resolved", entry.name, entry.malicious == true ? "malicious" : entry.kind.rawValue, entry.severity ?? "", entry.version, entry.fixed,
             dates.string(from: entry.firstSeen), dates.string(from: entry.lastSeen), entry.resolved.map(dates.string) ?? "", entry.resolution ?? "", entry.place,
             entry.advisories.joined(separator: " "), entry.command ?? ""].map(cell).joined(separator: ",")
        }
        return ([header.map(cell).joined(separator: ",")] + rows).joined(separator: "\n") + "\n"
    }

    static func changed(from old: String, to new: String) -> String {
        looseLess(new, old) ? "Changed to \(new)" : "Updated to \(new)"
    }
}
// Pre-release builds kept their data in a folder under an earlier name. It moves to the current folder on
// first launch; if that move fails, the old folder keeps being used so nothing appears lost.
enum StateFolder {
    static let formerName = "Security Monitor"
    static func resolve(in support: URL, name: String = appName) -> URL {
        let fm = FileManager.default
        let current = support.appendingPathComponent(name, isDirectory: true), former = support.appendingPathComponent(formerName, isDirectory: true)
        guard !fm.fileExists(atPath: current.path), fm.fileExists(atPath: former.path) else { return current }
        return (try? fm.moveItem(at: former, to: current)) == nil ? former : current
    }
}
enum Schedule {
    static var calendar: Calendar { var c = Calendar(identifier: .gregorian); c.timeZone = TimeZone(identifier: "America/Los_Angeles")!; return c }
    static func day(_ date: Date) -> String {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return "\(c.year!)-\(c.month!)-\(c.day!)"
    }
    static func isDue(now: Date, lastDay: String?) -> Bool {
        calendar.component(.hour, from: now) >= 9 && day(now) != lastDay
    }
}
struct MonitorError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}
struct HTTPStatusError: LocalizedError {
    let host: String
    let status: Int
    var errorDescription: String? { "\(host) returned HTTP \(status)" }
}
