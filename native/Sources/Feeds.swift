import Foundation
import CryptoKit

let appName = "Shipshape"  // also CFBundleName in Info.plist, which the build scripts read
let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"

enum Fetch {
    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 30
        c.timeoutIntervalForResource = 120
        c.httpMaximumConnectionsPerHost = 4
        c.httpAdditionalHeaders = ["User-Agent": "\(appName)/\(appVersion) (macOS)", "Accept": "application/json, text/html;q=0.9"]
        return URLSession(configuration: c)
    }()
    // A body makes the request a JSON POST (OSV batch queries); everything else is a GET. `reuse` is how old a
    // saved response a minute refresh may use instead of downloading again.
    static func data(_ address: String, limit: Int = 12_000_000, body: Data? = nil, reuse: TimeInterval = 0) async throws -> Data {
        guard let url = URL(string: address), url.scheme == "https" else { throw MonitorError(message: "Invalid source URL") }
        let key = "fetch|" + address + (body.map { "|" + SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() } ?? "")
        return try await Reuse.value(key, maxAge: reuse) {
            var request = URLRequest(url: url)
            if let body { request.httpMethod = "POST"; request.httpBody = body; request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
            let (data, response) = try await session.data(for: request)
            guard let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode) else {
                throw HTTPStatusError(host: url.host ?? "Vendor source", status: (response as? HTTPURLResponse)?.statusCode ?? 0)
            }
            guard data.count < limit else { throw MonitorError(message: "Source exceeded response limit") }
            return data
        }
    }
    static func json(_ url: String, limit: Int = 12_000_000, body: Data? = nil, reuse: TimeInterval = 0) async throws -> Any {
        try JSONSerialization.jsonObject(with: await data(url, limit: limit, body: body, reuse: reuse))
    }
    static func string(_ url: String, reuse: TimeInterval = 0) async throws -> String { String(decoding: try await data(url, reuse: reuse), as: UTF8.self) }
}

// Results kept between checks while the app is open. A minute refresh runs with `enabled` set and reuses
// results younger than the age each caller allows; full checks (at launch, daily and Check now) always
// fetch again and replace them. Nothing here is written to disk.
enum Reuse {
    @TaskLocal static var enabled = false
    static let hour: TimeInterval = 3600
    private actor Store {
        var entries: [String: (date: Date, value: any Sendable)] = [:]
        func get(_ key: String, maxAge: TimeInterval) -> (any Sendable)? {
            guard let entry = entries[key], Date().timeIntervalSince(entry.date) < maxAge else { return nil }
            return entry.value
        }
        func set(_ key: String, _ value: any Sendable) { entries[key] = (Date(), value) }
    }
    private static let store = Store()
    static func value<T: Sendable>(_ key: String, maxAge: TimeInterval, _ compute: () async throws -> T) async rethrows -> T {
        guard maxAge > 0 else { return try await compute() }
        if enabled, let hit = await store.get(key, maxAge: maxAge) as? T { return hit }
        let value = try await compute()
        await store.set(key, value)
        return value
    }
    // For lookups made in bulk (OSV): the saved values for the keys that have them.
    static func values<T: Sendable>(_ keys: [String], maxAge: TimeInterval) async -> [String: T] {
        guard enabled else { return [:] }
        var found: [String: T] = [:]
        for key in keys { if let hit = await store.get(key, maxAge: maxAge) as? T { found[key] = hit } }
        return found
    }
    static func save(_ values: [String: any Sendable]) async { for (key, value) in values { await store.set(key, value) } }
}

enum Rules {
    static func node(_ item: Installation, releases: [[String: Any]], schedule: [String: Any], now: Date = Date()) throws -> Finding? {
        guard let installed = Version(item.version) else { throw MonitorError(message: "Unrecognized Node version") }
        let branch = releases.filter { row in (row["version"] as? String).flatMap(Version.init)?.major == installed.major }
        guard !branch.isEmpty else { throw MonitorError(message: "Node branch is absent from release data") }
        let fixed = branch.filter { ($0["security"] as? Bool) == true }.compactMap { $0["version"] as? String }.filter { Version($0) != nil }.sorted { Version($0)! > Version($1)! }.first
        let end = ((schedule["v\(installed.major)"] as? [String: Any])?["end"] as? String).flatMap { ISO8601DateFormatter().date(from: $0 + "T23:59:59Z") }
        guard let end else { throw MonitorError(message: "Node branch support date is unknown") }
        if end < now {
            return Finding(source: "node", installation: item, kind: .unsupported, fixed: "Supported LTS branch", reason: "This Node branch is past its published end-of-life date.", action: "Move consumers to a supported Node LTS release, or remove this copy after checking what uses it.", links: ["https://nodejs.org/en/about/previous-releases"], advisories: ["Node \(installed.major) EOL"])
        }
        if let fixed, let v = Version(fixed), installed < v {
            return Finding(source: "node", installation: item, kind: .security, fixed: String(fixed.drop(while: { $0 == "v" })), reason: "A newer security release exists on this installed Node branch.", action: "Update this installation through its package manager or Node installer. Restart its consumers; check old copies separately.", links: ["https://nodejs.org/en/blog/vulnerability", "https://nodejs.org/dist/index.json"])
        }
        return nil
    }
    static func bun(_ item: Installation, advisories: [[String: Any]]) throws -> Finding? {
        try github(item, advisories: advisories, packages: ["bun"], source: "bun",
                   action: "Update Bun using its existing installation method. Review each advisory's usage conditions, restart consumers, and rebuild standalone executables that embed Bun.")
    }
    // A project's own GitHub security advisories. Ranges must be explicit and numeric, and a version at or
    // above an advisory's patched release never matches, even when the published range is open-ended.
    static func github(_ item: Installation, advisories: [[String: Any]], packages: Set<String>, source: String, action: String) throws -> Finding? {
        guard let version = Version(item.version) else { throw MonitorError(message: "Unrecognized \(item.name) version") }
        var ids: [String] = [], links: [String] = [], titles: [String] = [], fixed = "0"
        for advisory in advisories {
            if advisory["withdrawn_at"] is String { continue }
            guard let vulnerabilities = advisory["vulnerabilities"] as? [[String: Any]] else { throw MonitorError(message: "\(item.name) advisory schema changed") }
            for vulnerability in vulnerabilities {
                guard let package = vulnerability["package"] as? [String: Any], let name = package["name"] as? String, packages.contains(name) else { continue }
                guard let range = vulnerability["vulnerable_version_range"] as? String, let affected = version.matches(range) else { throw MonitorError(message: "A \(item.name) advisory uses an unsupported version range") }
                let patched = (vulnerability["patched_versions"] as? String).flatMap(Version.init)
                guard affected, patched.map({ version < $0 }) ?? true else { continue }
                let description = (advisory["description"] as? String ?? "").lowercased()
                if description.contains("windows-only") || description.contains("linux-only") || description.contains("only affects windows") {
                    throw MonitorError(message: "A matching \(item.name) advisory requires a manual platform review")
                }
                guard patched != nil, let patchedText = vulnerability["patched_versions"] as? String,
                      let id = advisory["ghsa_id"] as? String, let link = advisory["html_url"] as? String else { throw MonitorError(message: "A matching \(item.name) advisory has no unambiguous fixed version") }
                fixed = higher(fixed, patchedText)
                ids.append(advisory["cve_id"] as? String ?? id)
                links.append(link)
                titles.append(advisory["summary"] as? String ?? id)
            }
        }
        guard !ids.isEmpty else { return nil }
        return Finding(source: source, installation: item, kind: .security, fixed: fixed, reason: titles.joined(separator: "; "), action: action, links: Array(Set(links)).sorted(), advisories: Array(Set(ids)).sorted())
    }
    static func postgres(_ item: Installation, html: String) throws -> Finding? {
        guard let installed = Version(item.version), installed.major >= 10 else { throw MonitorError(message: "PostgreSQL branch needs manual review") }
        var ids: [String] = [], fixed = "0"
        var parsed = 0
        for row in captures("<tr[^>]*>(.*?)</tr>", html) {
            let cells = captures("<td[^>]*>(.*?)</td>", row[1]).map { plain($0[1]) }
            guard cells.count >= 5, let id = captures("CVE-[0-9]+-[0-9]+", cells[0]).first?[0] else { continue }
            let affected = cells[1].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            let versions = cells[2].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            parsed += 1
            if affected.contains(String(installed.major)) {
                guard let patch = versions.first(where: { Version($0)?.major == installed.major }), let v = Version(patch) else { throw MonitorError(message: "PostgreSQL fixed-version table changed") }
                if installed < v { ids.append(id); fixed = higher(fixed, patch) }
            }
        }
        guard parsed > 0 else { throw MonitorError(message: "PostgreSQL security table could not be parsed") }
        guard html.contains("/support/security/\(installed.major)/") else { throw MonitorError(message: "PostgreSQL branch is absent from the supported-versions table; review support status") }
        guard !ids.isEmpty else { return nil }
        return Finding(source: "postgres", installation: item, kind: .security, fixed: fixed, reason: "\(ids.count) published PostgreSQL security fixes apply to this installed version. Exposure depends on server and client usage.", action: item.package == "libpq" ? "Update the libpq client library, then restart programs that use it." : "Back up databases, update within major version \(installed.major), and review the vendor's migration notes before restarting services.", links: ["https://www.postgresql.org/support/security/\(installed.major)/", "https://www.postgresql.org/docs/release/\(fixed)/"], advisories: ids.sorted())
    }
    // Release branches the OpenSSL vulnerabilities index links to, such as 3.6 and 4.0.
    static func opensslIndexedBranches(_ html: String) -> Set<String> {
        Set(captures("href=\"[^\"]*vulnerabilities-([0-9]+(?:\\.[0-9]+)+)/?(?:index\\.html)?\"", html).map { $0[1] })
    }
    // A branch has no published vulnerabilities only when a loaded index links other branches but not this one.
    static func opensslUnpublished(_ branch: String, indexed: Set<String>) -> Bool { !indexed.isEmpty && !indexed.contains(branch) }
    static func openssl(_ item: Installation, html: String) throws -> Finding? {
        guard let installed = Version(item.version), installed.major >= 3 else { throw MonitorError(message: "OpenSSL branch needs manual review") }
        let headers = captures("<h2 id=\"(CVE-[0-9]+-[0-9]+)\">", html)
        guard !headers.isEmpty else { throw MonitorError(message: "OpenSSL advisory format changed") }
        var fixed = "0", ids: [String] = []
        var parsed = 0
        for (index, header) in headers.enumerated() {
            guard let start = html.range(of: header[0])?.upperBound else { continue }
            let end = index + 1 < headers.count ? html.range(of: headers[index + 1][0], range: start..<html.endIndex)!.lowerBound : html.endIndex
            let block = String(html[start..<end])
            let ranges = captures("from ([0-9]+(?:\\.[0-9]+){1,2}) before ([0-9]+(?:\\.[0-9]+){1,2})(?=\\s|<)", block)
            for r in ranges {
                guard let from = Version(r[1]), let to = Version(r[2]), from.branch == installed.branch else { continue }
                parsed += 1
                if installed >= from && installed < to { ids.append(header[1]); fixed = higher(fixed, r[2]) }
            }
        }
        guard parsed > 0 else { throw MonitorError(message: "No recognized OpenSSL ranges for this branch; manual review needed") }
        guard !ids.isEmpty else { return nil }
        return Finding(source: "openssl", installation: item, kind: .security, fixed: fixed, reason: "\(Set(ids).count) published fixes match this OpenSSL version. Applicability depends on how dependent software uses the library.", action: "Update the owning package and its dependents, then restart consumers. Verify the package manager's branch before accepting a branch change.", links: ["https://openssl-library.org/news/vulnerabilities-\(installed.branch)/"], advisories: Array(Set(ids)).sorted())
    }
}

// Newest releases from Homebrew's public API, parsed once and kept for minute refreshes. Builds include
// Homebrew's rebuild number (26.12.1_1); casks also say whether the app updates itself and where its site is.
struct HomebrewMetadata: Sendable {
    var latest: [String: String] = [:]
    var builds: [String: String] = [:]
    var casks: [String: CaskInfo] = [:]
    static func load(_ kind: String) async throws -> HomebrewMetadata {
        guard let rows = try await Fetch.json("https://formulae.brew.sh/api/\(kind).json", limit: 150_000_000) as? [[String: Any]] else { throw MonitorError(message: "Homebrew \(kind) metadata was not a list") }
        var metadata = HomebrewMetadata()
        for row in rows {
            if kind == "formula", let name = row["name"] as? String, let stable = (row["versions"] as? [String: Any])?["stable"] as? String {
                let revision = row["revision"] as? Int ?? 0
                metadata.latest[name] = stable
                metadata.builds[name] = revision > 0 ? "\(stable)_\(revision)" : stable
            }
            if kind == "cask", let token = row["token"] as? String, let version = row["version"] as? String {
                metadata.latest[token] = version.components(separatedBy: ",")[0]
                metadata.casks[token] = CaskInfo(autoUpdates: row["auto_updates"] as? Bool ?? false, homepage: row["homepage"] as? String)
            }
        }
        return metadata
    }
}

enum Scanner {
    static func run(previous: ScanReport? = nil, projectFolders: [String] = [], progress: @escaping (String) -> Void = { _ in }) async -> ScanReport {
        progress("Finding developer tools and packages")
        var report = Inventory.collect(projectFolders: projectFolders)
        func items(_ product: String) -> [Installation] { report.installations.filter { $0.product == product } }
        func record(_ id: String, _ name: String, _ detail: String, url: String? = nil, status: String = "checked") {
            report.checks.append(SourceCheck(id: id, name: name, status: status, detail: detail, url: url))
        }
        func failure(_ id: String, _ name: String, _ error: Error) { record(id, name, error.localizedDescription, status: "failed") }

        progress("Checking vendor security releases")
        do {
            let installed = items("node")
            if !installed.isEmpty {
                async let releaseData = Fetch.json("https://nodejs.org/dist/index.json", reuse: Reuse.hour)
                async let scheduleData = Fetch.json("https://raw.githubusercontent.com/nodejs/Release/main/schedule.json", reuse: Reuse.hour)
                guard let releases = try await releaseData as? [[String: Any]], let schedule = try await scheduleData as? [String: Any] else { throw MonitorError(message: "Invalid Node release data") }
                for item in installed { if let f = try Rules.node(item, releases: releases, schedule: schedule) { report.findings.append(f) } }
            }
            record("node", "Node security & support", "\(installed.count) copies checked against branch security releases and support dates.", url: "https://nodejs.org/en/blog/vulnerability")
        } catch { failure("node", "Node security & support", error) }
        for product in Catalog.products {
            guard let (repo, packages) = product.github else { continue }
            let name = "\(product.name) security advisories"
            do {
                let installed = items(product.id)
                if !installed.isEmpty {
                    guard let advisories = try await Fetch.json("https://api.github.com/repos/\(repo)/security-advisories?per_page=100", reuse: Reuse.hour) as? [[String: Any]], advisories.count < 100 else { throw MonitorError(message: "\(product.name) advisory response was invalid or needs pagination") }
                    for item in installed {
                        let finding = product.id == "bun" ? try Rules.bun(item, advisories: advisories)
                            : try Rules.github(item, advisories: advisories, packages: Set(packages), source: product.id, action: "Update \(product.name) with its existing installation method, then restart it.")
                        if let finding { report.findings.append(finding) }
                    }
                }
                record(product.id, name, "\(installed.count) copies checked against the project's published affected-version ranges.", url: "https://github.com/\(repo)/security/advisories")
            } catch { failure(product.id, name, error) }
        }
        do {
            let installed = items("postgresql")
            if !installed.isEmpty {
                let html = try await Fetch.string("https://www.postgresql.org/support/security/", reuse: Reuse.hour)
                for item in installed { if let f = try Rules.postgres(item, html: html) { report.findings.append(f) } }
            }
            record("postgres", "PostgreSQL security", "\(installed.count) copies checked against the vendor's affected and fixed versions.", url: "https://www.postgresql.org/support/security/")
        } catch { failure("postgres", "PostgreSQL security", error) }
        do {
            let installed = items("openssl")
            guard installed.allSatisfy({ Version($0.version) != nil }) else { throw MonitorError(message: "An OpenSSL version uses an unsupported format; review it manually") }
            var indexed: Set<String>? = nil, unpublished: [String] = []
            for branch in Set(installed.compactMap { Version($0.version)?.branch }).sorted() {
                let html: String
                do { html = try await Fetch.string("https://openssl-library.org/news/vulnerabilities-\(branch)/index.html", reuse: Reuse.hour) }
                catch let error as HTTPStatusError where error.status == 404 {
                    // A missing page means no published vulnerabilities only when the index confirms it.
                    if indexed == nil { indexed = Rules.opensslIndexedBranches(try await Fetch.string("https://openssl-library.org/news/vulnerabilities/index.html", reuse: Reuse.hour)) }
                    guard Rules.opensslUnpublished(branch, indexed: indexed!) else {
                        throw MonitorError(message: indexed!.isEmpty ? "OpenSSL's vulnerabilities index lists no branches; review manually" : "OpenSSL's \(branch) vulnerability page is missing although the index lists it; review manually")
                    }
                    unpublished.append(branch)
                    continue
                }
                for item in installed where Version(item.version)?.branch == branch { if let f = try Rules.openssl(item, html: html) { report.findings.append(f) } }
            }
            record("openssl", "OpenSSL security", "\(installed.count) copies checked against vendor version ranges. Apple LibreSSL is excluded."
                   + (unpublished.isEmpty ? "" : " No vulnerabilities are published yet for OpenSSL \(unpublished.joined(separator: ", ")); OpenSSL's index doesn't list \(unpublished.count == 1 ? "that branch" : "those branches")."),
                   url: "https://openssl-library.org/news/vulnerabilities/")
        } catch { failure("openssl", "OpenSSL security", error) }

        // Package-level advisories and malicious-package reports for every inventoried package version.
        let packages = report.installations.filter { OSV.key($0) != nil && $0.manager != "brew-old" }
        progress("Checking \(Set(packages.compactMap(OSV.key)).count) package versions with OSV")
        do {
            let matches = try await OSV.query(packages)
            let vulns = try await OSV.details(Set(matches.values.flatMap { $0 }))
            report.findings += OSV.findings(for: packages, matches: matches, vulns: vulns)
            record("osv", "Package advisories (OSV)", "\(Set(packages.compactMap(OSV.key)).count) package versions across npm, PyPI, crates.io, Go and RubyGems checked, including OpenSSF malicious-package reports.", url: "https://osv.dev/")
        } catch { failure("osv", "Package advisories (OSV)", error) }

        // NVD version ranges for catalog tools and libraries without a vendor rule. Without an API key NVD
        // allows about five requests per 30 seconds, so requests are spaced and results reused for 20 hours.
        var cache = (previous?.nvdCache ?? [:]).filter { Date().timeIntervalSince($0.value.date) < 20 * 3600 }
        let nvdItems = report.installations.filter { item in
            guard let product = Catalog.byID[item.product], product.cpe != nil else { return false }
            return !Catalog.vendorRules.contains(product.id) && item.manager != "brew-old"
        }
        var nvdResults: [String: (checked: Int, problems: [String])] = [:]
        var requested = false
        for (index, item) in nvdItems.enumerated() {
            // The leading number versions the matching rules; change it when NVD.evaluate changes.
            let product = Catalog.byID[item.product]!, key = "3|" + product.cpe! + "|" + item.version
            progress("Checking NVD (\(index + 1) of \(nvdItems.count)): \(product.name)")
            do {
                var hits = cache[key]?.hits
                if hits == nil {
                    if requested { try await Task.sleep(nanoseconds: 6_500_000_000) }
                    requested = true
                    hits = try await NVD.hits(cpe: product.cpe!, version: item.version)
                    cache[key] = NVDCacheEntry(date: Date(), hits: hits!)
                }
                if let finding = NVD.finding(item, product: product, hits: hits!) { report.findings.append(finding) }
                nvdResults[product.id, default: (0, [])].checked += 1
            } catch { nvdResults[product.id, default: (0, [])].problems.append("\(item.version): \(error.localizedDescription)") }
        }
        for (id, result) in nvdResults.sorted(by: { $0.key < $1.key }) {
            let name = Catalog.byID[id]!.name
            record("nvd:" + id, name + " (NVD)", result.problems.isEmpty ? "\(result.checked) cop\(result.checked == 1 ? "y" : "ies") checked against NVD version ranges." : result.problems.joined(separator: "; "),
                   url: "https://nvd.nist.gov/products/cpe/search", status: result.problems.isEmpty ? "checked" : "failed")
        }
        report.nvdCache = cache

        // Public Homebrew metadata supplies update candidates, not security verdicts. Cask metadata also says
        // whether each app updates itself and where its vendor page is, which ranks the update options.
        progress("Checking Homebrew release metadata")
        var context = CommandContext.detect()
        let formulae = report.installations.filter { $0.manager == "brew" && $0.package != nil }
        let apps = report.installations.filter { ($0.manager == "cask" || $0.manager == "app") && $0.package != nil }
        var newestFormulae: [String: String] = [:]
        for (kind, items) in [("formula", formulae), ("cask", apps)] where !items.isEmpty {
            do {
                let metadata = try await Reuse.value("homebrew|" + kind, maxAge: Reuse.hour) { try await HomebrewMetadata.load(kind) }
                let latest = metadata.latest, builds = metadata.builds
                for token in Set(items.compactMap(\.package)) { if let info = metadata.casks[token] { context.casks[token] = info } }
                if kind == "formula" { newestFormulae = latest }
                var candidates = 0
                for item in items {
                    // Formulae compare the installed build (its Cellar folder, e.g. 26.12.1) with Homebrew's newest, rebuilds included.
                    let installed = kind == "formula" ? (item.path as NSString).lastPathComponent : item.version
                    guard let target = (kind == "formula" ? builds : latest)[item.package!], target != "latest",
                          kind == "formula" ? homebrewOlder(installed, target) : looseLess(item.version, target),
                          !report.findings.contains(where: { $0.installation.path == item.path && $0.kind != .update }) else { continue }
                    candidates += 1
                    let rebuild = kind == "formula" && !looseLess(item.version, latest[item.package!] ?? target)
                    report.findings.append(Finding(source: "homebrew-\(kind)", installation: item, kind: .update, fixed: target,
                                                   reason: rebuild ? "Homebrew rebuilt \(item.version) as \(target), usually because a library it depends on changed. The program's own version is the same."
                                                       : "Newer release metadata is available. This alone does not establish a security vulnerability.",
                                                   action: item.manager == "app" ? "Install the new release with one of the options below." : "Review the release notes, then update with Homebrew.", links: ["https://formulae.brew.sh/\(kind)/\(item.package!)"]))
                }
                record("homebrew-\(kind)", "Homebrew \(kind) metadata", "\(items.count) installations compared with Homebrew's current releases; \(candidates) newer.", url: "https://formulae.brew.sh/")
            } catch { failure("homebrew-\(kind)", "Homebrew \(kind) metadata", error) }
        }
        for item in report.installations where item.manager == "brew-old" && !report.findings.contains(where: { $0.installation.path == item.path }) {
            report.findings.append(Finding(source: "inventory-brew", installation: item, kind: .update, fixed: "Remove older copy",
                                           reason: "An older Homebrew copy is still on disk. It is not the active version, but anything that references its path directly still loads it.",
                                           action: "Remove retained copies once nothing depends on them.", links: ["https://docs.brew.sh/Manpage#cleanup-options-formulacask-"]))
        }

        markAwaiting(&report.findings, newest: newestFormulae)
        let skipped = dropSameReleaseUpdates(&report.findings)
        if skipped > 0 {
            record("same-release", "Update sanity check", "\(skipped) update\(skipped == 1 ? "" : "s") skipped because the newer version was the installed release written differently.", status: "checked")
        }

        do {
            let result = try await Reuse.value("softwareupdate", maxAge: Reuse.hour) { try command("/usr/sbin/softwareupdate", ["--list"], timeout: 90) }
            guard result.code == 0 else { throw MonitorError(message: "Apple Software Update could not complete; use System Settings") }
            if result.text.contains("* Label:") {
                let os = Installation(product: "macos", name: "Apple software", version: ProcessInfo.processInfo.operatingSystemVersionString, path: "System Settings → Software Update", domain: "apple")
                report.findings.append(Finding(source: "apple", installation: os, kind: .update, fixed: "Available in System Settings", reason: String(result.text.suffix(3500)), action: "Review Apple's eligible updates, including Command Line Tools for Xcode, and their security notes.", links: ["https://support.apple.com/en-us/100100"]))
            } else if !result.text.contains("No new software available") { throw MonitorError(message: "Apple Software Update returned an unrecognized response") }
            record("apple", "Apple Software Update", "Checked macOS and Command Line Tools update eligibility. This does not verify App Store apps or pending process restarts.", url: "https://support.apple.com/en-us/100100")
        } catch { failure("apple", "Apple Software Update", error) }

        do {
            if report.findings.contains(where: { $0.advisories.contains { $0.hasPrefix("CVE-") } }) {
                guard let obj = try await Fetch.json("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json", reuse: Reuse.hour) as? [String: Any],
                      let rows = obj["vulnerabilities"] as? [[String: Any]], !rows.isEmpty else { throw MonitorError(message: "CISA catalog could not be parsed") }
                let known = Set(rows.compactMap { $0["cveID"] as? String })
                for i in report.findings.indices { report.findings[i].exploited = !known.isDisjoint(with: report.findings[i].advisories) }
            }
            record("kev", "Known exploitation", "CISA CVE identifiers are matched only after version matching. This is prioritization, not proof of exploitation on this Mac.", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        } catch {
            failure("kev", "Known exploitation", error)
            for index in report.findings.indices {
                if previous?.findings.contains(where: { $0.id == report.findings[index].id && $0.exploited }) == true { report.findings[index].exploited = true }
            }
        }
        record("scope", "Security coverage limits", "Vendor rules: Node, Bun, OpenCode, PostgreSQL (including libpq) and OpenSSL. OSV: npm, PyPI, crates.io, Go and RubyGems packages in projects, global installs, Python environments, the npx cache and pinned MCP servers. NVD: \(Catalog.products.filter { $0.cpe != nil }.count) catalog tools and libraries. Excluded by design: Google Chrome and Mac App Store apps. Not covered: editor extensions, containers and images, Java and other ecosystems, unpinned MCP servers that npx hasn't cached, software outside the catalog and arbitrary install paths.", status: "manual")
        report.retainUnverified(from: previous)
        for index in report.findings.indices { report.findings[index].commands = Commands.commands(for: report.findings[index], context: context) }
        report.findings.sort { a, b in
            if (a.malicious == true) != (b.malicious == true) { return a.malicious == true }
            if a.exploited != b.exploited { return a.exploited }
            if (a.kind == .update) != (b.kind == .update) { return a.kind != .update }
            if (a.installation.domain == "projects") != (b.installation.domain == "projects") { return b.installation.domain == "projects" }
            let x = severityRank[a.severity ?? ""] ?? 0, y = severityRank[b.severity ?? ""] ?? 0
            if x != y { return x > y }
            return a.installation.name.localizedCaseInsensitiveCompare(b.installation.name) == .orderedAscending
        }
        report.date = Date()
        return report
    }

    // A final check on every update: never offer a "newer" release that is the installed one written differently,
    // such as Build 4215 against 4215. Homebrew formulae compare their installed build (the Cellar folder, which
    // keeps the rebuild number) so that rebuilds like 15.0.0_1 still count as updates.
    static func dropSameReleaseUpdates(_ findings: inout [Finding]) -> Int {
        let before = findings.count
        findings.removeAll { finding in
            let item = finding.installation
            let installed = item.manager == "brew" ? (item.path as NSString).lastPathComponent : item.version
            return finding.kind == .update && sameRelease(installed, finding.fixed)
        }
        return before - findings.count
    }

    // An NVD finding with no fixed release, on a copy that is already Homebrew's newest: nothing to install yet.
    // It becomes an ordinary finding again, with its command, once Homebrew ships a newer release.
    static func markAwaiting(_ findings: inout [Finding], newest: [String: String]) {
        for index in findings.indices {
            let finding = findings[index], item = finding.installation
            guard finding.source.hasPrefix("nvd:"), finding.kind == .security, item.manager == "brew", let package = item.package, let latest = newest[package],
                  !looseLess(item.version, latest), finding.fixed == NVD.noFixListed || finding.expectedFix != nil else { continue }
            findings[index].awaitingFix = true
            findings[index].fixed = finding.expectedFix.map { "\($0), not released yet" } ?? "No fix released yet"
            findings[index].action = "You have Homebrew's newest \(item.name) (\(latest)), and no release fixes these yet."
                + (finding.expectedFix.map { " The advisory names \($0) as the fix." } ?? "") + " \(appName) alerts you when a fixed release is available."
        }
    }
}
