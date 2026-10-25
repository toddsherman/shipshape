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
        return Vuln(id: id, summary: summary, aliases: obj["aliases"] as? [String] ?? [], severity: severity, fixed: fixed, informational: informational)
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
            let reason = malicious
                ? "OpenSSF's malicious-package database lists this exact version. Assume anything it could reach is exposed."
                : count + ": " + chosen.prefix(3).map(\.summary).joined(separator: "; ") + (chosen.count > 3 ? "; …" : "") + (unfixed > 0 && !fixes.isEmpty ? " \(unfixed) without a published fix." : "")
            let advisories = Set(chosen.flatMap { [$0.id] + $0.aliases.filter { $0.hasPrefix("CVE-") } })
            findings.append(Finding(source: "osv", installation: item, kind: .security,
                                    fixed: malicious ? "Remove this version" : fixes.max(by: looseLess) ?? "No fixed version published",
                                    reason: reason, action: Commands.action(for: item, malicious: malicious, fixed: fixes.max(by: looseLess)),
                                    links: chosen.prefix(4).map { "https://osv.dev/vulnerability/" + $0.id }, advisories: advisories.sorted(),
                                    severity: malicious ? "CRITICAL" : severity, malicious: malicious ? true : nil))
        }
        return findings
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
            return NVDHit(id: id, fixed: fixed, severity: severity(cve), expected: fixed == nil ? expectedFix(cve, version: version) : nil)
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
    static func finding(_ item: Installation, product: Product, hits: [NVDHit]) -> Finding? {
        guard !hits.isEmpty else { return nil }
        let unknown = hits.filter { $0.fixed == nil }.count
        let listed = hits.compactMap(\.fixed).max(by: looseLess), expected = listed == nil ? hits.compactMap(\.expected).max(by: looseLess) : nil
        let count = hits.count == 1 ? "1 NVD-listed vulnerability affects" : "\(hits.count) NVD-listed vulnerabilities affect"
        let reason = count + " this version" + (unknown > 0 ? "; \(unknown) list no fixed version" : "") + ". NVD can lag vendor advisories"
            + (item.domain == "brew" ? ", and Homebrew sometimes ships patches without changing the version." : ".")
            + (expected.map { " The advisory text names \($0) as the fix." } ?? "")
        return Finding(source: "nvd:" + product.id, installation: item, kind: .security, fixed: listed ?? expected ?? noFixListed,
                       reason: reason, action: "Install the update below, then restart programs that use it.",
                       links: hits.prefix(3).map { "https://nvd.nist.gov/vuln/detail/" + $0.id }, advisories: hits.map(\.id).sorted(),
                       severity: hits.reduce(nil) { worse($0, $1.severity) }, expectedFix: expected)
    }
}
