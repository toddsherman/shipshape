import Foundation

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
        let (foundApps, _, skipped) = Inventory.apps(roots: [applications])
        expect(foundApps.map(\.product) == ["vscode"] && skipped == 3, "Chrome and App Store copies are skipped; other catalog apps are found")
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
        expect(listedFix[0].awaitingFix == nil, "a listed fixed version is left as an ordinary finding")
        let vscodeCopy = Installation(product: "vscode", name: "Visual Studio Code", version: "1.90", path: "/Applications/Visual Studio Code.app", domain: "apps", package: "visual-studio-code", manager: "app")
        var appFinding = [NVD.finding(vscodeCopy, product: Catalog.byID["vscode"]!, hits: [NVDHit(id: "CVE-2026-8", fixed: nil, severity: "LOW")])!]
        Scanner.markAwaiting(&appFinding, newest: ["visual-studio-code": "1.90"])
        expect(appFinding[0].awaitingFix == nil, "only Homebrew formulae are compared with Homebrew's newest release")

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
               "the former Security Monitor folder moves to the Shipshape folder")
        try FileManager.default.createDirectory(at: former, withIntermediateDirectories: true)
        expect(StateFolder.resolve(in: support) == moved && FileManager.default.fileExists(atPath: former.path), "an existing Shipshape folder is kept and a leftover old folder is left alone")
        try? FileManager.default.removeItem(at: support)

        // Minute refreshes reuse saved results; full checks always compute again and replace them.
        var computed = 0
        func compute() async -> Int { computed += 1; return computed }
        let first = await Reuse.value("test|reuse", maxAge: 60) { await compute() }
        let full = await Reuse.value("test|reuse", maxAge: 60) { await compute() }
        let quick = await Reuse.$enabled.withValue(true) { await Reuse.value("test|reuse", maxAge: 60) { await compute() } }
        let expired = await Reuse.$enabled.withValue(true) { await Reuse.value("test|reuse", maxAge: 0) { await compute() } }
        expect(first == 1 && full == 2 && quick == 2 && expired == 3, "minute refreshes reuse a fresh result; full checks and expired entries fetch again")
        let bulk: [String: Int] = await Reuse.$enabled.withValue(true) { await Reuse.values(["test|reuse", "test|missing"], maxAge: 60) }
        let bulkFull: [String: Int] = await Reuse.values(["test|reuse"], maxAge: 60)
        expect(bulk == ["test|reuse": 2] && bulkFull.isEmpty, "bulk lookups return only saved keys, and nothing outside a minute refresh")

        let summer = ISO8601DateFormatter().date(from: "2026-10-24T16:00:00Z")!
        let winter = ISO8601DateFormatter().date(from: "2026-12-24T17:00:00Z")!
        expect(Schedule.isDue(now: summer, lastDay: nil), "9 a.m. PDT")
        expect(Schedule.isDue(now: winter, lastDay: nil), "9 a.m. PST")
        expect(!Schedule.isDue(now: summer.addingTimeInterval(-60), lastDay: nil), "not before scheduled time")
        expect(!Schedule.isDue(now: summer, lastDay: Schedule.day(summer)), "once per Pacific day")
        expect(Schedule.isDue(now: summer.addingTimeInterval(3600 * 4), lastDay: nil), "catch up after sleep")

        // Optional live-format fixtures are kept outside the distributable app.
        let root = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "native/work"
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
        print("Passed \(count) rule, failure-retention, notification-fingerprint and scheduling checks")
    }
}
