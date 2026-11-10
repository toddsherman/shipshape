import Foundation

// Lockfiles are read as text or JSON only. Nothing in a project is executed, and only package names,
// versions and whether a dependency is direct are kept.
struct LockPackage: Hashable {
    let name: String
    let version: String
    let ecosystem: String
    var dependency: String? = nil
}

enum Lockfiles {
    // File name → package manager used for update commands.
    static let managers: [String: String] = [
        "package-lock.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn", "bun.lock": "bun-lock",
        "uv.lock": "uv", "poetry.lock": "poetry", "requirements.txt": "pip-req", "Cargo.lock": "cargo",
        "Gemfile.lock": "bundler", "go.mod": "go", "Package.resolved": "swift", "composer.lock": "composer", "pubspec.lock": "pub",
        "packages.lock.json": "nuget", "mix.lock": "mix", "gradle.lockfile": "gradle"
    ]
    static let skipped: Set<String> = ["node_modules", ".git", ".venv", "venv", "env", ".tox", "vendor", "dist", "build", "target", ".next",
                                       ".nuxt", ".svelte-kit", ".turbo", "Pods", "DerivedData", ".build", "__pycache__", ".cache", "coverage"]

    // System folders and package-manager internals, such as Homebrew's own Library, are never projects. They are
    // skipped while walking a chosen folder; a chosen folder inside one of them is still checked.
    static var skippedRoots: Set<String> {
        let home = Inventory.home
        return ["/opt/homebrew", "/usr", "/System", "/Library", "/private", "/bin", "/sbin", "/cores", "/dev", "/Applications",
                home + "/Library", home + "/Applications", home + "/go/pkg"]
    }
    static let fileLimit = 2000
    static func find(in root: String, depth limit: Int = 8, skipping roots: Set<String> = skippedRoots) -> [String] {
        search(in: root, depth: limit, skipping: roots).files
    }
    // The walk stops at a depth and at a number of files, so one huge folder can't hold up a check. `deeper` counts the
    // folders below the depth limit that weren't read, and `full` says the file limit was reached: Coverage reports both.
    static func search(in root: String, depth limit: Int = 8, skipping roots: Set<String> = skippedRoots) -> (files: [String], deeper: Int, full: Bool) {
        var found: [String] = [], deeper = 0, full = false
        func walk(_ dir: String, _ depth: Int) {
            if depth > limit { deeper += 1; return }
            if found.count >= fileLimit { full = true; return }
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
            for name in names.sorted() {
                let path = dir == "/" ? "/" + name : dir + "/" + name
                // lstat doesn't follow links: linked folders and files are skipped, so a scan stays inside the chosen folder.
                var info = stat()
                guard lstat(path, &info) == 0 else { continue }
                let type = info.st_mode & S_IFMT
                if type == S_IFDIR {
                    if name == ".github" { found += workflows(path) }  // checked for GitHub Actions
                    if !skipped.contains(name), !name.hasPrefix("."), !name.hasSuffix(".app"), !name.hasSuffix(".framework"), !roots.contains(path) { walk(path, depth + 1) }
                } else if type == S_IFREG, managers[name] != nil || name == ".mcp.json" { found.append(path) }
            }
        }
        walk(root, 0)
        return (found, deeper, full)
    }

    static let sizeLimit = 64_000_000
    static func parse(_ path: String, data: Data? = nil) -> (manager: String, packages: [LockPackage])? {
        let file = (path as NSString).lastPathComponent
        guard var manager = managers[file] ?? (path.contains("/.github/workflows/") ? "actions" : nil), let data = data ?? Inventory.read(path, limit: sizeLimit) else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        let packages: [LockPackage]
        switch manager {
        case "npm": packages = npm(data)
        case "pnpm": packages = pnpm(text)
        case "yarn": if text.contains("__metadata:") { manager = "yarn-berry" }; packages = yarn(text)
        case "bun-lock": packages = bun(text)
        case "uv": packages = toml(text, ecosystem: "PyPI") { !localSource($0) }
        case "poetry": packages = toml(text, ecosystem: "PyPI") { _ in true }
        case "cargo": packages = toml(text, ecosystem: "crates.io") { $0.contains("registry+") }
        case "pip-req": packages = requirements(text)
        case "bundler": packages = gemfile(text)
        case "swift": packages = swift(data)
        case "composer": packages = composer(data)
        case "pub": packages = pub(text)
        case "nuget": packages = nuget(data)
        case "mix": packages = mix(text)
        case "gradle": packages = gradle(text)
        case "actions": packages = actions(text)
        default: packages = goModules(text)
        }
        let directory = (path as NSString).deletingLastPathComponent
        let javascript = manager.hasPrefix("yarn") || ["npm", "pnpm", "bun-lock"].contains(manager)
        var manifest: (roles: [String: String], requests: Set<String>) = ([:], [])
        if javascript { manifest = jsManifest(directory) }
        var roles = manifest.roles
        if manager == "composer" { roles = composerRoles(directory) }
        // A lockfile can hold several versions of one name, and package.json asks for only one of them: the others
        // came along with other packages. Where the lockfile says which copy the project asked for, only that copy
        // gets the direct or dev role, so the others aren't offered a command that would leave them in place.
        var rooted: Set<String> = []
        if manager == "pnpm" { rooted = pnpmRooted(text) } else if manager == "bun-lock" { rooted = bunRooted(text) } else if manager.hasPrefix("yarn") { rooted = yarnRooted(text, requests: manifest.requests) }
        // One entry per name and version, preferring the most direct role.
        var unique: [String: LockPackage] = [:]
        for var package in packages {
            let key = package.name + "@" + package.version
            if package.dependency == nil, let role = roles[package.name] {
                package.dependency = rooted.isEmpty || rooted.contains(key) ? role : "transitive"
            } else if package.dependency == nil, manager == "npm", !roles.isEmpty {
                package.dependency = "transitive"  // a version 1 lockfile's top level also holds packages the project never asked for
            }
            if let old = unique[key], rank(old.dependency) >= rank(package.dependency) { continue }
            unique[key] = package
        }
        return (manager, unique.values.sorted { ($0.name, $0.version) < ($1.name, $1.version) })
    }
    // The folder a project lives in. Xcode keeps Package.resolved inside its .xcodeproj or .xcworkspace, so
    // those findings belong to the folder holding the project, where people work on it.
    static func projectFolder(_ lockfile: String) -> String {
        if let range = lockfile.range(of: "/.github/workflows/") { return String(lockfile[..<range.lowerBound]) }
        let parts = (lockfile as NSString).deletingLastPathComponent.components(separatedBy: "/")
        if let index = parts.firstIndex(where: { $0.hasSuffix(".xcodeproj") || $0.hasSuffix(".xcworkspace") }) {
            return parts[..<index].joined(separator: "/")
        }
        return (lockfile as NSString).deletingLastPathComponent
    }
    static func rank(_ role: String?) -> Int { role == "direct" ? 3 : role == "dev" ? 2 : role == "transitive" ? 1 : 0 }

    // Direct and dev dependency names from the package.json beside a JavaScript lockfile.
    static func jsRoles(_ directory: String) -> [String: String] { jsManifest(directory).roles }
    // The roles, and each request as "name@range" the way yarn.lock writes it (without "npm:").
    static func jsManifest(_ directory: String) -> (roles: [String: String], requests: Set<String>) {
        guard let data = Inventory.read(directory + "/package.json", limit: 8_000_000),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return ([:], []) }
        var roles: [String: String] = [:], requests: Set<String> = []
        for key in ["devDependencies", "dependencies", "optionalDependencies", "peerDependencies"] {
            for (name, range) in (obj[key] as? [String: Any]) ?? [:] {
                roles[name] = key == "devDependencies" ? "dev" : "direct"
                if let range = range as? String { requests.insert(name + "@" + (range.hasPrefix("npm:") ? String(range.dropFirst(4)) : range)) }
            }
        }
        return (roles, requests)
    }

    static func npm(_ data: Data) -> [LockPackage] {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        var result: [LockPackage] = []
        if let packages = obj["packages"] as? [String: [String: Any]] {
            let root = packages[""] ?? [:]
            let devs = Set(((root["devDependencies"] as? [String: Any]) ?? [:]).keys)
            let direct = Set(["dependencies", "optionalDependencies", "peerDependencies"].flatMap { ((root[$0] as? [String: Any]) ?? [:]).keys })
            for (key, value) in packages {
                guard let marker = key.range(of: "node_modules/", options: .backwards), value["link"] as? Bool != true,
                      let version = value["version"] as? String else { continue }
                let name = value["name"] as? String ?? String(key[marker.upperBound...])
                let top = key == "node_modules/" + name
                result.append(LockPackage(name: name, version: version, ecosystem: "npm",
                                          dependency: top && direct.contains(name) ? "direct" : top && devs.contains(name) ? "dev" : "transitive"))
            }
        } else if let dependencies = obj["dependencies"] as? [String: Any] {
            func walk(_ dependencies: [String: Any], top: Bool) {
                for (name, value) in dependencies {
                    guard let value = value as? [String: Any], let version = value["version"] as? String else { continue }
                    result.append(LockPackage(name: name, version: version, ecosystem: "npm", dependency: top ? nil : "transitive"))
                    if let nested = value["dependencies"] as? [String: Any] { walk(nested, top: false) }
                }
            }
            walk(dependencies, top: true)
        }
        return result.filter { $0.version.first?.isNumber == true }
    }

    // Splits "name@version", keeping a leading scope: "@scope/name@1.2.3".
    static func splitSpec(_ spec: String) -> (String, String)? {
        guard let at = spec.dropFirst().lastIndex(of: "@") else { return nil }
        return (String(spec[..<at]), String(spec[spec.index(after: at)...]))
    }

    static func pnpm(_ text: String) -> [LockPackage] {
        var result: [LockPackage] = [], inPackages = false
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            if !line.hasPrefix(" ") && !line.isEmpty { inPackages = line == "packages:"; continue }
            guard inPackages, line.hasPrefix("  "), !line.hasPrefix("   "), line.hasSuffix(":") else { continue }
            var key = line.trimmingCharacters(in: .whitespaces).dropLast().trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
            if key.hasPrefix("/") { key.removeFirst() }
            if let paren = key.firstIndex(of: "(") { key = String(key[..<paren]) }
            // Lockfile v5 keys are /name/1.2.3_peer; later versions use name@1.2.3.
            let parsed = captures("^((?:@[^/]+/)?[^/@]+)/([0-9][^/_]*)", key).first.map { ($0[1], $0[2]) } ?? splitSpec(key)
            guard let (name, version) = parsed, !name.isEmpty, version.first?.isNumber == true else { continue }
            result.append(LockPackage(name: name, version: version, ecosystem: "npm"))
        }
        return result
    }

    static func yarn(_ text: String) -> [LockPackage] { yarnEntries(text).map(\.package) }
    // Each entry with the requests it answers, as "name@range" without Berry's "npm:" ("lodash@^4.17.21").
    static func yarnEntries(_ text: String) -> [(package: LockPackage, specs: [String])] {
        var result: [(package: LockPackage, specs: [String])] = [], name: String? = nil, specs: [String] = []
        for line in text.split(separator: "\n") {
            if !line.hasPrefix(" ") && !line.hasPrefix("#") && line.hasSuffix(":") {
                let raw = line.dropLast().split(separator: ",").map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\" ")) }
                specs = raw.map { $0.replacingOccurrences(of: "@npm:", with: "@") }
                name = raw.first.flatMap(yarnName)
            } else if let current = name, let m = captures("^\\s+version:?\\s+\"?([^\"\\s]+)\"?$", String(line)).first {
                if m[1].first?.isNumber == true && !m[1].contains("use.local") { result.append((LockPackage(name: current, version: m[1], ecosystem: "npm"), specs)) }
                name = nil
            }
        }
        return result
    }
    // The package an entry installs. An alias ("string-width-cjs@npm:string-width@^4.2.0") installs the package named
    // after "npm:", so that is the one to check; workspace and patch entries have no registry package.
    static func yarnName(_ spec: String) -> String? {
        if let marker = spec.range(of: "@npm:"), let real = splitSpec(String(spec[marker.upperBound...]))?.0, !real.isEmpty { return real }
        guard let name = splitSpec(spec.replacingOccurrences(of: "@npm:", with: "@"))?.0 else { return nil }
        return name.contains(":") ? nil : name
    }
    // Which name@version entries the project's own package.json asks for: those answering one of its "name@range" requests.
    static func yarnRooted(_ text: String, requests: Set<String>) -> Set<String> {
        var rooted: Set<String> = []
        for entry in yarnEntries(text) where entry.specs.contains(where: { requests.contains($0) }) { rooted.insert(entry.package.name + "@" + entry.package.version) }
        return rooted
    }
    // pnpm lists what each project asks for, with the version it resolved to, under importers (or at the top of a
    // single project's lockfile): "lodash:", "specifier: ^4.17.21", "version: 4.17.21".
    static func pnpmRooted(_ text: String) -> Set<String> {
        let pattern = "(?m)^( {2}| {6})'?((?:@[^/\\s']+/)?[^@\\s':]+)'?:\\n\\1  specifier: [^\\n]*\\n\\1  version: '?([0-9][^\\s(_']*)"
        return Set(captures(pattern, text).map { $0[2] + "@" + $0[3] })
    }
    // In bun.lock the copy a project's own package.json gets is the one keyed by the bare name; copies nested under
    // another package are keyed "parent/name".
    static func bunRooted(_ text: String) -> Set<String> {
        guard let start = text.range(of: "\"packages\"") else { return [] }
        let entries = captures("\"([^\"]+)\":\\s*\\[\\s*\"((?:@[^@\"/]+/)?[^@\"]+)@([0-9][^\"]*)\"", String(text[start.lowerBound...]))
        return Set(entries.filter { $0[1] == $0[2] }.map { $0[2] + "@" + $0[3] })
    }

    static func bun(_ text: String) -> [LockPackage] {
        guard let start = text.range(of: "\"packages\"") else { return [] }
        return captures("\"[^\"]+\":\\s*\\[\\s*\"((?:@[^@\"/]+/)?[^@\"]+)@([0-9][^\"]*)\"", String(text[start.lowerBound...]))
            .map { LockPackage(name: $0[1], version: $0[2], ecosystem: "npm") }
    }

    // A uv.lock source that is the project itself or a folder on disk: { editable = "." }, { virtual = "." },
    // { directory = "../x" } or { path = "x.whl" }. Only the key counts, so a registry whose address contains one of
    // those words, such as Artifactory's "pypi-virtual", is still a registry.
    static func localSource(_ source: String) -> Bool {
        source.range(of: "[{,]\\s*(editable|virtual|directory|path)\\s*=", options: .regularExpression) != nil
    }

    // [[package]] tables with name, version and an optional source filter (uv, Poetry, Cargo).
    static func toml(_ text: String, ecosystem: String, include: (String) -> Bool) -> [LockPackage] {
        var result: [LockPackage] = []
        for block in text.components(separatedBy: "[[package]]").dropFirst() {
            let header = block.components(separatedBy: "\n[").first ?? block
            guard let name = captures("(?m)^name = \"([^\"]+)\"", header).first?[1],
                  let version = captures("(?m)^version = \"([^\"]+)\"", header).first?[1] else { continue }
            let source = captures("(?m)^source = ([^\\n]+)", header).first?[1] ?? ""
            if include(source) { result.append(LockPackage(name: name, version: version, ecosystem: ecosystem)) }
        }
        return result
    }

    static func requirements(_ text: String) -> [LockPackage] {
        // Extras stay on their line, so a file of unclosed brackets can't make matching slow down quadratically.
        captures("(?m)^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\\[[^\\]\\r\\n]*\\])?[ \\t]*==[ \\t]*([0-9][^\\s;#,]*)", text)
            .map { LockPackage(name: $0[1], version: $0[2], ecosystem: "PyPI", dependency: "direct") }
    }

    static func gemfile(_ text: String) -> [LockPackage] {
        // Bundler writes one GEM section per gem source, so a private source and rubygems.org each get their own.
        let sections = text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n\n").filter { $0.hasPrefix("GEM\n") }
        return sections.flatMap { section in
            captures("(?m)^    ([A-Za-z0-9_.-]+) \\(([0-9][^)-]*)", section).map { LockPackage(name: $0[1], version: $0[2], ecosystem: "RubyGems") }
        }
    }

    // Swift Package Manager: Package.resolved v1 (object.pins, repositoryURL) and v2–v3 (pins, location). OSV
    // names Swift packages by repository URL without the scheme or .git, and matches that name case-sensitively.
    static func swift(_ data: Data) -> [LockPackage] {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        let pins = (obj["pins"] as? [[String: Any]]) ?? ((obj["object"] as? [String: Any])?["pins"] as? [[String: Any]]) ?? []
        return pins.compactMap { pin in
            guard let url = (pin["location"] ?? pin["repositoryURL"]) as? String, let name = swiftName(url),
                  let version = (pin["state"] as? [String: Any])?["version"] as? String, version.first?.isNumber == true else { return nil }
            return LockPackage(name: name, version: version, ecosystem: "SwiftURL")
        }
    }
    static func swiftName(_ url: String) -> String? {
        var value = url.hasPrefix("git@") ? String(url.dropFirst(4)).replacingOccurrences(of: ":", with: "/", options: [], range: nil) : url
        value = value.replacingOccurrences(of: "^[a-z+]+://([^@/]+@)?", with: "", options: .regularExpression)
        if value.hasSuffix("/") { value.removeLast() }
        if value.hasSuffix(".git") { value.removeLast(4) }
        return value.range(of: "^[A-Za-z0-9.-]+(/[A-Za-z0-9._-]+)+$", options: .regularExpression) != nil ? value : nil
    }

    // Composer (PHP): packages and packages-dev in composer.lock; versions may carry a leading v.
    static func composer(_ data: Data) -> [LockPackage] {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        var result: [LockPackage] = []
        for (key, role) in [("packages", nil), ("packages-dev", "dev")] as [(String, String?)] {
            for package in (obj[key] as? [[String: Any]]) ?? [] {
                guard let name = package["name"] as? String, var version = package["version"] as? String else { continue }
                if version.hasPrefix("v") { version.removeFirst() }
                if version.first?.isNumber == true { result.append(LockPackage(name: name, version: version, ecosystem: "Packagist", dependency: role)) }
            }
        }
        return result
    }
    static func composerRoles(_ directory: String) -> [String: String] {
        guard let data = Inventory.read(directory + "/composer.json", limit: 8_000_000),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        var roles: [String: String] = [:]
        for name in ((obj["require-dev"] as? [String: Any]) ?? [:]).keys { roles[name] = "dev" }
        for name in ((obj["require"] as? [String: Any]) ?? [:]).keys { roles[name] = "direct" }
        return roles
    }

    // Dart and Flutter: pubspec.lock lists each package with its dependency kind, source and version.
    // Only packages from a package host (pub.dev) are checked; git, path and SDK packages aren't.
    static func pub(_ text: String) -> [LockPackage] {
        var result: [LockPackage] = [], name: String?, kind: String?, source: String?, version: String?
        func flush() {
            if let name, let version, source == "hosted", version.first?.isNumber == true {
                result.append(LockPackage(name: name, version: version, ecosystem: "Pub",
                                          dependency: kind == "direct main" ? "direct" : kind == "direct dev" ? "dev" : kind == "transitive" ? "transitive" : nil))
            }
        }
        for line in text.split(separator: "\n").map(String.init) {
            if let match = captures("^  ([a-z_][a-z0-9_]*):\\s*$", line).first { flush(); name = match[1]; kind = nil; source = nil; version = nil; continue }
            if !line.hasPrefix("  ") { flush(); name = nil; continue }
            func value(_ key: String) -> String? { captures("^    \(key):\\s*\"?([^\"]*)\"?\\s*$", line).first?[1] }
            if let v = value("dependency") { kind = v } else if let v = value("source") { source = v } else if let v = value("version") { version = v }
        }
        flush()
        return result
    }

    // .NET: packages.lock.json lists resolved packages per target framework; project references are skipped.
    static func nuget(_ data: Data) -> [LockPackage] {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let targets = obj["dependencies"] as? [String: Any] else { return [] }
        var result: [LockPackage] = []
        for case let packages as [String: Any] in targets.values {
            for (name, value) in packages {
                guard let info = value as? [String: Any], let type = info["type"] as? String, type != "Project",
                      let version = info["resolved"] as? String, version.first?.isNumber == true else { continue }
                result.append(LockPackage(name: name, version: version, ecosystem: "NuGet", dependency: type == "Direct" ? "direct" : "transitive"))
            }
        }
        return result
    }

    // Elixir: mix.lock entries from Hex ({:hex, :name, "version", ...}); git dependencies are skipped.
    static func mix(_ text: String) -> [LockPackage] {
        captures("\"[a-z0-9_]+\":\\s*\\{:hex,\\s*:([a-z0-9_]+),\\s*\"([0-9][^\"]*)\"", text).map { LockPackage(name: $0[1], version: $0[2], ecosystem: "Hex") }
    }

    // Gradle: gradle.lockfile lines are group:artifact:version=configurations. Packages used only by test
    // configurations count as dev dependencies.
    static func gradle(_ text: String) -> [LockPackage] {
        captures("(?m)^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([0-9][^=\\s]*)=([^\\r\\n]*)$", text).map { match in
            let configurations = match[4].split(separator: ",")
            let testOnly = !configurations.isEmpty && configurations.allSatisfy { $0.lowercased().contains("test") }
            return LockPackage(name: match[1] + ":" + match[2], version: match[3], ecosystem: "Maven", dependency: testOnly ? "dev" : nil)
        }
    }

    // Workflow files in a project's .github/workflows folder, which name the GitHub Actions they run.
    static func workflows(_ github: String) -> [String] {
        let folder = github + "/workflows"
        return Inventory.children(folder).filter { $0.hasSuffix(".yml") || $0.hasSuffix(".yaml") }.map { folder + "/" + $0 }.filter { path in
            var info = stat()
            return lstat(path, &info) == 0 && info.st_mode & S_IFMT == S_IFREG
        }
    }

    // GitHub Actions a workflow uses, as owner/repo and the reference after @. Local actions (./) and Docker
    // images are skipped. A commit hash keeps the version comment beside it when there is one, the convention
    // Dependabot and Renovate maintain ("v4.1.1 (commit 8e8c483)"); otherwise it reads "commit 8e8c483".
    static func actions(_ text: String) -> [LockPackage] {
        captures("(?m)^[ \\t-]*uses:[ \\t]*[\"']?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[^@\\s\"']*)?@([^\\s\"'#]+)[\"']?(?:[ \\t]*#[ \\t]*(\\S+))?", text).map { match in
            var ref = match[2]
            if ref.range(of: "^[0-9a-f]{40}$", options: .regularExpression) != nil {
                let short = String(ref.prefix(7))
                ref = match[3].range(of: "^v?[0-9]+(\\.[0-9]+)*$", options: .regularExpression) != nil ? "\(match[3]) (commit \(short))" : "commit \(short)"
            }
            return LockPackage(name: match[1], version: ref, ecosystem: "GitHub Actions")
        }
    }

    // go.mod's require lines, alone or in a require ( ) block. Lines in exclude and retract blocks aren't built, so
    // they aren't read. A replace line swaps a module for another one, which is what gets built: the replacement is
    // checked in its place, and a module replaced by a folder on disk isn't checked.
    static func goModules(_ text: String) -> [LockPackage] {
        var result: [LockPackage] = [], block = ""
        var replaces: [(old: String, oldVersion: String, new: String, newVersion: String)] = []
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line == ")" { block = ""; continue }
            if let open = captures("^(require|exclude|replace|retract)\\s*\\($", line).first { block = open[1].lowercased(); continue }
            var kind = block, body = line
            if block.isEmpty, let single = captures("^(require|exclude|replace|retract)\\s+([^\\n]+)$", line).first { kind = single[1].lowercased(); body = single[2] }
            if kind == "require", let m = captures("^([A-Za-z0-9][A-Za-z0-9.\\-_~/]*)\\s+v([0-9][^\\s]*)(\\s*// indirect)?", body).first {
                result.append(LockPackage(name: m[1], version: m[2], ecosystem: "Go", dependency: m[3].isEmpty ? "direct" : "transitive"))
            } else if kind == "replace", let m = captures("^(\\S+)(?:\\s+v(\\S+))?\\s*=>\\s*(\\S+)(?:\\s+v([0-9]\\S*))?", body).first {
                replaces.append((m[1], m[2], m[3], m[4]))
            }
        }
        return result.compactMap { package in
            guard let swap = replaces.first(where: { $0.old == package.name && ($0.oldVersion.isEmpty || $0.oldVersion == package.version) }) else { return package }
            return swap.newVersion.isEmpty ? nil : LockPackage(name: swap.new, version: swap.newVersion, ecosystem: "Go", dependency: package.dependency)
        }
    }
}
