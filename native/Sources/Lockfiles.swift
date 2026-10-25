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
        "Gemfile.lock": "bundler", "go.mod": "go"
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
    static func find(in root: String, depth limit: Int = 5, skipping roots: Set<String> = skippedRoots) -> [String] {
        var found: [String] = []
        func walk(_ dir: String, _ depth: Int) {
            guard depth <= limit, found.count < 2000, let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
            for name in names.sorted() {
                let path = dir == "/" ? "/" + name : dir + "/" + name
                // lstat doesn't follow links: linked folders and files are skipped, so a scan stays inside the chosen folder.
                var info = stat()
                guard lstat(path, &info) == 0 else { continue }
                let type = info.st_mode & S_IFMT
                if type == S_IFDIR {
                    if !skipped.contains(name), !name.hasPrefix("."), !name.hasSuffix(".app"), !name.hasSuffix(".framework"), !roots.contains(path) { walk(path, depth + 1) }
                } else if type == S_IFREG, managers[name] != nil || name == ".mcp.json" { found.append(path) }
            }
        }
        walk(root, 0)
        return found
    }

    static let sizeLimit = 64_000_000
    static func parse(_ path: String, data: Data? = nil) -> (manager: String, packages: [LockPackage])? {
        let file = (path as NSString).lastPathComponent
        guard var manager = managers[file], let data = data ?? Inventory.read(path, limit: sizeLimit) else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        let packages: [LockPackage]
        switch manager {
        case "npm": packages = npm(data)
        case "pnpm": packages = pnpm(text)
        case "yarn": if text.contains("__metadata:") { manager = "yarn-berry" }; packages = yarn(text)
        case "bun-lock": packages = bun(text)
        case "uv": packages = toml(text, ecosystem: "PyPI") { !$0.contains("editable") && !$0.contains("virtual") && !$0.contains("directory") && !$0.contains("path =") }
        case "poetry": packages = toml(text, ecosystem: "PyPI") { _ in true }
        case "cargo": packages = toml(text, ecosystem: "crates.io") { $0.contains("registry+") }
        case "pip-req": packages = requirements(text)
        case "bundler": packages = gemfile(text)
        default: packages = goModules(text)
        }
        let directory = (path as NSString).deletingLastPathComponent
        let roles = manager.hasPrefix("yarn") || manager == "pnpm" || manager == "bun-lock" ? jsRoles(directory) : [:]
        // One entry per name and version, preferring the most direct role.
        var unique: [String: LockPackage] = [:]
        for var package in packages {
            if package.dependency == nil, let role = roles[package.name] { package.dependency = role }
            let key = package.name + "@" + package.version
            if let old = unique[key], rank(old.dependency) >= rank(package.dependency) { continue }
            unique[key] = package
        }
        return (manager, unique.values.sorted { ($0.name, $0.version) < ($1.name, $1.version) })
    }
    static func rank(_ role: String?) -> Int { role == "direct" ? 3 : role == "dev" ? 2 : role == "transitive" ? 1 : 0 }

    // Direct and dev dependency names from the package.json beside a JavaScript lockfile.
    static func jsRoles(_ directory: String) -> [String: String] {
        guard let data = Inventory.read(directory + "/package.json", limit: 8_000_000),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        var roles: [String: String] = [:]
        for name in ((obj["devDependencies"] as? [String: Any]) ?? [:]).keys { roles[name] = "dev" }
        for key in ["dependencies", "optionalDependencies", "peerDependencies"] { for name in ((obj[key] as? [String: Any]) ?? [:]).keys { roles[name] = "direct" } }
        return roles
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
                    result.append(LockPackage(name: name, version: version, ecosystem: "npm", dependency: top && value["dev"] as? Bool == true ? "dev" : top ? nil : "transitive"))
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

    static func yarn(_ text: String) -> [LockPackage] {
        var result: [LockPackage] = [], name: String? = nil
        for line in text.split(separator: "\n") {
            if !line.hasPrefix(" ") && !line.hasPrefix("#") && line.hasSuffix(":") {
                let first = line.dropLast().split(separator: ",").first.map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\" ")) } ?? ""
                name = splitSpec(first.replacingOccurrences(of: "@npm:", with: "@")).map(\.0).flatMap { $0.contains(":") ? nil : $0 }
            } else if let current = name, let m = captures("^\\s+version:?\\s+\"?([^\"\\s]+)\"?$", String(line)).first {
                if m[1].first?.isNumber == true && !m[1].contains("use.local") { result.append(LockPackage(name: current, version: m[1], ecosystem: "npm")) }
                name = nil
            }
        }
        return result
    }

    static func bun(_ text: String) -> [LockPackage] {
        guard let start = text.range(of: "\"packages\"") else { return [] }
        return captures("\"[^\"]+\":\\s*\\[\\s*\"((?:@[^@\"/]+/)?[^@\"]+)@([0-9][^\"]*)\"", String(text[start.lowerBound...]))
            .map { LockPackage(name: $0[1], version: $0[2], ecosystem: "npm") }
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
        guard let gem = text.range(of: "GEM\n") else { return [] }
        let section = text[gem.upperBound...].components(separatedBy: "\n\n").first ?? ""
        return captures("(?m)^    ([A-Za-z0-9_.-]+) \\(([0-9][^)-]*)", section).map { LockPackage(name: $0[1], version: $0[2], ecosystem: "RubyGems") }
    }

    static func goModules(_ text: String) -> [LockPackage] {
        captures("(?m)^(?:require\\s+|\\t)([A-Za-z0-9][A-Za-z0-9.\\-_~/]*)\\s+v([0-9][^\\s]*)(\\s*// indirect)?", text)
            .map { LockPackage(name: $0[1], version: $0[2], ecosystem: "Go", dependency: $0[3].isEmpty ? "direct" : "transitive") }
    }
}
