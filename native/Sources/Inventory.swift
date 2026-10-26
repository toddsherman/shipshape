import Foundation

struct CommandResult { let text: String; let code: Int32 }
func trustedExecutable(_ path: String, uid: uid_t = getuid()) -> Bool {
    var info = stat()
    guard stat(URL(fileURLWithPath: path).resolvingSymlinksInPath().path, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return false }
    return (info.st_uid == uid || info.st_uid == 0) && info.st_mode & 0o022 == 0
}
func command(_ executable: String, _ arguments: [String], timeout: TimeInterval = 20) throws -> CommandResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    // Only binaries owned by this account or root, and writable by no one else, are run, with a minimal
    // environment, so another account can't plant code that runs as you and inherited variables can't change it.
    guard trustedExecutable(executable) else { throw MonitorError(message: "Not run: \(executable) isn't owned by this account or root, or others can change it") }
    let inherited = ProcessInfo.processInfo.environment
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": inherited["HOME"] ?? NSHomeDirectory(), "TMPDIR": inherited["TMPDIR"] ?? NSTemporaryDirectory(),
                           "USER": NSUserName(), "LC_ALL": "C"]
    // A temporary file avoids pipe-buffer deadlock for large package inventories.
    let file = FileManager.default.temporaryDirectory.appendingPathComponent("\(appName.lowercased())-\(UUID().uuidString)")
    FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600])
    let handle = try FileHandle(forWritingTo: file)
    defer { try? handle.close(); try? FileManager.default.removeItem(at: file) }
    process.standardOutput = handle
    process.standardError = handle
    try process.run()
    let end = Date().addingTimeInterval(timeout)
    while process.isRunning && Date() < end { Thread.sleep(forTimeInterval: 0.05) }
    if process.isRunning {
        process.terminate()
        // Bound cancellation too; no process can leave the scanner waiting indefinitely.
        Thread.sleep(forTimeInterval: 0.2)
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit()
        throw MonitorError(message: "Timed out after \(Int(timeout)) seconds")
    }
    process.waitUntilExit()
    let data = try Data(contentsOf: file)
    guard data.count < 20_000_000 else { throw MonitorError(message: "Command response exceeded size limit") }
    return CommandResult(text: String(decoding: data, as: UTF8.self), code: process.terminationStatus)
}

// Reads versions from bundle metadata, package manifests, lockfiles and a few `--version` calls on known
// runtime paths. MCP configurations are read for each server's command and arguments only; environment
// variables, headers and other settings are never kept.
enum Inventory {
    static let fm = FileManager.default
    static let home = fm.homeDirectoryForCurrentUser.path
    static func product(forFormula name: String) -> String { Catalog.product(formula: name)?.id ?? name }
    static func display(_ path: String) -> String { path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path }
    static func children(_ path: String) -> [String] { ((try? fm.contentsOfDirectory(atPath: path)) ?? []).filter { !$0.hasPrefix(".") }.sorted() }
    // Files are read only up to a size limit, after checking they're regular files. Links are refused in project
    // folders (a repo could point one at a huge or private file); settings in the home folder may be links.
    static func read(_ path: String, limit: Int, followLinks: Bool = false) -> Data? {
        var info = stat()
        guard (followLinks ? stat(path, &info) : lstat(path, &info)) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size <= limit,
              let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: limit + 1)).flatMap { $0.count > limit ? nil : $0 }
    }
    static func head(_ path: String, bytes: Int) -> Data? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        return try? handle.read(upToCount: bytes)
    }
    static func json(_ path: String, limit: Int = 32_000_000) -> [String: Any]? {
        read(path, limit: limit, followLinks: true).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    }

    static func collect(projectFolders: [String] = []) -> ScanReport {
        var report = ScanReport()
        var seen = Set<String>()
        func add(_ items: [Installation]) { for item in items where seen.insert(item.path).inserted { report.installations.append(item) } }
        func check(_ id: String, _ name: String, _ domain: String, _ errors: [String], _ detail: String, failed: Bool = false) {
            report.domains[domain] = errors.isEmpty
            report.checks.append(SourceCheck(id: id, name: name, status: errors.isEmpty ? "checked" : failed ? "failed" : "partial", detail: errors.isEmpty ? detail : errors.prefix(8).joined(separator: "; ")))
        }
        let (apps, appErrors, skipped) = self.apps()
        add(apps)
        check("inventory-apps", "Developer apps", "apps", appErrors, "Read \(apps.filter { $0.manager == "app" }.count) apps in /Applications and your Applications folder: catalog developer apps, plus self-updating apps with a Sparkle feed or a bundled Sparkle, and the Sparkle version inside \(apps.filter { $0.manager == "sparkle-framework" }.count) of them. Skipped \(skipped) App Store or Google Chrome app\(skipped == 1 ? "" : "s") by design.")
        let (brew, brewErrors) = homebrew()
        add(brew)
        check("inventory-brew", "Homebrew inventory", "brew", brewErrors, "Read \(brew.count) installed formula, cask and bundled Python package versions, including retained copies.", failed: true)
        let (tools, toolErrors) = runtimes(existing: report.installations)
        add(tools)
        add(mise())
        check("inventory-tools", "Runtimes and AI coding tools", "tools", toolErrors, "Node (standard, nvm, Volta, fnm), Bun, Deno, uv, Go, python.org, uv and pyenv Pythons, runtimes installed with mise, and native installs of Claude Code, OpenCode and Copilot CLI.")
        let (packages, packageErrors) = globalPackages()
        add(packages)
        check("inventory-packages", "Global packages", "packages", packageErrors, "Read \(packages.count) globally installed npm, Bun, pnpm, pip, pipx, uv tool, cargo, Ruby gem and go install packages, the npx cache, and VS Code, Cursor and Windsurf extensions.")
        var lockfiles: [String] = [], mcpFiles: [String] = [], projectErrors: [String] = []
        for folder in projectFolders {
            guard fm.fileExists(atPath: folder) else { projectErrors.append("Cannot read \(display(folder))"); continue }
            for path in Lockfiles.find(in: folder) { if path.hasSuffix(".mcp.json") { mcpFiles.append(path) } else { lockfiles.append(path) } }
        }
        let projectItems = projects(lockfiles, errors: &projectErrors)
        add(projectItems)
        check("inventory-projects", "Project dependencies", "projects", projectErrors, projectFolders.isEmpty
              ? "No project folders chosen. Add them in Settings to check your apps' dependencies."
              : "Read \(projectItems.count) package versions from \(lockfiles.count) lockfiles in \(projectFolders.count) project folder\(projectFolders.count == 1 ? "" : "s").")
        let (servers, mcpErrors) = mcpServers(projectFiles: mcpFiles)
        add(servers)
        check("inventory-mcp", "MCP servers", "mcp", mcpErrors, "Read \(servers.count) package-based MCP servers from Claude Code, Claude, Codex, Cursor, Windsurf, VS Code and Gemini CLI settings.")
        report.domains["apple"] = true
        report.installations.sort { ($0.domain, $0.name.lowercased(), $0.path) < ($1.domain, $1.name.lowercased(), $1.path) }
        return report
    }

    // App Store apps (those with a Mac App Store receipt) and Google Chrome are skipped by design.
    static func apps(roots: [String] = ["/Applications", home + "/Applications"]) -> ([Installation], [String], skipped: Int) {
        var items: [Installation] = [], errors: [String] = [], skipped = 0
        for root in roots where fm.fileExists(atPath: root) {
            let base = URL(fileURLWithPath: root)
            guard let enumerator = fm.enumerator(at: base, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles], errorHandler: { url, _ in
                errors.append("Cannot inspect \(url.lastPathComponent)"); return true
            }) else { errors.append("Cannot read \(root)"); continue }
            while let url = enumerator.nextObject() as? URL {
                if url.pathExtension == "app" {
                    enumerator.skipDescendants()
                    guard let data = try? Data(contentsOf: url.appendingPathComponent("Contents/Info.plist")),
                          let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
                          let bundleID = info["CFBundleIdentifier"] as? String else { continue }
                    if Catalog.excludedBundleIDs.contains(bundleID) || fm.fileExists(atPath: url.appendingPathComponent("Contents/_MASReceipt/receipt").path) { skipped += 1; continue }
                    let build = info["CFBundleVersion"] as? String
                    let feed = (info["SUFeedURL"] as? String).flatMap { $0.hasPrefix("https://") ? $0 : nil }
                    let sparkle = sparkleBuild(url.path)
                    let title = (info["CFBundleDisplayName"] ?? info["CFBundleName"]) as? String ?? url.deletingPathExtension().lastPathComponent
                    // Apps outside the catalog are kept when Sparkle can say something about them: a feed with
                    // their newest release, or a bundled Sparkle with known advisories.
                    let product = Catalog.byBundleID[bundleID]
                    guard product != nil || feed != nil || sparkle != nil else { continue }
                    guard let version = info["CFBundleShortVersionString"] as? String ?? build else { errors.append("Unreadable version: \(url.lastPathComponent)"); continue }
                    let name = product?.name ?? title
                    items.append(Installation(product: product?.id ?? "app:" + bundleID, name: name, version: version, path: url.path, domain: "apps", package: product?.casks.first,
                                              ecosystem: product.flatMap { Catalog.osv($0, version: version)?.ecosystem }, packageName: product.flatMap { Catalog.osv($0, version: version)?.name },
                                              manager: "app", build: build, feed: feed))
                    if let sparkle {
                        let modified = sparkle.changes.map { " It's a modified Sparkle build, \(sparkle.version) plus \($0.formatted()) change\($0 == 1 ? "" : "s"), so its version may not show fixes made since." } ?? ""
                        items.append(Installation(product: "swifturl:github.com/sparkle-project/Sparkle", name: "Sparkle in \(name)", version: sparkle.version, path: url.path + "/Contents/Frameworks/Sparkle.framework",
                                                  domain: "apps", note: "The update framework bundled inside \(name). It is updated with the app." + modified, ecosystem: "SwiftURL",
                                                  packageName: "github.com/sparkle-project/Sparkle", manager: "sparkle-framework", location: url.path))
                    }
                } else if url.pathComponents.count - base.pathComponents.count >= 3 { enumerator.skipDescendants() }
            }
        }
        return (items, errors, skipped)
    }

    // The version of the Sparkle framework bundled in an app, trimmed of build suffixes ("1.27.1-3-g05be1d71",
    // "1.22.0 1354-g4e0506a") so it can be compared; prerelease tags such as -beta.1 are kept. A suffix of the
    // form N-g<commit> means the app ships its own build with N changes on top of that Sparkle release.
    static func sparkleBuild(_ app: String) -> (version: String, changes: Int?)? {
        let framework = app + "/Contents/Frameworks/Sparkle.framework"
        guard let data = ["/Versions/A/Resources/Info.plist", "/Resources/Info.plist"].lazy.compactMap({ read(framework + $0, limit: 1_000_000, followLinks: true) }).first,
              let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
              let raw = (info["CFBundleShortVersionString"] ?? info["CFBundleVersion"]) as? String, let version = trimmedSparkleVersion(raw) else { return nil }
        return (version, sparkleChanges(raw))
    }
    static func sparkleChanges(_ raw: String) -> Int? {
        captures("^[0-9]+(?:\\.[0-9]+)*[ -]([0-9]+)-g[0-9a-f]{6,}", raw).first.flatMap { Int($0[1]) }
    }
    static func trimmedSparkleVersion(_ raw: String) -> String? {
        captures("^([0-9]+\\.[0-9]+(?:\\.[0-9]+)?(?:-(?:alpha|beta|rc)[0-9.]*)?)", raw).first?[1]
    }

    // Read straight from Homebrew's folders instead of running brew: Cellar holds each formula's installed
    // copies, opt/ links point at the active one, var/homebrew/pinned marks pins and Caskroom holds casks.
    // No Homebrew code runs (another account may own it), and nothing waits on Ruby.
    static func homebrew(prefixes: [String] = ["/opt/homebrew", "/usr/local"]) -> ([Installation], [String]) {
        var items: [Installation] = [], errors: [String] = []
        for prefix in prefixes where fm.fileExists(atPath: prefix + "/Cellar") || fm.fileExists(atPath: prefix + "/Caskroom") {
            if fm.fileExists(atPath: prefix + "/Cellar") && !fm.isReadableFile(atPath: prefix + "/Cellar") { errors.append("\(prefix)/Cellar can't be read"); continue }
            // Renamed formulae leave links in Cellar (vercel-cli -> vercel); only real folders are installs.
            for name in children(prefix + "/Cellar") where directory(prefix + "/Cellar/" + name) {
                let kegs = children(prefix + "/Cellar/" + name).filter { directory(prefix + "/Cellar/" + name + "/" + $0) }
                guard !kegs.isEmpty else { continue }
                let product = Catalog.product(formula: name)
                let active = (try? fm.destinationOfSymbolicLink(atPath: prefix + "/opt/" + name)).map { ($0 as NSString).lastPathComponent }
                let pinned = (try? fm.destinationOfSymbolicLink(atPath: prefix + "/var/homebrew/pinned/" + name)) != nil
                for raw in kegs {
                    let old = kegs.count > 1 && active != nil && raw != active
                    var item = Installation(product: product?.id ?? name, name: name, version: raw.components(separatedBy: "_")[0], path: prefix + "/Cellar/" + name + "/" + raw, domain: "brew",
                                            package: name, note: old ? "Older Homebrew copy retained on disk; not the active version." : "Homebrew copy; running processes may still use an earlier version.",
                                            manager: old ? "brew-old" : "brew")
                    if !old, let osv = Catalog.osv(product, version: item.version) { item.ecosystem = osv.ecosystem; item.packageName = osv.name }
                    if pinned { item.pinned = true }
                    items.append(item)
                }
                // Homebrew's Python bundles pip inside its framework.
                if name.hasPrefix("python@"), let active, let branch = captures("^python@([0-9]+\\.[0-9]+)$", name).first?[1] {
                    let site = "\(prefix)/Cellar/\(name)/\(active)/Frameworks/Python.framework/Versions/\(branch)/lib/python\(branch)/site-packages"
                    items += pythonPackages(site: site, interpreter: "\(prefix)/bin/python\(branch)", manager: "brew-python", package: name, label: "Homebrew \(name)")
                    items += pythonPackages(site: "\(prefix)/lib/python\(branch)/site-packages", interpreter: "\(prefix)/bin/python\(branch)", manager: "pip-brew", label: "Homebrew Python \(branch) site-packages")
                }
            }
            for token in children(prefix + "/Caskroom") where !Catalog.excludedCasks.contains(token) && directory(prefix + "/Caskroom/" + token) {
                guard let version = children(prefix + "/Caskroom/" + token).filter({ directory(prefix + "/Caskroom/" + token + "/" + $0) }).max(by: looseLess) else { continue }
                let product = Catalog.byCask[token], osv = Catalog.osv(Catalog.byCask[token], version: version.components(separatedBy: ",")[0])
                items.append(Installation(product: product?.id ?? token, name: product?.name ?? token, version: version.components(separatedBy: ",")[0], path: prefix + "/Caskroom/" + token + "/" + version,
                                          domain: "brew", package: token, note: "Homebrew cask.", ecosystem: osv?.ecosystem, packageName: osv?.name, manager: "cask"))
            }
        }
        return (items, errors)
    }
    static func directory(_ path: String) -> Bool { var info = stat(); return lstat(path, &info) == 0 && info.st_mode & S_IFMT == S_IFDIR }  // a real folder, not a link

    static func runtimes(existing: [Installation]) -> ([Installation], [String]) {
        var items: [Installation] = [], errors: [String] = []
        var candidates: [(product: String, path: String, manager: String?)] = [
            ("node", "/usr/local/bin/node", fm.fileExists(atPath: "/var/db/receipts/org.nodejs.node.pkg.bom") ? "node-pkg" : nil),
            ("node", "/opt/homebrew/bin/node", "brew"), ("node", home + "/.local/bin/node", nil),
            ("bun", home + "/.bun/bin/bun", "bun"), ("deno", home + "/.deno/bin/deno", "deno"), ("uv", home + "/.local/bin/uv", "uv-self"), ("uv", home + "/.cargo/bin/uv", "uv-self"),
            ("opencode", home + "/.opencode/bin/opencode", "opencode"), ("copilot-cli", home + "/.local/bin/copilot", "copilot"), ("copilot-cli", "/usr/local/bin/copilot", "copilot")
        ]
        for (root, manager) in [(home + "/.nvm/versions/node", "nvm"), (home + "/.volta/tools/image/node", "volta"), (home + "/.local/share/fnm/node-versions", "fnm")] {
            for child in children(root) { candidates.append(("node", root + "/" + child + (manager == "fnm" ? "/installation/bin/node" : "/bin/node"), manager)) }
        }
        let names = ["node": "Node.js", "bun": "Bun", "deno": "Deno", "uv": "uv", "opencode": "OpenCode", "copilot-cli": "GitHub Copilot CLI"]
        var resolved = Set<String>()
        for (product, path, manager) in candidates where fm.isExecutableFile(atPath: path) {
            let real = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
            if existing.contains(where: { real.hasPrefix($0.path + "/") }) || !resolved.insert(real).inserted { continue }
            do {
                let result = try command(path, ["--version"], timeout: 5)
                guard result.code == 0, let value = captures("([0-9]+(?:\\.[0-9]+)+)", result.text.components(separatedBy: "\n")[0]).first?[1] else { throw MonitorError(message: "Version could not be read") }
                let osv = Catalog.osv(Catalog.byID[product], version: value)
                items.append(Installation(product: product, name: names[product] ?? product, version: value, path: real, domain: "tools", note: "Located at \(display(path)).",
                                          ecosystem: osv?.ecosystem, packageName: osv?.name, manager: manager))
            } catch { errors.append("\(display(path)): \(error.localizedDescription)") }
        }
        // Claude Code's native installer links ~/.local/bin/claude to a versioned build.
        if let target = try? fm.destinationOfSymbolicLink(atPath: home + "/.local/bin/claude"), let version = Version((target as NSString).lastPathComponent).map({ _ in (target as NSString).lastPathComponent }) {
            items.append(Installation(product: "claude-code", name: "Claude Code", version: version, path: target, domain: "tools", note: "Native install at ~/.local/bin/claude.",
                                      ecosystem: "npm", packageName: "@anthropic-ai/claude-code", manager: "claude"))
        }
        if let manifest = json(home + "/.claude/local/node_modules/@anthropic-ai/claude-code/package.json"), let version = manifest["version"] as? String {
            items.append(Installation(product: "claude-code", name: "Claude Code", version: version, path: home + "/.claude/local", domain: "tools", note: "Local install in ~/.claude/local.",
                                      ecosystem: "npm", packageName: "@anthropic-ai/claude-code", manager: "claude"))
        }
        if let text = read("/usr/local/go/VERSION", limit: 4096, followLinks: true).map({ String(decoding: $0, as: UTF8.self) }), let version = captures("^go([0-9][^\\s]*)", text).first?[1] {
            items.append(Installation(product: "go", name: "Go", version: version, path: "/usr/local/go", domain: "tools", note: "Installed from go.dev.", ecosystem: "Go", packageName: "stdlib", manager: "go-pkg"))
        }
        let framework = "/Library/Frameworks/Python.framework/Versions"
        for child in children(framework) where Version(child) != nil {
            let path = framework + "/" + child
            guard let data = read(path + "/Resources/Info.plist", limit: 4_000_000, followLinks: true), let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
                  let version = info["CFBundleShortVersionString"] as? String else { errors.append("Cannot read Python \(child) metadata"); continue }
            items.append(Installation(product: "python", name: "Python (python.org)", version: version, path: path, domain: "tools", manager: "python-org"))
            items += pythonPackages(site: "\(path)/lib/python\(child)/site-packages", interpreter: "\(path)/bin/python\(child)", manager: "pip", label: "python.org Python \(child)")
        }
        for (root, manager) in [(home + "/.local/share/uv/python", "uv-python"), (home + "/.pyenv/versions", "pyenv")] {
            for child in children(root) {
                guard let version = captures("^(?:cpython-)?([0-9]+\\.[0-9]+\\.[0-9]+)(?:-|$)", child).first?[1] else { continue }
                let branch = version.split(separator: ".").prefix(2).joined(separator: ".")
                items.append(Installation(product: "python", name: "Python (\(manager == "pyenv" ? "pyenv" : "uv"))", version: version, path: root + "/" + child, domain: "tools", manager: manager))
                items += pythonPackages(site: "\(root)/\(child)/lib/python\(branch)/site-packages", interpreter: "\(root)/\(child)/bin/python\(branch)", manager: "pip", label: "Python \(version) (\(manager))")
            }
        }
        return (items, errors)
    }

    // mise keeps each runtime in installs/<tool>/<version>. Alias symlinks such as "22" or "latest" are
    // skipped; the experimental identity layout's <label>-<hash> folders are read by their leading version.
    static func mise(root: String = home + "/.local/share/mise/installs") -> [Installation] {
        let tools = ["node": "Node.js", "python": "Python", "go": "Go", "ruby": "Ruby", "bun": "Bun", "deno": "Deno"]
        var items: [Installation] = []
        for tool in children(root) {
            guard let name = tools[tool] else { continue }
            for child in children(root + "/" + tool) where (try? fm.destinationOfSymbolicLink(atPath: "\(root)/\(tool)/\(child)")) == nil {
                guard let version = captures("^([0-9]+(?:\\.[0-9]+)+)", child).first?[1] else { continue }
                let path = "\(root)/\(tool)/\(child)", osv = Catalog.osv(Catalog.byID[tool], version: version)
                items.append(Installation(product: tool, name: name + " (mise)", version: version, path: path, domain: "tools", note: "Installed with mise at \(display(path)).",
                                          ecosystem: osv?.ecosystem, packageName: osv?.name, manager: "mise", location: tool))
                if tool == "python" {
                    let branch = version.split(separator: ".").prefix(2).joined(separator: ".")
                    items += pythonPackages(site: "\(path)/lib/python\(branch)/site-packages", interpreter: "\(path)/bin/python\(branch)", manager: "pip", label: "Python \(version) (mise)")
                }
                if tool == "node" { items += nodePackages(root: path + "/lib/node_modules", manager: "npm-global", location: path + "/bin/npm", label: "global npm (Node \(version), mise)") }
            }
        }
        return items
    }

    static func pythonPackages(site: String, interpreter: String, manager: String, package: String? = nil, label: String) -> [Installation] {
        children(site).filter { $0.hasSuffix(".dist-info") }.compactMap { dist in
            guard let data = head(site + "/" + dist + "/METADATA", bytes: 4096) else { return nil }
            let head = String(decoding: data.prefix(4096), as: UTF8.self)
            guard let name = captures("(?m)^Name: ([^\\r\\n]+)", head).first?[1], let version = captures("(?m)^Version: ([^\\r\\n]+)", head).first?[1] else { return nil }
            return Installation(product: "pypi:" + OSV.normalized(name, "PyPI"), name: name, version: version, path: site + "/" + dist, domain: "packages", package: package,
                                note: "Python package in \(label).", ecosystem: "PyPI", packageName: name, manager: manager, location: interpreter)
        }
    }
    static func nodePackages(root: String, manager: String, location: String?, label: String) -> [Installation] {
        var items: [Installation] = []
        for name in children(root) {
            for directory in name.hasPrefix("@") ? children(root + "/" + name).map({ name + "/" + $0 }) : [name] {
                guard let manifest = json(root + "/" + directory + "/package.json"), let package = manifest["name"] as? String, let version = manifest["version"] as? String else { continue }
                items.append(Installation(product: "npm:" + package, name: package, version: version, path: root + "/" + directory, domain: "packages", note: "npm package in \(label).",
                                          ecosystem: "npm", packageName: package, manager: manager, location: location))
            }
        }
        return items
    }

    static func globalPackages() -> ([Installation], [String]) {
        var items: [Installation] = []
        var roots: [(String, String)] = [("/opt/homebrew/lib/node_modules", "/opt/homebrew/bin/npm"), ("/usr/local/lib/node_modules", "/usr/local/bin/npm")]
        for version in children(home + "/.nvm/versions/node") { roots.append(("\(home)/.nvm/versions/node/\(version)/lib/node_modules", "\(home)/.nvm/versions/node/\(version)/bin/npm")) }
        for version in children(home + "/.local/share/fnm/node-versions") { roots.append(("\(home)/.local/share/fnm/node-versions/\(version)/installation/lib/node_modules", "\(home)/.local/share/fnm/node-versions/\(version)/installation/bin/npm")) }
        for (root, npm) in roots { items += nodePackages(root: root, manager: "npm-global", location: npm, label: "global npm (\(display(root)))") }
        items += nodePackages(root: home + "/.bun/install/global/node_modules", manager: "bun-global", location: nil, label: "Bun's global packages")
        for store in children(home + "/Library/pnpm/global") { items += nodePackages(root: "\(home)/Library/pnpm/global/\(store)/node_modules", manager: "pnpm-global", location: nil, label: "pnpm's global packages") }
        for cache in children(home + "/.npm/_npx") { items += nodePackages(root: "\(home)/.npm/_npx/\(cache)/node_modules", manager: "npx-cache", location: "\(home)/.npm/_npx/\(cache)", label: "the npx cache") }
        for (root, manager) in [(home + "/.local/pipx/venvs", "pipx"), (home + "/.local/share/uv/tools", "uv-tool")] {
            for tool in children(root) {
                for lib in children("\(root)/\(tool)/lib") where lib.hasPrefix("python") {
                    items += pythonPackages(site: "\(root)/\(tool)/lib/\(lib)/site-packages", interpreter: tool, manager: manager, label: "\(manager == "pipx" ? "pipx" : "uv tool") \(tool)")
                }
            }
        }
        items += cargoInstalls()
        items += rubyGems()
        items += editorExtensions()
        let (goItems, goErrors) = goBinaries()
        items += goItems
        return (items, goErrors)
    }

    // Crates installed with cargo install, from cargo's own record (~/.cargo/.crates2.json). Only crates from
    // crates.io are kept; git and path installs have no published versions to compare.
    static func cargoInstalls(root: String = home + "/.cargo") -> [Installation] {
        guard let installs = json(root + "/.crates2.json")?["installs"] as? [String: Any] else { return [] }
        return installs.keys.sorted().compactMap { key in
            guard let match = captures("^([A-Za-z0-9_-]+) ([0-9][^ ]*) \\(registry\\+", key).first else { return nil }
            return Installation(product: "crates.io:" + match[1], name: match[1], version: match[2], path: root + "/.crates2.json#" + match[1], domain: "packages",
                                note: "Installed with cargo install.", ecosystem: "crates.io", packageName: match[1], manager: "cargo-install", location: root + "/bin")
        }
    }

    // Ruby gems in Homebrew, rbenv, mise and per-user Rubies, named by their gemspec files (name-version, with an
    // optional platform). Default gems that ship with Ruby are included, since they get security releases too.
    // Apple's system Ruby is left out; Apple updates it.
    static func rubyGems() -> [Installation] {
        var specifications: [(folder: String, gem: String?)] = []
        func add(_ gems: String, ruby: String?) {
            for version in children(gems) { for folder in ["specifications", "specifications/default"] { specifications.append(("\(gems)/\(version)/\(folder)", ruby.map { $0 + "/bin/gem" })) } }
        }
        for prefix in ["/opt/homebrew", "/usr/local"] { add(prefix + "/lib/ruby/gems", ruby: prefix + "/opt/ruby") }
        for (root, layout) in [(home + "/.rbenv/versions", ""), (home + "/.local/share/mise/installs/ruby", "")] {
            for version in children(root) { add("\(root)/\(version)\(layout)/lib/ruby/gems", ruby: "\(root)/\(version)") }
        }
        add(home + "/.gem/ruby", ruby: nil)
        var items: [Installation] = []
        for (folder, gem) in specifications {
            for file in children(folder) {
                guard let (name, version) = gemSpec(file) else { continue }
                let installed = gem.map { fm.isExecutableFile(atPath: $0) } == true ? gem : nil
                items.append(Installation(product: "rubygems:" + name, name: name, version: version, path: folder + "/" + file, domain: "packages",
                                          note: "Ruby gem in \(display(folder.components(separatedBy: "/lib/ruby/gems").first ?? folder)).", ecosystem: "RubyGems",
                                          packageName: name, manager: "gem", location: installed))
            }
        }
        return items
    }

    // Extensions installed in VS Code and editors built on it, identified as publisher.name from each
    // extension's package.json. The editor's command-line tool, when installed, is kept for uninstalling.
    static func editorExtensions(roots: [(editor: String, folder: String, cli: String)]? = nil) -> [Installation] {
        let editors = roots ?? [("VS Code", home + "/.vscode/extensions", "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"),
                                ("VS Code Insiders", home + "/.vscode-insiders/extensions", "/Applications/Visual Studio Code - Insiders.app/Contents/Resources/app/bin/code-insiders"),
                                ("Cursor", home + "/.cursor/extensions", "/Applications/Cursor.app/Contents/Resources/app/bin/cursor"),
                                ("Windsurf", home + "/.windsurf/extensions", "/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf"),
                                ("VSCodium", home + "/.vscode-oss/extensions", "/Applications/VSCodium.app/Contents/Resources/app/bin/codium")]
        var items: [Installation] = []
        for (editor, folder, cli) in editors {
            for child in children(folder) where directory(folder + "/" + child) {
                guard let manifest = json(folder + "/" + child + "/package.json", limit: 4_000_000), let publisher = manifest["publisher"] as? String,
                      let name = manifest["name"] as? String, let version = manifest["version"] as? String else { continue }
                items.append(Installation(product: "extension:" + (publisher + "." + name).lowercased(), name: publisher + "." + name, version: version, path: folder + "/" + child,
                                          domain: "packages", package: editor, note: "\(editor) extension.", manager: "extension", location: fm.isExecutableFile(atPath: cli) ? cli : nil))
            }
        }
        return items
    }

    // "rspec-core-3.12.0.gemspec" → rspec-core 3.12.0; a platform suffix ("-arm64-darwin") is dropped.
    static func gemSpec(_ file: String) -> (name: String, version: String)? {
        captures("^(.+?)-([0-9]+(?:\\.[0-9A-Za-z]+)*)(?:-[A-Za-z0-9_]+)*\\.gemspec$", file).first.map { ($0[1], $0[2]) }
    }

    // Go programs installed with go install embed their module versions; go version -m reads them without
    // running the programs. The Go toolchain itself must pass the usual trust check.
    static func goBinaries(folder: String = home + "/go/bin") -> ([Installation], [String]) {
        let binaries = children(folder).map { folder + "/" + $0 }.filter { fm.isExecutableFile(atPath: $0) && !directory($0) }
        guard !binaries.isEmpty, let go = ["/opt/homebrew/bin/go", "/usr/local/go/bin/go", "/usr/local/bin/go"].first(where: fm.isExecutableFile) else { return ([], []) }
        do {
            let result = try command(go, ["version", "-m"] + binaries, timeout: 30)
            return (goModules(result.text), [])
        } catch { return ([], ["go version -m: \(error.localizedDescription)"]) }
    }
    static func goModules(_ text: String) -> [Installation] {
        var items: [Installation] = [], binary: String?, main: String?
        for line in text.components(separatedBy: "\n") {
            if !line.hasPrefix("\t"), let match = captures("^(/[^:]+): go[0-9]", line).first { binary = match[1]; main = nil; continue }
            let fields = line.split(separator: "\t").map(String.init)
            guard let binary, fields.count >= 2 else { continue }
            if fields[0] == "path" { main = fields[1]; continue }
            guard fields[0] == "mod" || fields[0] == "dep", fields.count >= 3, fields[2].hasPrefix("v") else { continue }
            let version = String(fields[2].dropFirst()), name = fields[1], tool = (binary as NSString).lastPathComponent
            items.append(Installation(product: "go:" + name, name: name, version: version, path: binary + "#" + name, domain: "packages", package: main,
                                      note: fields[0] == "mod" ? "Go program \(tool), installed with go install." : "Built into the Go program \(tool).",
                                      ecosystem: "Go", packageName: name, manager: "go-install", location: binary, dependency: fields[0] == "mod" ? "direct" : "transitive"))
        }
        return items
    }

    // Reading stops after a time limit, so one hostile lockfile can't hold up the whole check; what's left is reported.
    static func projects(_ lockfiles: [String], errors: inout [String], timeLimit: TimeInterval = 60) -> [Installation] {
        var items: [Installation] = []
        let deadline = Date().addingTimeInterval(timeLimit)
        for (index, path) in lockfiles.enumerated() {
            if Date() > deadline { errors.append("Stopped reading lockfiles after \(Int(timeLimit)) seconds; \(lockfiles.count - index) not checked"); break }
            guard let data = read(path, limit: Lockfiles.sizeLimit) else { errors.append("Skipped \(display(path)): a link, not a regular file, or larger than 64 MB"); continue }
            guard let (manager, packages) = Lockfiles.parse(path, data: data) else { errors.append("Cannot parse \(display(path))"); continue }
            let directory = Lockfiles.projectFolder(path), file = (path as NSString).lastPathComponent
            for package in packages {
                items.append(Installation(product: package.ecosystem.lowercased() + ":" + package.name, name: package.name, version: package.version, path: path + "#" + package.name + "@" + package.version,
                                          domain: "projects", note: display(directory) + " · " + file + (package.dependency.map { " · " + $0 } ?? ""), ecosystem: package.ecosystem,
                                          packageName: package.name, manager: manager, location: directory, dependency: package.dependency, file: path))
            }
        }
        return items
    }

    // Package-runner MCP servers (npx, bunx, pnpm dlx, uvx, pipx run) become package installations.
    static func mcpPackage(command: String, args: [String]) -> (ecosystem: String, spec: String)? {
        var rest = args, ecosystem = "npm"
        switch (command as NSString).lastPathComponent {
        case "npx", "bunx", "pnpx": break
        case "pnpm", "yarn": guard rest.first == "dlx" else { return nil }; rest.removeFirst()
        case "uvx": ecosystem = "PyPI"
        case "uv": guard rest.prefix(2) == ["tool", "run"] else { return nil }; rest.removeFirst(2); ecosystem = "PyPI"
        case "pipx": guard rest.first == "run" else { return nil }; rest.removeFirst(); ecosystem = "PyPI"
        default: return nil
        }
        let packageFlags: Set<String> = ecosystem == "npm" ? ["-p", "--package"] : ["--from"]
        let valueFlags: Set<String> = ecosystem == "npm" ? ["--registry", "--cache", "--userconfig", "--prefix"] : ["--python", "-p", "--with", "--index", "--index-url", "--extra-index-url", "-w", "--with-requirements"]
        // An unknown option before the package may take a value (--api-key KEY), which would then look like the
        // package name and be saved; in that case nothing is recorded.
        let switches: Set<String> = ecosystem == "npm" ? ["-y", "--yes", "--no", "--no-install", "-q", "--quiet", "--silent", "-s", "--ignore-existing", "--prefer-offline", "--prefer-online", "--offline"]
            : ["-q", "--quiet", "-v", "--verbose", "--isolated", "--no-cache", "--offline", "-n", "--refresh", "--no-progress", "--native-tls"]
        var index = 0
        while index < rest.count {
            let arg = rest[index]
            if packageFlags.contains(arg) { return index + 1 < rest.count ? (ecosystem, rest[index + 1]) : nil }
            if let flag = packageFlags.first(where: { arg.hasPrefix($0 + "=") }) { return (ecosystem, String(arg.dropFirst(flag.count + 1))) }
            if !arg.hasPrefix("-") { return (ecosystem, arg) }
            if valueFlags.contains(arg) { index += 2 } else if switches.contains(arg) || arg.contains("=") { index += 1 } else { return nil }
        }
        return nil
    }
    // Splits a runner spec into name and pinned version ("pkg@1.2.3", "pkg==1.2.3"); tags count as unpinned.
    static func pinned(_ spec: String, _ ecosystem: String) -> (name: String, version: String?) {
        let clean = spec.hasPrefix("npm:") ? String(spec.dropFirst(4)) : spec
        if ecosystem == "PyPI", let m = captures("^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\\[[^\\]]*\\])?(?:==|@)([0-9][^\\s]*)$", clean).first { return (m[1], m[2]) }
        if ecosystem == "PyPI" { return (clean.components(separatedBy: CharacterSet(charactersIn: "[=<>~!@ ")).first ?? clean, nil) }
        guard let (name, version) = Lockfiles.splitSpec(clean) else { return (clean, nil) }
        return (name, version.first?.isNumber == true ? version : nil)
    }

    // MCP settings Shipshape reads, and may open for editing, besides project .mcp.json files.
    static var mcpConfigFiles: [String] {
        [home + "/.claude.json", home + "/Library/Application Support/Claude/claude_desktop_config.json", home + "/.cursor/mcp.json",
         home + "/.codeium/windsurf/mcp_config.json", home + "/Library/Application Support/Code/User/mcp.json", home + "/.gemini/settings.json", home + "/.codex/config.toml"]
    }
    static func mcpServers(projectFiles: [String]) -> ([Installation], [String]) {
        var servers: [(config: String, name: String, command: String, args: [String])] = [], errors: [String] = []
        func collect(_ config: String, _ table: Any?) {
            for (name, value) in (table as? [String: Any]) ?? [:] {
                guard let server = value as? [String: Any], let command = server["command"] as? String else { continue }
                servers.append((config, name, command, (server["args"] as? [Any])?.compactMap { $0 as? String } ?? []))
            }
        }
        for file in mcpConfigFiles.filter({ $0.hasSuffix(".json") }) + projectFiles where fm.fileExists(atPath: file) {
            guard let obj = json(file) else { errors.append("Cannot parse \(display(file))"); continue }
            collect(file, obj["mcpServers"])
            collect(file, obj["servers"])
            for project in ((obj["projects"] as? [String: Any]) ?? [:]).values { collect(file, (project as? [String: Any])?["mcpServers"]) }
        }
        let codex = mcpConfigFiles.first { $0.hasSuffix(".toml") }!
        if let text = read(codex, limit: 4_000_000, followLinks: true).map({ String(decoding: $0, as: UTF8.self) }) {
            for section in text.components(separatedBy: "\n[").dropFirst() {
                guard let name = captures("^mcp_servers\\.([A-Za-z0-9_\"-]+)\\]", section).first?[1], let command = captures("(?m)^command\\s*=\\s*\"([^\"]*)\"", section).first?[1] else { continue }
                let args = captures("(?m)^args\\s*=\\s*\\[([^\\]]*)\\]", section).first.map { captures("\"([^\"]*)\"", $0[1]).map { $0[1] } } ?? []
                servers.append((codex, name.replacingOccurrences(of: "\"", with: ""), command, args))
            }
        }
        // Unpinned npm servers run whatever npx last cached; report that version when it is present.
        var cached: [String: String] = [:]
        for cache in children(home + "/.npm/_npx") {
            for item in nodePackages(root: "\(home)/.npm/_npx/\(cache)/node_modules", manager: "", location: nil, label: "") where cached[item.name].map({ looseLess($0, item.version) }) ?? true {
                cached[item.name] = item.version
            }
        }
        var items: [Installation] = []
        for server in servers {
            guard let (ecosystem, spec) = mcpPackage(command: server.command, args: server.args) else { continue }
            let (name, version) = pinned(spec, ecosystem)
            guard Commands.safe(name, Commands.namePatterns[ecosystem]!) != nil else { continue }
            let running = version ?? (ecosystem == "npm" ? cached[name] : nil)
            let pin = version != nil ? "pinned" : running != nil ? "unpinned; npx cache holds \(running!)" : "unpinned; runs the latest release"
            items.append(Installation(product: "mcp:" + name, name: "\(server.name) (\(name))", version: running ?? "unpinned", path: server.config + "#" + server.name, domain: "mcp",
                                      note: "MCP server in \(display(server.config)) · \(pin)", ecosystem: running == nil ? nil : ecosystem, packageName: name, manager: "mcp", location: server.config, file: server.config))
        }
        return (items, errors)
    }
}
