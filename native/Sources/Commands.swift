import Foundation

// Update options for each finding, best first. A Terminal command is chosen to match how the software was
// installed and what is available on this Mac; links, apps and files are opened only when the user clicks.
// Every value placed in a command is checked against its ecosystem's naming rules and shell-quoted, and the
// app never runs these commands itself.
enum Shell {
    static func quote(_ value: String) -> String {
        value.range(of: "^[A-Za-z0-9@%+=:,./_-]+$", options: .regularExpression) != nil
            ? value : "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

struct CaskInfo: Hashable {
    let autoUpdates: Bool
    let homepage: String?
}

// What this Mac can run, found by looking in the usual install folders (apps opened from Finder don't
// inherit a shell PATH), plus Homebrew's data on whether each app updates itself.
struct CommandContext {
    var tools: Set<String>
    var casks: [String: CaskInfo] = [:]
    func has(_ tool: String) -> Bool { tools.contains(tool) }
    static let known = ["brew", "mise", "npm", "pnpm", "yarn", "bun", "corepack", "uv", "pipx", "poetry", "cargo", "bundle", "go", "deno", "volta", "fnm"]
    static let all = CommandContext(tools: Set(known + ["nvm"]))
    static func detect() -> CommandContext {
        let home = Inventory.home
        var folders = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/usr/local/go/bin", home + "/.local/bin", home + "/.bun/bin", home + "/.cargo/bin",
                       home + "/.volta/bin", home + "/.deno/bin", home + "/go/bin", home + "/.local/share/mise/shims"]
        folders += Inventory.children(home + "/.nvm/versions/node").map { "\(home)/.nvm/versions/node/\($0)/bin" }
        var tools = Set(known.filter { tool in folders.contains { FileManager.default.isExecutableFile(atPath: $0 + "/" + tool) } })
        if FileManager.default.fileExists(atPath: home + "/.nvm/nvm.sh") { tools.insert("nvm") }
        return CommandContext(tools: tools)
    }
}

// What the signed-in account may change. Package managers fail with "Permission denied" in folders that
// belong to another account (another person's projects, a Homebrew installed by someone else) or to root
// (often left by an install run with sudo), so commands for those aren't offered. Tests pass their own answers.
struct FileAccess {
    var user: String
    var exists: (String) -> Bool
    var canWrite: (String) -> Bool
    var owner: (String) -> String?
    var children: (String) -> [String]
    static var live: FileAccess {
        FileAccess(user: NSUserName(), exists: { FileManager.default.fileExists(atPath: $0) }, canWrite: { Darwin.access($0, W_OK) == 0 },
                   owner: { (try? FileManager.default.attributesOfItem(atPath: $0))?[.ownerAccountName] as? String }, children: { Inventory.children($0) })
    }
    // One answer per path for a whole check, since many findings share a project folder.
    func memoized() -> FileAccess {
        final class Cache { var exists: [String: Bool] = [:], writable: [String: Bool] = [:], owners: [String: String?] = [:], children: [String: [String]] = [:] }
        let cache = Cache(), base = self
        return FileAccess(user: user,
                          exists: { path in if let hit = cache.exists[path] { return hit }; let value = base.exists(path); cache.exists[path] = value; return value },
                          canWrite: { path in if let hit = cache.writable[path] { return hit }; let value = base.canWrite(path); cache.writable[path] = value; return value },
                          owner: { path in if let hit = cache.owners[path] { return hit }; let value = base.owner(path); cache.owners[path] = value; return value },
                          children: { path in if let hit = cache.children[path] { return hit }; let value = base.children(path); cache.children[path] = value; return value })
    }
}

// A file or app is opened only when it is what Shipshape found. A cloned repo can make package.json a link to a
// script, or name a file run.command, and the default app for such a file would run it; so a file must be a
// plain, non-executable text file inside a chosen project folder or one of the MCP settings files Shipshape
// reads, and an app a real bundle in an Applications folder. Each check returns why not, or nil.
enum SafeOpen {
    static let textExtensions: Set<String> = ["json", "jsonc", "txt", "toml", "yaml", "yml"]
    static func fileProblem(_ path: String, folders: [String], files: [String]) -> String? {
        let place = Inventory.display(path)
        var info = stat()
        guard lstat(path, &info) == 0 else { return "\(place) no longer exists. Run a new check." }
        guard info.st_mode & S_IFMT == S_IFREG else { return "\(place) is a link or not a regular file, so Shipshape won't open it. Open it yourself if you trust it." }
        guard info.st_mode & 0o111 == 0, textExtensions.contains((path as NSString).pathExtension.lowercased()) else {
            return "\(place) isn't a plain text file, so Shipshape won't open it. Open it yourself if you trust it."
        }
        let real = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        func resolved(_ path: String) -> String { URL(fileURLWithPath: path).resolvingSymlinksInPath().path }
        guard files.map(resolved).contains(real) || folders.map(resolved).contains(where: { real.hasPrefix($0 + "/") }) else {
            return "\(place) is outside your project folders and the MCP settings Shipshape reads, so it won't be opened."
        }
        return nil
    }
    static func appProblem(_ path: String, roots: [String] = ["/Applications", Inventory.home + "/Applications"]) -> String? {
        var info = stat()
        guard lstat(path, &info) == 0 else { return "\(Inventory.display(path)) no longer exists. Run a new check." }
        guard info.st_mode & S_IFMT == S_IFDIR, path.hasSuffix(".app"), roots.contains(where: { path.hasPrefix($0 + "/") }) else {
            return "\(Inventory.display(path)) isn't an app in an Applications folder, so Shipshape won't open it."
        }
        return nil
    }
}

enum Ownership {
    static let projectManagers: Set<String> = ["npm", "pnpm", "yarn", "yarn-berry", "bun-lock", "uv", "poetry", "pip-req", "cargo", "bundler", "go"]
    static let homebrewManagers: Set<String> = ["brew", "brew-old", "brew-python", "cask", "pip-brew"]

    // The folders and files an update for this installation changes. Projects include node_modules and .venv,
    // and npm's scope folders inside them, since npm moves packages aside there. Apps and runtimes with their
    // own installers or updaters aren't checked.
    static func targets(_ item: Installation, _ access: FileAccess) -> [String] {
        let parent = (item.path as NSString).deletingLastPathComponent
        switch item.manager ?? "" {
        case "brew", "brew-old", "brew-python", "cask", "pip", "pip-brew", "npm-global", "bun-global", "pnpm-global", "pipx", "uv-tool", "mise": return [parent]
        case "npx-cache": return item.location.map { [($0 as NSString).deletingLastPathComponent, $0] } ?? []
        case "mcp": return item.location.map { [$0] } ?? []
        case let manager where projectManagers.contains(manager):
            guard let folder = item.location else { return [] }
            var paths = [folder, item.sourceFile]
            for environment in ["node_modules", ".venv"] {
                let path = folder + "/" + environment
                guard access.exists(path) else { continue }
                paths.append(path)
                paths += access.children(path).filter { $0.hasPrefix("@") }.map { path + "/" + $0 }
            }
            return paths
        default: return []
        }
    }

    // Why this account can't make the change, or nil when it can.
    static func blocked(_ finding: Finding, access: FileAccess) -> String? {
        guard finding.awaitingFix != true, finding.source != "apple" else { return nil }
        let item = finding.installation
        if let name = [item.location, item.path, item.packageName, item.package].compactMap({ $0 }).first(where: Commands.hasHiddenCharacters) {
            return "\(Commands.visible(Inventory.display(name))) contains invisible characters (shown as \u{FFFD}), which could change what a pasted command does, so none is offered. Rename it, then run a new check."
        }
        guard let target = targets(item, access).first(where: { access.exists($0) && !access.canWrite($0) }) else { return nil }
        return notice(target, owner: access.owner(target), user: access.user, homebrew: homebrewManagers.contains(item.manager ?? ""), project: item.domain == "projects")
    }

    static func notice(_ path: String, owner: String?, user: String, homebrew: Bool, project: Bool) -> String {
        let place = Inventory.display(path)
        guard let owner, owner != user else { return "\(place) is read-only for this account, so the update would fail. Check the folder's permissions, then run a new check." }
        if owner == "root" {
            return project
                ? "\(place) belongs to root, usually left by an install run with sudo, so the update would fail. Change its owner back to your account, then run a new check."
                : "\(place) belongs to root, so this account can't change it. Update it from an administrator account, or use a copy you own."
        }
        if homebrew { return "Homebrew on this Mac belongs to \(owner), so only that account can upgrade it. Run the update from \(owner)'s account, or ask them to." }
        return "\(place) belongs to \(owner), so this account can't change it. Make the fix from \(owner)'s account, or ask them to."
    }

    // Marks findings this account can't fix and drops their commands, keeping links to vendor pages.
    // The findings stay listed: the vulnerable code is still on this Mac.
    static func restrict(_ findings: inout [Finding], access: FileAccess) {
        for index in findings.indices {
            guard let reason = blocked(findings[index], access: access) else { continue }
            findings[index].blocked = reason
            findings[index].commands = findings[index].commands?.filter { $0.kind == "link" }
        }
    }

    // Shown when a project folder is added: folders this account can't change, and folders that take in
    // system or Homebrew files, which are skipped. Root owns broad parents such as / and /Users even when
    // the projects inside are yours, so a root-owned folder isn't flagged here; its findings are checked one by one.
    static func folderWarning(_ path: String, access: FileAccess) -> String? {
        var notes: [String] = []
        if Lockfiles.skippedRoots.contains(where: { $0.hasPrefix(path == "/" ? "/" : path + "/") }) {
            notes.append("\(Inventory.display(path)) includes system or Homebrew folders. Those are skipped; projects elsewhere in it are checked.")
        }
        if access.exists(path), !access.canWrite(path), access.owner(path) != "root" {
            let owner = access.owner(path)
            notes.append(owner.map { $0 != access.user } == true
                ? "\(Inventory.display(path)) belongs to \(owner!). Its vulnerabilities are reported, but fixes have to be made from \(owner!)'s account."
                : "\(Inventory.display(path)) is read-only for this account. Projects in it that you can't change are reported without commands.")
        }
        return notes.isEmpty ? nil : notes.joined(separator: " ")
    }
}

enum Commands {
    static let namePatterns = [
        "npm": "^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", "PyPI": "^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$",
        "crates.io": "^[a-z0-9][a-z0-9_-]*$", "RubyGems": "^[a-z0-9][a-z0-9._-]*$", "Go": "^[a-z0-9][a-z0-9.~_/-]*$"
    ]
    static let installPages = [
        "npm": "https://nodejs.org/en/download", "pnpm": "https://pnpm.io/installation", "yarn": "https://yarnpkg.com/getting-started/install",
        "bun": "https://bun.sh/docs/installation", "uv": "https://docs.astral.sh/uv/getting-started/installation/", "poetry": "https://python-poetry.org/docs/#installation",
        "cargo": "https://rustup.rs", "bundle": "https://bundler.io", "go": "https://go.dev/dl/"
    ]
    static func safe(_ value: String?, _ pattern: String = "^[a-z0-9][a-z0-9.+_@-]*$") -> String? {
        value.flatMap { $0.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil ? $0 : nil }
    }
    static func terminal(_ text: String, _ note: String) -> UpdateCommand { UpdateCommand(text: text, note: note) }
    // A command whose argument can be combined with others of the same template, such as brew upgrade a b c.
    static func batchable(_ template: [String], _ argument: String, _ note: String) -> UpdateCommand {
        UpdateCommand(text: template.joined(separator: argument), note: note, template: template, argument: argument)
    }
    // Only https pages and System Settings panes are offered as links.
    static func link(_ url: String?, _ note: String, label: String? = nil, verb: String = "Open") -> UpdateCommand? {
        guard let url, url.hasPrefix("https://") || url.hasPrefix("x-apple.systempreferences:"), let host = URL(string: url)?.host ?? (url.hasPrefix("x-apple") ? "System Settings" : nil) else { return nil }
        return UpdateCommand(text: label ?? verb + " " + host.replacingOccurrences(of: "www.", with: ""), note: note, kind: "link", target: url)
    }
    static func file(_ path: String, _ note: String) -> UpdateCommand { UpdateCommand(text: "Open " + (path as NSString).lastPathComponent, note: note, kind: "file", target: path) }

    // A project's package manager may not be installed. Chain an install step in front when another tool can
    // install it; otherwise point to its install page first.
    static func prerequisite(_ tool: String, _ context: CommandContext) -> (prefix: String, page: UpdateCommand?) {
        if context.has(tool) { return ("", nil) }
        let javascript = tool == "pnpm" || tool == "yarn"
        if javascript && context.has("corepack") { return ("corepack enable \(tool) && ", nil) }
        if javascript && context.has("npm") { return ("npm install -g \(tool) && ", nil) }
        if ["uv", "poetry", "go"].contains(tool) && context.has("brew") { return ("brew install \(tool) && ", nil) }
        if tool == "npm" && context.has("brew") { return ("brew install node && ", nil) }
        if tool == "bun" && context.has("brew") { return ("brew install oven-sh/bun/bun && ", nil) }
        return ("", link(installPages[tool], "\(tool) isn't installed on this Mac. Install it, then run the command.", label: "Install \(tool)"))
    }

    // Control, format (including bidi) and line-separator characters are invisible in the app but act on a
    // terminal when pasted (^U erases the line, a carriage return runs what follows), so no command carries them.
    static func hasHiddenCharacters(_ value: String) -> Bool {
        value.unicodeScalars.contains { [.control, .format, .lineSeparator, .paragraphSeparator].contains($0.properties.generalCategory) }
    }
    static func visible(_ value: String) -> String {
        String(String.UnicodeScalarView(value.unicodeScalars.map { hasHiddenCharacters(String($0)) ? "\u{FFFD}" : $0 }))
    }
    static func commands(for finding: Finding, context: CommandContext = .all) -> [UpdateCommand] {
        options(for: finding, context: context).filter { $0.kind != nil || !hasHiddenCharacters($0.text) }
    }
    private static func options(for finding: Finding, context: CommandContext) -> [UpdateCommand] {
        if finding.awaitingFix == true { return [] }  // no release fixes it yet, so there is nothing to install
        let item = finding.installation
        let fix = safe(finding.fixed, "^[0-9][a-z0-9.+_-]*$")
        let removing = finding.malicious == true
        let package = item.ecosystem.flatMap { safe(item.packageName, namePatterns[$0] ?? "^$") }
        let cd = item.location.map { "cd " + Shell.quote($0) + " && " } ?? ""
        let dev = item.dependency == "dev"
        let direct = item.dependency == "direct" || dev
        func command(_ text: String, _ note: String) -> [UpdateCommand] { [terminal(text, note)] }
        func project(_ tool: String, _ text: String, _ note: String) -> [UpdateCommand] {
            let (prefix, page) = prerequisite(tool, context)
            return [page].compactMap { $0 } + command(prefix + cd + text, note)
        }
        func batch(_ template: [String], _ argument: String, _ note: String) -> [UpdateCommand] { [batchable(template, argument, note)] }
        func projectBatch(_ tool: String, _ template: [String], _ argument: String, _ note: String) -> [UpdateCommand] {
            let (prefix, page) = prerequisite(tool, context)
            return [page].compactMap { $0 } + batch([prefix + cd + template[0]] + template.dropFirst(), argument, note)
        }
        if finding.source == "apple" {
            return [link("x-apple.systempreferences:com.apple.Software-Update-Settings.extension", "Shows Apple's eligible updates with their security notes.", label: "Open Software Update")].compactMap { $0 }
                + command("sudo softwareupdate --install --recommended", "Installs Apple's recommended updates from Terminal. Some need a restart.")
        }
        switch item.manager ?? "" {
        case "brew", "brew-python":
            guard let name = safe(item.package) else { return [] }
            let unpin = item.pinned == true
            return batch(unpin ? ["brew unpin ", " && brew upgrade ", ""] : ["brew upgrade ", ""], name, (item.manager == "brew-python" ? "pip and the other tools bundled with Homebrew's Python update with the formula." : "Upgrades the Homebrew formula. Restart services and programs that use it.")
                           + (!unpin ? "" : " It's pinned in Homebrew, so this unpins it first; run brew pin \(name) afterwards to hold it again."))
        case "brew-old":
            // Homebrew removes old copies only once its newest build (including rebuilds such as 26.12.1_1) is
            // installed, so upgrade first; upgrading something already current changes nothing.
            guard let name = safe(item.package) else { return [] }
            let cleanup = batchable(["brew upgrade ", " && brew cleanup ", ""], name, "Homebrew deletes older copies only after its newest build is installed, so this upgrades first (nothing changes if it already is), then removes every older copy.")
            let keg = item.path.range(of: "^(/opt/homebrew|/usr/local)/Cellar/\(NSRegularExpression.escapedPattern(for: name))/[^/]+$", options: .regularExpression) != nil
                ? batchable(["rm -rf ", ""], Shell.quote(item.path), "Deletes just this unused copy and leaves the active version as it is.") : nil
            return (item.pinned == true ? [keg] : [cleanup, keg]).compactMap { $0 }
        case "cask":
            guard let token = safe(item.package) else { return [] }
            // Homebrew skips apps that update themselves unless asked to be greedy.
            let greedy = context.casks[token]?.autoUpdates == true
            return batch(["brew upgrade --cask " + (greedy ? "--greedy " : ""), ""], token, greedy ? "Upgrades the Homebrew-installed app. It also updates itself, so --greedy makes Homebrew include it." : "Upgrades the Homebrew-installed app.")
        case "app": return app(item, context)
        case "nvm":
            guard let major = fix?.split(separator: ".").first else { return [] }
            return command(". \"$HOME/.nvm/nvm.sh\" && nvm install \(major)", "Installs the newest Node \(major) release with nvm. Reinstall any global packages you rely on.")
        case "volta":
            guard let fix else { return [] }
            return command("volta install node@" + fix, "Installs this Node release with Volta.")
        case "fnm":
            guard let fix else { return [] }
            return command("fnm install " + fix, "Installs this Node release with fnm. Switch to it with fnm default.")
        case "node-pkg":
            let page = link("https://nodejs.org/en/download", "Download the macOS installer for a supported release.", label: "Download from nodejs.org")
            guard let fix else { return [page].compactMap { $0 } }
            let file = "node-v\(fix).pkg"
            return command("cd \"$TMPDIR\" && curl -fLO https://nodejs.org/dist/v\(fix)/\(file) && spctl --assess --type install \(file) && sudo installer -pkg \(file) -target /",
                           "Downloads Node's installer, stops unless Apple's notarization check passes, then installs it. Asks for your administrator password.") + [page].compactMap { $0 }
        case "python-org":
            guard let fix else { return [link("https://www.python.org/downloads/macos/", "Choose the newest release for your Python branch.", label: "Download from python.org")].compactMap { $0 } }
            let file = "python-\(fix)-macos11.pkg"
            return command("cd \"$TMPDIR\" && curl -fLO https://www.python.org/ftp/python/\(fix)/\(file) && spctl --assess --type install \(file) && sudo installer -pkg \(file) -target /",
                           "Downloads python.org's installer, stops unless Apple's notarization check passes, then installs it. Asks for your administrator password.")
                + [link("https://www.python.org/downloads/release/python-\(fix.replacingOccurrences(of: ".", with: ""))/", "The release page with the macOS installer.", label: "Download from python.org")].compactMap { $0 }
        case "uv-python":
            guard let fix else { return [] }
            return command("uv python install --reinstall " + fix, "Installs this Python release with uv.")
        case "pyenv":
            guard let fix else { return [] }
            return command("pyenv install " + fix, "Then select it with pyenv global or pyenv local.")
        case "go-pkg": return [link("https://go.dev/dl/", "Download the current installer for your Go branch.", label: "Download from go.dev")].compactMap { $0 }
        case "bun": return command("bun upgrade", "Updates Bun in place. Restart Bun processes and rebuild standalone executables.")
        case "deno": return command("deno upgrade", "Updates Deno in place.")
        case "claude": return command("claude update", "Updates Claude Code's native install.")
        case "opencode": return command("opencode upgrade", "Updates OpenCode's native install to the latest release.")
        case "copilot":
            return [link("https://github.com/github/copilot-cli#installation", "Re-run GitHub's install script to replace the binary in place.", label: "Open Copilot CLI install steps")].compactMap { $0 }
                + (context.has("brew") ? command("brew install --cask copilot-cli", "Alternative: install with Homebrew, which handles later updates. Remove the old copy in ~/.local/bin afterwards.") : [])
        case "mise":
            guard let tool = safe(item.location) else { return [] }
            guard let fix else { return batch(["mise upgrade --bump ", ""], tool, "Moves past the version range in mise.toml to the newest release and updates the config.") }
            return batch(["mise upgrade ", ""], tool, "Installs the newest release within the version range in your mise.toml.")
                + command("mise use -g " + tool + "@" + fix, "Alternative: sets your global default to the fixed version. Projects that pin an older version need their own mise.toml updated.")
        case "uv-self": return command("uv self update", "Updates the standalone uv install.")
        case "mcp":
            guard let config = item.location else { return [] }
            return [file(config, "Pin the server's package to \(fix ?? "a fixed release") or later, then restart the app that runs it.")]
        case "pip-req":
            let requirements = item.sourceFile
            return [file(requirements, "Change the pin to \(item.packageName ?? item.name)==\(fix ?? "a fixed release"), then reinstall the project's environment.")]
        default: break
        }
        guard let package else { return [] }
        let spec = Shell.quote(package + "@" + (fix ?? ""))
        let quoted = Shell.quote(package)  // validated above, and quoted anyway so no name can expand in a shell
        switch item.manager ?? "" {
        case "npm-global":
            let npm = item.location.map(Shell.quote) ?? "npm"
            if removing { return batch([npm + " uninstall -g ", ""], quoted, "Removes the global package.") }
            guard fix != nil else { return [] }
            return batch([npm + " install -g ", ""], spec, "Installs the fixed version for this Node installation.")
        case "bun-global":
            if removing { return batch(["bun remove -g ", ""], quoted, "Removes the global package.") }
            return fix == nil ? [] : batch(["bun add -g ", ""], spec, "Installs the fixed version globally with Bun.")
        case "pnpm-global":
            if removing { return batch(["pnpm remove -g ", ""], quoted, "Removes the global package.") }
            return fix == nil ? [] : batch(["pnpm add -g ", ""], spec, "Installs the fixed version globally with pnpm.")
        case "pip", "pip-brew":
            guard let python = item.location.map(Shell.quote) else { return [] }
            if removing { return batch([python + " -m pip uninstall -y ", ""], quoted, "Removes the package from this Python installation.") }
            guard let fix else { return [] }
            return batch([python + " -m pip install --upgrade ", item.manager == "pip-brew" ? " --break-system-packages" : ""], Shell.quote(package + "==" + fix),
                           item.manager == "pip-brew" ? "Homebrew's Python is externally managed, so pip needs this override. A virtual environment is safer for project packages." : "Upgrades the package for this Python installation.")
        case "pipx":
            guard let app = safe(item.location) else { return [] }
            if OSV.normalized(package, "PyPI") == OSV.normalized(app, "PyPI") { return command("pipx upgrade " + app, "Upgrades the app and its environment.") }
            return fix == nil ? [] : command("pipx runpip \(app) install --upgrade " + Shell.quote(package + "==" + fix!), "Upgrades this dependency inside \(app)'s environment.")
        case "uv-tool":
            guard let tool = safe(item.location) else { return [] }
            return command("uv tool upgrade " + tool, "Reinstalls the tool with its newest allowed dependencies.")
        case "npx-cache":
            guard let directory = item.location else { return [] }
            return batch(["rm -rf ", ""], Shell.quote(directory), "Deletes this cached npx install. The next npx run downloads the current release.")
        case "npm":
            if removing { return projectBatch("npm", ["npm uninstall ", ""], quoted, "Removes the package from this project.") }
            if direct, fix != nil { return projectBatch("npm", ["npm install ", dev ? " --save-dev" : ""], spec, "Updates the dependency and package-lock.json.") }
            return project("npm", "npm audit fix", "Updates vulnerable dependencies within allowed ranges. If a package is still flagged afterwards, update the one that depends on it; npm explain <package> shows which.")
        case "pnpm":
            if removing { return projectBatch("pnpm", ["pnpm remove ", ""], quoted, "Removes the package from this project.") }
            if direct, fix != nil { return projectBatch("pnpm", ["pnpm add ", dev ? " -D" : ""], spec, "Updates the dependency and pnpm-lock.yaml.") }
            return project("pnpm", "pnpm audit --fix && pnpm install", "Adds overrides for vulnerable dependencies, then reinstalls.")
        case "yarn":
            if removing { return projectBatch("yarn", ["yarn remove ", ""], quoted, "Removes the package from this project.") }
            if direct, fix != nil { return projectBatch("yarn", ["yarn upgrade ", ""], spec, "Updates the dependency and yarn.lock.") }
            return item.location.map { [file($0 + "/package.json", "Add a \"resolutions\" entry for \(package) at \(fix ?? "a fixed release") or later, then run yarn install.")] } ?? []
        case "yarn-berry":
            if removing { return projectBatch("yarn", ["yarn remove ", ""], quoted, "Removes the package from this project.") }
            if direct, fix != nil { return projectBatch("yarn", ["yarn up ", ""], spec, "Updates the dependency and yarn.lock.") }
            return projectBatch("yarn", ["yarn up -R ", ""], quoted, "Updates this package everywhere in the dependency tree within allowed ranges.")
        case "bun-lock":
            if removing { return projectBatch("bun", ["bun remove ", ""], quoted, "Removes the package from this project.") }
            if direct, fix != nil { return projectBatch("bun", ["bun add ", dev ? " -d" : ""], spec, "Updates the dependency and bun.lock.") }
            return projectBatch("bun", ["bun update ", ""], quoted, "Updates within allowed ranges. If it is still flagged, update the package that depends on it.")
        case "uv": return projectBatch("uv", ["uv lock ", " && uv sync"], "--upgrade-package " + quoted, "Upgrades this package in uv.lock and syncs the environment.")
        case "poetry": return projectBatch("poetry", ["poetry update ", ""], quoted, "Updates this package in poetry.lock within allowed ranges.")
        case "cargo":
            guard let fix else { return [] }
            return project("cargo", "cargo update -p " + quoted + " --precise " + fix, "Updates Cargo.lock. Raise the version requirement in Cargo.toml if Cargo refuses.")
        case "bundler": return projectBatch("bundle", ["bundle update ", " --conservative"], quoted, "Updates this gem in Gemfile.lock with minimal other changes.")
        case "go":
            guard let fix else { return [] }
            return projectBatch("go", ["go get ", " && go mod tidy"], Shell.quote(package + "@v" + fix), "Updates go.mod and go.sum.")
        default: return []
        }
    }

    // Recommended Terminal commands for many findings, as few lines as possible: commands built from the same
    // template run once with all their arguments (brew upgrade a b c; rm -rf dir1 dir2); others appear once.
    static func combined(_ commands: [UpdateCommand]) -> [String] {
        var order: [String] = [], templates: [String: [String]] = [:], arguments: [String: [String]] = [:]
        for command in commands where command.kind == nil {
            let key = command.template.map { "template\u{1}" + $0.joined(separator: "\u{1}") } ?? "text\u{1}" + command.text
            if templates[key] == nil { order.append(key); templates[key] = command.template ?? [command.text]; arguments[key] = [] }
            if let argument = command.argument, command.template != nil, !arguments[key]!.contains(argument) { arguments[key]!.append(argument) }
        }
        let lines = order.map { key in key.hasPrefix("text") ? templates[key]![0] : templates[key]!.joined(separator: arguments[key]!.joined(separator: " ")) }
        // Keep each project's commands together: order by where a line's "cd <folder>" first appears.
        func place(_ line: String) -> String { line.hasPrefix("cd ") ? String(line.prefix { $0 != "&" }) : line }
        var first: [String: Int] = [:]
        for (index, line) in lines.enumerated() where first[place(line)] == nil { first[place(line)] = index }
        return lines.enumerated().sorted { (first[place($0.element)]!, $0.offset) < (first[place($1.element)]!, $1.offset) }.map(\.element)
    }

    // A directly downloaded app: its own updater first when it has one, then Homebrew when available, then
    // the vendor's download page. Apps without a known self-updater lead with Homebrew or the download page.
    static func app(_ item: Installation, _ context: CommandContext) -> [UpdateCommand] {
        let product = Catalog.byID[item.product], name = product?.name ?? item.name
        let token = safe(item.package), cask = token.flatMap { context.casks[$0] }
        let opener = UpdateCommand(text: "Open \(name)", note: cask?.autoUpdates == false ? "Use \(name)'s update command if it has one, then restart it." : "\(name) updates itself. Opening it lets its updater install the new version; restart it afterwards.",
                                   kind: "app", target: item.path)
        let homebrew = context.has("brew") ? token.map { terminal("brew install --cask --force " + $0, "Replaces this copy with Homebrew's current release. Homebrew manages its updates from then on.") } : nil
        let page = link(product?.download ?? cask?.homepage, "Download the current release from the vendor and replace the copy in Applications.", verb: "Download from")
        return (cask?.autoUpdates == false ? [homebrew, page, opener] : [opener, homebrew, page]).compactMap { $0 }
    }

    // Written guidance for package findings, including cases where no command applies.
    static func action(for item: Installation, malicious: Bool, fixed: String?) -> String {
        let name = item.packageName ?? item.name
        if malicious { return "Remove this package now, then rotate credentials this Mac can reach: npm and GitHub tokens, cloud keys and SSH keys." }
        guard let fixed else { return "No fixed release is published yet. Remove or replace \(name) if the advisory applies to how you use it." }
        switch item.manager ?? "" {
        case "pip-req": return "Change the pin in requirements.txt to \(name)==\(fixed), then reinstall the project's environment."
        case "yarn" where item.dependency != "direct" && item.dependency != "dev":
            return "Add a \"resolutions\" entry for \(name) at \(fixed) or later in package.json, then run yarn install."
        case "mcp": return "Pin this MCP server's package to \(fixed) or later in \(item.location.map { Inventory.display($0) } ?? "its configuration"), then restart the app that runs it."
        default: return item.domain == "projects" ? "Update \(name) to \(fixed) or later, then commit the new lockfile." : "Update to \(fixed) or later."
        }
    }
}
