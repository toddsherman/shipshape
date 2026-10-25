import Foundation

// Developer software that AI-assisted app builders commonly install. Each entry names how to find a copy
// (bundle IDs, Homebrew formulae or casks) and which advisory source applies: a built-in vendor rule,
// an NVD CPE (vendor:product) or an OSV package. Adding coverage is a data change, not new code.
struct Product {
    let id: String
    let name: String
    var bundleIDs: [String] = []
    var formulae: [String] = []  // also matches versioned formulae such as node@22
    var casks: [String] = []
    var cpe: String? = nil
    var osv: (ecosystem: String, name: String)? = nil  // "{major}" in the name follows the installed major version
    var github: (repo: String, packages: [String])? = nil  // the project's own GitHub security advisories
    var download: String? = nil  // vendor download page for directly installed apps
}

enum Catalog {
    static let vendorRules: Set<String> = ["node", "bun", "postgresql", "openssl", "opencode"]
    // Never inventoried or checked. Chrome updates through its own updater; apps with a Mac App Store
    // receipt, which Inventory skips, update through the App Store.
    static let excludedBundleIDs: Set<String> = ["com.google.Chrome", "com.google.Chrome.beta", "com.google.Chrome.dev", "com.google.Chrome.canary"]
    static let excludedCasks: Set<String> = ["google-chrome", "google-chrome@beta", "google-chrome@dev", "google-chrome@canary"]
    static let products: [Product] = [
        // Runtimes and languages
        Product(id: "node", name: "Node.js", formulae: ["node"], cpe: "nodejs:node.js"),
        Product(id: "bun", name: "Bun", formulae: ["bun"], github: ("oven-sh/bun", ["bun"])),
        Product(id: "deno", name: "Deno", formulae: ["deno"], cpe: "deno:deno"),
        Product(id: "python", name: "Python", formulae: ["python"], cpe: "python:python"),
        Product(id: "go", name: "Go", formulae: ["go"], osv: ("Go", "stdlib")),
        Product(id: "rust", name: "Rust", formulae: ["rust"], cpe: "rust-lang:rust"),
        Product(id: "ruby", name: "Ruby", formulae: ["ruby"], cpe: "ruby-lang:ruby"),
        Product(id: "php", name: "PHP", formulae: ["php"], cpe: "php:php"),
        Product(id: "openjdk", name: "OpenJDK", formulae: ["openjdk"], cpe: "oracle:openjdk"),
        // Package managers distributed as packages
        Product(id: "pnpm", name: "pnpm", formulae: ["pnpm"], osv: ("npm", "pnpm")),
        Product(id: "yarn", name: "Yarn", formulae: ["yarn"], osv: ("npm", "yarn")),
        Product(id: "uv", name: "uv", formulae: ["uv"], osv: ("PyPI", "uv")),
        Product(id: "pipx", name: "pipx", formulae: ["pipx"], osv: ("PyPI", "pipx")),
        Product(id: "poetry", name: "Poetry", formulae: ["poetry"], osv: ("PyPI", "poetry")),
        // AI coding tools
        Product(id: "claude-code", name: "Claude Code", casks: ["claude-code", "claude-code@latest"], osv: ("npm", "@anthropic-ai/claude-code")),
        Product(id: "codex-cli", name: "Codex CLI", formulae: ["codex"], casks: ["codex"], osv: ("npm", "@openai/codex")),
        Product(id: "gemini-cli", name: "Gemini CLI", formulae: ["gemini-cli"], osv: ("npm", "@google/gemini-cli")),
        Product(id: "copilot-cli", name: "GitHub Copilot CLI", casks: ["copilot-cli", "copilot-cli@prerelease"], osv: ("npm", "@github/copilot")),
        // OpenCode's Homebrew and desktop builds follow the repository's tags; its advisories name the npm package.
        Product(id: "opencode", name: "OpenCode", formulae: ["opencode"], casks: ["opencode-desktop"], github: ("anomalyco/opencode", ["opencode-ai", "opencode"])),
        Product(id: "ollama", name: "Ollama", bundleIDs: ["com.electron.ollama", "com.ollama.ollama"], formulae: ["ollama"], casks: ["ollama-app", "ollama"], cpe: "ollama:ollama", download: "https://ollama.com/download"),
        Product(id: "claude-desktop", name: "Claude", bundleIDs: ["com.anthropic.claudefordesktop"], casks: ["claude"], download: "https://claude.ai/download"),
        Product(id: "codex-app", name: "Codex", bundleIDs: ["com.openai.codex"]),
        Product(id: "chatgpt", name: "ChatGPT", bundleIDs: ["com.openai.chat"], casks: ["chatgpt"]),
        Product(id: "cursor", name: "Cursor", bundleIDs: ["com.todesktop.230313mzl4w4u92"], casks: ["cursor"], cpe: "anysphere:cursor", download: "https://cursor.com/downloads"),
        Product(id: "windsurf", name: "Windsurf", bundleIDs: ["com.exafunction.windsurf"], casks: ["windsurf"], download: "https://windsurf.com/download"),
        Product(id: "vscode", name: "Visual Studio Code", bundleIDs: ["com.microsoft.VSCode"], casks: ["visual-studio-code"], cpe: "microsoft:visual_studio_code", download: "https://code.visualstudio.com/download"),
        Product(id: "zed", name: "Zed", bundleIDs: ["dev.zed.Zed"], casks: ["zed"], cpe: "zed:zed", download: "https://zed.dev/download"),
        Product(id: "lm-studio", name: "LM Studio", bundleIDs: ["ai.elementlabs.lmstudio"], casks: ["lm-studio"], download: "https://lmstudio.ai/download"),
        // Developer apps
        Product(id: "firefox", name: "Firefox", bundleIDs: ["org.mozilla.firefox"], casks: ["firefox"], cpe: "mozilla:firefox", download: "https://www.mozilla.org/firefox/new/"),
        Product(id: "brave", name: "Brave", bundleIDs: ["com.brave.Browser"], casks: ["brave-browser"], cpe: "brave:brave", download: "https://brave.com/download/"),
        Product(id: "edge", name: "Microsoft Edge", bundleIDs: ["com.microsoft.edgemac"], casks: ["microsoft-edge"], cpe: "microsoft:edge_chromium", download: "https://www.microsoft.com/edge/download"),
        Product(id: "iterm2", name: "iTerm2", bundleIDs: ["com.googlecode.iterm2"], casks: ["iterm2"], cpe: "iterm2:iterm2", download: "https://iterm2.com/downloads.html"),
        Product(id: "ghostty", name: "Ghostty", bundleIDs: ["com.mitchellh.ghostty"], casks: ["ghostty"], download: "https://ghostty.org/download"),
        Product(id: "warp", name: "Warp", bundleIDs: ["dev.warp.Warp-Stable"], casks: ["warp"], download: "https://www.warp.dev/download"),
        Product(id: "docker-desktop", name: "Docker Desktop", bundleIDs: ["com.docker.docker"], casks: ["docker-desktop"], cpe: "docker:desktop", download: "https://www.docker.com/products/docker-desktop/"),
        Product(id: "orbstack", name: "OrbStack", bundleIDs: ["dev.kdrag0n.MacVirt"], casks: ["orbstack"], download: "https://orbstack.dev/download"),
        Product(id: "github-desktop", name: "GitHub Desktop", bundleIDs: ["com.github.GitHubClient"], casks: ["github"], download: "https://desktop.github.com/download/"),
        Product(id: "postman", name: "Postman", bundleIDs: ["com.postmanlabs.mac"], casks: ["postman"], cpe: "postman:postman", download: "https://www.postman.com/downloads/"),
        Product(id: "intellij", name: "IntelliJ IDEA", bundleIDs: ["com.jetbrains.intellij", "com.jetbrains.intellij.ce"], casks: ["intellij-idea", "intellij-idea-ce"], cpe: "jetbrains:intellij_idea", download: "https://www.jetbrains.com/idea/download/"),
        Product(id: "pycharm", name: "PyCharm", bundleIDs: ["com.jetbrains.pycharm", "com.jetbrains.pycharm.ce"], casks: ["pycharm", "pycharm-ce"], cpe: "jetbrains:pycharm", download: "https://www.jetbrains.com/pycharm/download/"),
        Product(id: "webstorm", name: "WebStorm", bundleIDs: ["com.jetbrains.WebStorm"], casks: ["webstorm"], cpe: "jetbrains:webstorm", download: "https://www.jetbrains.com/webstorm/download/"),
        Product(id: "android-studio", name: "Android Studio", bundleIDs: ["com.google.android.studio"], casks: ["android-studio"], download: "https://developer.android.com/studio"),
        Product(id: "sublime-text", name: "Sublime Text", bundleIDs: ["com.sublimetext.4"], casks: ["sublime-text"], download: "https://www.sublimetext.com/download"),
        Product(id: "tailscale", name: "Tailscale", bundleIDs: ["io.tailscale.ipn.macsys", "io.tailscale.ipn.macos"], casks: ["tailscale-app"], cpe: "tailscale:tailscale", download: "https://tailscale.com/download/mac"),
        Product(id: "tableplus", name: "TablePlus", bundleIDs: ["com.tinyapp.TablePlus"], casks: ["tableplus"], download: "https://tableplus.com/download"),
        Product(id: "dbeaver", name: "DBeaver", bundleIDs: ["org.jkiss.dbeaver.core.product"], casks: ["dbeaver-community"], cpe: "dbeaver:dbeaver", download: "https://dbeaver.io/download/"),
        // Command-line tools
        Product(id: "git", name: "Git", formulae: ["git"], cpe: "git-scm:git"),
        Product(id: "gh", name: "GitHub CLI", formulae: ["gh"], cpe: "github:cli"),
        Product(id: "git-lfs", name: "Git LFS", formulae: ["git-lfs"]),
        Product(id: "curl", name: "curl", formulae: ["curl"], cpe: "haxx:curl"),
        Product(id: "wget", name: "Wget", formulae: ["wget"], cpe: "gnu:wget"),
        Product(id: "openssh", name: "OpenSSH", formulae: ["openssh"], cpe: "openbsd:openssh"),
        Product(id: "gnupg", name: "GnuPG", formulae: ["gnupg"], cpe: "gnupg:gnupg"),
        Product(id: "docker-cli", name: "Docker CLI", formulae: ["docker"], cpe: "docker:docker"),
        Product(id: "docker-compose", name: "Docker Compose", formulae: ["docker-compose"], osv: ("Go", "github.com/docker/compose/v{major}")),
        Product(id: "kubectl", name: "kubectl", formulae: ["kubernetes-cli"]),
        Product(id: "helm", name: "Helm", formulae: ["helm"], cpe: "helm:helm"),
        Product(id: "terraform", name: "Terraform", formulae: ["terraform"], cpe: "hashicorp:terraform"),
        Product(id: "awscli", name: "AWS CLI", formulae: ["awscli"], cpe: "amazon:aws_command_line_interface"),
        Product(id: "vercel-cli", name: "Vercel CLI", formulae: ["vercel-cli"], osv: ("npm", "vercel")),
        Product(id: "cloudflared", name: "cloudflared", formulae: ["cloudflared"], cpe: "cloudflare:cloudflared"),
        Product(id: "ngrok", name: "ngrok", casks: ["ngrok"]),
        Product(id: "jq", name: "jq", formulae: ["jq"], cpe: "jqlang:jq"),
        Product(id: "ffmpeg", name: "FFmpeg", formulae: ["ffmpeg"], cpe: "ffmpeg:ffmpeg"),
        Product(id: "imagemagick", name: "ImageMagick", formulae: ["imagemagick"], cpe: "imagemagick:imagemagick"),
        Product(id: "vim", name: "Vim", formulae: ["vim"], cpe: "vim:vim"),
        Product(id: "neovim", name: "Neovim", formulae: ["neovim"], cpe: "neovim:neovim"),
        Product(id: "tmux", name: "tmux", formulae: ["tmux"], cpe: "tmux_project:tmux"),
        Product(id: "bash", name: "Bash", formulae: ["bash"], cpe: "gnu:bash"),
        Product(id: "zsh", name: "Zsh", formulae: ["zsh"], cpe: "zsh:zsh"),
        // Databases and servers
        Product(id: "postgresql", name: "PostgreSQL", formulae: ["postgresql", "libpq"], cpe: "postgresql:postgresql"),
        Product(id: "mysql", name: "MySQL", formulae: ["mysql"], cpe: "oracle:mysql"),
        Product(id: "redis", name: "Redis", formulae: ["redis"], cpe: "redis:redis"),
        Product(id: "mongodb", name: "MongoDB", formulae: ["mongodb-community"], cpe: "mongodb:mongodb"),
        Product(id: "sqlite", name: "SQLite", formulae: ["sqlite"], cpe: "sqlite:sqlite"),
        Product(id: "nginx", name: "nginx", formulae: ["nginx"], cpe: "f5:nginx"),
        Product(id: "caddy", name: "Caddy", formulae: ["caddy"], cpe: "caddyserver:caddy"),
        // Shared libraries that other tools load
        Product(id: "openssl", name: "OpenSSL", formulae: ["openssl"], cpe: "openssl:openssl"),
        Product(id: "libxml2", name: "libxml2", formulae: ["libxml2"], cpe: "xmlsoft:libxml2"),
        Product(id: "libxslt", name: "libxslt", formulae: ["libxslt"], cpe: "xmlsoft:libxslt"),
        Product(id: "libpng", name: "libpng", formulae: ["libpng"], cpe: "libpng:libpng"),
        Product(id: "libtiff", name: "LibTIFF", formulae: ["libtiff"], cpe: "libtiff:libtiff"),
        Product(id: "libwebp", name: "libwebp", formulae: ["webp"], cpe: "webmproject:libwebp"),
        Product(id: "libjpeg-turbo", name: "libjpeg-turbo", formulae: ["jpeg-turbo"], cpe: "libjpeg-turbo:libjpeg-turbo"),
        Product(id: "giflib", name: "GIFLIB", formulae: ["giflib"], cpe: "giflib_project:giflib"),
        Product(id: "freetype", name: "FreeType", formulae: ["freetype"], cpe: "freetype:freetype"),
        Product(id: "xz", name: "XZ Utils", formulae: ["xz"], cpe: "tukaani:xz"),
        Product(id: "zstd", name: "Zstandard", formulae: ["zstd"], cpe: "facebook:zstandard"),
        Product(id: "zlib", name: "zlib", formulae: ["zlib"], cpe: "zlib:zlib"),
        Product(id: "expat", name: "Expat", formulae: ["expat"], cpe: "libexpat_project:libexpat"),
        Product(id: "libssh2", name: "libssh2", formulae: ["libssh2"], cpe: "libssh2:libssh2"),
        Product(id: "libssh", name: "libssh", formulae: ["libssh"], cpe: "libssh:libssh"),
        Product(id: "nghttp2", name: "nghttp2", formulae: ["libnghttp2", "nghttp2"], cpe: "nghttp2:nghttp2"),
        Product(id: "c-ares", name: "c-ares", formulae: ["c-ares"], cpe: "c-ares:c-ares"),
        Product(id: "libuv", name: "libuv", formulae: ["libuv"], cpe: "libuv:libuv"),
        Product(id: "icu4c", name: "ICU", formulae: ["icu4c"], cpe: "icu-project:international_components_for_unicode"),
        Product(id: "pcre2", name: "PCRE2", formulae: ["pcre2"], cpe: "pcre:pcre2"),
        Product(id: "libgcrypt", name: "Libgcrypt", formulae: ["libgcrypt"], cpe: "gnupg:libgcrypt"),
        Product(id: "gnutls", name: "GnuTLS", formulae: ["gnutls"], cpe: "gnu:gnutls"),
        Product(id: "krb5", name: "MIT Kerberos", formulae: ["krb5"], cpe: "mit:kerberos_5"),
        Product(id: "libarchive", name: "libarchive", formulae: ["libarchive"], cpe: "libarchive:libarchive"),
        Product(id: "libheif", name: "libheif", formulae: ["libheif"], cpe: "struktur:libheif"),
        Product(id: "glib", name: "GLib", formulae: ["glib"], cpe: "gnome:glib"),
        Product(id: "libyaml", name: "LibYAML", formulae: ["libyaml"], cpe: "pyyaml:libyaml"),
        Product(id: "protobuf", name: "Protocol Buffers", formulae: ["protobuf"], cpe: "google:protobuf"),
        Product(id: "unbound", name: "Unbound", formulae: ["unbound"], cpe: "nlnetlabs:unbound"),
        Product(id: "libevent", name: "libevent", formulae: ["libevent"], cpe: "libevent_project:libevent"),
        Product(id: "ghostscript", name: "Ghostscript", formulae: ["ghostscript"], cpe: "artifex:ghostscript"),
        Product(id: "poppler", name: "Poppler", formulae: ["poppler"], cpe: "freedesktop:poppler"),
    ]
    static let byID = Dictionary(products.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
    static let byBundleID = Dictionary(products.flatMap { p in p.bundleIDs.map { ($0, p) } }, uniquingKeysWith: { a, _ in a })
    static let byCask = Dictionary(products.flatMap { p in p.casks.map { ($0, p) } }, uniquingKeysWith: { a, _ in a })
    static let byFormula = Dictionary(products.flatMap { p in p.formulae.map { ($0, p) } }, uniquingKeysWith: { a, _ in a })
    // Exact or versioned names only; "node-build" or "openssl-osx-ca" are separate products.
    // OSV package for a product at an installed version. Go modules carry /vN from major version 2 on.
    static func osv(_ product: Product?, version: String) -> (ecosystem: String, name: String)? {
        guard let osv = product?.osv else { return nil }
        guard osv.name.contains("{major}") else { return osv }
        guard let major = Int(version.prefix { $0.isNumber }) else { return nil }
        return (osv.ecosystem, major >= 2 ? osv.name.replacingOccurrences(of: "{major}", with: String(major)) : osv.name.replacingOccurrences(of: "/v{major}", with: ""))
    }
    static func product(formula name: String) -> Product? {
        byFormula[name] ?? byFormula[String(name.prefix { $0 != "@" })].flatMap { name.contains("@") ? $0 : nil }
    }
}
