import Foundation

// The Sparkle appcast for one release, attached to its GitHub release as appcast.xml. Installed copies read it
// from the latest release's download link (SUFeedURL), so it lists only that release. Its notes are the
// version's CHANGELOG.md section as HTML, which Sparkle shows above Install Update.
enum Appcast {
    static let repository = "https://github.com/toddsherman/shipshape"
    static let feed = repository + "/releases/latest/download/appcast.xml"
    struct Release {
        var name: String
        var version: String
        var build: String
        var minimumSystem: String
        var date: Date
        var download: String
        var length: Int
        var signature: String
        var notes: String
    }
    static func download(name: String, version: String) -> String {
        "\(repository)/releases/download/v\(version)/\(name.replacingOccurrences(of: " ", with: "-"))-\(version).dmg"
    }
    // The CHANGELOG.md section under "## <version> — <date>", up to the next heading. Unreleased and undated
    // sections don't count, so a feed can't go out before the changelog says the version shipped.
    static func section(_ changelog: String, version: String) -> String? {
        var lines: [Substring] = [], found = false
        for line in changelog.split(separator: "\n", omittingEmptySubsequences: false) {
            if line.hasPrefix("## ") {
                if found { break }
                found = line.dropFirst(3).hasPrefix(version + " — ")
                continue
            }
            if found { lines.append(line) }
        }
        let text = lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        return found && !text.isEmpty ? text : nil
    }
    // Changelog Markdown as HTML: "- " bullets become a list, other lines paragraphs.
    static func html(_ markdown: String) -> String {
        var out: [String] = [], list = false
        for raw in markdown.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("- ") {
                if !list { out.append("<ul>"); list = true }
                out.append("<li>" + inline(String(line.dropFirst(2))) + "</li>")
            } else {
                if list { out.append("</ul>"); list = false }
                if !line.isEmpty { out.append("<p>" + inline(line) + "</p>") }
            }
        }
        if list { out.append("</ul>") }
        return out.joined(separator: "\n")
    }
    // **bold**, `code` and [text](https://…) links; everything else is escaped.
    static func inline(_ text: String) -> String {
        escape(text)
            .replacingOccurrences(of: "\\*\\*(.+?)\\*\\*", with: "<strong>$1</strong>", options: .regularExpression)
            .replacingOccurrences(of: "`([^`]+)`", with: "<code>$1</code>", options: .regularExpression)
            .replacingOccurrences(of: "\\[([^\\]]+)\\]\\((https://[^)\\s]+)\\)", with: "<a href=\"$2\">$1</a>", options: .regularExpression)
    }
    static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
    }
    static func rfc822(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return formatter.string(from: date)
    }
    static func xml(_ release: Release) -> String {
        let name = escape(release.name), version = escape(release.version)
        let notes = release.notes.replacingOccurrences(of: "]]>", with: "]]]]><![CDATA[>")
        return """
        <?xml version="1.0" encoding="utf-8"?>
        <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
          <channel>
            <title>\(name)</title>
            <link>\(repository)</link>
            <item>
              <title>\(name) \(version)</title>
              <pubDate>\(rfc822(release.date))</pubDate>
              <sparkle:version>\(escape(release.build))</sparkle:version>
              <sparkle:shortVersionString>\(version)</sparkle:shortVersionString>
              <sparkle:minimumSystemVersion>\(escape(release.minimumSystem))</sparkle:minimumSystemVersion>
              <sparkle:fullReleaseNotesLink>\(repository)/releases/tag/v\(version)</sparkle:fullReleaseNotesLink>
              <description><![CDATA[\(notes)]]></description>
              <enclosure url="\(escape(release.download))" length="\(release.length)" type="application/octet-stream" sparkle:edSignature="\(escape(release.signature))"/>
            </item>
          </channel>
        </rss>

        """
    }
}
