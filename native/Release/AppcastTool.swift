import Foundation

// appcast <Info.plist> <CHANGELOG.md> <dmg> <EdDSA signature> [download URL]
// Prints the appcast for the version in Info.plist. The download URL defaults to the GitHub release asset.
@main
struct AppcastTool {
    static func main() {
        let arguments = CommandLine.arguments
        guard arguments.count == 5 || arguments.count == 6 else { fail("Usage: appcast Info.plist CHANGELOG.md DMG SIGNATURE [DOWNLOAD-URL]") }
        guard let info = NSDictionary(contentsOfFile: arguments[1]) as? [String: Any],
              let name = info["CFBundleName"] as? String, let version = info["CFBundleShortVersionString"] as? String,
              let build = info["CFBundleVersion"] as? String, let minimum = info["LSMinimumSystemVersion"] as? String else { fail("Can't read the version from \(arguments[1]).") }
        guard let changelog = try? String(contentsOfFile: arguments[2], encoding: .utf8), let section = Appcast.section(changelog, version: version) else {
            fail("CHANGELOG.md has no dated section for \(version).")
        }
        guard let length = (try? FileManager.default.attributesOfItem(atPath: arguments[3]))?[.size] as? Int, length > 0 else { fail("Can't read \(arguments[3]).") }
        let signature = arguments[4].trimmingCharacters(in: .whitespacesAndNewlines)
        guard Data(base64Encoded: signature)?.count == 64 else { fail("The EdDSA signature isn't 64 bytes of base64.") }
        let download = arguments.count == 6 ? arguments[5] : Appcast.download(name: name, version: version)
        print(Appcast.xml(.init(name: name, version: version, build: build, minimumSystem: minimum, date: Date(), download: download,
                                length: length, signature: signature, notes: Appcast.html(section))), terminator: "")
    }
    static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        exit(1)
    }
}
