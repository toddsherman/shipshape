import Foundation
// Command-line scan with the app's engine: check [output.json] [project folder ...]
@main struct Check {
    static func main() async throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let output = arguments.first { $0.hasSuffix(".json") }
        let previous = output.flatMap { FileManager.default.contents(atPath: $0) }.flatMap { data -> ScanReport? in
            let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
            return try? decoder.decode(ScanReport.self, from: data)
        }
        let report = await Scanner.run(previous: previous, projectFolders: arguments.filter { !$0.hasSuffix(".json") && $0 != "--refresh" }) { message in
            FileHandle.standardError.write(Data((message + "\n").utf8))
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(report)
        if let output { try data.write(to: URL(fileURLWithPath: output), options: .atomic) } else { print(String(decoding: data, as: UTF8.self)) }
        print("\(report.installations.count) installations; \(report.security.count) security findings; \(report.updates.count) updates; \(report.errors.count) incomplete checks")
        // --refresh times a minute refresh after the full check, as the app runs one while it is open.
        if arguments.contains("--refresh") {
            let start = Date()
            let again = await Reuse.$enabled.withValue(true) { await Scanner.run(previous: report, projectFolders: arguments.filter { !$0.hasSuffix(".json") && $0 != "--refresh" }) }
            print(String(format: "Minute refresh: %.1f s; %d security findings; %d updates; %d incomplete checks; same findings: %@", Date().timeIntervalSince(start), again.security.count, again.updates.count, again.errors.count,
                         again.findings.map(\.fingerprint).sorted() == report.findings.map(\.fingerprint).sorted() ? "yes" : "no"))
        }
    }
}
