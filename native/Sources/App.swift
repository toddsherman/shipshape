import SwiftUI
import AppKit
import UserNotifications
import ServiceManagement
import Network
import UniformTypeIdentifiers

@MainActor
final class Monitor: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    @Published var state = SavedState()
    @Published var scanning = false
    @Published var progress: String? = nil
    @Published var message: String? = nil
    @Published var notificationStatus = "Not enabled"
    @Published var loginEnabled = false
    @Published var section = "Security"
    private var timer: Timer?
    private var pathMonitor: NWPathMonitor?
    private var launchCheckStarted = false
    private var task: Task<Void, Never>?
    private var needsStateRecovery = false
    private let folder: URL
    private var stateURL: URL { folder.appendingPathComponent("state.json") }
    var report: ScanReport? { state.report }
    var security: [Finding] { report?.security ?? [] }
    var updates: [Finding] { report?.updates ?? [] }
    var awaiting: [Finding] { report?.awaiting ?? [] }
    var projectFolders: [String] { state.projectFolders ?? [] }
    var history: [HistoryEntry] { state.history ?? [] }
    var stale: Bool { report.map { Date().timeIntervalSince($0.date) > 36 * 3600 } ?? true }
    var statusTitle: String {
        if scanning { return "Checking this Mac" }
        if report == nil { return "Ready for your first check" }
        if !security.isEmpty { return "\(security.count) items need attention" }
        if stale { return "A fresh check is due" }
        if !awaiting.isEmpty { return "Nothing to install right now" }
        return "No fixes found in covered checks"
    }
    override init() {
        // SHIPSHAPE_STATE_DIR keeps a development build's state apart from the installed app's.
        folder = ProcessInfo.processInfo.environment["SHIPSHAPE_STATE_DIR"].map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? StateFolder.resolve(in: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!)
        super.init()
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            if FileManager.default.fileExists(atPath: stateURL.path) {
                state = try JSONDecoder().decode(SavedState.self, from: Data(contentsOf: stateURL))
            }
        } catch { needsStateRecovery = true; message = "Saved state could not be read: \(error.localizedDescription). The original file will be preserved for recovery." }
        // History starts from the last saved result, dated when that check ran.
        if state.history == nil, let report = state.report {
            var history: [HistoryEntry] = []
            History.update(&history, with: report, projectFolders: projectFolders, at: report.date)
            state.history = history
        }
        UNUserNotificationCenter.current().delegate = self
        refreshSettings()
        // Only the daily check needs a timer; a generous tolerance lets macOS group its wake-ups with other work.
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in Task { @MainActor in self?.checkSchedule() } }
        timer?.tolerance = 30
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(woke), name: NSWorkspace.didWakeNotification, object: nil)
        checkAtLaunch()
    }
    @objc private func woke() { checkSchedule() }
    func refreshSettings() {
        loginEnabled = SMAppService.mainApp.status == .enabled
        Task {
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral: notificationStatus = "Enabled"
            case .denied: notificationStatus = "Disabled in System Settings"
            default: notificationStatus = "Not enabled"
            }
        }
    }
    func enableNotifications() {
        Task {
            do { _ = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]); refreshSettings(); if await notifyChanges() { save() } }
            catch { message = "Notifications: \(error.localizedDescription)" }
        }
    }
    func setLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            refreshSettings()
            if SMAppService.mainApp.status == .requiresApproval { message = "Approve \(appName) in System Settings → General → Login Items." }
        } catch { message = "Start at login: \(error.localizedDescription)"; refreshSettings() }
    }
    func addProjectFolders() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true; panel.canChooseFiles = false; panel.allowsMultipleSelection = true; panel.prompt = "Add"
        panel.message = "Choose folders that contain your projects. Lockfiles up to five levels deep are checked; nothing in them is run."
        guard panel.runModal() == .OK else { return }
        state.projectFolders = Array(Set(projectFolders + panel.urls.map(\.path))).sorted()
        save()
        let warnings = panel.urls.compactMap { Ownership.folderWarning($0.path, access: .live) }
        if !warnings.isEmpty { message = warnings.joined(separator: " ") }
    }
    func removeProjectFolder(_ path: String) { state.projectFolders = projectFolders.filter { $0 != path }; save() }
    func copy(_ text: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string) }
    // Every launch, including at login, starts a fresh check once the network is up. After 30 seconds it
    // checks anyway; sources that can't be reached are reported as usual and earlier findings are kept.
    private func checkAtLaunch() {
        let path = NWPathMonitor()
        path.pathUpdateHandler = { [weak self] update in
            guard update.status == .satisfied else { return }
            Task { @MainActor in self?.startLaunchCheck() }
        }
        path.start(queue: .main)
        pathMonitor = path
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in Task { @MainActor in self?.startLaunchCheck() } }
    }
    private func startLaunchCheck() {
        guard !launchCheckStarted else { return }
        launchCheckStarted = true
        pathMonitor?.cancel()
        pathMonitor = nil
        check()
    }
    // Links open only for https pages and System Settings panes; apps and files only when they still exist.
    func perform(_ option: UpdateCommand) {
        guard let target = option.target else { return }
        switch option.kind {
        case "link":
            guard target.hasPrefix("https://") || target.hasPrefix("x-apple.systempreferences:"), let url = URL(string: target) else { return }
            NSWorkspace.shared.open(url)
        case "app":
            if let problem = SafeOpen.appProblem(target) { message = problem; return }
            NSWorkspace.shared.open(URL(fileURLWithPath: target))
        case "file":
            // Files open in the text editor, never in whatever app their type would launch.
            if let problem = SafeOpen.fileProblem(target, folders: projectFolders, files: Inventory.mcpConfigFiles) { message = problem; return }
            let editor = NSWorkspace.shared.urlForApplication(toOpen: .plainText) ?? URL(fileURLWithPath: "/System/Applications/TextEdit.app")
            NSWorkspace.shared.open([URL(fileURLWithPath: target)], withApplicationAt: editor, configuration: NSWorkspace.OpenConfiguration())
        default: break
        }
    }
    private func save() {
        do {
            if needsStateRecovery && FileManager.default.fileExists(atPath: stateURL.path) {
                try FileManager.default.copyItem(at: stateURL, to: folder.appendingPathComponent("state-recovery-\(UUID().uuidString).json"))
                needsStateRecovery = false
            }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            try encoder.encode(state).write(to: stateURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stateURL.path)
        } catch { message = "The latest result could not be saved: \(error.localizedDescription)" }
    }
    func checkSchedule() {
        if state.report != nil && Schedule.isDue(now: Date(), lastDay: state.lastScheduledDay) { check() }
    }
    func check() {
        guard !scanning else { return }
        message = nil
        state.lastAttempt = Date()
        if Schedule.calendar.component(.hour, from: Date()) >= 9 { state.lastScheduledDay = Schedule.day(Date()) }
        save()
        scanning = true
        let previous = state.report, folders = projectFolders
        let wasAwaiting = Set(previous?.awaiting.map(\.id) ?? [])
        task = Task {
            let result = await Task.detached(priority: .utility) {
                await Scanner.run(previous: previous, projectFolders: folders) { text in Task { @MainActor in self.progress = text } }
            }.value
            state.report = result
            var history = state.history ?? []
            History.update(&history, with: result, projectFolders: folders, at: result.date)
            state.history = history
            scanning = false
            progress = nil
            await notifyChanges(wasAwaiting: wasAwaiting)
            save()
        }
    }
    // Findings that were waiting for a fix and now have one get their own alert title.
    // Returns whether the record of delivered alerts changed and needs saving.
    @discardableResult private func notifyChanges(wasAwaiting: Set<String> = []) async -> Bool {
        guard let report else { return false }
        let before = (state.delivered, state.lastFailure)
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else { return false }
        let changed = report.security.filter { !$0.stale && state.delivered[$0.id] != $0.fingerprint }
        let failureSignature = report.checks.filter { $0.status == "failed" }.map(\.id).sorted().joined(separator: ",")
        if !changed.isEmpty {
            let content = UNMutableNotificationContent()
            let malicious = changed.contains { $0.malicious == true }
            let released = changed.contains { wasAwaiting.contains($0.id) }
            content.title = malicious ? "Malicious package found" : released ? "Fix now available" : "Security updates to review"
            let names = Array(Set(changed.map { $0.installation.packageName ?? $0.installation.name })).sorted()
            content.body = names.prefix(4).joined(separator: ", ") + (names.count > 4 ? " and \(names.count - 4) more" : "") + ". Open \(appName) for versions and update commands."
            content.sound = .default
            do {
                try await center.add(UNNotificationRequest(identifier: "security-findings", content: content, trigger: nil))
                for finding in changed { state.delivered[finding.id] = finding.fingerprint }
            } catch { message = "Could not schedule an alert: \(error.localizedDescription)" }
        }
        if !failureSignature.isEmpty && state.lastFailure != failureSignature {
            let content = UNMutableNotificationContent(); content.title = "Some security checks need attention"
            content.body = "A vendor source or local check could not complete. Previous findings are retained. Open Coverage for details."
            do {
                try await center.add(UNNotificationRequest(identifier: "security-check-failure", content: content, trigger: nil))
                state.lastFailure = failureSignature
            } catch { message = "Could not schedule a check-failure alert: \(error.localizedDescription)" }
        } else if failureSignature.isEmpty { state.lastFailure = nil }
        // Remove delivered fingerprints only after the corresponding issue really disappeared.
        let ids = Set(report.findings.map(\.id))
        state.delivered = state.delivered.filter { ids.contains($0.key) }
        return before.0 != state.delivered || before.1 != state.lastFailure
    }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions { [.banner, .sound] }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        await MainActor.run {
            NotificationCenter.default.post(name: .init("ShowDashboard"), object: nil)
            NSApp.activate(ignoringOtherApps: true)
        }
    }
    func export() {
        guard let report else { return }
        let panel = NSSavePanel(); panel.nameFieldStringValue = "\(appName) Report.json"
        panel.message = "This report includes installed software versions, project paths and package names."
        if panel.runModal() == .OK, let url = panel.url {
            do { let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601; try encoder.encode(report).write(to: url, options: .atomic) }
            catch { message = "Report export failed: \(error.localizedDescription)" }
        }
    }
    func exportHistory() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "\(appName) History.csv"
        panel.message = "The history includes software names, versions, install paths and project paths."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try History.csv(history).write(to: url, atomically: true, encoding: .utf8) }
        catch { message = "History export failed: \(error.localizedDescription)" }
    }
    func openData() { NSWorkspace.shared.open(folder) }
}

@main
struct ShipshapeApp: App {
    @StateObject private var monitor = Monitor()
    var body: some Scene {
        Window(appName, id: "dashboard") {
            Dashboard().environmentObject(monitor)
        }.defaultSize(width: 1040, height: 760)
        MenuBarExtra {
            MenuPanel().environmentObject(monitor)
        } label: {
            Image(systemName: monitor.scanning ? "arrow.triangle.2.circlepath" : monitor.security.isEmpty ? "shield.lefthalf.filled" : "exclamationmark.shield.fill")
            if !monitor.security.isEmpty { Text("\(monitor.security.count)") }
        }.menuBarExtraStyle(.window)
    }
}

struct MenuPanel: View {
    @EnvironmentObject var monitor: Monitor
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(appName, systemImage: "shield.lefthalf.filled").font(.headline)
            Text(monitor.statusTitle).font(.title3.weight(.semibold))
            if let progress = monitor.progress { Text(progress).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
            else if let date = monitor.report?.date { LastCheck(date: date, prefix: "Checked ").font(.caption).foregroundStyle(.secondary) }
            HStack {
                Label("\(monitor.security.count) security", systemImage: "exclamationmark.shield")
                Spacer()
                Label("\(monitor.updates.count) updates", systemImage: "arrow.down.circle")
            }.font(.caption)
            if !(monitor.report?.errors.isEmpty ?? true) { Text("Some checks need attention").foregroundStyle(.orange).font(.caption) }
            Divider()
            Button("Open \(appName)") { openWindow(id: "dashboard"); NSApp.activate(ignoringOtherApps: true) }.buttonStyle(.borderedProminent).frame(maxWidth: .infinity)
            HStack {
                Button(monitor.scanning ? "Checking…" : "Check now") { monitor.check() }.disabled(monitor.scanning)
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
            }
            Text("At launch, daily at 9 a.m. Pacific and when you click Check now").font(.caption2).foregroundStyle(.secondary)
        }.padding(18).frame(width: 310)
        .onReceive(NotificationCenter.default.publisher(for: .init("ShowDashboard"))) { _ in openWindow(id: "dashboard") }
    }
}

struct Dashboard: View {
    @EnvironmentObject var monitor: Monitor
    @Environment(\.openWindow) private var openWindow
    @State private var query = ""
    @State private var domain = "all"
    let sections = [("Security", "exclamationmark.shield"), ("Updates", "arrow.down.circle"), ("History", "clock.arrow.circlepath"), ("Inventory", "desktopcomputer"), ("Coverage", "checklist"), ("Settings", "gearshape")]
    let domains = [("all", "All"), ("projects", "Projects"), ("packages", "Packages"), ("mcp", "MCP"), ("tools", "Runtimes"), ("brew", "Homebrew"), ("apps", "Apps")]
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 5) {
                Label(appName, systemImage: "shield.lefthalf.filled").font(.title3.weight(.semibold)).padding(.bottom, 25).padding(.top, 14)
                ForEach(sections, id: \.0) { title, symbol in
                    Button { monitor.section = title; query = "" } label: {
                        HStack { Image(systemName: symbol).frame(width: 20); Text(title); Spacer(); if title == "Security" && !monitor.security.isEmpty { Text("\(monitor.security.count)").font(.caption.weight(.semibold)) } }
                            .padding(.horizontal, 12).padding(.vertical, 10).contentShape(Rectangle())
                            .background(monitor.section == title ? Color.accentColor.opacity(0.13) : .clear, in: RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(.plain)
                }
                Spacer()
                Text("ON THIS MAC").font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                Text(Host.current().localizedName ?? "This Mac").font(.caption).lineLimit(2)
                Text("Version \(appVersion) · Preview").font(.caption2).foregroundStyle(.tertiary).padding(.top, 12)
            }.padding(20).frame(width: 200).background(Color(nsColor: .controlBackgroundColor))
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(monitor.section).font(.largeTitle.weight(.bold))
                        Text(monitor.progress ?? subtitle).font(.subheadline).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if monitor.scanning { ProgressView().controlSize(.small).padding(.top, 7) }
                    Button(monitor.scanning ? "Checking…" : "Check now") { monitor.check() }.buttonStyle(.borderedProminent).disabled(monitor.scanning)
                }.padding(28)
                ForEach([monitor.message].compactMap { $0 }, id: \.self) { Text($0).font(.callout).foregroundStyle(.orange).padding(.horizontal, 28).padding(.bottom, 16).textSelection(.enabled) }
                if monitor.section != "Settings", monitor.report == nil { welcome }
                else { content }
                Divider()
                HStack {
                    if let date = monitor.report?.date { LastCheck(date: date, prefix: "Last check: ") } else { Text("No check yet") }
                    Spacer()
                    Text("Checks at launch, daily at 9 a.m. Pacific and on Check now")
                }.font(.caption).foregroundStyle(.secondary).padding(16)
            }.frame(maxWidth: .infinity)
        }.frame(minWidth: 900, minHeight: 640)
        .onReceive(NotificationCenter.default.publisher(for: .init("ShowDashboard"))) { _ in openWindow(id: "dashboard") }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in monitor.refreshSettings() }
    }
    var subtitle: String {
        switch monitor.section {
        case "Security": return "Published fixes and malicious-package reports that match your developer tools and dependencies."
        case "Updates": return "Newer releases, with security significance unconfirmed."
        case "Inventory": return "Developer software and packages found by the latest check."
        case "History": return "Every recommendation on this Mac: when it was found, and when and how it was resolved."
        case "Coverage": return "What was checked, what failed, and what needs manual review."
        default: return "Checks, alerts and project folders. Everything is stored on this Mac."
        }
    }
    var welcome: some View {
        VStack(alignment: .leading, spacing: 22) {
            Image(systemName: "shield.lefthalf.filled").font(.system(size: 48)).foregroundStyle(.blue)
            Text("Know what in your dev stack needs a fix.").font(.title.weight(.semibold))
            Text("Checks the runtimes, package managers, AI coding tools, MCP servers, Homebrew libraries and project dependencies you build with against OSV, NVD and vendor advisories. Every finding comes with its evidence and a command you can copy into Terminal.").foregroundStyle(.secondary)
            Text("Add the folders that hold your projects so their lockfiles are included. Inventory stays on this Mac; public advisory services receive package names and versions only. No accounts or API keys are needed.").font(.callout)
            HStack {
                Button("Add project folders…") { monitor.addProjectFolders() }
                Button("Run first check") { monitor.check() }.buttonStyle(.borderedProminent).disabled(monitor.scanning)
                Button("Enable notifications") { monitor.enableNotifications() }.disabled(monitor.notificationStatus == "Enabled")
            }
            if !monitor.projectFolders.isEmpty { Text("Projects: " + monitor.projectFolders.map { Inventory.display($0) }.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary) }
            Spacer()
        }.padding(32).frame(maxWidth: 680, alignment: .leading).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
    @ViewBuilder var content: some View {
        switch monitor.section {
        case "Security", "Updates":
            let findings = monitor.section == "Security" ? monitor.security : monitor.updates
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 14) {
                    if monitor.section == "Security" {
                        HStack(spacing: 12) {
                            StatCard(number: "\(monitor.security.count)", label: "Security items", color: .orange)
                            StatCard(number: "\(monitor.security.filter { $0.malicious == true }.count)", label: "Malicious packages", color: .red)
                            StatCard(number: "\(monitor.updates.count)", label: "Other updates", color: .blue)
                            StatCard(number: "\(monitor.report?.errors.count ?? 0)", label: "Check issues", color: .secondary)
                        }
                        HStack {
                            Text("Coverage is partial. No finding does not mean everything is safe; see Coverage.").font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            AllCommandsButton(findings: findings)
                        }.padding(.vertical, 3)
                    } else if !findings.isEmpty {
                        HStack { Spacer(); AllCommandsButton(findings: findings) }
                    }
                    if findings.isEmpty {
                        Label(monitor.section != "Security" ? "No newer releases found in covered metadata." : monitor.awaiting.isEmpty ? "No security fixes found in covered checks." : "Nothing to install right now.", systemImage: "tray").foregroundStyle(.secondary).padding(.vertical, 30)
                    }
                    let installed = findings.filter { $0.installation.domain != "projects" }, dependencies = findings.filter { $0.installation.domain == "projects" }
                    if !installed.isEmpty && !dependencies.isEmpty { Text("Installed on this Mac · \(installed.count)").font(.headline).padding(.top, 6) }
                    FindingList(findings: installed)
                    if !dependencies.isEmpty {
                        Text("Project dependencies · \(dependencies.count) in \(Set(dependencies.compactMap(\.installation.location)).count) folders").font(.headline).padding(.top, 10)
                        FindingList(findings: dependencies)
                    }
                    if monitor.section == "Security" && !monitor.awaiting.isEmpty {
                        Text("No fix released yet · \(monitor.awaiting.count)").font(.headline).padding(.top, 10)
                        Text("You already have the newest release, and the advisories list no fixed version. These don't count as needing attention; \(appName) alerts you when a fixed release ships.").font(.caption).foregroundStyle(.secondary)
                        ForEach(monitor.awaiting) { FindingCard(finding: $0) }
                    }
                }.padding(.horizontal, 28).padding(.bottom, 24)
            }
        case "History": HistoryView()
        case "Inventory":
            let items = (monitor.report?.installations ?? []).filter { (domain == "all" || $0.domain == domain) && (query.isEmpty || ($0.name + $0.path + $0.note).localizedCaseInsensitiveContains(query)) }
            VStack(spacing: 10) {
                Picker("Show", selection: $domain) { ForEach(domains, id: \.0) { Text($0.1).tag($0.0) } }.pickerStyle(.segmented).labelsHidden().padding(.horizontal, 28)
                TextField("Search software, package, project or path", text: $query).textFieldStyle(.roundedBorder).padding(.horizontal, 28)
                Text("\(items.count) items").font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 28)
                List(items) { item in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack { Text(item.name).fontWeight(.medium); Spacer(); Text(item.version).monospaced() }
                        Text(item.note.isEmpty ? item.path : item.note).font(.caption).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(2)
                    }.padding(.vertical, 4)
                }.listStyle(.inset)
            }
        case "Coverage":
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach((monitor.report?.checks ?? []).filter { $0.status != "checked" || !$0.id.hasPrefix("nvd:") }) { check in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack { Text(check.name).fontWeight(.semibold); Spacer(); Text(check.status.uppercased()).font(.caption2.weight(.semibold)).foregroundStyle(check.status == "failed" || check.status == "partial" ? Color.orange : .secondary) }
                            Text(check.detail).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                            if let url = check.url, let link = URL(string: url) { Link("Open website", destination: link).font(.caption) }
                        }.padding(16).frame(maxWidth: .infinity, alignment: .leading).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                    }
                    let nvd = (monitor.report?.checks ?? []).filter { $0.status == "checked" && $0.id.hasPrefix("nvd:") }
                    if !nvd.isEmpty { Text("Also checked against NVD: " + nvd.map { $0.name.replacingOccurrences(of: " (NVD)", with: "") }.joined(separator: ", ") + ".").font(.callout).foregroundStyle(.secondary).padding(.top, 4) }
                }.padding(.horizontal, 28).padding(.bottom, 24)
            }
        default: settings
        }
    }
    var settings: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Project folders").font(.headline)
                    Text("Lockfiles up to five levels deep are checked: package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, uv.lock, poetry.lock, requirements.txt, Cargo.lock, Gemfile.lock and go.mod, plus project .mcp.json files. node_modules, virtual environments, build folders, app bundles, Homebrew and system folders are skipped. Nothing in a project is run.").foregroundStyle(.secondary)
                    ForEach(monitor.projectFolders, id: \.self) { path in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack { Image(systemName: "folder"); Text(Inventory.display(path)).textSelection(.enabled); Spacer(); Button("Remove") { monitor.removeProjectFolder(path) }.buttonStyle(.link) }
                            if let warning = Ownership.folderWarning(path, access: .live) { Text(warning).font(.caption).foregroundStyle(.orange).padding(.leading, 26) }
                        }
                    }
                    Button("Add project folders…") { monitor.addProjectFolders() }
                }
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text("Checks").font(.headline)
                    Text("A full check runs when the app opens, daily at 9 a.m. America/Los_Angeles (including daylight saving changes) and when you click Check now. A missed daily check runs after wake or the next app launch after 9 a.m. The app must be running to check and alert.").foregroundStyle(.secondary)
                    Toggle("Start \(appName) when I log in", isOn: Binding(get: { monitor.loginEnabled }, set: { monitor.setLogin($0) }))
                }
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text("Notifications").font(.headline)
                    Text(monitor.notificationStatus).foregroundStyle(.secondary)
                    Text("Alerts appear for new or changed security findings, malicious packages and failed checks. Identical findings and ordinary updates stay quiet. Delivery also follows macOS Focus and notification settings.").foregroundStyle(.secondary)
                    HStack {
                        Button("Enable notifications") { monitor.enableNotifications() }.disabled(monitor.notificationStatus == "Enabled")
                        Button("Notification settings") { openTrusted("x-apple.systempreferences:com.apple.Notifications-Settings.extension") }
                    }
                }
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text("Local data & privacy").font(.headline)
                    Text("No account, cloud inventory, analytics or AI service. Package names and versions go to OSV, product versions to NVD, and release lookups to Homebrew and vendors. Private package names in your lockfiles are included in OSV queries. MCP settings are read for server commands only; environment variables and keys are ignored.").foregroundStyle(.secondary)
                    Text("Update commands are shown for you to copy and run; the app never installs, removes or changes anything itself. This preview does not update itself.").foregroundStyle(.secondary)
                    Text("History is kept on this Mac with the latest result, up to the newest \(History.limit.formatted()) entries.").foregroundStyle(.secondary)
                    HStack { Button("Open local data") { monitor.openData() }; Button("Export report…") { monitor.export() }.disabled(monitor.report == nil) }
                }
            }.padding(.horizontal, 28).padding(.bottom, 24)
        }
    }
}
// The History tab: a log of every recommendation, newest event first. Open entries are still reported by the
// latest check; resolved ones say when they went away and what happened to the software.
struct HistoryView: View {
    @EnvironmentObject var monitor: Monitor
    @State private var filter = "all"
    @State private var query = ""
    var body: some View {
        let history = monitor.history
        let open = history.filter { $0.resolved == nil }.count
        let monthAgo = Date().addingTimeInterval(-30 * 86_400)
        let entries = history.filter { entry in
            (filter == "all" || (filter == "open") == (entry.resolved == nil))
                && (query.isEmpty || ([entry.name, entry.place, entry.version, entry.fixed, entry.resolution ?? "", entry.command ?? ""] + entry.advisories).joined(separator: " ").localizedCaseInsensitiveContains(query))
        }.sorted { ($0.resolved ?? $0.firstSeen, $0.name) > ($1.resolved ?? $1.firstSeen, $1.name) }
        VStack(spacing: 10) {
            HStack(spacing: 12) {
                StatCard(number: "\(open)", label: "Open", color: .orange)
                StatCard(number: "\(history.count - open)", label: "Resolved", color: .green)
                StatCard(number: "\(history.filter { ($0.resolved ?? .distantPast) > monthAgo }.count)", label: "Resolved in the last 30 days", color: .green)
                StatCard(number: history.map(\.firstSeen).min().map { $0.formatted(.dateTime.month(.abbreviated).day()) } ?? "—", label: "Tracking since", color: .secondary)
            }.padding(.horizontal, 28)
            HStack {
                Picker("Show", selection: $filter) { Text("All").tag("all"); Text("Open").tag("open"); Text("Resolved").tag("resolved") }.pickerStyle(.segmented).labelsHidden().frame(width: 260)
                TextField("Search software, project, advisory or resolution", text: $query).textFieldStyle(.roundedBorder)
                Button("Export CSV…") { monitor.exportHistory() }.disabled(history.isEmpty)
            }.padding(.horizontal, 28)
            if entries.isEmpty {
                Label(history.isEmpty ? "Recommendations appear here after a check." : "No entries match.", systemImage: "tray").foregroundStyle(.secondary).padding(.vertical, 30).frame(maxHeight: .infinity, alignment: .top)
            } else {
                List(entries) { HistoryRow(entry: $0) }.listStyle(.inset)
            }
        }
    }
}
struct HistoryRow: View {
    let entry: HistoryEntry
    var body: some View {
        let (label, color) = historyBadge(entry)
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: entry.resolved == nil ? "circle.dashed" : "checkmark.circle.fill").foregroundStyle(entry.resolved == nil ? Color.orange : .green).padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    Text(entry.name).fontWeight(.medium)
                    Text(label).font(.caption2.weight(.semibold)).foregroundStyle(color)
                    Spacer()
                    Text(entry.version + " → " + entry.fixed).font(.callout.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                }
                Text(status).font(.caption)
                Text(Inventory.display(entry.place)).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                if let command = entry.command { Text("Recommended: " + command).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled) }
            }
        }.padding(.vertical, 5)
    }
    var status: String {
        let found = "Found " + entry.firstSeen.formatted(date: .abbreviated, time: .shortened)
        guard let resolved = entry.resolved else { return found + (entry.awaiting == true ? " · Waiting for a fixed release" : " · Open") }
        return found + " · Resolved " + resolved.formatted(date: .abbreviated, time: .shortened) + " · " + (entry.resolution ?? "No longer reported")
    }
}
func historyBadge(_ entry: HistoryEntry) -> (String, Color) {
    if entry.malicious == true { return ("MALICIOUS PACKAGE", .red) }
    switch entry.kind {
    case .security: return ((entry.severity.map { $0 + " · " } ?? "") + "SECURITY FIX", entry.resolved != nil ? .secondary : entry.severity == "CRITICAL" ? .red : .orange)
    case .unsupported: return ("END OF SUPPORT", entry.resolved != nil ? .secondary : .orange)
    case .update: return ("UPDATE", entry.resolved != nil ? .secondary : .blue)
    }
}
struct StatCard: View {
    let number: String; let label: String; let color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 6) { Text(number).font(.system(size: 30, weight: .semibold, design: .rounded)).foregroundStyle(color); Text(label).font(.caption).foregroundStyle(.secondary) }
            .frame(maxWidth: .infinity, alignment: .leading).padding(16).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
    }
}
func findingBadge(_ finding: Finding) -> (String, Color) {
    if finding.malicious == true { return ("MALICIOUS PACKAGE", .red) }
    if finding.exploited { return ("KNOWN EXPLOITATION", .red) }
    if finding.awaitingFix == true { return ((finding.severity.map { $0 + " · " } ?? "") + "NO FIX RELEASED YET", .secondary) }
    switch finding.kind {
    case .security: return ((finding.severity.map { $0 + " · " } ?? "") + "SECURITY FIX", finding.severity == "CRITICAL" ? .red : .orange)
    case .unsupported: return ("END OF SUPPORT", .orange)
    case .update: return ("UPDATE", .blue)
    }
}
struct CardStyle: ViewModifier {
    var alert = false
    func body(content: Content) -> some View {
        content.padding(18).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(alert ? Color.red.opacity(0.5) : Color.primary.opacity(0.07)))
    }
}
// Location, linked advisory IDs and the source page for one finding.
struct FindingEvidence: View {
    let finding: Finding
    // The lockfile or MCP settings file for project and MCP findings; the install path otherwise.
    var location: String { Inventory.display(finding.installation.sourceFile) }
    // Advisory IDs, each linked to its own page: the finding's link for it, NVD for CVEs, OSV otherwise.
    var advisories: AttributedString {
        var text = AttributedString("Advisories: ")
        for (index, id) in finding.advisories.enumerated() {
            if index > 0 { text += AttributedString(", ") }
            var part = AttributedString(id)
            let page = finding.links.first { $0.hasPrefix("https://") && $0.hasSuffix("/" + id) }
                ?? (id.hasPrefix("CVE-") ? "https://nvd.nist.gov/vuln/detail/" + id : "https://osv.dev/vulnerability/" + id)
            if id.range(of: "^[A-Za-z0-9._:-]+$", options: .regularExpression) != nil { part.link = URL(string: page) }
            text += part
        }
        return text
    }
    var body: some View {
        HStack(alignment: .bottom) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Location: " + location).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                if !finding.advisories.isEmpty { Text(advisories).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
            }
            Spacer()
            if let source = finding.links.first, let url = URL(string: source), url.scheme == "https" { Link("Open website", destination: url).font(.callout) }
        }
    }
}
struct FindingCard: View {
    let finding: Finding
    var body: some View {
        let badge = findingBadge(finding)
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(finding.installation.name).font(.headline)
                Spacer()
                Text(badge.0).font(.caption2.weight(.bold)).foregroundStyle(badge.1)
            }
            if !finding.installation.note.isEmpty { Text(finding.installation.note).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
            Text("\(finding.installation.version)  →  \(finding.fixed)").font(.system(.callout, design: .monospaced))
            if finding.stale { Label("Previous finding · could not verify on this check", systemImage: "clock.badge.exclamationmark").font(.caption).foregroundStyle(.orange) }
            Text(finding.reason).font(.callout).foregroundStyle(.secondary)
            Text(finding.action).font(.callout)
            if let blocked = finding.blocked { BlockedNotice(text: blocked) }
            UpdateOptions(options: finding.commands ?? [])
            FindingEvidence(finding: finding)
        }.modifier(CardStyle(alert: finding.malicious == true))
    }
}
// Every recommended Terminal command in a list, combined into as few lines as possible, to review and copy at once.
struct AllCommandsButton: View {
    @EnvironmentObject var monitor: Monitor
    let findings: [Finding]
    @State private var showing = false
    var commands: [UpdateCommand] { findings.compactMap { $0.commands?.first }.filter { $0.kind == nil } }
    var body: some View {
        let lines = Commands.combined(commands)
        Button("All commands…") { showing = true }.disabled(lines.isEmpty)
            .help("Shows every recommended Terminal command in this list, combined where possible, to review and copy at once.")
            .sheet(isPresented: $showing) {
                VStack(alignment: .leading, spacing: 12) {
                    Text("\(lines.count) command\(lines.count == 1 ? "" : "s") for \(commands.count) finding\(commands.count == 1 ? "" : "s")").font(.title3.weight(.semibold))
                    Text("Commands that differ only in what they act on are combined, such as brew upgrade a b c or rm -rf with several folders. Findings whose best option is a website, app or file aren't included, and neither are those this account can't change. Review before running.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    ScrollView {
                        VStack(alignment: .leading, spacing: 10) { ForEach(lines, id: \.self) { UpdateOptionRow(option: UpdateCommand(text: $0, note: ""), primary: false) } }.padding(.vertical, 2)
                    }.frame(minHeight: 160, maxHeight: 460)
                    HStack {
                        Button("Close") { showing = false }.keyboardShortcut(.cancelAction)
                        Spacer()
                        Button("Copy all") { monitor.copy(lines.joined(separator: "\n")); showing = false }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    }
                }.padding(20).frame(width: 760).environmentObject(monitor)
            }
    }
}
// Findings in list order, with those that share a recommended command combined into one card.
struct FindingList: View {
    let findings: [Finding]
    var body: some View {
        ForEach(groupByCommand(findings)) { group in
            if group.findings.count > 1 { FindingGroupCard(group: group) } else { FindingCard(finding: group.findings[0]) }
        }
    }
}
// Several findings fixed by one command: the command once, then each finding's own details.
struct FindingGroupCard: View {
    @EnvironmentObject var monitor: Monitor
    let group: FindingGroup
    var findings: [Finding] { group.findings }
    var sameName: Bool { Set(findings.map(\.installation.name)).count == 1 }
    var place: String? { Set(findings.compactMap(\.installation.location)).count == 1 ? findings[0].installation.location : nil }
    static let labels = ["brew": "Homebrew formulae", "brew-python": "Homebrew formulae", "brew-old": "Older Homebrew copies", "cask": "Homebrew apps",
                         "npm-global": "Global npm packages", "bun-global": "Global Bun packages", "pnpm-global": "Global pnpm packages",
                         "pip": "Python packages", "pip-brew": "Python packages", "npx-cache": "npx cache", "mise": "mise runtimes"]
    // A project is named by its path inside the chosen project folder, such as shop/backend.
    var title: String {
        if sameName { return findings[0].installation.name }
        guard findings[0].installation.domain == "projects", let place else { return Self.labels[findings[0].installation.manager ?? ""] ?? "\(findings.count) findings" }
        let root = monitor.projectFolders.filter { place.hasPrefix($0 + "/") }.max { $0.count < $1.count }
        return root.map { String(place.dropFirst($0.count + 1)) } ?? (place as NSString).lastPathComponent
    }
    var subtitle: String {
        if !sameName, findings[0].installation.domain == "projects", let place { return Inventory.display(place) }
        return Set(findings.map(\.installation.note)).count == 1 ? findings[0].installation.note : ""
    }
    var body: some View {
        let badge = findingBadge(findings[0])  // the list is sorted, so the first member is the most urgent
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(.headline)
                Text("\(findings.count) \(findings[0].kind == .update ? "updates" : "findings")" + (findings[0].blocked == nil ? ", one command" : "")).font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text(badge.0).font(.caption2.weight(.bold)).foregroundStyle(badge.1)
            }
            if !subtitle.isEmpty { Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
            if let blocked = findings[0].blocked { BlockedNotice(text: blocked) }
            if let command = group.command { UpdateOptionRow(option: command, primary: true) }
            ForEach(findings) { finding in
                let itemBadge = findingBadge(finding)
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .firstTextBaseline) {
                        if !sameName { Text(finding.installation.name).font(.callout.weight(.semibold)) }
                        Text("\(finding.installation.version)  →  \(finding.fixed)").font(.system(.callout, design: .monospaced))
                        Spacer()
                        Text(itemBadge.0).font(.caption2.weight(.semibold)).foregroundStyle(itemBadge.1)
                    }
                    if finding.stale { Label("Previous finding · could not verify on this check", systemImage: "clock.badge.exclamationmark").font(.caption).foregroundStyle(.orange) }
                    Text(finding.reason).font(.callout).foregroundStyle(.secondary)
                    AlternativeOptions(options: finding.blocked == nil ? Array((finding.commands ?? []).dropFirst()) : finding.commands ?? [])
                    FindingEvidence(finding: finding)
                }
            }
        }.modifier(CardStyle(alert: findings.contains { $0.malicious == true }))
    }
}
// The time of the last check and how long ago it was, kept current while it's on screen.
struct LastCheck: View {
    let date: Date
    let prefix: String
    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { context in Text(prefix + lastCheckText(date, now: context.date)) }
    }
}
// Why no command is offered: the software belongs to another account, or to root.
struct BlockedNotice: View {
    let text: String
    var body: some View {
        Label(text, systemImage: "lock").font(.callout).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
    }
}
// The recommended way to update, with the other detected routes one click away.
struct UpdateOptions: View {
    let options: [UpdateCommand]
    var body: some View {
        if let primary = options.first {
            VStack(alignment: .leading, spacing: 8) {
                UpdateOptionRow(option: primary, primary: true)
                AlternativeOptions(options: Array(options.dropFirst()))
            }
        }
    }
}
struct AlternativeOptions: View {
    let options: [UpdateCommand]
    @State private var expanded = false
    var body: some View {
        if !options.isEmpty {
            DisclosureGroup(isExpanded: $expanded) {
                VStack(alignment: .leading, spacing: 12) { ForEach(options, id: \.self) { UpdateOptionRow(option: $0, primary: false) } }.padding(.top, 6)
            } label: { Text("Other ways to update (\(options.count))").font(.callout) }
        }
    }
}
struct UpdateOptionRow: View {
    @EnvironmentObject var monitor: Monitor
    let option: UpdateCommand
    let primary: Bool
    @State private var copied = false
    var symbol: String { option.kind == "link" ? "safari" : option.kind == "app" ? "arrow.down.app" : "doc.text" }
    @ViewBuilder func styled<Content: View>(_ button: Content, prominent: Bool) -> some View {
        if prominent { button.buttonStyle(.borderedProminent) } else { button.buttonStyle(.bordered) }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if option.kind == nil {
                HStack(alignment: .center, spacing: 8) {
                    Text(option.text).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                        .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 7))
                    styled(Button(copied ? "Copied" : "Copy") { monitor.copy(option.text); flash() }, prominent: primary).frame(minWidth: 70)
                }
            } else {
                styled(Button { monitor.perform(option) } label: { Label(option.text, systemImage: symbol) }, prominent: primary)
            }
            if !option.note.isEmpty { Text(option.note).font(.caption).foregroundStyle(.secondary) }
        }
    }
    func flash() { copied = true; DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false } }
}
func openTrusted(_ address: String) { if let url = URL(string: address) { NSWorkspace.shared.open(url) } }
