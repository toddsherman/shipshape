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
    @Published var feedbackOpen = false
    @Published var filter: FindingCategory? = nil  // the Security page's selected tile; nil lists what needs attention
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
    var attention: [Finding] { report?.attention ?? [] }
    var projectFolders: [String] { state.projectFolders ?? [] }
    var history: [HistoryEntry] { state.history ?? [] }
    var stale: Bool { report.map { Date().timeIntervalSince($0.date) > 36 * 3600 } ?? true }
    // A scenario preview (native/scenario.sh) shows a made-up saved state as it is: with SHIPSHAPE_NO_CHECKS=1 beside
    // SHIPSHAPE_STATE_DIR, no check runs at launch, on schedule or from Check now, so its findings aren't replaced.
    static let checksOff: Bool = {
        let env = ProcessInfo.processInfo.environment
        return env["SHIPSHAPE_STATE_DIR"] != nil && env["SHIPSHAPE_NO_CHECKS"] == "1"
    }()
    // The made-up states a scenario preview can switch between: index.tsv in SHIPSHAPE_SCENARIOS lists each one's name,
    // title and description, and <name>/state.json holds it. Empty outside a preview.
    struct Scenario: Identifiable { let id: String; let title: String; let detail: String; let file: URL }
    static let scenarios: [Scenario] = {
        guard checksOff, let folder = ProcessInfo.processInfo.environment["SHIPSHAPE_SCENARIOS"],
              let index = try? String(contentsOfFile: folder + "/index.tsv", encoding: .utf8) else { return [] }
        return index.split(separator: "\n").compactMap { line in
            let fields = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard fields.count == 3 else { return nil }
            return Scenario(id: fields[0], title: fields[1], detail: fields[2], file: URL(fileURLWithPath: folder + "/" + fields[0] + "/state.json"))
        }
    }()
    @Published private(set) var scenario = ProcessInfo.processInfo.environment["SHIPSHAPE_SCENARIO"]
    // Shows a scenario from its original file, so choosing the current one again also resets it.
    func show(_ scenario: Scenario) {
        guard Monitor.checksOff, let data = try? Data(contentsOf: scenario.file), let loaded = try? JSONDecoder().decode(SavedState.self, from: data) else {
            message = "The \(scenario.title) scenario couldn't be read. Run native/scenario.sh again to regenerate it."
            return
        }
        state = loaded
        self.scenario = scenario.id
        filter = nil
        section = "Security"
        message = nil
        save()
    }
    var statusTitle: String {
        if scanning { return "Checking this Mac" }
        if report == nil { return "Ready for your first check" }
        if !attention.isEmpty { return FindingCategory.attentionTitle(attention.count) }
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
        guard !Monitor.checksOff else { return }
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
        if !Monitor.checksOff, state.report != nil && Schedule.isDue(now: Date(), lastDay: state.lastScheduledDay) { check() }
    }
    func check() {
        guard !Monitor.checksOff else { message = "Checks are off in this scenario preview, so its made-up findings stay as they are."; return }
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
    // Findings that were waiting for a fix and now have one, or whose app has a new release, get their own alert (see Alerts).
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
            (content.title, content.body) = Alerts.findings(changed, released: wasAwaiting)
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
        state.delivered = Alerts.pruned(state.delivered, report: report)
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

// Quit in the Dock closes the dashboard and removes the Dock icon instead of quitting (see Quitting); the Dashboard puts
// the icon back when it opens. The Dock sends Quit as an Apple event, so its sender tells it apart from Command-Q.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminate(_ app: NSApplication) -> NSApplication.TerminateReply {
        guard let event = NSAppleEventManager.shared().currentAppleEvent, event.eventClass == AEEventClass(kCoreEventClass),
              event.eventID == AEEventID(kAEQuitApplication) else { return .terminateNow }
        let pid = event.attributeDescriptor(forKeyword: AEKeyword(keySenderPIDAttr))?.int32Value
        guard Quitting.staysInMenuBar(quitFrom: pid.flatMap { NSRunningApplication(processIdentifier: $0)?.bundleIdentifier }) else { return .terminateNow }
        for window in app.windows where window.isVisible && window.canBecomeMain { window.close() }
        app.setActivationPolicy(.accessory)
        return .terminateCancel
    }
}

@main
struct ShipshapeApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var monitor = Monitor()
    @StateObject private var updates = Updates()
    var body: some Scene {
        Window(displayName, id: "dashboard") {
            Dashboard().environmentObject(monitor).environmentObject(updates)
        }.defaultSize(width: 1040, height: 760)
        .commands {
            CommandGroup(after: .appInfo) { CheckForUpdatesButton(updates: updates) }
            if !Monitor.scenarios.isEmpty { CommandMenu("Scenarios") { ScenarioPicker(monitor: monitor, style: .inline) } }
        }
        MenuBarExtra {
            MenuPanel().environmentObject(monitor)
        } label: {
            Image(systemName: monitor.scanning ? "arrow.triangle.2.circlepath" : monitor.attention.isEmpty ? "sailboat" : "sailboat.fill")
            if !monitor.attention.isEmpty { Text("\(monitor.attention.count)") }
        }.menuBarExtraStyle(.window)
    }
}

struct MenuPanel: View {
    @EnvironmentObject var monitor: Monitor
    @Environment(\.openWindow) private var openWindow
    @State private var panel: NSWindow?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label(displayName, systemImage: "sailboat.fill").font(.headline)
                Spacer()
                // Check now, as a refresh button; a spinner takes its place while a check runs.
                if monitor.scanning { ProgressView().controlSize(.small).frame(width: 22, height: 22) }
                else {
                    Button { monitor.check() } label: { Image(systemName: "arrow.clockwise.circle").font(.title2) }
                        .buttonStyle(.borderless).help("Check now").accessibilityLabel("Check now").frame(width: 22, height: 22)
                }
            }
            Text(monitor.statusTitle).font(.title3.weight(.semibold))
            if let progress = monitor.progress { Text(progress).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
            else if let date = monitor.report?.date { LastCheck(date: date, prefix: "Checked ").font(.caption).foregroundStyle(.secondary) }
            let counts = monitor.report.map { FindingCategory.counts(in: $0) } ?? [:]
            let shown = FindingCategory.allCases.filter { (counts[$0] ?? 0) > 0 }
            if !shown.isEmpty {
                VStack(spacing: 5) {
                    ForEach(shown) { category in
                        CategoryRow(category: category, count: counts[category] ?? 0) { monitor.section = "Security"; monitor.filter = category; open() }
                    }
                }
            }
            if !(monitor.report?.errors.isEmpty ?? true) {
                Button("Some checks need attention") { monitor.section = "Coverage"; open() }.buttonStyle(.link).foregroundStyle(.orange).font(.caption)
            }
            Divider()
            HStack(spacing: 8) {
                Button { open() } label: { Text("Open \(displayName)").frame(maxWidth: .infinity) }.buttonStyle(.borderedProminent)
                Button("Quit") { NSApp.terminate(nil) }
            }
            if !Monitor.scenarios.isEmpty {
                HStack { Text("Scenario").font(.caption).foregroundStyle(.secondary); ScenarioPicker(monitor: monitor, style: .menu) }
            }
            Text("Checks at launch, daily at 9 a.m. Pacific and when you click \(Image(systemName: "arrow.clockwise.circle"))").font(.caption2).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }.padding(18).frame(width: 310)
        .background(WindowReader { panel = $0 })
        .onReceive(NotificationCenter.default.publisher(for: .init("ShowDashboard"))) { _ in openWindow(id: "dashboard") }
    }
    // Opens the dashboard and dismisses this panel, which would otherwise stay open in front of it. The panel is
    // dismissed the way Escape does it: closing its window instead leaves the menu bar icon needing two clicks.
    func open() {
        if let panel, let escape = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: panel.windowNumber,
                                                    context: nil, characters: "\u{1b}", charactersIgnoringModifiers: "\u{1b}", isARepeat: false, keyCode: 53) {
            panel.sendEvent(escape)
        }
        openWindow(id: "dashboard"); NSApp.activate(ignoringOtherApps: true)
    }
}
// Reports the window a view is shown in, so the menu bar panel can close itself.
struct WindowReader: NSViewRepresentable {
    let found: (NSWindow?) -> Void
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { found(view.window) }
        return view
    }
    func updateNSView(_ view: NSView, context: Context) {}
}
// Picks the made-up scenario a preview shows, in the Scenarios menu (inline, with checkmarks) and the menu bar panel.
struct ScenarioPicker: View {
    enum Style { case inline, menu }
    @ObservedObject var monitor: Monitor
    let style: Style
    var body: some View {
        let picker = Picker("Scenario", selection: Binding(get: { monitor.scenario ?? "" }, set: { name in
            if let scenario = Monitor.scenarios.first(where: { $0.id == name }) { monitor.show(scenario) }
        })) {
            ForEach(Monitor.scenarios) { Text($0.title).tag($0.id) }
        }.labelsHidden()
        switch style {
        case .inline:
            picker.pickerStyle(.inline)
            Divider()
            Button("Reset Scenario") { if let current = Monitor.scenarios.first(where: { $0.id == monitor.scenario }) { monitor.show(current) } }
                .keyboardShortcut("r", modifiers: [.command, .shift]).disabled(monitor.scenario == nil)
        case .menu: picker.pickerStyle(.menu).fixedSize()
        }
    }
}
// One kind of finding in the menu bar panel. Clicking it opens the Security page listing them.
struct CategoryRow: View {
    let category: FindingCategory
    let count: Int
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: category.symbol).frame(width: 18)
                Text(category.title)
                Spacer()
                Text("\(count)").monospacedDigit().fontWeight(.semibold)
                Image(systemName: "chevron.right").font(.caption2.weight(.semibold)).opacity(0.6)
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .foregroundStyle(category.urgent ? Color.white : .primary)
            .background(category.urgent ? alarmRed : Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 7))
            .contentShape(RoundedRectangle(cornerRadius: 7))
        }.buttonStyle(.plain)
    }
}

struct Dashboard: View {
    @EnvironmentObject var monitor: Monitor
    @EnvironmentObject var updates: Updates
    @Environment(\.openWindow) private var openWindow
    @State private var query = ""
    @State private var domain = "all"
    let sections = [("Security", "exclamationmark.shield"), ("History", "clock.arrow.circlepath"), ("Inventory", "desktopcomputer"), ("Coverage", "checklist"), ("Settings", "gearshape")]
    let domains = [("all", "All"), ("projects", "Projects"), ("packages", "Packages"), ("mcp", "MCP"), ("tools", "Runtimes"), ("brew", "Homebrew"), ("apps", "Apps"), ("signatures", "Signatures")]
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 5) {
                Label(displayName, systemImage: "sailboat.fill").font(.title3.weight(.semibold)).padding(.bottom, 25).padding(.top, 14)
                ForEach(sections, id: \.0) { title, symbol in
                    Button { monitor.section = title; query = ""; if title == "Security" { monitor.filter = nil } } label: {
                        HStack { Image(systemName: symbol).frame(width: 20); Text(title); Spacer(); if title == "Security" && !monitor.attention.isEmpty { Text("\(monitor.attention.count)").font(.caption.weight(.semibold)) } }
                            .padding(.horizontal, 12).padding(.vertical, 10).contentShape(Rectangle())
                            .background(monitor.section == title ? Color.accentColor.opacity(0.13) : .clear, in: RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(.plain)
                }
                Spacer()
                Text("ON THIS MAC").font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                Text(Host.current().localizedName ?? "This Mac").font(.caption).lineLimit(2)
                Text("Version \(appVersion) · Preview").font(.caption2).foregroundStyle(.tertiary).padding(.top, 12)
                if let current = Monitor.scenarios.first(where: { $0.id == monitor.scenario }) {
                    Text("Scenario: \(current.title)").font(.caption2.weight(.semibold)).foregroundStyle(.orange).help(current.detail)
                }
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
        .sheet(isPresented: $monitor.feedbackOpen) { FeedbackSheet().environmentObject(monitor) }
        .onAppear { NSApp.setActivationPolicy(.regular) }
        .onReceive(NotificationCenter.default.publisher(for: .init("ShowDashboard"))) { _ in openWindow(id: "dashboard") }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in monitor.refreshSettings() }
    }
    var subtitle: String {
        switch monitor.section {
        case "Security": return "Published fixes, malicious-package reports and newer releases that match your developer tools and dependencies."
        case "Inventory": return "Developer software and packages found by the latest check."
        case "History": return "Every recommendation on this Mac: when it was found, and when and how it was resolved."
        case "Coverage": return "What was checked, what failed, and what needs manual review."
        default: return "Checks, alerts and project folders. Everything is stored on this Mac."
        }
    }
    var welcome: some View {
        VStack(alignment: .leading, spacing: 22) {
            Image(systemName: "sailboat.fill").font(.system(size: 48)).foregroundStyle(.blue)
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
        case "Security":
            let filter = monitor.filter
            let findings = filter.map { category in (monitor.report?.findings ?? []).filter { FindingCategory(of: $0) == category } } ?? monitor.attention
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 14) {
                        if let report = monitor.report { Overview(report: report) }
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text(filter?.title ?? "Needs attention").font(.title2.weight(.semibold))
                            Text("\(findings.count)").font(.title2).foregroundStyle(.secondary)
                            if filter != nil { Button("Show all that need attention") { monitor.filter = nil }.buttonStyle(.link) }
                            Spacer()
                            AllCommandsButton(findings: findings)
                        }.padding(.top, 14).id("findings")
                        if filter == .waiting {
                            Text("Nothing you can install fixes these yet: you have the newest release and no fixed one is out, or the app that bundles the affected code hasn't shipped a fix to you yet. These don't count as needing attention; \(appName) alerts you when a fix is out.").font(.callout).foregroundStyle(.secondary)
                        }
                        if findings.isEmpty {
                            Label(filter == nil ? "Nothing needs attention in covered checks." : "None found in covered checks.", systemImage: "tray").foregroundStyle(.secondary).padding(.vertical, 30)
                        }
                        let installed = findings.filter { $0.installation.domain != "projects" }, dependencies = findings.filter { $0.installation.domain == "projects" }
                        if !installed.isEmpty && !dependencies.isEmpty { Text("Installed on this Mac · \(installed.count)").font(.headline).padding(.top, 6) }
                        FindingList(findings: installed)
                        if !dependencies.isEmpty {
                            Text("Project dependencies · \(dependencies.count) in \(Set(dependencies.compactMap(\.installation.location)).count) folders").font(.headline).padding(.top, 10)
                            FindingList(findings: dependencies)
                        }
                    }.padding(.horizontal, 28).padding(.bottom, 24)
                }
                // Also when the page opens from the menu bar panel with a tile already chosen.
                .onReceive(monitor.$filter) { chosen in
                    if chosen != nil { DispatchQueue.main.async { withAnimation { proxy.scrollTo("findings", anchor: .top) } } }
                }
            }
        case "History": HistoryView()
        case "Inventory":
            let items = (monitor.report?.installations ?? []).filter { (domain == "all" || $0.domain == domain) && (query.isEmpty || ($0.name + $0.path + $0.note).localizedCaseInsensitiveContains(query)) }
            // An app that is ad-hoc signed, unsigned or without the Hardened Runtime says so beside its version.
            let notable = Dictionary((monitor.report?.signatures ?? []).filter(\.notable).map { ($0.path, $0) }, uniquingKeysWith: { first, _ in first })
            VStack(spacing: 10) {
                Picker("Show", selection: $domain) { ForEach(domains, id: \.0) { Text($0.1).tag($0.0) } }.pickerStyle(.segmented).labelsHidden().padding(.horizontal, 28)
                TextField(domain == "signatures" ? "Search apps, team IDs or paths" : "Search software, package, project or path", text: $query).textFieldStyle(.roundedBorder).padding(.horizontal, 28)
                if domain == "signatures" { SignatureList(signatures: monitor.report?.signatures, query: query) }
                else {
                    Text("\(items.count) items").font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 28)
                    List(items) { item in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(item.name).fontWeight(.medium)
                                Spacer()
                                if item.manager == "app", let signature = notable[item.path] { Text(signature.summary).font(.caption).foregroundStyle(.orange) }
                                Text(item.version).monospaced()
                            }
                            Text(item.note.isEmpty ? item.path : item.note).font(.caption).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(2)
                        }.padding(.vertical, 4)
                    }.listStyle(.inset)
                }
            }
        case "Coverage":
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach((monitor.report?.checks ?? []).filter { $0.status != "checked" || !$0.id.hasPrefix("nvd:") }) { check in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack { Text(check.name).fontWeight(.semibold); Spacer(); Text(check.status.uppercased()).font(.caption2.weight(.semibold)).foregroundStyle(check.status == "failed" || check.status == "partial" ? Color.orange : .secondary) }
                            Text(check.detail).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                            if let url = check.url, let link = URL(string: url) { Link("Open website", destination: link).font(.caption).linkCursor() }
                            if check.id == "app-signatures" { Button("Show every app's signature") { query = ""; domain = "signatures"; monitor.section = "Inventory" }.buttonStyle(.link).font(.caption) }
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
                    Text("Lockfiles up to five levels deep are checked: package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, uv.lock, poetry.lock, requirements.txt, Cargo.lock, Gemfile.lock, go.mod, Package.resolved, composer.lock, pubspec.lock, packages.lock.json, mix.lock and gradle.lockfile, plus GitHub Actions workflows and project .mcp.json files. node_modules, virtual environments, build folders, app bundles, Homebrew and system folders are skipped. Nothing in a project is run.").foregroundStyle(.secondary)
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
                    Text("Updates").font(.headline)
                    Text("\(appName) checks GitHub for a new version of itself once a day and shows it with its release notes. Install Update downloads it, checks that it's signed by \(appName)'s developer, then quits, replaces and reopens \(appName). Nothing is installed until you click.").foregroundStyle(.secondary)
                    Toggle("Check for updates automatically", isOn: $updates.automatic).disabled(!Updates.enabled)
                    Button("Check for Updates…") { updates.check() }.disabled(!updates.canCheck)
                    if !Updates.enabled { Text("This build doesn't check for updates.").font(.caption).foregroundStyle(.secondary) }
                }
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text("Local data & privacy").font(.headline)
                    Text("No account, cloud inventory, analytics or AI service. Package names and versions go to OSV, product versions to NVD, release lookups to Homebrew and vendors, and \(appName)'s own update check to GitHub. Private package names in your lockfiles are included in OSV queries. MCP settings are read for server commands only; environment variables and keys are ignored.").foregroundStyle(.secondary)
                    Text("Update commands are shown for you to copy and run; \(appName) never installs, removes or changes other software. The only thing it installs is its own update, when you click Install Update.").foregroundStyle(.secondary)
                    Text("History is kept on this Mac with the latest result, up to the newest \(History.limit.formatted()) entries.").foregroundStyle(.secondary)
                    HStack { Button("Open local data") { monitor.openData() }; Button("Export report…") { monitor.export() }.disabled(monitor.report == nil) }
                }
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text("Feedback").font(.headline)
                    Text("Ideas, problems and software \(appName) should check go to its GitHub repository as issues, which are public. You review each one on GitHub and submit it with your own account. For a finding that's wrong, use the bug button (Report a problem) on its card.").foregroundStyle(.secondary)
                    Button("Send feedback…") { monitor.feedbackOpen = true }
                }
            }.padding(.horizontal, 28).padding(.bottom, 24)
        }
    }
}
// Inventory's Signatures list: how each app in /Applications and your Applications folder is signed, with the apps worth
// a look first. It's informational; none of it counts as needing attention.
struct SignatureList: View {
    let signatures: [AppSignature]?
    let query: String
    @State private var filter = "all"
    func shown(_ all: [AppSignature]) -> [AppSignature] {
        let kept = all.filter { signature in
            let kind = filter == "all" || (filter == "ad-hoc" ? signature.kind == .adHoc || signature.kind == .unsigned : signature.lacksRuntime)
            return kind && (query.isEmpty || [signature.name, signature.path, signature.summary].joined(separator: " ").localizedCaseInsensitiveContains(query))
        }
        return kept.sorted { ($0.notable ? 0 : 1, $0.name.lowercased()) < ($1.notable ? 0 : 1, $1.name.lowercased()) }
    }
    var body: some View {
        let all = signatures ?? []
        let adHoc = all.filter { $0.kind == .adHoc || $0.kind == .unsigned }.count, noRuntime = all.filter(\.lacksRuntime).count
        let rows = shown(all)
        VStack(alignment: .leading, spacing: 10) {
            Picker("Show", selection: $filter) {
                Text("All apps · \(all.count)").tag("all")
                Text("Ad-hoc or unsigned · \(adHoc)").tag("ad-hoc")
                Text("No Hardened Runtime · \(noRuntime)").tag("runtime")
            }.pickerStyle(.segmented).labelsHidden().fixedSize()
            Text("For your information: an ad-hoc signature names no developer, and the Hardened Runtime protects an app from code injection. Apps built on this Mac and some Homebrew casks are ad-hoc signed by design, so nothing here counts as needing attention. App Store apps and Google Chrome are skipped.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }.padding(.horizontal, 28)
        if signatures == nil {
            Label("App signatures appear here after the next check.", systemImage: "tray").foregroundStyle(.secondary).padding(.vertical, 30).frame(maxHeight: .infinity, alignment: .top)
        } else {
            List(rows) { signature in
                VStack(alignment: .leading, spacing: 4) {
                    HStack { Text(signature.name).fontWeight(.medium); Spacer(); Text(signature.summary).font(.callout).foregroundStyle(signature.notable ? Color.orange : .secondary) }
                    Text(Inventory.display(signature.path)).font(.caption).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                }.padding(.vertical, 4)
            }.listStyle(.inset)
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
// The top of the Security page: how much of the inventory has no findings, then the findings sorted into the
// kinds of action they need. Clicking a tile lists its findings below; clicking it again lists everything.
struct Overview: View {
    @EnvironmentObject var monitor: Monitor
    let report: ScanReport
    var body: some View {
        let counts = FindingCategory.counts(in: report)
        VStack(alignment: .leading, spacing: 12) {
            StackSummary(report: report, counts: counts)
            Grid(horizontalSpacing: 12, verticalSpacing: 12) {
                GridRow { tiles(Array(FindingCategory.allCases.prefix(3)), counts: counts) }
                GridRow { tiles(Array(FindingCategory.allCases.suffix(3)), counts: counts) }
            }
            HStack(spacing: 4) {
                Text("Coverage is partial. No finding doesn't mean everything is safe.").foregroundStyle(.secondary)
                Button("See coverage") { monitor.section = "Coverage" }.buttonStyle(.link)
            }.font(.caption)
        }
    }
    func tiles(_ categories: [FindingCategory], counts: [FindingCategory: Int]) -> some View {
        ForEach(categories) { category in
            CategoryTile(category: category, count: counts[category] ?? 0, selected: monitor.filter == category) {
                monitor.filter = monitor.filter == category ? nil : category
            }
        }
    }
}
// What needs attention, and every inventory item colored by its most urgent finding.
struct StackSummary: View {
    @EnvironmentObject var monitor: Monitor
    let report: ScanReport
    let counts: [FindingCategory: Int]
    struct Share: Identifiable { let label: String; let count: Int; let color: Color; var id: String { label } }
    var body: some View {
        let items = FindingCategory.items(in: report)
        let total = report.installations.count
        let clear = max(0, total - items.values.reduce(0, +)), settled = FindingCategory.settled(in: report)
        let urgency = FindingCategory.Urgency(counts)
        // Items needing no action come first: green, then gray. Each segment has its tiles' color.
        let shares = [Share(label: "No findings", count: clear, color: .green),
                      Share(label: "Waiting for a fix", count: items[.waiting] ?? 0, color: FindingCategory.waiting.color),
                      Share(label: "Updates", count: items[.updates] ?? 0, color: FindingCategory.updates.color),
                      Share(label: "Fixes or end of support", count: (items[.security] ?? 0) + (items[.unsupported] ?? 0), color: FindingCategory.security.color),
                      Share(label: "Exploited or malicious", count: (items[.exploited] ?? 0) + (items[.malicious] ?? 0), color: FindingCategory.malicious.color)]
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 14) {
                VStack(alignment: .leading, spacing: 5) {
                    // The status, set by the most urgent kind of finding, however few: one malicious package among
                    // hundreds of clean items is still the most urgent thing Shipshape can find.
                    Text(urgency.label.uppercased()).font(.caption2.weight(.bold)).foregroundStyle(.white)
                        .padding(.horizontal, 9).padding(.vertical, 3).background(urgency.color, in: Capsule()).padding(.bottom, 3)
                        .accessibilityLabel("Status: \(urgency.label)")
                    Text(FindingCategory.attentionTitle(report.attention.count)).font(.title2.weight(.semibold))
                    if !urgent.isEmpty { Text(urgent).foregroundStyle(.secondary) }
                    if !report.errors.isEmpty {
                        Button("\(report.errors.count) check\(report.errors.count == 1 ? "" : "s") incomplete") { monitor.section = "Coverage" }.buttonStyle(.link).font(.callout)
                    }
                }
                Spacer()
                // How much of the inventory needs no action: no findings, or only findings waiting for a fixed release.
                // It rounds down, so 100% means there's nothing left to do.
                VStack(alignment: .trailing, spacing: 2) {
                    Text("\(total == 0 ? 100 : settled * 100 / total)% need no action").font(.caption.weight(.semibold))
                    Text("\(settled.formatted()) of \(total.formatted()) inventory items").font(.caption).foregroundStyle(.secondary)
                }
            }
            ShareBar(parts: shares.map { ($0.count, $0.color) })
            HStack(spacing: 14) {
                ForEach(shares.filter { $0.count > 0 }) { share in
                    HStack(spacing: 5) {
                        RoundedRectangle(cornerRadius: 2).fill(share.color).frame(width: 8, height: 8)
                        Text(share.label)
                        Text(share.count.formatted()).foregroundStyle(.primary).monospacedDigit()
                    }
                }
            }.font(.caption).foregroundStyle(.secondary)
        }.modifier(CardStyle())
    }
    var urgent: String {
        let malicious = counts[.malicious] ?? 0, exploited = counts[.exploited] ?? 0
        return [malicious > 0 ? "\(malicious) malicious package\(malicious == 1 ? "" : "s")" : nil,
                exploited > 0 ? "\(exploited) actively exploited" : nil].compactMap { $0 }.joined(separator: " · ")
    }
}
// One bar split in proportion to the counts. A nonzero share is never thinner than a few points, so a single
// malicious package still shows beside a thousand clean items.
struct ShareBar: View {
    let parts: [(Int, Color)]
    var body: some View {
        GeometryReader { geometry in
            let shown = parts.filter { $0.0 > 0 }
            let widths = ShareBar.widths(shown.map { $0.0 }, in: geometry.size.width - CGFloat(max(0, shown.count - 1)) * 2)
            HStack(spacing: 2) { ForEach(shown.indices, id: \.self) { Rectangle().fill(shown[$0].1).frame(width: widths[$0]) } }
        }.frame(height: 10).clipShape(Capsule())
    }
    static func widths(_ counts: [Int], in width: CGFloat, minimum: CGFloat = 7) -> [CGFloat] {
        let total = CGFloat(max(1, counts.reduce(0, +)))
        var widths = counts.map { max(minimum, width * CGFloat($0) / total) }
        if let widest = widths.indices.max(by: { widths[$0] < widths[$1] }) { widths[widest] -= widths.reduce(0, +) - width }
        return widths
    }
}
// One kind of finding: how many, what it means and a button that lists them. A tile with findings has its bar color
// as a stripe and on its count; malware and known exploitation are filled red instead, so they stand out. Empty
// tiles are dimmed.
struct CategoryTile: View {
    let category: FindingCategory
    let count: Int
    let selected: Bool
    let action: () -> Void
    var body: some View {
        let hot = category.urgent && count > 0
        let ink: Color = hot ? .white : count == 0 ? .secondary : .primary
        Button { if count > 0 { action() } } label: {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("\(count)").font(.system(size: 30, weight: .semibold, design: .rounded)).foregroundStyle(count > 0 && !hot ? category.color : ink)
                    Text(category.title).font(.headline)
                    Text(category.detail).font(.callout).foregroundStyle(hot ? Color.white.opacity(0.9) : .secondary).fixedSize(horizontal: false, vertical: true)
                }
                .padding(16).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .overlay(alignment: .topTrailing) {
                    Image(systemName: category.symbol).font(.system(size: 30)).foregroundStyle(hot ? Color.white.opacity(0.35) : Color.secondary.opacity(0.3)).padding(14)
                }
                Rectangle().fill(hot ? Color.white.opacity(0.25) : Color.primary.opacity(0.08)).frame(height: 1)
                HStack {
                    Text(count == 0 ? "None found" : selected ? "Showing below" : "Show items")
                    Spacer()
                    Image(systemName: count == 0 ? "checkmark" : selected ? "arrow.down" : "arrow.right")
                }
                .font(.callout).foregroundStyle(hot ? Color.white : count == 0 ? Color.secondary : Color.accentColor)
                .padding(.horizontal, 16).padding(.vertical, 10)
            }
            .foregroundStyle(ink)
            .background(hot ? alarmRed : Color(nsColor: .controlBackgroundColor))
            .overlay(alignment: .leading) { if count > 0 && !hot { Rectangle().fill(category.color).frame(width: 4) } }
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(selected ? Color.accentColor : Color.primary.opacity(0.07), lineWidth: selected ? 2.5 : 1))
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }.buttonStyle(.plain).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
// A brick red, darker than system red, so white text on it stays readable.
let alarmRed = Color(red: 0.74, green: 0.22, blue: 0.13)
extension FindingCategory {
    // Each kind of finding's color, on its tile and its segment of the summary bar, so the bar works as the tiles' key.
    var color: Color {
        switch self {
        case .malicious, .exploited: return alarmRed
        case .security, .unsupported: return .orange
        case .waiting: return .gray
        case .updates: return .blue
        }
    }
}
extension FindingCategory.Urgency {
    // Dark enough for the status badge's white text in light and dark mode.
    var color: Color {
        switch self {
        case .actNow: return alarmRed
        case .fixSoon: return Color(red: 0.80, green: 0.40, blue: 0.02)
        case .nothingUrgent, .clear: return Color(red: 0.16, green: 0.55, blue: 0.27)
        }
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
    @EnvironmentObject var monitor: Monitor
    let finding: Finding
    @State private var reporting = false
    @State private var copied = false
    @State private var hovering = false
    // The lockfile or MCP settings file for project and MCP findings; the install path otherwise.
    var location: String { Inventory.display(finding.installation.sourceFile) }
    // Each advisory ID is its own link, so the cursor shows which one a click opens; Copy is on its menu. Hovering one
    // shows when it was published, which would make the line too long to show for every ID.
    var advisories: some View {
        WrappingStack {
            Text("Advisories:").foregroundStyle(.secondary)
            ForEach(Array(finding.advisories.enumerated()), id: \.offset) { index, id in
                HStack(spacing: 0) {
                    if let url = finding.page(id) { Link(id, destination: url).linkCursor().help(finding.publishedNote(for: id) ?? "").contextMenu { Button("Copy \(id)") { monitor.copy(id) } } }
                    else { Text(id).foregroundStyle(.secondary).textSelection(.enabled).help(finding.publishedNote(for: id) ?? "") }
                    if index < finding.advisories.count - 1 { Text(",").foregroundStyle(.secondary) }
                }
            }
        }.font(.caption)
    }
    // The location as a path to copy: the full path when it is one, since "~" means nothing outside a shell.
    var locationPath: String { finding.installation.sourceFile.hasPrefix("/") ? finding.installation.sourceFile : location }
    // The location on disk, for Show in Finder, when it is a path that still exists.
    var locationURL: URL? {
        let path = finding.installation.sourceFile
        return path.hasPrefix("/") && FileManager.default.fileExists(atPath: path) ? URL(fileURLWithPath: path) : nil
    }
    var body: some View {
        HStack(alignment: .bottom) {
            VStack(alignment: .leading, spacing: 4) {
                // Copy and Show in Finder appear while the pointer is over the location. They keep their place when hidden,
                // so nothing shifts.
                HStack(spacing: 6) {
                    Text("Location: " + location).foregroundStyle(.secondary).textSelection(.enabled)
                    HStack(spacing: 6) {
                        Button { monitor.copy(locationPath); flash() } label: { Image(systemName: copied ? "checkmark" : "doc.on.doc") }
                            .help(copied ? "Copied" : "Copy \(locationPath)").accessibilityLabel("Copy location")
                        if let url = locationURL {
                            Button { showInFinder(url) } label: { Image(systemName: "folder") }.help("Show in Finder").accessibilityLabel("Show in Finder")
                        }
                    }.opacity(hovering || copied ? 1 : 0).allowsHitTesting(hovering || copied)
                }.font(.caption).buttonStyle(.borderless).contentShape(Rectangle()).onHover { hovering = $0 }
                if !finding.advisories.isEmpty { advisories }
            }
            Spacer()
            Button { reporting = true } label: { Image(systemName: "ladybug") }.buttonStyle(.borderless).font(.callout).foregroundStyle(Color.accentColor)
                .help("Report a problem: opens a GitHub issue about this finding, filled in for you to check and submit.").accessibilityLabel("Report a problem")
        }.sheet(isPresented: $reporting) { ReportSheet(finding: finding).environmentObject(monitor) }
    }
    func flash() { copied = true; DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false } }
}
// Shows a location in a Finder window. A folder opens in its own window; a file, or a bundle such as an app, is
// selected in a window of its folder, so nothing is opened or launched. Finder won't open a window at a folder
// inside an app (Folx.app/Contents/Frameworks/Sparkle.framework), so such a folder is selected in its parent.
func showInFinder(_ url: URL) {
    let path = url.path, parent = url.deletingLastPathComponent().path
    var folder: ObjCBool = false
    if FileManager.default.fileExists(atPath: path, isDirectory: &folder), folder.boolValue, !NSWorkspace.shared.isFilePackage(atPath: path),
       NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: path) { return }
    NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: parent)
}
// Report a problem with one finding: the issue's text, editable, before it opens on GitHub.
struct ReportSheet: View {
    let finding: Finding
    @State private var problem = Feedback.Problem.fixFailed
    @State private var title = ""
    @State private var details = ""
    @State private var summary = ""
    var body: some View {
        // The suggested title follows the choice of problem until it's edited.
        let choice = Binding(get: { problem }, set: { new in
            if title == Feedback.title(for: finding, problem: problem) { title = Feedback.title(for: finding, problem: new) }
            problem = new
        })
        VStack(alignment: .leading, spacing: 12) {
            Text("Report a problem with \(finding.installation.name)").font(.title3.weight(.semibold))
            Text("This opens a new issue on GitHub with the text below filled in, for you to check and submit with your GitHub account. Issues are public, so remove anything private, such as project names. Your home folder is shown as ~.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Picker("What's wrong", selection: choice) { ForEach(Feedback.Problem.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
            FeedbackField(label: "Title", text: $title)
            FeedbackEditor(label: "What happened", prompt: "Paste the Terminal output, or describe what you saw.", text: $details, height: 110)
            FeedbackEditor(label: "The finding", prompt: "", text: $summary, height: 130)
            Text(Feedback.system).font(.caption).foregroundStyle(.secondary)
            FeedbackButtons { Feedback.report(finding, problem: problem, title: title, details: details, summary: summary) }
        }.padding(20).frame(width: 640)
        .onAppear { if title.isEmpty { title = Feedback.title(for: finding, problem: problem); summary = Feedback.summary(of: finding) } }
    }
}
// Send feedback: an idea, a question or a problem, or software Shipshape should check.
struct FeedbackSheet: View {
    @State private var kind = Feedback.Kind.feedback
    @State private var title = ""
    @State private var text = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Send feedback").font(.title3.weight(.semibold))
            Text("This opens a new issue on GitHub with your text filled in, for you to check and submit with your GitHub account. Issues are public. For a finding that's wrong, use the bug button (Report a problem) on its card instead.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Picker("About", selection: $kind) { ForEach(Feedback.Kind.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
            FeedbackField(label: "Title", text: $title)
            FeedbackEditor(label: kind == .feedback ? "Your feedback" : "What should be covered",
                           prompt: kind == .feedback ? "What would make \(appName) better, or what went wrong?" : "The software, lockfile or install location, how people install it, and where its advisories are published.",
                           text: $text, height: 160)
            Text(Feedback.system).font(.caption).foregroundStyle(.secondary)
            FeedbackButtons { Feedback.feedback(kind, title: title, text: text) }
        }.padding(20).frame(width: 560)
    }
}
struct FeedbackField: View {
    let label: String
    @Binding var text: String
    var body: some View {
        VStack(alignment: .leading, spacing: 4) { Text(label).font(.callout.weight(.semibold)); TextField(label, text: $text, prompt: Text("")).labelsHidden() }
    }
}
// A labeled text box for several lines, with a prompt while it's empty.
struct FeedbackEditor: View {
    let label: String
    let prompt: String
    @Binding var text: String
    let height: CGFloat
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.callout.weight(.semibold))
            TextEditor(text: $text).font(.system(.callout, design: .monospaced)).frame(height: height)
                .overlay(alignment: .topLeading) {
                    if text.isEmpty { Text(prompt).font(.callout).foregroundStyle(.tertiary).padding(.leading, 5).allowsHitTesting(false) }
                }
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.primary.opacity(0.15)))
        }
    }
}
// Opens the filled-in issue on GitHub. When it had to be shortened to fit the link, the full text is copied first.
struct FeedbackButtons: View {
    @EnvironmentObject var monitor: Monitor
    @Environment(\.dismiss) private var dismiss
    let issue: () -> Feedback.Issue?
    @State private var tooLong = false
    var body: some View {
        HStack {
            Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
            if tooLong { Text("The title is too long for a GitHub link.").font(.caption).foregroundStyle(.orange) }
            Spacer()
            Button("Open in GitHub") {
                guard let issue = issue() else { tooLong = true; return }
                if issue.shortened { monitor.copy(issue.text) }
                NSWorkspace.shared.open(issue.url)
                dismiss()
            }.buttonStyle(.borderedProminent).linkCursor()
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
            Text(finding.reasonWithDates()).font(.callout).foregroundStyle(.secondary)
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
    static let labels = ["brew": "Homebrew formulae", "brew-python": "Homebrew formulae", "brew-old": "Older Homebrew copies", "uv-python-old": "Older uv Pythons", "cask": "Homebrew apps",
                         "npm-global": "Global npm packages", "bun-global": "Global Bun packages", "pnpm-global": "Global pnpm packages",
                         "pip": "Python packages", "pip-brew": "Python packages", "pip-uv": "Python packages", "npx-cache": "npx cache", "mise": "mise runtimes"]
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
                    Text(finding.reasonWithDates()).font(.callout).foregroundStyle(.secondary)
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
                styled(Button { monitor.perform(option) } label: { Label(option.text, systemImage: symbol) }, prominent: primary).linkCursor(option.kind == "link")
            }
            if !option.note.isEmpty { Text(option.note).font(.caption).foregroundStyle(.secondary) }
        }
    }
    func flash() { copied = true; DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false } }
}
func openTrusted(_ address: String) { if let url = URL(string: address) { NSWorkspace.shared.open(url) } }
// The pointing-hand cursor over controls that open a web page, as in a browser. macOS 15 has it built in;
// earlier versions push the cursor on hover and pop it on leaving, or when the control goes away.
struct LinkCursor: ViewModifier {
    @State private var pushed = false
    @ViewBuilder func body(content: Content) -> some View {
        if #available(macOS 15, *) { content.pointerStyle(.link) } else {
            content.onHover { inside in
                guard inside != pushed else { return }
                pushed = inside
                if inside { NSCursor.pointingHand.push() } else { NSCursor.pop() }
            }.onDisappear { if pushed { NSCursor.pop(); pushed = false } }
        }
    }
}
extension View {
    @ViewBuilder func linkCursor(_ enabled: Bool = true) -> some View { if enabled { modifier(LinkCursor()) } else { self } }
}
// Views in rows that wrap when one is full, like words in a paragraph.
struct WrappingStack: Layout {
    var spacing: CGFloat = 4, lineSpacing: CGFloat = 2
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(proposal.width ?? .infinity, subviews).size
    }
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        for (view, origin) in zip(subviews, arrange(bounds.width, subviews).origins) {
            view.place(at: CGPoint(x: bounds.minX + origin.x, y: bounds.minY + origin.y), proposal: .unspecified)
        }
    }
    private func arrange(_ width: CGFloat, _ subviews: Subviews) -> (origins: [CGPoint], size: CGSize) {
        var origins: [CGPoint] = [], x: CGFloat = 0, y: CGFloat = 0, row: CGFloat = 0, widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > width { x = 0; y += row + lineSpacing; row = 0 }
            origins.append(CGPoint(x: x, y: y))
            x += size.width + spacing
            row = max(row, size.height); widest = max(widest, x - spacing)
        }
        return (origins, CGSize(width: widest, height: y + row))
    }
}
