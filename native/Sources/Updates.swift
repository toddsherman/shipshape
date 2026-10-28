import SwiftUI
import Combine
import Sparkle

// Shipshape's own updates, through Sparkle. Once a day Sparkle reads the appcast attached to Shipshape's latest
// GitHub release (SUFeedURL). A newer version appears in Sparkle's window with its release notes; Install Update
// downloads it, checks its EdDSA signature against SUPublicEDKey and its Developer ID signature against this
// copy's, then quits, replaces and relaunches Shipshape. Nothing is installed without that one click.
// Development builds, which run with SHIPSHAPE_STATE_DIR, don't check unless SHIPSHAPE_CHECK_UPDATES=1, which
// exists to test an update end to end.
@MainActor
final class Updates: ObservableObject {
    static var enabled: Bool {
        let env = ProcessInfo.processInfo.environment, info = Bundle.main.infoDictionary ?? [:]
        guard info["SUFeedURL"] != nil, info["SUPublicEDKey"] != nil else { return false }
        return env["SHIPSHAPE_STATE_DIR"] == nil || env["SHIPSHAPE_CHECK_UPDATES"] == "1"
    }
    private let driver: OneClickUserDriver
    private let updater: SPUUpdater
    @Published private(set) var canCheck = false
    @Published var automatic: Bool { didSet { updater.automaticallyChecksForUpdates = automatic } }
    init() {
        driver = OneClickUserDriver(hostBundle: .main, delegate: nil)
        updater = SPUUpdater(hostBundle: .main, applicationBundle: .main, userDriver: driver, delegate: nil)
        automatic = updater.automaticallyChecksForUpdates
        updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheck)
        if Updates.enabled {
            do { try updater.start() } catch { NSLog("Shipshape's updater didn't start: %@", error.localizedDescription) }
        }
    }
    func check() { updater.checkForUpdates() }
}
// Sparkle's standard windows, with one change: Install Update also means install now. Sparkle otherwise stops at
// "Ready to Install" after downloading and waits for a second click on Install and Relaunch, unless the app has
// already quit. Sparkle has verified the download by the time it asks.
final class OneClickUserDriver: SPUStandardUserDriver {
    override func showReady(toInstallAndRelaunch reply: @escaping (SPUUserUpdateChoice) -> Void) { reply(.install) }
}
// The Check for Updates… command in the app menu. Its own view, so the menu item follows canCheck.
struct CheckForUpdatesButton: View {
    @ObservedObject var updates: Updates
    var body: some View {
        Button("Check for Updates…") { updates.check() }.disabled(!updates.canCheck)
    }
}
