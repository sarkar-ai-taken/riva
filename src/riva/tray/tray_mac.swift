import AppKit
import Foundation

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

func argValue(_ flag: String) -> String? {
    let args = CommandLine.arguments
    guard let idx = args.firstIndex(of: flag), idx + 1 < args.count else { return nil }
    return args[idx + 1]
}

let appVersion  = argValue("--version") ?? "?"
let webHost     = argValue("--web-host") ?? "127.0.0.1"
let webPort     = argValue("--web-port") ?? "8585"
let parentPid: pid_t = {
    if let s = argValue("--pid"), let p = Int32(s) { return p }
    return getppid()
}()

// ---------------------------------------------------------------------------
// Helper — emit action to stdout (Python reads this)
// ---------------------------------------------------------------------------

func emit(_ action: String) {
    print(action)
    fflush(stdout)
}

// ---------------------------------------------------------------------------
// Parent-process watchdog — exit if parent dies (prevents orphaned tray)
// ---------------------------------------------------------------------------

func startParentWatchdog() {
    let source = DispatchSource.makeProcessSource(
        identifier: parentPid,
        eventMask: .exit,
        queue: .main
    )
    source.setEventHandler {
        exit(0)
    }
    source.resume()
}

// ---------------------------------------------------------------------------
// Web server status polling
// ---------------------------------------------------------------------------

var webRunning = false

func checkWebStatus() {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    task.arguments = ["bash", "-c", "lsof -ti tcp:\(webPort) >/dev/null 2>&1"]
    task.standardOutput = FileHandle.nullDevice
    task.standardError  = FileHandle.nullDevice
    try? task.run()
    task.waitUntilExit()
    webRunning = (task.terminationStatus == 0)
}

// ---------------------------------------------------------------------------
// App delegate
// ---------------------------------------------------------------------------

class TrayDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var webStatusItem: NSMenuItem!
    var startWebItem: NSMenuItem!
    var stopWebItem: NSMenuItem!
    var statusTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "RI"

        let menu = NSMenu()

        // Header
        let versionItem = NSMenuItem(title: "Riva v\(appVersion)", action: nil, keyEquivalent: "")
        versionItem.isEnabled = false
        menu.addItem(versionItem)

        webStatusItem = NSMenuItem(title: "\u{25CF} Web: checking…", action: nil, keyEquivalent: "")
        webStatusItem.isEnabled = false
        menu.addItem(webStatusItem)

        menu.addItem(NSMenuItem.separator())

        // Dashboards
        let tuiItem = NSMenuItem(title: "Open TUI Dashboard", action: #selector(openTUI), keyEquivalent: "t")
        tuiItem.target = self
        menu.addItem(tuiItem)

        let webItem = NSMenuItem(title: "Open Web Dashboard", action: #selector(openWeb), keyEquivalent: "w")
        webItem.target = self
        menu.addItem(webItem)

        menu.addItem(NSMenuItem.separator())

        // Web server controls
        startWebItem = NSMenuItem(title: "Start Web Server", action: #selector(startWeb), keyEquivalent: "")
        startWebItem.target = self
        menu.addItem(startWebItem)

        stopWebItem = NSMenuItem(title: "Stop Web Server", action: #selector(stopWeb), keyEquivalent: "")
        stopWebItem.target = self
        menu.addItem(stopWebItem)

        menu.addItem(NSMenuItem.separator())

        // Quick actions
        let scanItem = NSMenuItem(title: "Quick Scan", action: #selector(quickScan), keyEquivalent: "s")
        scanItem.target = self
        menu.addItem(scanItem)

        let auditItem = NSMenuItem(title: "Security Audit", action: #selector(securityAudit), keyEquivalent: "a")
        auditItem.target = self
        menu.addItem(auditItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = menu

        // Kick off first status check and start periodic polling
        refreshWebStatus()
        statusTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.refreshWebStatus()
        }
    }

    func refreshWebStatus() {
        DispatchQueue.global(qos: .utility).async {
            checkWebStatus()
            DispatchQueue.main.async { [self] in
                if webRunning {
                    webStatusItem.title = "\u{25CF} Web: running on :\(webPort)"
                    startWebItem.isHidden = true
                    stopWebItem.isHidden = false
                } else {
                    webStatusItem.title = "\u{25CB} Web: stopped"
                    startWebItem.isHidden = false
                    stopWebItem.isHidden = true
                }
            }
        }
    }

    // --- Actions ----------------------------------------------------------

    @objc func openTUI() {
        emit("open_tui")
    }

    @objc func openWeb() {
        emit("open_web")
    }

    @objc func startWeb() {
        emit("start_web")
        // Refresh after a brief delay to let the server come up
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            self?.refreshWebStatus()
        }
    }

    @objc func stopWeb() {
        emit("stop_web")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
            self?.refreshWebStatus()
        }
    }

    @objc func quickScan() {
        emit("scan")
    }

    @objc func securityAudit() {
        emit("audit")
    }

    @objc func quit() {
        emit("quit")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            NSApp.terminate(nil)
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

startParentWatchdog()

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

let delegate = TrayDelegate()
app.delegate = delegate
app.run()
