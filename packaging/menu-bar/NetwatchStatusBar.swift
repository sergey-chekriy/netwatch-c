import AppKit
import Darwin
import Foundation

private struct LastUnknown: Decodable {
  let pid: Int?
  let processName: String?
  let remoteEndpoint: String?
  let reason: String?
}

private struct Snapshot: Decodable {
  let status: String
  let daemonRunning: Bool
  let configValid: Bool
  let dryRun: Bool
  let lastScanAt: Int64
  let lastScanResult: String
  let unknownCount: Int
  let wouldDisableWifi: Bool
  let wifiDisabled: Bool
  let activeConfigPath: String
  let pollIntervalSeconds: Int
  let lastUnknownProcessSummary: LastUnknown?
}

private struct StatusBarError: LocalizedError {
  let message: String
  var errorDescription: String? { message }
}

private final class StatusBarController: NSObject, NSApplicationDelegate {
  private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
  private let statusURL: URL
  private var timer: Timer?
  private var lastSnapshot: Snapshot?
  private var lastError: String?
  private var lastActionMessage: String?

  init(statusPath: String?) {
    if let statusPath, !statusPath.isEmpty {
      statusURL = URL(fileURLWithPath: NSString(string: statusPath).expandingTildeInPath)
    } else {
      statusURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".watch/netwatch.status.json")
    }
    super.init()
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.accessory)
    item.button?.imagePosition = .imageOnly
    update()
    timer = Timer.scheduledTimer(timeInterval: 5, target: self, selector: #selector(update), userInfo: nil, repeats: true)
    RunLoop.main.add(timer!, forMode: .common)
  }

  @objc private func update() {
    do {
      let data = try Data(contentsOf: statusURL)
      lastSnapshot = try JSONDecoder().decode(Snapshot.self, from: data)
      lastError = nil
    } catch {
      lastSnapshot = nil
      lastError = error.localizedDescription
    }
    render()
  }

  private func render() {
    let status = displayStatus()
    item.button?.image = circleImage(color: color(for: lastSnapshot))
    item.button?.toolTip = tooltip(status: status)
    item.button?.setAccessibilityLabel(accessibilityLabel(status: status))
    item.menu = menu(status: status)
  }

  private func color(for snapshot: Snapshot?) -> NSColor {
    guard let snapshot else { return .systemGray }
    if !scanIsOk(snapshot) || !scanIsFresh(snapshot) { return .systemRed }
    if snapshot.dryRun { return .systemOrange }
    return .systemGreen
  }

  private func displayStatus() -> String {
    guard let snapshot = lastSnapshot else { return "unavailable" }
    if !scanIsOk(snapshot) || !scanIsFresh(snapshot) { return "problem" }
    if snapshot.dryRun { return "dry run" }
    return "ok"
  }

  private func scanIsOk(_ snapshot: Snapshot) -> Bool {
    snapshot.configValid && snapshot.lastScanResult == "ok" && snapshot.unknownCount == 0
      && !snapshot.wouldDisableWifi && !snapshot.wifiDisabled
  }

  private func scanIsFresh(_ snapshot: Snapshot) -> Bool {
    if snapshot.lastScanAt <= 0 || snapshot.pollIntervalSeconds <= 0 { return false }
    return Int64(Date().timeIntervalSince1970) - snapshot.lastScanAt <= Int64(snapshot.pollIntervalSeconds)
  }

  private func freshnessText(_ snapshot: Snapshot) -> String {
    if snapshot.lastScanAt <= 0 { return "no" }
    let age = max(0, Int64(Date().timeIntervalSince1970) - snapshot.lastScanAt)
    return scanIsFresh(snapshot) ? "yes (\(age)s old)" : "no (\(age)s old)"
  }

  private func colorName(_ snapshot: Snapshot?) -> String {
    guard let snapshot else { return "gray" }
    if !scanIsOk(snapshot) || !scanIsFresh(snapshot) { return "red" }
    if snapshot.dryRun { return "orange" }
    return "green"
  }

  private func staleReason(_ snapshot: Snapshot) -> String? {
    if scanIsFresh(snapshot) { return nil }
    if snapshot.lastScanAt <= 0 { return "last scan missing" }
    return "last scan is older than \(snapshot.pollIntervalSeconds)s"
  }

  private func problemReason(_ snapshot: Snapshot) -> String? {
    if !snapshot.configValid { return "config invalid" }
    if snapshot.lastScanResult != "ok" { return "result \(snapshot.lastScanResult)" }
    if snapshot.unknownCount > 0 { return "\(snapshot.unknownCount) unknown process(es)" }
    if snapshot.wouldDisableWifi { return "would disable Wi-Fi" }
    if snapshot.wifiDisabled { return "Wi-Fi disabled" }
    return staleReason(snapshot)
  }

  private func circleImage(color: NSColor) -> NSImage {
    let size = NSSize(width: 18, height: 18)
    let image = NSImage(size: size)
    image.lockFocus()
    NSColor.clear.setFill()
    NSRect(origin: .zero, size: size).fill()
    color.setFill()
    NSBezierPath(ovalIn: NSRect(x: 4, y: 4, width: 10, height: 10)).fill()
    image.unlockFocus()
    image.isTemplate = false
    return image
  }

  private func tooltip(status: String) -> String {
    guard let snapshot = lastSnapshot else { return "Netwatch unavailable: \(lastError ?? "no status snapshot")" }
    if let reason = problemReason(snapshot) {
      return "Netwatch \(colorName(snapshot)): \(reason), last scan \(formatTime(snapshot.lastScanAt))"
    }
    return "Netwatch \(colorName(snapshot)): \(status), last scan \(formatTime(snapshot.lastScanAt))"
  }

  private func accessibilityLabel(status: String) -> String {
    guard let snapshot = lastSnapshot else { return "Netwatch gray: status unavailable" }
    if let reason = problemReason(snapshot) { return "Netwatch \(colorName(snapshot)): \(reason)" }
    return "Netwatch \(colorName(snapshot)): \(status)"
  }

  private func menu(status: String) -> NSMenu {
    let menu = NSMenu()
    addDisabled(menu, "Netwatch: \(status)")
    if let snapshot = lastSnapshot {
      addDisabled(menu, "Indicator: \(colorName(snapshot))")
      if let reason = problemReason(snapshot) { addDisabled(menu, "Reason: \(reason)") }
      if let message = lastActionMessage { addDisabled(menu, "Action: \(message)") }
      addDisabled(menu, "Daemon: \(snapshot.daemonRunning ? "running" : "stopped")")
      addDryRunToggle(menu, snapshot)
      addDisabled(menu, "Last scan: \(formatTime(snapshot.lastScanAt))")
      addDisabled(menu, "Fresh: \(freshnessText(snapshot))")
      addDisabled(menu, "Result: \(snapshot.lastScanResult)")
      addDisabled(menu, "Unknown: \(snapshot.unknownCount)")
      if let unknown = snapshot.lastUnknownProcessSummary {
        menu.addItem(.separator())
        addDisabled(menu, "Last unknown: \(unknown.processName ?? "unknown")")
        if let remote = unknown.remoteEndpoint { addDisabled(menu, "Remote: \(remote)") }
        if let reason = unknown.reason { addDisabled(menu, "Reason: \(reason)") }
      }
      addDisabled(menu, "Interval: \(snapshot.pollIntervalSeconds)s")
    } else {
      addDisabled(menu, lastError ?? "status snapshot unavailable")
      addDisabled(menu, statusURL.path)
    }
    menu.addItem(.separator())
    let refresh = NSMenuItem(title: "Refresh", action: #selector(update), keyEquivalent: "r")
    refresh.target = self
    menu.addItem(refresh)
    let quit = NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q")
    quit.target = self
    menu.addItem(quit)
    return menu
  }

  private func addDryRunToggle(_ menu: NSMenu, _ snapshot: Snapshot) {
    let item = NSMenuItem(title: "Dry run: \(snapshot.dryRun ? "on" : "off")",
                          action: #selector(toggleDryRun), keyEquivalent: "")
    item.target = self
    item.state = snapshot.dryRun ? .on : .off
    item.isEnabled = snapshot.configValid && !snapshot.activeConfigPath.isEmpty
    menu.addItem(item)
  }

  private func addDisabled(_ menu: NSMenu, _ title: String) {
    let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
    item.isEnabled = false
    menu.addItem(item)
  }

  private func formatTime(_ seconds: Int64) -> String {
    if seconds <= 0 { return "never" }
    let formatter = DateFormatter()
    formatter.dateStyle = .none
    formatter.timeStyle = .medium
    return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
  }

  @objc private func toggleDryRun() {
    guard let snapshot = lastSnapshot else { lastActionMessage = "status unavailable"; render(); return }
    do {
      try setDryRun(!snapshot.dryRun, configPath: snapshot.activeConfigPath)
      try requestDaemonReload()
      lastActionMessage = "dryRun saved: \(!snapshot.dryRun ? "on" : "off"), reload requested"
      update()
    } catch {
      lastActionMessage = error.localizedDescription
      render()
    }
  }

  private func setDryRun(_ value: Bool, configPath: String) throws {
    if configPath.isEmpty { throw StatusBarError(message: "active config path missing") }
    let url = URL(fileURLWithPath: NSString(string: configPath).expandingTildeInPath)
    let data = try Data(contentsOf: url)
    guard var root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw StatusBarError(message: "config root is not an object")
    }
    root["dryRun"] = value
    var out = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
    out.append(0x0a)
    _ = try JSONSerialization.jsonObject(with: out)
    try writeAtomically(out, to: url)
  }

  private func writeAtomically(_ data: Data, to url: URL) throws {
    let manager = FileManager.default
    let directory = url.deletingLastPathComponent()
    let mode = (try? manager.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.uint16Value ?? 0o600
    let tmpURL = directory.appendingPathComponent(".\(url.lastPathComponent).tmp.\(getpid())")
    let fd = open(tmpURL.path, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, mode_t(mode))
    if fd < 0 { throw posixError("open", tmpURL.path) }
    var shouldClose = true
    var renamed = false
    defer {
      if shouldClose { close(fd) }
      if !renamed { unlink(tmpURL.path) }
    }

    try data.withUnsafeBytes { raw in
      guard let base = raw.baseAddress else { return }
      var offset = 0
      while offset < data.count {
        let n = Darwin.write(fd, base.advanced(by: offset), data.count - offset)
        if n < 0 {
          if errno == EINTR { continue }
          throw posixError("write", tmpURL.path)
        }
        if n == 0 { throw StatusBarError(message: "short write to \(tmpURL.path)") }
        offset += n
      }
    }

    if fsync(fd) < 0 { throw posixError("fsync", tmpURL.path) }
    if close(fd) < 0 { shouldClose = false; throw posixError("close", tmpURL.path) }
    shouldClose = false
    if rename(tmpURL.path, url.path) < 0 { throw posixError("rename", url.path) }
    renamed = true
    fsyncDirectory(directory)
  }

  private func requestDaemonReload() throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    process.arguments = ["kill", "SIGHUP", "gui/\(getuid())/com.serg.netwatch"]
    let errorPipe = Pipe()
    process.standardError = errorPipe
    try process.run()
    process.waitUntilExit()
    if process.terminationStatus != 0 {
      let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
      let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
      throw StatusBarError(message: text?.isEmpty == false ? text! : "daemon reload request failed")
    }
  }

  private func fsyncDirectory(_ url: URL) {
    let fd = open(url.path, O_RDONLY)
    if fd >= 0 {
      _ = fsync(fd)
      close(fd)
    }
  }

  private func posixError(_ operation: String, _ path: String) -> Error {
    StatusBarError(message: "\(operation) failed for \(path): \(String(cString: strerror(errno)))")
  }

  @objc private func quit() { NSApp.terminate(nil) }
}

private let controller = StatusBarController(statusPath: CommandLine.arguments.dropFirst().first)
private let app = NSApplication.shared
app.delegate = controller
app.run()
