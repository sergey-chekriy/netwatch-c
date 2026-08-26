import AppKit
import Darwin
import Foundation

fileprivate struct LastUnknown: Decodable {
  let pid: Int?
  let processName: String?
  let commandLine: String?
  let executablePath: String?
  let cwd: String?
  let remoteEndpoint: String?
  let reason: String?
}

fileprivate struct Snapshot: Decodable {
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

extension Snapshot: NetwatchStatusPresentable {}

private struct StatusBarError: LocalizedError {
  let message: String
  var errorDescription: String? { message }
}

private let minimumPollIntervalSeconds = 30
private let maximumPollIntervalSeconds = 1800
private let staleRefreshWindowSeconds: TimeInterval = 20
private let manualRefreshTimeoutSeconds: TimeInterval = 5

private let popoverWidth: CGFloat = 330

private final class StatusBarController: NSObject, NSApplicationDelegate {
  private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
  private let popover = NSPopover()
  private let statusURL: URL
  private var timer: Timer?
  private var logWindowController: LogViewerWindowController?
  fileprivate var lastSnapshot: Snapshot?
  fileprivate var lastError: String?
  fileprivate var lastActionMessage: String?
  private var staleRefreshRequestedForLastScanAt: Int64?
  private var staleRefreshRequestedAt: Date?
  fileprivate var manualRefreshInProgress = false
  private var manualRefreshStartedAt: Date?
  private var manualRefreshPreviousScanAt: Int64?

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
    item.button?.target = self
    item.button?.action = #selector(togglePopover)
    popover.behavior = .transient
    popover.contentSize = NSSize(width: popoverWidth, height: 260)
    let viewController = NSViewController()
    viewController.view = StatusPopoverView(controller: self)
    popover.contentViewController = viewController
    update()
    timer = Timer.scheduledTimer(timeInterval: 5, target: self, selector: #selector(update), userInfo: nil, repeats: true)
    RunLoop.main.add(timer!, forMode: .common)
    NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(update),
      name: NSWorkspace.didWakeNotification, object: nil)
  }

  @objc fileprivate func update() {
    do {
      let data = try Data(contentsOf: statusURL)
      lastSnapshot = try JSONDecoder().decode(Snapshot.self, from: data)
      lastError = nil
      if let snapshot = lastSnapshot {
        finishManualRefreshIfDone(snapshot)
        requestRefreshIfOnlyStale(snapshot)
      }
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
    if popover.isShown { popoverView()?.reload() }
  }

  private func color(for snapshot: Snapshot?) -> NSColor {
    if staleRefreshActive(for: snapshot) { return .systemGray }
    switch NetwatchStatusPresentation.indicator(for: snapshot) {
    case .green: return .systemGreen
    case .orange: return .systemOrange
    case .red: return .systemRed
    case .gray: return .systemGray
    }
  }

  fileprivate func displayStatus() -> String {
    if staleRefreshActive(for: lastSnapshot) { return "refreshing" }
    return NetwatchStatusPresentation.displayStatus(for: lastSnapshot)
  }

  fileprivate func freshnessText(_ snapshot: Snapshot) -> String {
    NetwatchStatusPresentation.freshnessText(for: snapshot)
  }

  fileprivate func colorName(_ snapshot: Snapshot?) -> String {
    if staleRefreshActive(for: snapshot) { return "gray" }
    return NetwatchStatusPresentation.colorName(for: snapshot)
  }

  fileprivate func problemReason(_ snapshot: Snapshot) -> String? {
    if staleRefreshActive(for: snapshot) { return nil }
    return NetwatchStatusPresentation.problemReason(for: snapshot)
  }

  private func requestRefreshIfOnlyStale(_ snapshot: Snapshot) {
    if !isOnlyStale(snapshot) {
      staleRefreshRequestedForLastScanAt = nil
      staleRefreshRequestedAt = nil
      return
    }
    if !snapshot.daemonRunning || staleRefreshRequestedForLastScanAt == snapshot.lastScanAt { return }
    staleRefreshRequestedForLastScanAt = snapshot.lastScanAt
    staleRefreshRequestedAt = Date()
    do {
      try requestDaemonReload()
      lastActionMessage = "stale status, refresh requested"
    } catch {
      lastActionMessage = error.localizedDescription
    }
  }

  private func isOnlyStale(_ snapshot: Snapshot) -> Bool {
    NetwatchStatusPresentation.scanIsOk(snapshot)
      && !NetwatchStatusPresentation.scanIsFresh(snapshot)
  }

  private func staleRefreshActive(for snapshot: Snapshot?) -> Bool {
    guard let snapshot, isOnlyStale(snapshot),
      staleRefreshRequestedForLastScanAt == snapshot.lastScanAt,
      let requestedAt = staleRefreshRequestedAt else { return false }
    return Date().timeIntervalSince(requestedAt) < staleRefreshWindowSeconds
  }

  private func finishManualRefreshIfDone(_ snapshot: Snapshot) {
    if !manualRefreshInProgress { return }
    if let previous = manualRefreshPreviousScanAt, snapshot.lastScanAt > previous {
      manualRefreshInProgress = false
      manualRefreshStartedAt = nil
      manualRefreshPreviousScanAt = nil
      return
    }
    if let started = manualRefreshStartedAt,
       Date().timeIntervalSince(started) >= manualRefreshTimeoutSeconds {
      manualRefreshInProgress = false
      manualRefreshStartedAt = nil
      manualRefreshPreviousScanAt = nil
      lastActionMessage = "daemon refresh still pending"
    }
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

  @objc private func togglePopover() {
    guard let button = item.button else { return }
    if popover.isShown {
      popover.performClose(nil)
    } else {
      update()
      popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
      NSApp.activate(ignoringOtherApps: true)
    }
  }

  fileprivate func resizePopover(height: CGFloat) {
    popover.contentSize = NSSize(width: popoverWidth, height: height)
  }

  private func popoverView() -> StatusPopoverView? {
    popover.contentViewController?.view as? StatusPopoverView
  }

  fileprivate func statusDetailsAvailable() -> Bool {
    guard let snapshot = lastSnapshot else { return true }
    return problemReason(snapshot) != nil
  }

  fileprivate var statusPathText: String { statusURL.path }

  fileprivate func formatTime(_ seconds: Int64) -> String {
    if seconds <= 0 { return "never" }
    let formatter = DateFormatter()
    formatter.dateStyle = .none
    formatter.timeStyle = .medium
    return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
  }

  @objc fileprivate func toggleDryRun() {
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

  @objc fileprivate func showStatusDetails() {
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = "Netwatch status details"
    alert.informativeText = statusDetailsText()
    alert.addButton(withTitle: "OK")
    alert.runModal()
  }

  private func statusDetailsText() -> String {
    guard let snapshot = lastSnapshot else {
      return [
        "Status: unavailable",
        "Indicator: gray",
        "Error: \(lastError ?? "status snapshot unavailable")",
        "Status file: \(statusURL.path)"
      ].joined(separator: "\n")
    }

    var lines = [
      "Status: \(displayStatus())",
      "Indicator: \(colorName(snapshot))",
      "Reason: \(problemReason(snapshot) ?? "no problem")",
      "Config valid: \(snapshot.configValid ? "yes" : "no")",
      "Daemon: \(snapshot.daemonRunning ? "running" : "stopped")",
      "Dry run: \(snapshot.dryRun ? "on" : "off")",
      "Last scan: \(formatTime(snapshot.lastScanAt))",
      "Fresh: \(freshnessText(snapshot))",
      "Result: \(snapshot.lastScanResult)",
      "Unknown processes: \(snapshot.unknownCount)",
      "Would disable Wi-Fi: \(snapshot.wouldDisableWifi ? "yes" : "no")",
      "Wi-Fi disabled: \(snapshot.wifiDisabled ? "yes" : "no")"
    ]
    if let unknown = snapshot.lastUnknownProcessSummary {
      lines.append("")
      lines.append("Last unknown: \(unknownDisplayName(unknown))")
      if let pid = unknown.pid { lines.append("PID: \(pid)") }
      if let command = unknown.commandLine, !command.isEmpty { lines.append("Command: \(command)") }
      if let path = unknown.executablePath, !path.isEmpty { lines.append("Path: \(path)") }
      if let cwd = unknown.cwd, !cwd.isEmpty { lines.append("CWD: \(cwd)") }
      if let remote = unknown.remoteEndpoint { lines.append("Remote: \(remote)") }
      if let reason = unknown.reason { lines.append("Unknown reason: \(reason)") }
    }
    return lines.joined(separator: "\n")
  }

  fileprivate func unknownDisplayName(_ unknown: LastUnknown) -> String {
    if let path = unknown.executablePath, !path.isEmpty {
      return URL(fileURLWithPath: path).lastPathComponent
    }
    if let command = unknown.commandLine, let first = command.split(separator: " ").first {
      return URL(fileURLWithPath: String(first)).lastPathComponent
    }
    return unknown.processName ?? "unknown"
  }

  fileprivate func saveInterval(_ text: String) -> Bool {
    guard let snapshot = lastSnapshot else { lastActionMessage = "status unavailable"; return false }
    guard let seconds = Int(text.trimmingCharacters(in: .whitespacesAndNewlines)) else {
      lastActionMessage = "interval must be a number"; return false
    }
    if seconds == configuredPollIntervalSeconds(snapshot) { return true }
    do {
      try setPollInterval(seconds, configPath: snapshot.activeConfigPath)
      try requestDaemonReload()
      lastActionMessage = "interval saved: \(seconds)s, reload requested"
      return true
    } catch {
      lastActionMessage = error.localizedDescription
      return false
    }
  }

  @objc fileprivate func refreshDaemonNow() {
    if manualRefreshInProgress { return }
    manualRefreshInProgress = true
    manualRefreshStartedAt = Date()
    manualRefreshPreviousScanAt = lastSnapshot?.lastScanAt
    lastActionMessage = nil
    render()
    do {
      try requestDaemonReload()
      update()
      for delay in [1.0, 2.0, 4.0, manualRefreshTimeoutSeconds] {
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in self?.update() }
      }
    } catch {
      manualRefreshInProgress = false
      manualRefreshStartedAt = nil
      manualRefreshPreviousScanAt = nil
      lastActionMessage = error.localizedDescription
      render()
    }
  }

  @objc fileprivate func viewLog() {
    let url = logURL()
    if logWindowController?.logURL.path != url.path {
      logWindowController = LogViewerWindowController(logURL: url, onClear: { [weak self] url in
        guard let self else { throw StatusBarError(message: "statusbar unavailable") }
        try self.truncateFile(url)
      }, onAction: { [weak self] message in
        self?.lastActionMessage = message
        self?.render()
      })
    }
    logWindowController?.refresh()
    logWindowController?.showWindow(nil)
    NSApp.activate(ignoringOtherApps: true)
    lastActionMessage = "opened log viewer"
    render()
  }

  @objc fileprivate func openConfigurator() {
    guard let url = configuratorURL() else {
      lastActionMessage = "Configurator app not found"; render(); return
    }
    if !NSWorkspace.shared.open(url) {
      lastActionMessage = "failed to open Configurator"
    } else {
      lastActionMessage = "opened Configurator"
    }
    render()
  }

  private func setDryRun(_ value: Bool, configPath: String) throws {
    try updateConfig(configPath: configPath) { root in root["dryRun"] = value }
  }

  private func setPollInterval(_ seconds: Int, configPath: String) throws {
    if seconds < minimumPollIntervalSeconds || seconds > maximumPollIntervalSeconds {
      throw StatusBarError(message: "interval must be \(minimumPollIntervalSeconds)-\(maximumPollIntervalSeconds)s")
    }
    try updateConfig(configPath: configPath) { root in
      var daemon = root["daemon"] as? [String: Any] ?? [:]
      daemon["pollIntervalSeconds"] = seconds
      root["daemon"] = daemon
    }
  }

  private func updateConfig(configPath: String, change: (inout [String: Any]) throws -> Void) throws {
    if configPath.isEmpty { throw StatusBarError(message: "active config path missing") }
    let url = URL(fileURLWithPath: NSString(string: configPath).expandingTildeInPath)
    let data = try Data(contentsOf: url)
    guard var root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw StatusBarError(message: "config root is not an object")
    }
    try change(&root)
    var out = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
    out.append(0x0a)
    _ = try JSONSerialization.jsonObject(with: out)
    try writeAtomically(out, to: url)
  }

  fileprivate func configuredPollIntervalSeconds(_ snapshot: Snapshot) -> Int {
    guard !snapshot.activeConfigPath.isEmpty else { return snapshot.pollIntervalSeconds }
    let url = URL(fileURLWithPath: NSString(string: snapshot.activeConfigPath).expandingTildeInPath)
    guard let data = try? Data(contentsOf: url),
          let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let daemon = root["daemon"] as? [String: Any] else { return snapshot.pollIntervalSeconds }
    if let seconds = daemon["pollIntervalSeconds"] as? Int { return seconds }
    if let seconds = daemon["pollIntervalSeconds"] as? NSNumber { return seconds.intValue }
    return snapshot.pollIntervalSeconds
  }

  private func logURL() -> URL {
    if let snapshot = lastSnapshot, !snapshot.activeConfigPath.isEmpty,
       let data = try? Data(contentsOf: URL(fileURLWithPath: NSString(string: snapshot.activeConfigPath).expandingTildeInPath)),
       let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
       let path = root["logPath"] as? String, !path.isEmpty {
      return URL(fileURLWithPath: NSString(string: path).expandingTildeInPath)
    }
    return FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".watch/netwatch.log")
  }

  private func configuratorURL() -> URL? {
    let home = FileManager.default.homeDirectoryForCurrentUser
    let candidates = [
      home.appendingPathComponent(".watch/NetwatchConfigurator.app"),
      home.appendingPathComponent("Applications/NetwatchConfigurator.app"),
      URL(fileURLWithPath: "/Applications/NetwatchConfigurator.app"),
      URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("build/NetwatchConfigurator.app")
    ]
    return candidates.first { FileManager.default.fileExists(atPath: $0.path) }
  }

  private func truncateFile(_ url: URL) throws {
    let fd = open(url.path, O_WRONLY)
    if fd < 0 { throw posixError("open", url.path) }
    var shouldClose = true
    defer { if shouldClose { close(fd) } }
    if ftruncate(fd, 0) < 0 { throw posixError("truncate", url.path) }
    if fsync(fd) < 0 { throw posixError("fsync", url.path) }
    if close(fd) < 0 { shouldClose = false; throw posixError("close", url.path) }
    shouldClose = false
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

  @objc fileprivate func quit() { NSApp.terminate(nil) }
}

private final class PopoverRow: NSView {
  private let titleLabel = NSTextField(labelWithString: "")
  private let shortcutLabel = NSTextField(labelWithString: "")
  private let clickButton = RowClickButton(frame: .zero)
  private let callback: (() -> Void)?
  private let rowEnabled: Bool
  private var highlighted = false

  init(_ title: String, checked: Bool = false, shortcut: String? = nil,
       enabled: Bool = true, callback: (() -> Void)? = nil) {
    self.callback = callback
    self.rowEnabled = enabled && callback != nil
    super.init(frame: NSRect(x: 0, y: 0, width: popoverWidth, height: 32))
    wantsLayer = true
    titleLabel.stringValue = checked ? "✓ \(title)" : title
    titleLabel.font = NSFont.systemFont(ofSize: 15, weight: callback == nil ? .regular : .semibold)
    titleLabel.textColor = rowEnabled ? .labelColor : .secondaryLabelColor
    titleLabel.lineBreakMode = .byTruncatingTail
    titleLabel.frame = NSRect(x: 22, y: 7, width: 230, height: 18)
    addSubview(titleLabel)
    if let shortcut {
      shortcutLabel.stringValue = shortcut
      shortcutLabel.font = NSFont.systemFont(ofSize: 15, weight: .regular)
      shortcutLabel.textColor = .secondaryLabelColor
      shortcutLabel.alignment = .right
      shortcutLabel.frame = NSRect(x: 260, y: 7, width: 48, height: 18)
      addSubview(shortcutLabel)
    }
    clickButton.frame = bounds
    clickButton.autoresizingMask = [.width, .height]
    clickButton.isBordered = false
    clickButton.isTransparent = true
    clickButton.title = ""
    clickButton.target = self
    clickButton.action = #selector(clicked)
    clickButton.isEnabled = rowEnabled
    addSubview(clickButton)
  }

  required init?(coder: NSCoder) { nil }

  override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

  override func hitTest(_ point: NSPoint) -> NSView? {
    if rowEnabled && bounds.contains(point) { return clickButton }
    return super.hitTest(point)
  }

  override func updateTrackingAreas() {
    super.updateTrackingAreas()
    trackingAreas.forEach { removeTrackingArea($0) }
    addTrackingArea(NSTrackingArea(rect: bounds,
      options: [.activeAlways, .mouseEnteredAndExited, .inVisibleRect],
      owner: self, userInfo: nil))
  }

  override func mouseEntered(with event: NSEvent) { setHighlighted(true) }
  override func mouseExited(with event: NSEvent) { setHighlighted(false) }

  override func draw(_ dirtyRect: NSRect) {
    if highlighted {
      NSColor.controlAccentColor.setFill()
      bounds.insetBy(dx: 6, dy: 1).fill()
    }
    super.draw(dirtyRect)
  }

  private func setHighlighted(_ value: Bool) {
    highlighted = value && rowEnabled
    titleLabel.textColor = highlighted ? .selectedMenuItemTextColor
      : (rowEnabled ? .labelColor : .secondaryLabelColor)
    needsDisplay = true
  }

  @objc private func clicked() {
    callback?()
  }
}

private final class SeparatorRow: NSView {
  init() {
    super.init(frame: NSRect(x: 0, y: 0, width: popoverWidth, height: 11))
  }

  required init?(coder: NSCoder) { nil }

  override func draw(_ dirtyRect: NSRect) {
    NSColor.separatorColor.setStroke()
    let path = NSBezierPath()
    path.move(to: NSPoint(x: 18, y: 5.5))
    path.line(to: NSPoint(x: popoverWidth - 18, y: 5.5))
    path.stroke()
  }
}

private final class RowClickButton: NSButton {
  override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}

private final class LogViewerWindowController: NSWindowController {
  let logURL: URL
  private let textView = NSTextView()
  private let statusLabel = NSTextField(labelWithString: "")
  private let onClear: (URL) throws -> Void
  private let onAction: (String) -> Void

  init(logURL: URL, onClear: @escaping (URL) throws -> Void,
       onAction: @escaping (String) -> Void) {
    self.logURL = logURL
    self.onClear = onClear
    self.onAction = onAction
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 560),
      styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered, defer: false)
    window.title = "Netwatch Log"
    window.isReleasedWhenClosed = false
    super.init(window: window)
    buildContent()
    window.center()
  }

  required init?(coder: NSCoder) { nil }

  func refresh() {
    do {
      let data = try Data(contentsOf: logURL)
      textView.string = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
      statusLabel.stringValue = logURL.path
      textView.scrollToEndOfDocument(nil)
    } catch {
      textView.string = ""
      statusLabel.stringValue = "\(logURL.path) - \(error.localizedDescription)"
    }
  }

  private func buildContent() {
    guard let content = window?.contentView else { return }
    let scrollView = NSScrollView()
    scrollView.translatesAutoresizingMaskIntoConstraints = false
    scrollView.hasVerticalScroller = true
    scrollView.hasHorizontalScroller = true
    scrollView.borderType = .bezelBorder
    textView.isEditable = false
    textView.isSelectable = true
    textView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
    textView.frame = NSRect(x: 0, y: 0, width: 860, height: 460)
    textView.autoresizingMask = [.width, .height]
    textView.textContainer?.widthTracksTextView = false
    scrollView.documentView = textView

    statusLabel.translatesAutoresizingMaskIntoConstraints = false
    statusLabel.lineBreakMode = .byTruncatingMiddle
    let refreshButton = NSButton(title: "Refresh", target: self, action: #selector(refreshClicked))
    let clearButton = NSButton(title: "Clear log file", target: self, action: #selector(clearClicked))
    let closeButton = NSButton(title: "Close", target: self, action: #selector(closeClicked))
    let buttons = NSStackView(views: [refreshButton, clearButton, closeButton])
    buttons.translatesAutoresizingMaskIntoConstraints = false
    buttons.orientation = .horizontal
    buttons.spacing = 8

    content.addSubview(statusLabel)
    content.addSubview(scrollView)
    content.addSubview(buttons)
    NSLayoutConstraint.activate([
      statusLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
      statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
      statusLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
      scrollView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 8),
      scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
      scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
      scrollView.bottomAnchor.constraint(equalTo: buttons.topAnchor, constant: -12),
      buttons.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
      buttons.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12)
    ])
  }

  @objc private func refreshClicked() {
    refresh()
  }

  @objc private func clearClicked() {
    do {
      try onClear(logURL)
      refresh()
      onAction("cleared log file")
    } catch {
      onAction(error.localizedDescription)
    }
  }

  @objc private func closeClicked() {
    close()
  }
}

private final class StatusPopoverView: NSView, NSTextFieldDelegate {
  private weak var controller: StatusBarController?
  private var editingInterval = false
  private var intervalText = ""
  private var intervalError: String?
  private var rebuilding = false
  private weak var intervalField: NSTextField?
  private var nextY: CGFloat = 8

  init(controller: StatusBarController) {
    self.controller = controller
    super.init(frame: NSRect(x: 0, y: 0, width: popoverWidth, height: 260))
    reload(force: true)
  }

  required init?(coder: NSCoder) { nil }
  override var isFlipped: Bool { true }

  func reload(force: Bool = false) {
    if editingInterval && !force { return }
    rebuilding = true
    defer { rebuilding = false }
    subviews.forEach { $0.removeFromSuperview() }
    nextY = 8
    guard let controller else { return }
    addHeader(controller)
    if let snapshot = controller.lastSnapshot {
      addInfo("Indicator: \(controller.colorName(snapshot))")
      if let reason = controller.problemReason(snapshot) { addInfo("Reason: \(reason)") }
      if let message = controller.lastActionMessage { addInfo("Action: \(message)") }
      addInfo("Daemon: \(snapshot.daemonRunning ? "running" : "stopped")")
      addRow("Dry run: \(snapshot.dryRun ? "on" : "off")", checked: snapshot.dryRun,
             enabled: snapshot.configValid && !snapshot.activeConfigPath.isEmpty) {
        controller.toggleDryRun()
      }
      addInfo("Last scan: \(controller.formatTime(snapshot.lastScanAt))")
      addInfo("Fresh: \(controller.freshnessText(snapshot))")
      addInfo("Result: \(snapshot.lastScanResult)")
      if snapshot.unknownCount > 0 { addInfo("Unknown processes: \(snapshot.unknownCount)") }
      if let unknown = snapshot.lastUnknownProcessSummary {
        addSeparator()
        addInfo("Last unknown: \(controller.unknownDisplayName(unknown))")
        if let remote = unknown.remoteEndpoint { addInfo("Remote: \(remote)") }
        if let reason = unknown.reason { addInfo("Reason: \(reason)") }
      }
      addInterval(snapshot, controller)
    } else {
      addInfo(controller.lastError ?? "status snapshot unavailable")
      addInfo(controller.statusPathText)
    }
    addSeparator()
    if controller.manualRefreshInProgress {
      addRow("Refresh in progress...", shortcut: "⌘ R", enabled: false) {}
    } else {
      addRow("Refresh", shortcut: "⌘ R") { controller.refreshDaemonNow() }
    }
    addRow("View log", shortcut: "⌘ L") { controller.viewLog() }
    addRow("Configurator") { controller.openConfigurator() }
    addRow("Quit", shortcut: "⌘ Q") { controller.quit() }
    setFrameSize(NSSize(width: popoverWidth, height: nextY + 8))
    controller.resizePopover(height: frame.height)
  }

  private func addHeader(_ controller: StatusBarController) {
    let title = "Netwatch: \(controller.displayStatus())"
    if controller.statusDetailsAvailable() {
      addRow(title) { controller.showStatusDetails() }
    } else {
      addInfo(title, weight: .semibold)
    }
  }

  private func addInterval(_ snapshot: Snapshot, _ controller: StatusBarController) {
    let enabled = snapshot.configValid && !snapshot.activeConfigPath.isEmpty
    let seconds = controller.configuredPollIntervalSeconds(snapshot)
    if editingInterval {
      addIntervalEditor()
    } else {
      addRow("Interval: \(seconds)s", enabled: enabled) { [weak self] in
        self?.editingInterval = true
        self?.intervalText = "\(seconds)"
        self?.intervalError = nil
        self?.reload(force: true)
      }
    }
    if let intervalError { addInfo(intervalError) }
  }

  private func addIntervalEditor() {
    let row = NSView(frame: NSRect(x: 0, y: 0, width: popoverWidth, height: 34))
    let label = NSTextField(labelWithString: "Interval:")
    label.font = NSFont.systemFont(ofSize: 15, weight: .semibold)
    label.frame = NSRect(x: 22, y: 8, width: 100, height: 18)
    row.addSubview(label)
    let field = NSTextField(frame: NSRect(x: 140, y: 4, width: 74, height: 24))
    field.stringValue = intervalText
    field.alignment = .right
    field.delegate = self
    row.addSubview(field)
    let suffix = NSTextField(labelWithString: "s")
    suffix.font = NSFont.systemFont(ofSize: 15, weight: .semibold)
    suffix.frame = NSRect(x: 222, y: 8, width: 20, height: 18)
    row.addSubview(suffix)
    intervalField = field
    add(row)
    DispatchQueue.main.async { [weak self, weak field] in
      guard let self, let field else { return }
      self.window?.makeFirstResponder(field)
      field.selectText(nil)
    }
  }

  @objc private func saveInterval() {
    guard let controller, let field = intervalField else { return }
    intervalText = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let seconds = Int(intervalText) else { rejectInterval("Interval must be a number"); return }
    guard seconds >= minimumPollIntervalSeconds && seconds <= maximumPollIntervalSeconds else {
      rejectInterval("Interval must be \(minimumPollIntervalSeconds)-\(maximumPollIntervalSeconds)s")
      return
    }
    if controller.saveInterval(intervalText) {
      editingInterval = false
      intervalError = nil
      controller.update()
      reload(force: true)
    } else {
      rejectInterval(controller.lastActionMessage ?? "Failed to save interval")
    }
  }

  private func rejectInterval(_ message: String) {
    NSSound.beep()
    intervalError = message
    reload(force: true)
  }

  func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
    if commandSelector == #selector(NSResponder.insertNewline(_:)) {
      saveInterval()
      return true
    }
    if commandSelector == #selector(NSResponder.cancelOperation(_:)) {
      editingInterval = false
      intervalError = nil
      reload(force: true)
      return true
    }
    return false
  }

  private func addInfo(_ text: String, weight: NSFont.Weight = .regular) {
    let label = NSTextField(labelWithString: text)
    label.font = NSFont.systemFont(ofSize: 15, weight: weight)
    label.textColor = .secondaryLabelColor
    label.lineBreakMode = .byTruncatingTail
    label.frame = NSRect(x: 22, y: 5, width: popoverWidth - 44, height: 18)
    let row = NSView(frame: NSRect(x: 0, y: 0, width: popoverWidth, height: 28))
    row.addSubview(label)
    add(row)
  }

  private func addRow(_ text: String, checked: Bool = false, shortcut: String? = nil,
                      enabled: Bool = true, callback: @escaping () -> Void) {
    add(PopoverRow(text, checked: checked, shortcut: shortcut, enabled: enabled, callback: callback))
  }

  private func addSeparator() {
    add(SeparatorRow())
  }

  private func add(_ view: NSView) {
    view.frame.origin = NSPoint(x: 0, y: nextY)
    view.frame.size.width = popoverWidth
    addSubview(view)
    nextY += view.frame.height
  }
}

@main
private struct NetwatchStatusBarApp {
  private static var controller: StatusBarController?

  static func main() {
    controller = StatusBarController(statusPath: CommandLine.arguments.dropFirst().first)
    NSApplication.shared.delegate = controller
    NSApplication.shared.run()
  }
}
