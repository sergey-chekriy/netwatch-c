import Foundation

public protocol NetwatchStatusPresentable {
  var configValid: Bool { get }
  var dryRun: Bool { get }
  var lastScanAt: Int64 { get }
  var lastScanResult: String { get }
  var unknownCount: Int { get }
  var wouldDisableWifi: Bool { get }
  var wifiDisabled: Bool { get }
  var pollIntervalSeconds: Int { get }
}

public enum NetwatchStatusIndicator: String, Equatable {
  case green
  case orange
  case red
  case gray
}

public enum NetwatchStatusPresentation {
  public static let freshnessGraceSeconds: Int64 = 10

  public static func indicator<S: NetwatchStatusPresentable>(for snapshot: S?) -> NetwatchStatusIndicator {
    guard let snapshot else { return .gray }
    if !scanIsOk(snapshot) || !scanIsFresh(snapshot) { return .red }
    return snapshot.dryRun ? .orange : .green
  }

  public static func displayStatus<S: NetwatchStatusPresentable>(for snapshot: S?) -> String {
    guard let snapshot else { return "unavailable" }
    if !scanIsOk(snapshot) || !scanIsFresh(snapshot) { return "problem" }
    return snapshot.dryRun ? "dry run" : "ok"
  }

  public static func colorName<S: NetwatchStatusPresentable>(for snapshot: S?) -> String {
    indicator(for: snapshot).rawValue
  }

  public static func scanIsOk<S: NetwatchStatusPresentable>(_ snapshot: S) -> Bool {
    snapshot.configValid && snapshot.lastScanResult == "ok" && snapshot.unknownCount == 0
      && !snapshot.wouldDisableWifi && !snapshot.wifiDisabled
  }

  public static func scanIsFresh<S: NetwatchStatusPresentable>(_ snapshot: S) -> Bool {
    scanIsFresh(snapshot, now: Int64(Date().timeIntervalSince1970))
  }

  public static func scanIsFresh<S: NetwatchStatusPresentable>(_ snapshot: S, now: Int64) -> Bool {
    if snapshot.lastScanAt <= 0 || snapshot.pollIntervalSeconds <= 0 { return false }
    return now - snapshot.lastScanAt <= Int64(snapshot.pollIntervalSeconds) + freshnessGraceSeconds
  }

  public static func freshnessText<S: NetwatchStatusPresentable>(for snapshot: S) -> String {
    if snapshot.lastScanAt <= 0 { return "no" }
    let age = max(0, Int64(Date().timeIntervalSince1970) - snapshot.lastScanAt)
    if age <= Int64(snapshot.pollIntervalSeconds) { return "yes (\(age)s old)" }
    if scanIsFresh(snapshot) { return "yes (\(age)s old, scan grace)" }
    return "no (\(age)s old)"
  }

  public static func problemReason<S: NetwatchStatusPresentable>(for snapshot: S) -> String? {
    if !snapshot.configValid { return "config invalid" }
    if snapshot.lastScanResult != "ok" { return "result \(snapshot.lastScanResult)" }
    if snapshot.unknownCount > 0 { return "\(snapshot.unknownCount) unknown process(es)" }
    if snapshot.wouldDisableWifi { return "would disable Wi-Fi" }
    if snapshot.wifiDisabled { return "Wi-Fi disabled" }
    if scanIsFresh(snapshot) { return nil }
    if snapshot.lastScanAt <= 0 { return "last scan missing" }
    return "last scan is older than \(snapshot.pollIntervalSeconds)s"
  }
}
