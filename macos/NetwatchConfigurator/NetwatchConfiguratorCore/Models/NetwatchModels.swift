import Foundation

public struct StatusSnapshot: Decodable, Equatable {
  public let version: Int?
  public let status: String
  public let daemonRunning: Bool
  public let configValid: Bool
  public let dryRun: Bool
  public let lastScanAt: Int64
  public let lastScanResult: String
  public let unknownCount: Int
  public let wouldDisableWifi: Bool
  public let wifiDisabled: Bool
  public let activeConfigPath: String
  public let pollIntervalSeconds: Int
}

public enum DashboardIndicator: String, Equatable {
  case green
  case red
  case gray
}

public enum DashboardStatusMapper {
  public static func indicator(for snapshot: StatusSnapshot?) -> DashboardIndicator {
    guard let snapshot else { return .gray }
    if snapshot.dryRun { return .red }
    if snapshot.status == "ok" { return .green }
    if snapshot.status == "attention" || snapshot.status == "error" { return .red }
    return .gray
  }
}

public struct DiscoveredAppsResponse: Decodable, Equatable {
  public let apps: [DiscoveredApp]
}

public struct DiscoveredApp: Decodable, Equatable, Identifiable {
  public var id: String { executablePath }
  public let displayName: String
  public let bundlePath: String
  public let executablePath: String
  public let signingIdentifier: String
  public let teamId: String
  public let signatureValid: Bool
  public let appleSigned: Bool
  public let suitableTrustedPublisher: Bool
}

public struct ConfigSummary: Decodable, Equatable {
  public let version: Int?
  public let dryRun: Bool?
  public let daemon: DaemonConfig?
  public let allowAppleSystemComponents: Bool?
  public let interface: String?
  public let logPath: String?
  public let denyPatterns: [String]?
  public let allowRemoteHosts: [String]?
  public let trustedPublishers: [String: TrustedPublisherRule]?
  public let trustedWorkspaces: [String: TrustedWorkspaceRule]?
  public let allowProcesses: [String: AllowProcessRule]?

  public var publisherItems: [TrustedPublisherItem] {
    (trustedPublishers ?? [:]).map { TrustedPublisherItem(name: $0.key, rule: $0.value) }
      .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
  }

  public var workspaceItems: [TrustedWorkspaceItem] {
    (trustedWorkspaces ?? [:]).map { TrustedWorkspaceItem(name: $0.key, rule: $0.value) }
      .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
  }

  public var allowProcessItems: [AllowProcessItem] {
    (allowProcesses ?? [:]).map { AllowProcessItem(name: $0.key, rule: $0.value) }
      .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
  }
}

public struct DaemonConfig: Decodable, Equatable {
  public let pollIntervalSeconds: Int?
  public let reloadOnSighup: Bool?
  public let exitOnConfigError: Bool?
}

public struct TrustedPublisherRule: Decodable, Equatable {
  public let paths: [String]
  public let teamId: String
  public let signingIdentifier: String

  public init(paths: [String], teamId: String, signingIdentifier: String) {
    self.paths = paths
    self.teamId = teamId
    self.signingIdentifier = signingIdentifier
  }
}

public struct TrustedWorkspaceRule: Decodable, Equatable {
  public let roots: [String]
  public let allowSubdirectories: Bool
  public let interpreters: [String]
  public let allowByCwdOnly: Bool

  public init(roots: [String], allowSubdirectories: Bool, interpreters: [String], allowByCwdOnly: Bool) {
    self.roots = roots
    self.allowSubdirectories = allowSubdirectories
    self.interpreters = interpreters
    self.allowByCwdOnly = allowByCwdOnly
  }
}

public struct AllowProcessRule: Decodable, Equatable {
  public let paths: [String]

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if let path = try? container.decode(String.self) {
      paths = [path]
    } else {
      paths = try container.decode([String].self)
    }
  }
}

public struct TrustedPublisherItem: Identifiable, Equatable {
  public var id: String { name }
  public let name: String
  public let rule: TrustedPublisherRule
}

public struct TrustedWorkspaceItem: Identifiable, Equatable {
  public var id: String { name }
  public let name: String
  public let rule: TrustedWorkspaceRule
}

public struct AllowProcessItem: Identifiable, Equatable {
  public var id: String { name }
  public let name: String
  public let rule: AllowProcessRule
}

public struct TrustedPublisherEditForm: Equatable {
  public var originalName = ""
  public var name = ""
  public var pathsText = ""
  public var teamId = ""
  public var signingIdentifier = ""

  public init() {}
  public init(originalName: String, name: String, rule: TrustedPublisherRule) {
    self.originalName = originalName
    self.name = name
    self.pathsText = rule.paths.joined(separator: "\n")
    self.teamId = rule.teamId
    self.signingIdentifier = rule.signingIdentifier
  }

  public var paths: [String] { cleanedLines(pathsText) }

  public func validationError() -> String? {
    if originalName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Original publisher name is required." }
    if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Publisher name is required." }
    if paths.isEmpty { return "At least one publisher path is required." }
    if teamId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Team ID is required." }
    if signingIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Signing identifier is required." }
    var seen = Set<String>()
    for path in paths {
      if !path.hasPrefix("/") { return "Publisher paths must be absolute." }
      if path.contains("*") { return "Trusted publisher paths must be exact; wildcards are not supported." }
      if seen.contains(path) { return "Duplicate publisher paths are not allowed." }
      seen.insert(path)
    }
    return nil
  }
}

public struct AllowProcessForm: Equatable {
  public var name = ""
  public var path = ""

  public init() {}
  public init(name: String, path: String) {
    self.name = name
    self.path = path
  }

  public func validationError() -> String? {
    if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Allow rule name is required." }
    if path.isEmpty || !path.hasPrefix("/") { return "Path must be absolute." }
    if let star = path.firstIndex(of: "*"), star != path.index(before: path.endIndex) {
      return "Wildcard is supported only as a final *."
    }
    return nil
  }
}

public struct AllowProcessEditForm: Equatable {
  public var originalName = ""
  public var name = ""
  public var pathsText = ""

  public init() {}
  public init(originalName: String, name: String, paths: [String]) {
    self.originalName = originalName
    self.name = name
    self.pathsText = paths.joined(separator: "\n")
  }

  public var paths: [String] {
    pathsText.components(separatedBy: .newlines)
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
  }

  public func validationError() -> String? {
    if originalName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Original allow rule name is required." }
    if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Allow rule name is required." }
    if paths.isEmpty { return "At least one path is required." }
    var seen = Set<String>()
    for path in paths {
      if !path.hasPrefix("/") { return "Path must be absolute." }
      if let star = path.firstIndex(of: "*"), star != path.index(before: path.endIndex) {
        return "Wildcard is supported only as a final *."
      }
      if seen.contains(path) { return "Duplicate paths are not allowed." }
      seen.insert(path)
    }
    return nil
  }
}

public struct WorkspaceForm: Equatable {
  public var name = ""
  public var root = ""
  public var interpreter = ""
  public var allowSubdirectories = true
  public var allowByCwdOnly = false

  public init() {}

  public func validationError(fileManager: FileManager = .default) -> String? {
    if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Workspace name is required." }
    if root.isEmpty { return "Workspace root is required." }
    if interpreter.isEmpty { return "Interpreter path is required." }
    if !root.hasPrefix("/") || root.contains("*") { return "Workspace root must be an exact absolute path." }
    if !interpreter.hasPrefix("/") || interpreter.contains("*") { return "Interpreter must be an exact absolute path." }
    var isDir: ObjCBool = false
    if !fileManager.fileExists(atPath: root, isDirectory: &isDir) || !isDir.boolValue {
      return "Workspace root must exist and be a directory."
    }
    if !fileManager.isExecutableFile(atPath: interpreter) {
      return "Interpreter must exist and be executable."
    }
    return nil
  }
}

public struct WorkspaceEditForm: Equatable {
  public var originalName = ""
  public var name = ""
  public var rootsText = ""
  public var interpretersText = ""
  public var allowSubdirectories = true
  public var allowByCwdOnly = false

  public init() {}
  public init(originalName: String, name: String, rule: TrustedWorkspaceRule) {
    self.originalName = originalName
    self.name = name
    self.rootsText = rule.roots.joined(separator: "\n")
    self.interpretersText = rule.interpreters.joined(separator: "\n")
    self.allowSubdirectories = rule.allowSubdirectories
    self.allowByCwdOnly = rule.allowByCwdOnly
  }

  public var roots: [String] { cleanedLines(rootsText) }
  public var interpreters: [String] { cleanedLines(interpretersText) }

  public func validationError(fileManager: FileManager = .default) -> String? {
    if originalName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Original workspace name is required." }
    if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Workspace name is required." }
    if roots.isEmpty { return "At least one workspace root is required." }
    if interpreters.isEmpty { return "At least one interpreter is required." }
    var seenRoots = Set<String>()
    for root in roots {
      if !root.hasPrefix("/") { return "Workspace roots must be absolute." }
      if root.contains("*") { return "Workspace roots must be exact paths." }
      var isDir: ObjCBool = false
      if !fileManager.fileExists(atPath: root, isDirectory: &isDir) || !isDir.boolValue { return "Workspace root must exist and be a directory." }
      if seenRoots.contains(root) { return "Duplicate workspace roots are not allowed." }
      seenRoots.insert(root)
    }
    var seenInterpreters = Set<String>()
    for interpreter in interpreters {
      if !interpreter.hasPrefix("/") { return "Interpreter paths must be absolute." }
      if interpreter.contains("*") { return "Interpreter paths must be exact paths." }
      if !fileManager.isExecutableFile(atPath: interpreter) { return "Interpreter must exist and be executable." }
      if seenInterpreters.contains(interpreter) { return "Duplicate interpreters are not allowed." }
      seenInterpreters.insert(interpreter)
    }
    return nil
  }
}

private func cleanedLines(_ text: String) -> [String] {
  text.components(separatedBy: .newlines)
    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
    .filter { !$0.isEmpty }
}

public enum ConfigPermission {
  public static func isWritable(path: String, fileManager: FileManager = .default) -> Bool {
    fileManager.isWritableFile(atPath: NSString(string: path).expandingTildeInPath)
  }
}
