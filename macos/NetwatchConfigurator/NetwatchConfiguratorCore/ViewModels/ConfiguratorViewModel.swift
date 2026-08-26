import Combine
import Foundation

@MainActor
public final class ConfiguratorViewModel: ObservableObject {
  @Published public var binaryPath: String
  @Published public var configPath: String
  @Published public var status: StatusSnapshot?
  @Published public var apps: [DiscoveredApp] = []
  @Published public var config: ConfigSummary?
  @Published public var searchText = ""
  @Published public var workspaceForm = WorkspaceForm()
  @Published public var workspaceEditForm = WorkspaceEditForm()
  @Published public var editingWorkspaceName: String?
  @Published public var publisherEditForm = TrustedPublisherEditForm()
  @Published public var editingPublisherName: String?
  @Published public var allowProcessForm = AllowProcessForm()
  @Published public var allowProcessEditForm = AllowProcessEditForm()
  @Published public var editingAllowProcessName: String?
  @Published public var desiredDryRun = true
  @Published public var desiredPollInterval = 300
  @Published public var desiredAppleSystemTrust = false
  @Published public var desiredInterface = "Wi-Fi"
  @Published public var desiredLogPath = ""
  @Published public var desiredVerboseLog = false
  @Published public var desiredReloadOnSighup = true
  @Published public var desiredExitOnConfigError = false
  @Published public var denyPatternsText = ""
  @Published public var allowRemoteHostsText = ""
  @Published public var isLoading = false
  @Published public var lastMessage = ""
  @Published public var lastStatusJSON = ""
  @Published public var lastCommandOutput = ""
  @Published public var recentErrors: [String] = []

  private let service: NetwatchService

  public init(service: NetwatchService = NetwatchService()) {
    self.service = service
    binaryPath = service.binaryPath
    configPath = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".watch/netwatch.config.json").path
  }

  public var indicator: DashboardIndicator { DashboardStatusMapper.indicator(for: status) }
  public var filteredApps: [DiscoveredApp] {
    guard !searchText.isEmpty else { return apps }
    return apps.filter {
      $0.displayName.localizedCaseInsensitiveContains(searchText)
        || $0.bundlePath.localizedCaseInsensitiveContains(searchText)
        || $0.executablePath.localizedCaseInsensitiveContains(searchText)
    }
  }

  public func trustedPublisherName(for app: DiscoveredApp) -> String? {
    if config?.trustedPublishers?[app.displayName] != nil { return app.displayName }
    return config?.publisherItems.first { $0.rule.paths.contains(app.executablePath) }?.name
  }

  public func pathOnlyAllows(for app: DiscoveredApp) -> [AllowProcessItem] {
    (config?.allowProcessItems ?? []).filter { item in
      item.rule.paths.contains { path in
        pathMatches(path, executable: app.executablePath, bundle: app.bundlePath)
      }
    }
  }

  public func refreshAll() async {
    await refreshStatus()
    await refreshConfig()
  }

  public func refreshStatus() async {
    await perform("Status refreshed.") {
      status = try await service.status()
      lastStatusJSON = service.lastResult?.stdout ?? ""
      if let active = status?.activeConfigPath, !active.isEmpty { configPath = active }
    }
  }

  public func discoverApps() async {
    await perform("Applications discovered.") {
      apps = try await service.discoverApps()
    }
  }

  public func refreshConfig() async {
    await perform("Config loaded.") {
      config = try await service.configSummary(configPath: configPath)
      desiredDryRun = config?.dryRun ?? true
      desiredPollInterval = config?.daemon?.pollIntervalSeconds ?? 300
      desiredAppleSystemTrust = config?.allowAppleSystemComponents ?? false
      desiredInterface = config?.interface ?? "Wi-Fi"
      desiredLogPath = config?.logPath ?? ""
      desiredVerboseLog = config?.verboseLog ?? false
      desiredReloadOnSighup = config?.daemon?.reloadOnSighup ?? true
      desiredExitOnConfigError = config?.daemon?.exitOnConfigError ?? false
      denyPatternsText = (config?.denyPatterns ?? []).joined(separator: "\n")
      allowRemoteHostsText = (config?.allowRemoteHosts ?? []).joined(separator: "\n")
    }
  }

  public func checkConfig() async {
    await perform("Config check completed.") {
      lastCommandOutput = try await service.checkConfig(configPath: configPath)
    }
  }

  public func saveDryRun() async {
    await perform("dryRun saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setDryRun(desiredDryRun, configPath: configPath)
      await refreshConfig()
    }
  }

  public func savePollInterval() async {
    await perform("Poll interval saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setPollInterval(desiredPollInterval, configPath: configPath)
      await refreshConfig()
    }
  }

  public func saveAppleSystemTrust() async {
    await perform("Apple system trust saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setAppleSystemTrust(desiredAppleSystemTrust, configPath: configPath)
      await refreshConfig()
    }
  }

  public func saveInterfaceAndLogPath() async {
    await perform("Interface and logging saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setInterface(desiredInterface, configPath: configPath)
      lastCommandOutput += try await service.setLogPath(desiredLogPath, configPath: configPath)
      lastCommandOutput += try await service.setVerboseLog(desiredVerboseLog, configPath: configPath)
      await refreshConfig()
    }
  }

  public func saveDaemonFlags() async {
    await perform("Daemon flags saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setDaemonReloadOnSighup(desiredReloadOnSighup, configPath: configPath)
      lastCommandOutput += try await service.setDaemonExitOnConfigError(desiredExitOnConfigError, configPath: configPath)
      await refreshConfig()
    }
  }

  public func saveDenyPatterns() async {
    await perform("Deny patterns saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setDenyPatterns(lines(from: denyPatternsText), configPath: configPath)
      await refreshConfig()
    }
  }

  public func saveAllowRemoteHosts() async {
    await perform("Remote host allowlist saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setAllowRemoteHosts(lines(from: allowRemoteHostsText), configPath: configPath)
      await refreshConfig()
    }
  }

  public func addTrustedPublisher(_ app: DiscoveredApp) async {
    await perform("Trusted publisher added. Reload daemon when ready.") {
      lastCommandOutput = try await service.addTrustedPublisher(app, configPath: configPath)
      await refreshConfig()
    }
  }

  public func removeTrustedPublisher(name: String) async {
    await perform("Trusted publisher removed. Reload daemon when ready.") {
      lastCommandOutput = try await service.removeTrustedPublisher(name: name, configPath: configPath)
      await refreshConfig()
    }
  }

  public func startEditingTrustedPublisher(_ item: TrustedPublisherItem) {
    editingPublisherName = item.name
    publisherEditForm = TrustedPublisherEditForm(originalName: item.name, name: item.name, rule: item.rule)
  }

  public func cancelEditingTrustedPublisher() {
    editingPublisherName = nil
    publisherEditForm = TrustedPublisherEditForm()
  }

  public func saveTrustedPublisher() async {
    await perform("Trusted publisher saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setTrustedPublisher(publisherEditForm, configPath: configPath)
      cancelEditingTrustedPublisher()
      await refreshConfig()
    }
  }

  public func addPathOnlyAllowForApp(_ app: DiscoveredApp) async {
    await perform("Path-only allow added. Reload daemon when ready.") {
      lastCommandOutput = try await service.addAllowProcess(name: app.displayName, path: app.executablePath, configPath: configPath)
      await refreshConfig()
    }
  }

  public func addPathOnlyAllowForAppBundle(_ app: DiscoveredApp) async {
    await perform("Path-only app bundle allow added. Reload daemon when ready.") {
      lastCommandOutput = try await service.addAllowProcess(name: app.displayName, path: "\(app.bundlePath)/Contents/*", configPath: configPath)
      await refreshConfig()
    }
  }

  public func addPresetPathOnlyAllow(name: String, path: String) async {
    await perform("Path-only allow added. Reload daemon when ready.") {
      lastCommandOutput = try await service.addAllowProcess(name: name, path: path, configPath: configPath)
      await refreshConfig()
    }
  }

  public func addPathOnlyAllow() async {
    await perform("Path-only allow added. Reload daemon when ready.") {
      lastCommandOutput = try await service.addAllowProcess(allowProcessForm, configPath: configPath)
      allowProcessForm = AllowProcessForm()
      await refreshConfig()
    }
  }

  public func startEditingPathOnlyAllow(_ item: AllowProcessItem) {
    editingAllowProcessName = item.name
    allowProcessEditForm = AllowProcessEditForm(originalName: item.name, name: item.name, paths: item.rule.paths)
  }

  public func cancelEditingPathOnlyAllow() {
    editingAllowProcessName = nil
    allowProcessEditForm = AllowProcessEditForm()
  }

  public func savePathOnlyAllow() async {
    await perform("Path-only allow saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setAllowProcess(allowProcessEditForm, configPath: configPath)
      cancelEditingPathOnlyAllow()
      await refreshConfig()
    }
  }

  public func removePathOnlyAllow(name: String) async {
    await perform("Path-only allow removed. Reload daemon when ready.") {
      lastCommandOutput = try await service.removeAllowProcess(name: name, configPath: configPath)
      await refreshConfig()
    }
  }

  public func addTrustedWorkspace() async {
    await perform("Trusted workspace added. Reload daemon when ready.") {
      lastCommandOutput = try await service.addTrustedWorkspace(workspaceForm, configPath: configPath)
      workspaceForm = WorkspaceForm()
      await refreshConfig()
    }
  }

  public func removeTrustedWorkspace(name: String) async {
    await perform("Trusted workspace removed. Reload daemon when ready.") {
      lastCommandOutput = try await service.removeTrustedWorkspace(name: name, configPath: configPath)
      await refreshConfig()
    }
  }

  public func startEditingTrustedWorkspace(_ item: TrustedWorkspaceItem) {
    editingWorkspaceName = item.name
    workspaceEditForm = WorkspaceEditForm(originalName: item.name, name: item.name, rule: item.rule)
  }

  public func cancelEditingTrustedWorkspace() {
    editingWorkspaceName = nil
    workspaceEditForm = WorkspaceEditForm()
  }

  public func saveTrustedWorkspace() async {
    await perform("Trusted workspace saved. Reload daemon when ready.") {
      lastCommandOutput = try await service.setTrustedWorkspace(workspaceEditForm, configPath: configPath)
      cancelEditingTrustedWorkspace()
      await refreshConfig()
    }
  }

  public func reloadDaemon() async {
    await perform("Daemon reload requested.") {
      lastCommandOutput = try await service.reloadDaemon()
      await refreshStatus()
    }
  }

  private func perform(_ success: String, _ work: () async throws -> Void) async {
    service.binaryPath = binaryPath
    isLoading = true
    defer { isLoading = false }
    do {
      try await work()
      lastCommandOutput = service.lastResult?.stdout ?? lastCommandOutput
      lastMessage = success
    } catch {
      let message = error.localizedDescription
      lastMessage = message
      recentErrors.insert(message, at: 0)
      recentErrors = Array(recentErrors.prefix(6))
    }
  }

  private func lines(from text: String) -> [String] {
    text.components(separatedBy: .newlines)
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
  }

  private func pathMatches(_ rulePath: String, executable: String, bundle: String) -> Bool {
    if rulePath == executable { return true }
    if rulePath.hasSuffix("*") {
      return executable.hasPrefix(String(rulePath.dropLast()))
    }
    return rulePath.hasPrefix(bundle + "/")
  }
}
