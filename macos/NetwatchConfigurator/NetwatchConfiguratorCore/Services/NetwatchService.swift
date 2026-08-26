import Foundation

public enum NetwatchServiceError: LocalizedError, Equatable {
  case timeout
  case commandFailed(String)
  case invalidJSON(String)
  case configNotWritable(String)

  public var errorDescription: String? {
    switch self {
    case .timeout:
      return "netwatch command timed out."
    case .commandFailed(let message):
      return message
    case .invalidJSON(let message):
      return "Invalid backend JSON: \(message)"
    case .configNotWritable(let path):
      return "Config is not writable: \(path)"
    }
  }
}

public final class NetwatchService {
  public var binaryPath: String
  public let runner: CommandRunning
  public private(set) var lastResult: CommandResult?

  public init(binaryPath: String = NetwatchBinaryLocator.defaultPath(), runner: CommandRunning = ProcessCommandRunner()) {
    self.binaryPath = binaryPath
    self.runner = runner
  }

  public func run(arguments: [String], timeout: TimeInterval = 20) async -> CommandResult {
    let result = await runner.run(executable: binaryPath, arguments: arguments, timeout: timeout)
    lastResult = result
    return result
  }

  public func status() async throws -> StatusSnapshot {
    try decode(StatusSnapshot.self, from: await run(arguments: ["--status-json"], timeout: 10))
  }

  public func discoverApps() async throws -> [DiscoveredApp] {
    try decode(DiscoveredAppsResponse.self, from: await run(arguments: ["--discover-apps", "--json"], timeout: 60)).apps
  }

  public func configSummary(configPath: String) async throws -> ConfigSummary {
    try decode(ConfigSummary.self, from: await run(arguments: ["--config-show", "--config", configPath], timeout: 10))
  }

  public func checkConfig(configPath: String) async throws -> String {
    try checked(await run(arguments: ["--check-config", configPath], timeout: 20))
  }

  public func setDryRun(_ value: Bool, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-set-dry-run", value ? "true" : "false",
      "--config", configPath
    ]))
  }

  public func setAppleSystemTrust(_ value: Bool, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-set-apple-system-trust", value ? "true" : "false",
      "--config", configPath
    ]))
  }

  public func setInterface(_ value: String, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-set-interface", value,
      "--config", configPath
    ]))
  }

  public func setLogPath(_ value: String, configPath: String) async throws -> String {
    if !value.isEmpty && !value.hasPrefix("/") { throw NetwatchServiceError.commandFailed("logPath must be absolute or empty.") }
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-set-log-path", value,
      "--config", configPath
    ]))
  }

  public func setVerboseLog(_ value: Bool, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-set-verbose-log", value ? "true" : "false",
      "--config", configPath
    ]))
  }

  public func setPollInterval(_ seconds: Int, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-set-poll-interval", "\(seconds)",
      "--config", configPath
    ]))
  }

  public func setDaemonReloadOnSighup(_ value: Bool, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-set-daemon-reload-on-sighup", value ? "true" : "false",
      "--config", configPath
    ]))
  }

  public func setDaemonExitOnConfigError(_ value: Bool, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-set-daemon-exit-on-config-error", value ? "true" : "false",
      "--config", configPath
    ]))
  }

  public func setDenyPatterns(_ values: [String], configPath: String) async throws -> String {
    try await setStringArray(command: "--config-set-deny-patterns", values: values, configPath: configPath)
  }

  public func setAllowRemoteHosts(_ values: [String], configPath: String) async throws -> String {
    try await setStringArray(command: "--config-set-allow-remote-hosts", values: values, configPath: configPath)
  }

  public func addTrustedPublisher(_ app: DiscoveredApp, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-add-trusted-publisher", app.displayName,
      "--path", app.executablePath,
      "--team-id", app.teamId,
      "--signing-identifier", app.signingIdentifier,
      "--config", configPath
    ], timeout: 20))
  }

  public func setTrustedPublisher(_ form: TrustedPublisherEditForm, configPath: String) async throws -> String {
    if let error = form.validationError() { throw NetwatchServiceError.commandFailed(error) }
    try ensureWritable(configPath)
    var arguments = [
      "--config-set-trusted-publisher", form.originalName,
      "--name", form.name
    ]
    for path in form.paths {
      arguments.append("--path")
      arguments.append(path)
    }
    arguments.append(contentsOf: [
      "--team-id", form.teamId,
      "--signing-identifier", form.signingIdentifier,
      "--config", configPath
    ])
    return try checked(await run(arguments: arguments, timeout: 20))
  }

  public func removeTrustedPublisher(name: String, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-remove-trusted-publisher", name,
      "--config", configPath
    ]))
  }

  public func addAllowProcess(_ form: AllowProcessForm, configPath: String) async throws -> String {
    if let error = form.validationError() { throw NetwatchServiceError.commandFailed(error) }
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-add-allow-process", form.name,
      "--path", form.path,
      "--config", configPath
    ]))
  }

  public func addAllowProcess(name: String, path: String, configPath: String) async throws -> String {
    try await addAllowProcess(AllowProcessForm(name: name, path: path), configPath: configPath)
  }

  public func setAllowProcess(_ form: AllowProcessEditForm, configPath: String) async throws -> String {
    if let error = form.validationError() { throw NetwatchServiceError.commandFailed(error) }
    try ensureWritable(configPath)
    var arguments = [
      "--config-set-allow-process", form.originalName,
      "--name", form.name
    ]
    for path in form.paths {
      arguments.append("--path")
      arguments.append(path)
    }
    arguments.append("--config")
    arguments.append(configPath)
    return try checked(await run(arguments: arguments))
  }

  public func removeAllowProcess(name: String, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-remove-allow-process", name,
      "--config", configPath
    ]))
  }

  public func addTrustedWorkspace(_ form: WorkspaceForm, configPath: String) async throws -> String {
    if let error = form.validationError() { throw NetwatchServiceError.commandFailed(error) }
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-set-trusted-workspace", form.name,
      "--name", form.name,
      "--root", form.root,
      "--interpreter", form.interpreter,
      "--allow-subdirectories", form.allowSubdirectories ? "true" : "false",
      "--allow-by-cwd-only", form.allowByCwdOnly ? "true" : "false",
      "--config", configPath
    ]))
  }

  public func setTrustedWorkspace(_ form: WorkspaceEditForm, configPath: String) async throws -> String {
    if let error = form.validationError() { throw NetwatchServiceError.commandFailed(error) }
    try ensureWritable(configPath)
    var arguments = [
      "--config-set-trusted-workspace", form.originalName,
      "--name", form.name
    ]
    for root in form.roots {
      arguments.append("--root")
      arguments.append(root)
    }
    for interpreter in form.interpreters {
      arguments.append("--interpreter")
      arguments.append(interpreter)
    }
    arguments.append(contentsOf: [
      "--allow-subdirectories", form.allowSubdirectories ? "true" : "false",
      "--allow-by-cwd-only", form.allowByCwdOnly ? "true" : "false",
      "--config", configPath
    ])
    return try checked(await run(arguments: arguments))
  }

  public func removeTrustedWorkspace(name: String, configPath: String) async throws -> String {
    try ensureWritable(configPath)
    return try checked(await run(arguments: [
      "--config-remove-trusted-workspace", name,
      "--config", configPath
    ]))
  }

  public func reloadDaemon() async throws -> String {
    try checked(await run(arguments: ["--reload-daemon"], timeout: 10))
  }

  private func ensureWritable(_ configPath: String) throws {
    if !ConfigPermission.isWritable(path: configPath) {
      throw NetwatchServiceError.configNotWritable(configPath)
    }
  }

  private func setStringArray(command: String, values: [String], configPath: String) async throws -> String {
    try ensureWritable(configPath)
    var arguments = [command]
    for value in values {
      arguments.append("--value")
      arguments.append(value)
    }
    arguments.append("--config")
    arguments.append(configPath)
    return try checked(await run(arguments: arguments))
  }

  private func decode<T: Decodable>(_ type: T.Type, from result: CommandResult) throws -> T {
    let text = try checked(result)
    do {
      return try JSONDecoder().decode(type, from: text.data(using: .utf8) ?? Data())
    } catch {
      throw NetwatchServiceError.invalidJSON(error.localizedDescription)
    }
  }

  private func checked(_ result: CommandResult) throws -> String {
    if result.timedOut { throw NetwatchServiceError.timeout }
    if result.succeeded { return result.stdout }
    let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
    throw NetwatchServiceError.commandFailed(detail.isEmpty ? "netwatch exited with status \(result.exitCode)" : detail)
  }
}
