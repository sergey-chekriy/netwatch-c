import Foundation
import NetwatchConfiguratorCore

private enum TestFailure: Error, CustomStringConvertible {
  case failed(String)
  var description: String {
    switch self {
    case .failed(let message): return message
    }
  }
}

private final class FakeRunner: CommandRunning {
  var results: [CommandResult]
  var calls: [(String, [String], TimeInterval)] = []

  init(_ results: [CommandResult]) {
    self.results = results
  }

  func run(executable: String, arguments: [String], timeout: TimeInterval) async -> CommandResult {
    calls.append((executable, arguments, timeout))
    return results.isEmpty ? CommandResult(stdout: "", stderr: "missing fake result", exitCode: 1) : results.removeFirst()
  }
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw TestFailure.failed(message) }
}

@main
struct NetwatchConfiguratorSelfTest {
  static func main() async throws {
    try await statusJSONDecodingAndMapping()
    try dryRunMapsToOrangeAttention()
    try attentionAndErrorMapToRed()
    try await discoveredAppsJSONDecoding()
    try await configSummaryJSONDecoding()
    try trustedPublisherLookupUsesExecutablePath()
    try await runnerFailureIsStructured()
    try await timeoutHandling()
    try await fakeRunnerSuccessRecordsArguments()
    try await advancedSettingsCommands()
    try await trustedPublisherEditCommand()
    try await allowProcessCommands()
    try await workspaceCommands()
    try workspaceFormValidation()
    try allowProcessFormValidation()
    try allowProcessEditFormValidation()
    try configPathWritableBehavior()
    print("NetwatchConfiguratorSelfTest OK")
  }

  private static func statusJSONDecodingAndMapping() async throws {
    let now = Int64(Date().timeIntervalSince1970)
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: FakeRunner([
      CommandResult(stdout: """
      {"version":1,"status":"ok","daemonRunning":true,"configValid":true,"dryRun":false,"lastScanAt":\(now),"lastScanResult":"ok","unknownCount":0,"wouldDisableWifi":false,"wifiDisabled":false,"activeConfigPath":"/tmp/config.json","pollIntervalSeconds":300}
      """, stderr: "", exitCode: 0)
    ]))
    let status = try await service.status()
    try expect(status.activeConfigPath == "/tmp/config.json", "status activeConfigPath decode")
    try expect(DashboardStatusMapper.indicator(for: status) == .green, "ok maps to green")
  }

  private static func dryRunMapsToOrangeAttention() throws {
    let now = Int64(Date().timeIntervalSince1970)
    let status = try JSONDecoder().decode(StatusSnapshot.self, from: Data("""
    {"version":1,"status":"ok","daemonRunning":true,"configValid":true,"dryRun":true,"lastScanAt":\(now),"lastScanResult":"ok","unknownCount":0,"wouldDisableWifi":false,"wifiDisabled":false,"activeConfigPath":"/tmp/config.json","pollIntervalSeconds":300}
    """.utf8))
    try expect(DashboardStatusMapper.indicator(for: status) == .orange, "dryRun maps to orange")
    try expect(DashboardStatusMapper.indicator(for: nil) == .gray, "nil maps to gray")
  }

  private static func attentionAndErrorMapToRed() throws {
    let now = Int64(Date().timeIntervalSince1970)
    let base = """
    {"version":1,"status":"%@","daemonRunning":true,"configValid":true,"dryRun":false,"lastScanAt":\(now),"lastScanResult":"error","unknownCount":0,"wouldDisableWifi":false,"wifiDisabled":false,"activeConfigPath":"/tmp/config.json","pollIntervalSeconds":300}
    """
    for value in ["attention", "error"] {
      let status = try JSONDecoder().decode(StatusSnapshot.self, from: Data(String(format: base, value).utf8))
      try expect(DashboardStatusMapper.indicator(for: status) == .red, "\(value) maps to red")
    }
  }

  private static func discoveredAppsJSONDecoding() async throws {
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: FakeRunner([
      CommandResult(stdout: """
      {"apps":[{"displayName":"Chrome","bundlePath":"/Applications/Chrome.app","executablePath":"/Applications/Chrome.app/Contents/MacOS/Chrome","signingIdentifier":"com.google.Chrome","teamId":"TEAM","signatureValid":true,"appleSigned":false,"suitableTrustedPublisher":true}]}
      """, stderr: "", exitCode: 0)
    ]))
    let apps = try await service.discoverApps()
    try expect(apps.count == 1, "discover app count")
    try expect(apps[0].suitableTrustedPublisher, "discover suitability")
  }

  private static func configSummaryJSONDecoding() async throws {
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: FakeRunner([
      CommandResult(stdout: """
      {"version":2,"dryRun":true,"daemon":{"pollIntervalSeconds":300,"reloadOnSighup":true,"exitOnConfigError":false},"allowAppleSystemComponents":true,"interface":"Wi-Fi","logPath":"/tmp/netwatch.log","verboseLog":true,"denyPatterns":["bad"],"allowRemoteHosts":["17."],"allowProcesses":{"ssh":"/usr/bin/ssh","tool":["/a","/b"]},"trustedPublishers":{"Chrome":{"paths":["/a"],"teamId":"TEAM","signingIdentifier":"id"}},"trustedWorkspaces":{"scripts":{"roots":["/r"],"allowSubdirectories":true,"interpreters":["/bin/zsh"],"allowByCwdOnly":false}}}
      """, stderr: "", exitCode: 0)
    ]))
    let summary = try await service.configSummary(configPath: "/tmp/config.json")
    try expect(summary.allowAppleSystemComponents == true, "apple trust decode")
    try expect(summary.interface == "Wi-Fi", "interface decode")
    try expect(summary.logPath == "/tmp/netwatch.log", "log path decode")
    try expect(summary.verboseLog == true, "verbose log decode")
    try expect(summary.denyPatterns == ["bad"], "deny patterns decode")
    try expect(summary.allowRemoteHosts == ["17."], "remote hosts decode")
    try expect(summary.daemon?.reloadOnSighup == true, "daemon reload decode")
    try expect(summary.daemon?.exitOnConfigError == false, "daemon exit decode")
    try expect(summary.publisherItems.map(\.name) == ["Chrome"], "publisher summary decode")
    try expect(summary.workspaceItems.map(\.name) == ["scripts"], "workspace summary decode")
    try expect(summary.allowProcessItems.map(\.name) == ["ssh", "tool"], "allow process summary decode")
    try expect(summary.allowProcesses?["tool"]?.paths == ["/a", "/b"], "allow process array decode")
  }

  @MainActor private static func trustedPublisherLookupUsesExecutablePath() throws {
    let viewModel = ConfiguratorViewModel(service: NetwatchService(binaryPath: "/tmp/netwatch", runner: FakeRunner([])))
    viewModel.config = try JSONDecoder().decode(ConfigSummary.self, from: Data(#"""
    {"trustedPublishers":{"\u200eWhatsApp":{"paths":["/Applications/WhatsApp.app/Contents/MacOS/WhatsApp"],"teamId":"57T9237FN3","signingIdentifier":"net.whatsapp.WhatsApp"}}}
    """#.utf8))
    let app = try JSONDecoder().decode(DiscoveredApp.self, from: Data("""
    {"displayName":"WhatsApp","bundlePath":"/Applications/WhatsApp.app","executablePath":"/Applications/WhatsApp.app/Contents/MacOS/WhatsApp","signingIdentifier":"net.whatsapp.WhatsApp","teamId":"57T9237FN3","signatureValid":true,"appleSigned":false,"suitableTrustedPublisher":true}
    """.utf8))
    try expect(viewModel.trustedPublisherName(for: app) == "\u{200E}WhatsApp", "trusted publisher path lookup")
  }

  private static func runnerFailureIsStructured() async throws {
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: FakeRunner([
      CommandResult(stdout: "", stderr: "bad config", exitCode: 2)
    ]))
    do {
      _ = try await service.checkConfig(configPath: "/tmp/config.json")
      throw TestFailure.failed("expected command failure")
    } catch {
      try expect(error.localizedDescription.contains("bad config"), "command failure stderr")
    }
  }

  private static func timeoutHandling() async throws {
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: FakeRunner([
      CommandResult(stdout: "", stderr: "", exitCode: -1, timedOut: true)
    ]))
    do {
      _ = try await service.status()
      throw TestFailure.failed("expected timeout")
    } catch {
      try expect(error.localizedDescription.contains("timed out"), "timeout error")
    }
  }

  private static func fakeRunnerSuccessRecordsArguments() async throws {
    let runner = FakeRunner([CommandResult(stdout: "Config OK.\n", stderr: "", exitCode: 0)])
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: runner)
    let output = try await service.checkConfig(configPath: "/tmp/config.json")
    try expect(output == "Config OK.\n", "runner success")
    try expect(runner.calls.first?.1 == ["--check-config", "/tmp/config.json"], "runner args")
  }

  private static func advancedSettingsCommands() async throws {
    let config = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString).path
    FileManager.default.createFile(atPath: config, contents: Data("{}".utf8))
    let runner = FakeRunner(Array(repeating: CommandResult(stdout: "ok\n", stderr: "", exitCode: 0), count: 8))
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: runner)
    _ = try await service.setAppleSystemTrust(true, configPath: config)
    _ = try await service.setInterface("Wi-Fi", configPath: config)
    _ = try await service.setLogPath("/tmp/netwatch.log", configPath: config)
    _ = try await service.setVerboseLog(true, configPath: config)
    _ = try await service.setDaemonReloadOnSighup(false, configPath: config)
    _ = try await service.setDaemonExitOnConfigError(true, configPath: config)
    _ = try await service.setDenyPatterns(["bad", ":4444"], configPath: config)
    _ = try await service.setAllowRemoteHosts(["17."], configPath: config)
    try expect(runner.calls[0].1 == ["--config-set-apple-system-trust", "true", "--config", config], "set apple trust args")
    try expect(runner.calls[1].1 == ["--config-set-interface", "Wi-Fi", "--config", config], "set interface args")
    try expect(runner.calls[2].1 == ["--config-set-log-path", "/tmp/netwatch.log", "--config", config], "set log path args")
    try expect(runner.calls[3].1 == ["--config-set-verbose-log", "true", "--config", config], "set verbose log args")
    try expect(runner.calls[4].1 == ["--config-set-daemon-reload-on-sighup", "false", "--config", config], "set daemon reload args")
    try expect(runner.calls[5].1 == ["--config-set-daemon-exit-on-config-error", "true", "--config", config], "set daemon exit args")
    try expect(runner.calls[6].1 == ["--config-set-deny-patterns", "--value", "bad", "--value", ":4444", "--config", config], "set deny args")
    try expect(runner.calls[7].1 == ["--config-set-allow-remote-hosts", "--value", "17.", "--config", config], "set remote args")
  }

  private static func allowProcessCommands() async throws {
    let config = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString).path
    FileManager.default.createFile(atPath: config, contents: Data("{}".utf8))
    let runner = FakeRunner([
      CommandResult(stdout: "added\n", stderr: "", exitCode: 0),
      CommandResult(stdout: "set\n", stderr: "", exitCode: 0),
      CommandResult(stdout: "removed\n", stderr: "", exitCode: 0)
    ])
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: runner)
    _ = try await service.addAllowProcess(name: "ssh", path: "/usr/bin/ssh", configPath: config)
    _ = try await service.setAllowProcess(
      AllowProcessEditForm(originalName: "ssh", name: "remote tools", paths: ["/usr/bin/ssh", "/usr/bin/scp"]),
      configPath: config
    )
    _ = try await service.removeAllowProcess(name: "ssh", configPath: config)
    try expect(runner.calls[0].1 == ["--config-add-allow-process", "ssh", "--path", "/usr/bin/ssh", "--config", config], "add allow process args")
    try expect(runner.calls[1].1 == ["--config-set-allow-process", "ssh", "--name", "remote tools", "--path", "/usr/bin/ssh", "--path", "/usr/bin/scp", "--config", config], "set allow process args")
    try expect(runner.calls[2].1 == ["--config-remove-allow-process", "ssh", "--config", config], "remove allow process args")
  }

  private static func trustedPublisherEditCommand() async throws {
    let config = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString).path
    FileManager.default.createFile(atPath: config, contents: Data("{}".utf8))
    let runner = FakeRunner([CommandResult(stdout: "set\n", stderr: "", exitCode: 0)])
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: runner)
    _ = try await service.setTrustedPublisher(
      TrustedPublisherEditForm(
        originalName: "Chrome",
        name: "Chrome Stable",
        rule: TrustedPublisherRule(paths: ["/Applications/Chrome.app/Contents/MacOS/Chrome", "/Applications/Chrome.app/Contents/Helpers/Helper"], teamId: "TEAM", signingIdentifier: "id")
      ),
      configPath: config
    )
    try expect(runner.calls[0].1 == [
      "--config-set-trusted-publisher", "Chrome",
      "--name", "Chrome Stable",
      "--path", "/Applications/Chrome.app/Contents/MacOS/Chrome",
      "--path", "/Applications/Chrome.app/Contents/Helpers/Helper",
      "--team-id", "TEAM",
      "--signing-identifier", "id",
      "--config", config
    ], "set trusted publisher args")
  }

  private static func workspaceCommands() async throws {
    let tmp = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    let interpreter = tmp.appendingPathComponent("node")
    FileManager.default.createFile(atPath: interpreter.path, contents: Data("#!/bin/sh\n".utf8))
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: interpreter.path)
    let config = tmp.appendingPathComponent("config.json").path
    FileManager.default.createFile(atPath: config, contents: Data("{}".utf8))
    let runner = FakeRunner([
      CommandResult(stdout: "added\n", stderr: "", exitCode: 0),
      CommandResult(stdout: "set\n", stderr: "", exitCode: 0)
    ])
    let service = NetwatchService(binaryPath: "/tmp/netwatch", runner: runner)
    var form = WorkspaceForm()
    form.name = "scripts"
    form.root = tmp.path
    form.interpreter = interpreter.path
    form.allowSubdirectories = false
    form.allowByCwdOnly = true
    _ = try await service.addTrustedWorkspace(form, configPath: config)
    _ = try await service.setTrustedWorkspace(
      WorkspaceEditForm(originalName: "scripts", name: "scripts2", rule: TrustedWorkspaceRule(roots: [tmp.path], allowSubdirectories: true, interpreters: [interpreter.path], allowByCwdOnly: false)),
      configPath: config
    )
    try expect(runner.calls[0].1 == [
      "--config-set-trusted-workspace", "scripts",
      "--name", "scripts",
      "--root", tmp.path,
      "--interpreter", interpreter.path,
      "--allow-subdirectories", "false",
      "--allow-by-cwd-only", "true",
      "--config", config
    ], "add workspace preserves toggles")
    try expect(runner.calls[1].1 == [
      "--config-set-trusted-workspace", "scripts",
      "--name", "scripts2",
      "--root", tmp.path,
      "--interpreter", interpreter.path,
      "--allow-subdirectories", "true",
      "--allow-by-cwd-only", "false",
      "--config", config
    ], "set workspace args")
  }

  private static func workspaceFormValidation() throws {
    let tmp = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    let interpreter = tmp.appendingPathComponent("node")
    FileManager.default.createFile(atPath: interpreter.path, contents: Data("#!/bin/sh\n".utf8))
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: interpreter.path)

    var form = WorkspaceForm()
    form.name = "scripts"
    form.root = tmp.path
    form.interpreter = interpreter.path
    try expect(form.validationError() == nil, "workspace form valid")

    form.allowByCwdOnly = true
    try expect(form.validationError() == nil, "workspace cwd-only now supported")
  }

  private static func allowProcessFormValidation() throws {
    try expect(AllowProcessForm(name: "ssh", path: "/usr/bin/ssh").validationError() == nil, "allow form exact")
    try expect(AllowProcessForm(name: "App", path: "/Applications/App.app/Contents/*").validationError() == nil, "allow form wildcard")
    try expect(AllowProcessForm(name: "", path: "/usr/bin/ssh").validationError() == "Allow rule name is required.", "allow form name required")
    try expect(AllowProcessForm(name: "bad", path: "/Applications/*/bad").validationError() == "Wildcard is supported only as a final *.", "allow form wildcard final")
  }

  private static func allowProcessEditFormValidation() throws {
    var form = AllowProcessEditForm(originalName: "ssh", name: "remote tools", paths: ["/usr/bin/ssh", "/usr/bin/scp"])
    try expect(form.validationError() == nil, "allow edit form valid")
    form.pathsText = "/usr/bin/ssh\n/usr/bin/ssh"
    try expect(form.validationError() == "Duplicate paths are not allowed.", "allow edit duplicate paths")
    form.pathsText = "relative"
    try expect(form.validationError() == "Path must be absolute.", "allow edit absolute paths")
  }

  private static func configPathWritableBehavior() throws {
    let file = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    FileManager.default.createFile(atPath: file.path, contents: Data("{}".utf8))
    try expect(ConfigPermission.isWritable(path: file.path), "config writable")
    try expect(!ConfigPermission.isWritable(path: file.appendingPathComponent("missing").path), "missing config not writable")
  }
}
