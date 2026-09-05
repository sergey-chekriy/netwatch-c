import AppKit
import NetwatchConfiguratorCore
import SwiftUI

private enum ConfigSection: String, CaseIterable, Identifiable {
  case dashboard = "Dashboard"
  case applications = "Applications"
  case pathOnlyAllows = "Path-only Allows"
  case workspaces = "Workspaces"
  case settings = "Settings"
  case diagnostics = "Diagnostics"
  var id: String { rawValue }
}

struct ContentView: View {
  @ObservedObject var viewModel: ConfiguratorViewModel
  @State private var selection: ConfigSection? = .dashboard

  var body: some View {
    NavigationSplitView {
      List(ConfigSection.allCases, selection: $selection) { section in
        Text(section.rawValue).tag(section)
      }
      .navigationTitle("Netwatch")
    } detail: {
      ScrollView {
        VStack(alignment: .leading, spacing: 18) {
          switch selection ?? .dashboard {
          case .dashboard: DashboardView(viewModel: viewModel)
          case .applications: ApplicationsView(viewModel: viewModel)
          case .pathOnlyAllows: PathOnlyAllowsView(viewModel: viewModel)
          case .workspaces: WorkspacesView(viewModel: viewModel)
          case .settings: SettingsView(viewModel: viewModel)
          case .diagnostics: DiagnosticsView(viewModel: viewModel)
          }
        }
        .padding(24)
        .frame(maxWidth: .infinity, alignment: .leading)
      }
    }
    .task { await viewModel.refreshAll() }
    .onChange(of: selection) { section in
      if section == .dashboard { Task { await viewModel.refreshStatus() } }
    }
  }
}

private struct DashboardView: View {
  @ObservedObject var viewModel: ConfiguratorViewModel

  var body: some View {
    sectionTitle("Dashboard")
    HStack(spacing: 10) {
      Circle().fill(color(viewModel.indicator)).frame(width: 14, height: 14)
      Text(viewModel.indicator.rawValue.uppercased()).font(.headline)
    }
    if let status = viewModel.status {
      info("Daemon", status.daemonRunning ? "running" : "not running")
      info("Protection status", status.status)
      info("Dry run", status.dryRun ? "on" : "off")
      if status.dryRun {
        Text("Dry run is enabled. Wi-Fi will not be disabled.")
          .foregroundStyle(.red)
          .font(.callout.weight(.semibold))
      }
      info("Last scan", formatTime(status.lastScanAt))
      info("Last scan result", status.lastScanResult)
      info("Unknown processes", "\(status.unknownCount)")
      info("Wi-Fi enforcement", status.wifiDisabled ? "disabled" : (status.wouldDisableWifi ? "would disable" : "idle"))
      info("Active config", status.activeConfigPath)
      info("Poll interval", "\(status.pollIntervalSeconds)s")
      info("netwatch version", "not reported by backend")
    } else {
      Text("Status unavailable. Check that the daemon has written a status snapshot.")
        .foregroundStyle(.secondary)
    }
    buttonRow {
      Button("Refresh") { Task { await viewModel.refreshStatus() } }
      Button("Reload daemon") { Task { await viewModel.reloadDaemon() } }
      Button("Check config") { Task { await viewModel.checkConfig() } }
      Button("Open config file") { openPath(viewModel.configPath) }
      Button("Open logs") { openPath("~/.watch") }
    }
    statusLine(viewModel)
  }
}

private struct ApplicationsView: View {
  @ObservedObject var viewModel: ConfiguratorViewModel

  var body: some View {
    sectionTitle("Applications")
    HStack {
      TextField("Search apps", text: $viewModel.searchText)
      Button("Discover") { Task { await viewModel.discoverApps() } }
    }
    sectionTitle("Configured Trusted Publishers")
    ForEach(viewModel.config?.publisherItems ?? []) { item in
      VStack(alignment: .leading, spacing: 8) {
        if viewModel.editingPublisherName == item.name {
          TextField("Publisher name", text: $viewModel.publisherEditForm.name)
          Text("Executable paths").font(.headline)
          TextEditor(text: $viewModel.publisherEditForm.pathsText)
            .font(.system(.body, design: .monospaced))
            .frame(minHeight: 78)
          TextField("Team ID", text: $viewModel.publisherEditForm.teamId)
          TextField("Signing identifier", text: $viewModel.publisherEditForm.signingIdentifier)
          buttonRow {
            Button("Add executable") { chooseFile { viewModel.publisherEditForm.pathsText = appendLine(viewModel.publisherEditForm.pathsText, $0) } }
            Button("Save") { Task { await viewModel.saveTrustedPublisher() } }
            Button("Cancel") { viewModel.cancelEditingTrustedPublisher() }
          }
        } else {
          HStack {
            Text(item.name).font(.headline)
            Spacer()
            Button("Edit") { viewModel.startEditingTrustedPublisher(item) }
            Button("Remove") { Task { await viewModel.removeTrustedPublisher(name: item.name) } }
          }
          info("Paths", item.rule.paths.joined(separator: "\n"))
          info("Team ID", item.rule.teamId)
          info("Signing ID", item.rule.signingIdentifier)
        }
      }
      .padding(12)
      .background(.quaternary.opacity(0.4))
      .clipShape(RoundedRectangle(cornerRadius: 8))
    }
    sectionTitle("Configured Trusted App Bundles")
    ForEach(viewModel.config?.appBundleItems ?? []) { item in
      VStack(alignment: .leading, spacing: 8) {
        HStack {
          Text(item.name).font(.headline)
          Spacer()
          Button("Remove") { Task { await viewModel.removeTrustedAppBundle(name: item.name) } }
        }
        info("Bundle root", item.rule.bundleRoot)
        info("Team ID", item.rule.teamId)
        info("Signing IDs", item.rule.allowedSigningIdentifiers.joined(separator: "\n"))
        info("Signing ID prefixes", item.rule.allowedSigningIdentifierPrefixes.joined(separator: "\n"))
        info("Subdirectories", item.rule.allowSubdirectories ? "allowed" : "not allowed")
      }
      .padding(12)
      .background(.quaternary.opacity(0.4))
      .clipShape(RoundedRectangle(cornerRadius: 8))
    }
    Divider()
    sectionTitle("Discovered Applications")
    ForEach(viewModel.filteredTopLevelApps) { app in
      let pathOnlyAllows = viewModel.pathOnlyAllows(for: app)
      let helpers = viewModel.helpers(for: app)
      VStack(alignment: .leading, spacing: 8) {
        HStack {
          Text(app.displayName).font(.headline)
          Spacer()
          Text(app.suitableTrustedPublisher ? "trustedPublisher-ready" : "not suitable")
            .foregroundStyle(app.suitableTrustedPublisher ? .green : .secondary)
        }
        info("Executable", app.executablePath)
        info("Signature", app.signatureValid ? "valid" : "invalid")
        info("Team ID", app.teamId.isEmpty ? "missing" : app.teamId)
        info("Signing ID", app.signingIdentifier.isEmpty ? "missing" : app.signingIdentifier)
        info("Apple-signed", app.appleSigned ? "yes" : "no")
        DisclosureGroup("Technical details") {
          info("Bundle", app.bundlePath)
        }
        HStack {
          if let publisherName = viewModel.trustedPublisherName(for: app) {
            Button("Remove trusted publisher") {
              Task { await viewModel.removeTrustedPublisher(name: publisherName) }
            }
          } else {
            Button("Add as trusted publisher") {
              Task { await viewModel.addTrustedPublisher(app) }
            }
            .disabled(!app.suitableTrustedPublisher)
          }
          if let bundleName = viewModel.trustedAppBundleName(for: app) {
            Button("Remove signed app helpers trust") {
              Task { await viewModel.removeTrustedAppBundle(name: bundleName) }
            }
          } else {
            Button("Add signed app helpers as trusted") {
              Task { await viewModel.addTrustedAppBundle(app) }
            }
            .disabled(!app.suitableTrustedPublisher)
          }
          Button("Add path-only exact") { Task { await viewModel.addPathOnlyAllowForApp(app) } }
          if !app.suitableTrustedPublisher {
            Button("Add path-only app bundle") { Task { await viewModel.addPathOnlyAllowForAppBundle(app) } }
          }
        }
        if !helpers.isEmpty {
          DisclosureGroup("Helpers (\(helpers.count))") {
            VStack(alignment: .leading, spacing: 10) {
              ForEach(helpers) { helper in
                VStack(alignment: .leading, spacing: 5) {
                  HStack {
                    Text(helper.displayName).font(.headline)
                    Spacer()
                    Text(helper.signedHelperCandidate ? "signed helper candidate" : "not suitable")
                      .foregroundStyle(helper.signedHelperCandidate ? .green : .secondary)
                  }
                  info("Executable", helper.executablePath)
                  info("Signature", helper.signatureValid ? "valid" : "invalid")
                  info("Team ID", helper.teamId.isEmpty ? "missing" : helper.teamId)
                  info("Signing ID", helper.signingIdentifier.isEmpty ? "missing" : helper.signingIdentifier)
                  if viewModel.trustedAppBundleName(for: helper) != nil {
                    Text("Inside configured trusted app bundle")
                      .font(.caption)
                      .foregroundStyle(.green)
                  }
                }
                .padding(.vertical, 4)
              }
            }
            .padding(.top, 6)
          }
        }
        if !pathOnlyAllows.isEmpty {
          VStack(alignment: .leading, spacing: 6) {
            Text("Matching path-only rules").font(.caption.weight(.semibold))
            ForEach(pathOnlyAllows) { item in
              HStack {
                Text(item.name)
                Spacer()
                Button("Edit") { viewModel.startEditingPathOnlyAllow(item) }
                Button("Remove") { Task { await viewModel.removePathOnlyAllow(name: item.name) } }
              }
            }
          }
          Text("Path-only allow is weaker than trusted publisher verification.")
            .font(.caption)
            .foregroundStyle(.orange)
        }
      }
      .padding(12)
      .background(.quaternary.opacity(0.4))
      .clipShape(RoundedRectangle(cornerRadius: 8))
    }
    statusLine(viewModel)
  }
}

private struct PathOnlyAllowsView: View {
  @ObservedObject var viewModel: ConfiguratorViewModel

  var body: some View {
    sectionTitle("Path-only Allows")
    Text("These legacy rules allow by process name and path only. Prefer trusted publishers when a signed app has stable Team ID and signing identifier.")
      .foregroundStyle(.secondary)
    ForEach(viewModel.config?.allowProcessItems ?? []) { item in
      VStack(alignment: .leading, spacing: 8) {
        if viewModel.editingAllowProcessName == item.name {
          TextField("Rule name", text: $viewModel.allowProcessEditForm.name)
          TextEditor(text: $viewModel.allowProcessEditForm.pathsText)
            .font(.system(.body, design: .monospaced))
            .frame(minHeight: 78)
          buttonRow {
            Button("Add executable") { chooseFile { viewModel.allowProcessEditForm.pathsText = appendLine(viewModel.allowProcessEditForm.pathsText, $0) } }
            Button("Save") { Task { await viewModel.savePathOnlyAllow() } }
            Button("Cancel") { viewModel.cancelEditingPathOnlyAllow() }
          }
        } else {
          HStack {
            Text(item.name).font(.headline)
            Spacer()
            Button("Edit") { viewModel.startEditingPathOnlyAllow(item) }
            Button("Remove") { Task { await viewModel.removePathOnlyAllow(name: item.name) } }
          }
          info("Paths", item.rule.paths.joined(separator: "\n"))
        }
      }
      .padding(12)
      .background(.quaternary.opacity(0.4))
      .clipShape(RoundedRectangle(cornerRadius: 8))
    }
    Divider()
    sectionTitle("Add Path-only Allow")
    buttonRow {
      Button("Add ssh") { Task { await viewModel.addPresetPathOnlyAllow(name: "ssh", path: "/usr/bin/ssh") } }
      Button("Add scp") { Task { await viewModel.addPresetPathOnlyAllow(name: "scp", path: "/usr/bin/scp") } }
    }
    TextField("Process name", text: $viewModel.allowProcessForm.name)
    HStack {
      TextField("Exact path or suffix wildcard, e.g. /Applications/Foo.app/Contents/*", text: $viewModel.allowProcessForm.path)
      Button("Choose") { chooseFile { viewModel.allowProcessForm.path = $0 } }
    }
    Button("Add path-only allow") { Task { await viewModel.addPathOnlyAllow() } }
    statusLine(viewModel)
  }
}

private struct WorkspacesView: View {
  @ObservedObject var viewModel: ConfiguratorViewModel

  var body: some View {
    sectionTitle("Workspaces")
    Text("Trusted workspace rules bind interpreters to explicit project roots.")
      .foregroundStyle(.secondary)
    ForEach(viewModel.config?.workspaceItems ?? []) { item in
      VStack(alignment: .leading, spacing: 8) {
        if viewModel.editingWorkspaceName == item.name {
          TextField("Workspace name", text: $viewModel.workspaceEditForm.name)
          Text("Roots").font(.headline)
          TextEditor(text: $viewModel.workspaceEditForm.rootsText)
            .font(.system(.body, design: .monospaced))
            .frame(minHeight: 78)
          Text("Interpreters").font(.headline)
          TextEditor(text: $viewModel.workspaceEditForm.interpretersText)
            .font(.system(.body, design: .monospaced))
            .frame(minHeight: 78)
          Toggle("Allow subdirectories", isOn: $viewModel.workspaceEditForm.allowSubdirectories)
          Toggle("Allow by cwd only", isOn: $viewModel.workspaceEditForm.allowByCwdOnly)
          buttonRow {
            Button("Add root") { chooseDirectory { viewModel.workspaceEditForm.rootsText = appendLine(viewModel.workspaceEditForm.rootsText, $0) } }
            Button("Add interpreter") { chooseFile { viewModel.workspaceEditForm.interpretersText = appendLine(viewModel.workspaceEditForm.interpretersText, $0) } }
            Button("Save") { Task { await viewModel.saveTrustedWorkspace() } }
            Button("Cancel") { viewModel.cancelEditingTrustedWorkspace() }
          }
        } else {
          HStack {
            Text(item.name).font(.headline)
            Spacer()
            Button("Edit") { viewModel.startEditingTrustedWorkspace(item) }
            Button("Remove") { Task { await viewModel.removeTrustedWorkspace(name: item.name) } }
          }
          info("Roots", item.rule.roots.joined(separator: "\n"))
          info("Interpreters", item.rule.interpreters.joined(separator: "\n"))
          info("allowSubdirectories", item.rule.allowSubdirectories ? "true" : "false")
          info("allowByCwdOnly", item.rule.allowByCwdOnly ? "true" : "false")
        }
      }
      .padding(12)
      .background(.quaternary.opacity(0.4))
      .clipShape(RoundedRectangle(cornerRadius: 8))
    }
    Divider()
    sectionTitle("Add Workspace")
    TextField("Name", text: $viewModel.workspaceForm.name)
    HStack {
      TextField("Root folder", text: $viewModel.workspaceForm.root)
      Button("Choose") { chooseDirectory { viewModel.workspaceForm.root = $0 } }
    }
    HStack {
      TextField("Interpreter executable", text: $viewModel.workspaceForm.interpreter)
      Button("Choose") { chooseFile { viewModel.workspaceForm.interpreter = $0 } }
    }
    Toggle("Allow subdirectories", isOn: $viewModel.workspaceForm.allowSubdirectories)
    Toggle("Allow by cwd only", isOn: $viewModel.workspaceForm.allowByCwdOnly)
    Button("Add workspace") { Task { await viewModel.addTrustedWorkspace() } }
    statusLine(viewModel)
  }
}

private struct SettingsView: View {
  @ObservedObject var viewModel: ConfiguratorViewModel
  private let presets = [5, 30, 60, 900, 1800]

  var body: some View {
    sectionTitle("Settings")
    TextField("netwatch binary path", text: $viewModel.binaryPath)
    TextField("Config path", text: $viewModel.configPath)
    info("Config writable", ConfigPermission.isWritable(path: viewModel.configPath) ? "yes" : "no")
    Divider()
    Toggle("dryRun", isOn: $viewModel.desiredDryRun)
    if !viewModel.desiredDryRun {
      Text("Turning dry run off enables enforcement; UNKNOWN processes may disable Wi-Fi.")
        .foregroundStyle(.red)
        .font(.callout.weight(.semibold))
    }
    Button("Save dryRun") { Task { await viewModel.saveDryRun() } }
    Divider()
    Picker("Poll interval", selection: $viewModel.desiredPollInterval) {
      Text("Strict: 5 seconds").tag(5)
      Text("Balanced: 30 seconds").tag(30)
      Text("Light: 60 seconds").tag(60)
      Text("Passive audit: 900 seconds").tag(900)
      Text("Passive audit: 1800 seconds").tag(1800)
    }
    .pickerStyle(.radioGroup)
    Text("5-60 seconds is suitable for protection. 15-30 minutes is passive audit, not strong enforcement.")
      .foregroundStyle(.secondary)
    Button("Save poll interval") { Task { await viewModel.savePollInterval() } }
    Divider()
    Toggle("Allow Apple system components", isOn: $viewModel.desiredAppleSystemTrust)
    Button("Save Apple trust") { Task { await viewModel.saveAppleSystemTrust() } }
    Divider()
    TextField("Wi-Fi interface", text: $viewModel.desiredInterface)
    TextField("Log path, empty for default", text: $viewModel.desiredLogPath)
    Toggle("verboseLog", isOn: $viewModel.desiredVerboseLog)
    Button("Save interface/logging") { Task { await viewModel.saveInterfaceAndLogPath() } }
    Divider()
    Toggle("Reload on SIGHUP", isOn: $viewModel.desiredReloadOnSighup)
    Toggle("Exit daemon on config reload error", isOn: $viewModel.desiredExitOnConfigError)
    Button("Save daemon flags") { Task { await viewModel.saveDaemonFlags() } }
    Divider()
    Text("Deny patterns").font(.headline)
    TextEditor(text: $viewModel.denyPatternsText)
      .font(.system(.body, design: .monospaced))
      .frame(minHeight: 100)
    Button("Save deny patterns") { Task { await viewModel.saveDenyPatterns() } }
    Divider()
    Text("Allowed remote host prefixes").font(.headline)
    TextEditor(text: $viewModel.allowRemoteHostsText)
      .font(.system(.body, design: .monospaced))
      .frame(minHeight: 100)
    Button("Save remote hosts") { Task { await viewModel.saveAllowRemoteHosts() } }
    statusLine(viewModel)
  }
}

private struct DiagnosticsView: View {
  @ObservedObject var viewModel: ConfiguratorViewModel

  var body: some View {
    sectionTitle("Diagnostics")
    buttonRow {
      Button("Check config") { Task { await viewModel.checkConfig() } }
      Button("Show raw config summary") { Task { await viewModel.refreshConfig() } }
      Button("Refresh status JSON") { Task { await viewModel.refreshStatus() } }
      Button("Reload daemon") { Task { await viewModel.reloadDaemon() } }
    }
    sectionTitle("Last backend output")
    codeBlock(viewModel.lastCommandOutput)
    sectionTitle("Last status JSON")
    codeBlock(viewModel.lastStatusJSON)
    sectionTitle("Recent errors")
    if viewModel.recentErrors.isEmpty {
      Text("No recent errors.").foregroundStyle(.secondary)
    } else {
      ForEach(viewModel.recentErrors, id: \.self) { Text($0).foregroundStyle(.red) }
    }
  }
}

@ViewBuilder private func sectionTitle(_ text: String) -> some View {
  Text(text).font(.title2.weight(.semibold))
}

@ViewBuilder private func info(_ label: String, _ value: String) -> some View {
  HStack(alignment: .top) {
    Text(label).foregroundStyle(.secondary).frame(width: 150, alignment: .leading)
    Text(value).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
  }
}

@ViewBuilder private func buttonRow(@ViewBuilder content: () -> some View) -> some View {
  HStack(spacing: 10, content: content)
}

@MainActor @ViewBuilder private func statusLine(_ viewModel: ConfiguratorViewModel) -> some View {
  if viewModel.isLoading {
    ProgressView().controlSize(.small)
  }
  if !viewModel.lastMessage.isEmpty {
    Text(viewModel.lastMessage).foregroundStyle(.secondary)
  }
}

@ViewBuilder private func codeBlock(_ text: String) -> some View {
  ScrollView {
    Text(text.isEmpty ? "(empty)" : text)
      .font(.system(.body, design: .monospaced))
      .textSelection(.enabled)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(10)
  }
  .frame(minHeight: 120)
  .background(.quaternary.opacity(0.35))
  .clipShape(RoundedRectangle(cornerRadius: 8))
}

private func color(_ indicator: DashboardIndicator) -> Color {
  switch indicator {
  case .green: return .green
  case .orange: return .orange
  case .red: return .red
  case .gray: return .gray
  }
}

private func formatTime(_ seconds: Int64) -> String {
  if seconds <= 0 { return "never" }
  return Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(date: .abbreviated, time: .standard)
}

private func chooseDirectory(_ setPath: @escaping (String) -> Void) {
  let panel = NSOpenPanel()
  panel.canChooseDirectories = true
  panel.canChooseFiles = false
  if panel.runModal() == .OK, let url = panel.url { setPath(url.path) }
}

private func chooseFile(_ setPath: @escaping (String) -> Void) {
  let panel = NSOpenPanel()
  panel.canChooseDirectories = false
  panel.canChooseFiles = true
  if panel.runModal() == .OK, let url = panel.url { setPath(url.path) }
}

private func openPath(_ path: String) {
  NSWorkspace.shared.open(URL(fileURLWithPath: NSString(string: path).expandingTildeInPath))
}

private func appendLine(_ text: String, _ line: String) -> String {
  text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? line : text + "\n" + line
}
