import NetwatchConfiguratorCore
import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct NetwatchConfiguratorApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
  @StateObject private var viewModel = ConfiguratorViewModel()

  var body: some Scene {
    WindowGroup {
      ContentView(viewModel: viewModel)
        .frame(minWidth: 1040, minHeight: 680)
    }
  }
}
