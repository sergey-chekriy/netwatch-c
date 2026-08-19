import NetwatchConfiguratorCore
import SwiftUI

@main
struct NetwatchConfiguratorApp: App {
  @StateObject private var viewModel = ConfiguratorViewModel()

  var body: some Scene {
    WindowGroup {
      ContentView(viewModel: viewModel)
        .frame(minWidth: 1040, minHeight: 680)
    }
  }
}
