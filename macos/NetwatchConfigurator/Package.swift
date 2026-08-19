// swift-tools-version: 5.9
import PackageDescription

let package = Package(
  name: "NetwatchConfigurator",
  platforms: [.macOS(.v13)],
  products: [
    .executable(name: "NetwatchConfigurator", targets: ["NetwatchConfigurator"])
  ],
  targets: [
    .target(name: "NetwatchConfiguratorCore", path: "NetwatchConfiguratorCore"),
    .executableTarget(
      name: "NetwatchConfigurator",
      dependencies: ["NetwatchConfiguratorCore"],
      path: "NetwatchConfigurator",
      resources: [.copy("Resources")]
    ),
    .executableTarget(
      name: "NetwatchConfiguratorSelfTest",
      dependencies: ["NetwatchConfiguratorCore"],
      path: "Tests/NetwatchConfiguratorSelfTest"
    )
  ]
)
