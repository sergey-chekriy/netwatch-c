import Darwin
import Foundation

public struct CommandResult: Equatable {
  public let stdout: String
  public let stderr: String
  public let exitCode: Int32
  public let timedOut: Bool

  public var succeeded: Bool { exitCode == 0 && !timedOut }

  public init(stdout: String, stderr: String, exitCode: Int32, timedOut: Bool = false) {
    self.stdout = stdout
    self.stderr = stderr
    self.exitCode = exitCode
    self.timedOut = timedOut
  }
}

public protocol CommandRunning {
  func run(executable: String, arguments: [String], timeout: TimeInterval) async -> CommandResult
}

private final class CommandCapture: @unchecked Sendable {
  private let lock = NSLock()
  private var stdoutData = Data()
  private var stderrData = Data()
  private var didFinish = false
  private var timedOut = false

  func append(_ data: Data, toStdout: Bool) {
    guard !data.isEmpty else { return }
    lock.lock()
    if toStdout { stdoutData.append(data) } else { stderrData.append(data) }
    lock.unlock()
  }

  func markTimedOut() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    if didFinish { return false }
    timedOut = true
    return true
  }

  func finish() -> (String, String, Bool) {
    lock.lock()
    didFinish = true
    let out = String(data: stdoutData, encoding: .utf8) ?? ""
    let err = String(data: stderrData, encoding: .utf8) ?? ""
    let wasTimedOut = timedOut
    lock.unlock()
    return (out, err, wasTimedOut)
  }
}

public final class ProcessCommandRunner: CommandRunning {
  public init() {}

  public func run(executable: String, arguments: [String], timeout: TimeInterval) async -> CommandResult {
    await withCheckedContinuation { continuation in
      let process = Process()
      let stdoutPipe = Pipe()
      let stderrPipe = Pipe()
      let capture = CommandCapture()

      stdoutPipe.fileHandleForReading.readabilityHandler = { capture.append($0.availableData, toStdout: true) }
      stderrPipe.fileHandleForReading.readabilityHandler = { capture.append($0.availableData, toStdout: false) }
      process.executableURL = URL(fileURLWithPath: executable)
      process.arguments = arguments
      process.standardOutput = stdoutPipe
      process.standardError = stderrPipe

      let timer = DispatchSource.makeTimerSource(queue: .global())
      timer.schedule(deadline: .now() + timeout)
      timer.setEventHandler {
        if !capture.markTimedOut() { return }
        if process.isRunning {
          process.terminate()
          DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
          }
        }
      }

      process.terminationHandler = { process in
        timer.cancel()
        capture.append(stdoutPipe.fileHandleForReading.availableData, toStdout: true)
        capture.append(stderrPipe.fileHandleForReading.availableData, toStdout: false)
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        let (out, err, wasTimedOut) = capture.finish()
        continuation.resume(returning: CommandResult(
          stdout: out,
          stderr: err,
          exitCode: wasTimedOut ? -1 : process.terminationStatus,
          timedOut: wasTimedOut
        ))
      }

      do {
        try process.run()
        timer.resume()
      } catch {
        timer.resume()
        timer.cancel()
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        continuation.resume(returning: CommandResult(
          stdout: "",
          stderr: error.localizedDescription,
          exitCode: 127
        ))
      }
    }
  }
}

public enum NetwatchBinaryLocator {
  public static func defaultPath(
    bundle: Bundle = .main,
    environment: [String: String] = ProcessInfo.processInfo.environment,
    fileManager: FileManager = .default
  ) -> String {
    var candidates: [String] = []
    if let resourcePath = bundle.resourceURL?.appendingPathComponent("netwatch").path {
      candidates.append(resourcePath)
    }
    candidates.append("/usr/local/bin/netwatch")
    candidates.append("/opt/homebrew/bin/netwatch")
    candidates.append(contentsOf: pathCandidates(environment: environment))
    return candidates.first { fileManager.isExecutableFile(atPath: $0) } ?? "netwatch"
  }

  private static func pathCandidates(environment: [String: String]) -> [String] {
    (environment["PATH"] ?? "").split(separator: ":").map { "\($0)/netwatch" }
  }
}
