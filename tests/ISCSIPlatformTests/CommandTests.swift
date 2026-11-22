import Foundation
import ISCSICore
import Testing

@testable import ISCSIPlatform

@Test func commandDrainsStdoutAfterExitAtTheExactLimit() async throws {
    let data = try await SystemCommand.run(
        "/usr/bin/printf", arguments: ["%1048576s", "x"], timeout: 5)
    #expect(data.count == 1_048_576)
    #expect(data.last == UInt8(ascii: "x"))
    #expect(data.dropLast().allSatisfy { $0 == UInt8(ascii: " ") })
}

@Test func commandRejectsOutputBeyondItsLimit() async throws {
    await #expect(throws: ProtocolError.limitExceeded("command output")) {
        try await SystemCommand.run("/usr/bin/printf", arguments: ["%1048577s", "x"], timeout: 5)
    }
}

@Test func commandFailureKeepsOnlyTheBoundedErrorDetail() async throws {
    do {
        _ = try await SystemCommand.run(
            "/bin/ls", arguments: ["/iscsi-does-not-exist/" + String(repeating: "x", count: 5000)],
            timeout: 5)
        Issue.record("A missing path unexpectedly succeeded")
    } catch SystemCommandError.failed(let program, let status, let detail) {
        #expect(program == "ls" && status != 0)
        #expect(detail.utf8.count == 4096)
    }
}

private actor CommandStartGate {
    private var open = false
    private var waiter: CheckedContinuation<Void, Never>?
    func wait() async { if !open { await withCheckedContinuation { waiter = $0 } } }
    func release() {
        open = true
        waiter?.resume()
        waiter = nil
    }
}

@Test func alreadyCancelledCommandCannotLaunch() async throws {
    let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: marker) }
    let gate = CommandStartGate()
    let task = Task {
        await gate.wait()
        return try await SystemCommand.run("/usr/bin/touch", arguments: [marker.path])
    }
    task.cancel()
    await gate.release()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(!FileManager.default.fileExists(atPath: marker.path))
}

@Test func commandLaunchFailureDoesNotWaitForTheDeadline() async throws {
    let missing = "/private/tmp/iscsi-missing-\(UUID())"
    await #expect(throws: NSError.self) {
        try await SystemCommand.run(missing, arguments: [], timeout: 5)
    }
}
