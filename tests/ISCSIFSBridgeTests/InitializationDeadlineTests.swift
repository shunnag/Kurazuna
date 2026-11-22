import Foundation
import ISCSICore
import Testing

@testable import ISCSIFSBridge

private actor InitializationGate {
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var started = false
    func wait() async {
        started = true
        await withCheckedContinuation { waiter = $0 }
    }
    func release() {
        waiter?.resume()
        waiter = nil
    }
}

@Test private func initializationDeadlineClosesAnOpenerThatReturnsALateVolume() async throws {
    let gate = InitializationGate()
    let disk = try MemoryDisk()
    let task = Task {
        try await LUNVolumeFactory.withInitializationDeadline(timeout: .milliseconds(20)) {
            await gate.wait()  // Deliberately ignores cancellation.
            return LUNImageVolume(disk: disk, identifier: UUID())
        }
    }
    while !(await gate.started) { await Task.yield() }
    try await Task.sleep(for: .milliseconds(80))
    await gate.release()
    await #expect(throws: ProtocolError.timedOut) { _ = try await task.value }
    #expect(await disk.connectionState() == .closed)
}

@Test private func cancelledInitializationCannotPublishALateVolume() async throws {
    let gate = InitializationGate()
    let disk = try MemoryDisk()
    let task = Task {
        try await LUNVolumeFactory.withInitializationDeadline(timeout: .seconds(3)) {
            await gate.wait()
            return LUNImageVolume(disk: disk, identifier: UUID())
        }
    }
    while !(await gate.started) { await Task.yield() }
    task.cancel()
    await gate.release()
    await #expect(throws: CancellationError.self) { _ = try await task.value }
    #expect(await disk.connectionState() == .closed)
}

@Test private func successfulInitializationKeepsTheReturnedVolumeOpen() async throws {
    let disk = try MemoryDisk()
    let volume = try await LUNVolumeFactory.withInitializationDeadline(timeout: .seconds(1)) {
        LUNImageVolume(disk: disk, identifier: UUID())
    }
    #expect(await disk.connectionState() == .connected)
    await volume.shutdown()
    #expect(await disk.connectionState() == .closed)
}

private final class InitializationTime: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    private var cancelled = false
    var now: ContinuousClock.Instant { lock.withLock { instant } }
    var timerCancelled: Bool { lock.withLock { cancelled } }
    func advance() { lock.withLock { instant = instant.advanced(by: .seconds(2)) } }
    func recordTimerCancellation() { lock.withLock { cancelled = true } }
}

@Test(arguments: [false, true])
private func initializationRechecksDeadlineAndCancellationAfterDrainingItsTimer(cancel: Bool)
    async throws
{
    let clock = InitializationTime()
    let timer = InitializationGate()
    let disk = try MemoryDisk()
    let task = Task {
        try await LUNVolumeFactory.withInitializationDeadline(
            timeout: .seconds(1), now: { clock.now },
            sleepUntil: { _ in
                await withTaskCancellationHandler {
                    await timer.wait()  // Drain deliberately waits after cancellation.
                } onCancel: {
                    clock.recordTimerCancellation()
                }
            },
            operation: {
                while !(await timer.started) { await Task.yield() }
                return LUNImageVolume(disk: disk, identifier: UUID())
            })
    }
    while !clock.timerCancelled { await Task.yield() }
    if cancel { task.cancel() } else { clock.advance() }
    await timer.release()
    if cancel {
        await #expect(throws: CancellationError.self) { _ = try await task.value }
    } else {
        await #expect(throws: ProtocolError.timedOut) { _ = try await task.value }
    }
    #expect(await disk.connectionState() == .closed)
}

@Test private func aDelayedTimerCannotPublishAVolumeAfterTheInitializationDeadline() async throws {
    let clock = InitializationTime()
    let disk = try MemoryDisk()
    await #expect(throws: ProtocolError.timedOut) {
        _ = try await LUNVolumeFactory.withInitializationDeadline(
            timeout: .seconds(1), now: { clock.now },
            sleepUntil: { _ in try await Task.sleep(for: .seconds(60)) },
            operation: {
                clock.advance()
                return LUNImageVolume(disk: disk, identifier: UUID())
            })
    }
    #expect(await disk.connectionState() == .closed)
}
