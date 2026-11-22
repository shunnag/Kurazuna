import Darwin
import DiskArbitration
import Foundation
import IOKit
import ISCSICore
import ISCSIPlatformNative

/// CF objects are configured once, then used only on this serial callback queue.
/// Each request retains its owner until the OS delivers its completion callback.
final class DiskArbitrationEjectionHandle: DiskEjectionHandle, @unchecked Sendable {
    private let queue = DispatchQueue(label: "dev.soba.iscsi.disk-ejection")
    private let session: DASession
    private struct Target: Sendable {
        let device: String
        let mediaID: UInt64
        let index: Int
    }
    private let targets: [Target]
    private let parent: Target
    private let deadline: ContinuousClock.Instant
    private let force: Bool
    private let trace: DiskEjectionDiagnostics.Trace

    init(request: DiskEjectionRequest) throws {
        guard let session = DASessionCreate(kCFAllocatorDefault) else { throw POSIXError(.ENOMEM) }
        var targets: [Target] = []
        for (index, device) in request.unmountDevices.enumerated() {
            guard let disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, device) else {
                throw POSIXError(.ENXIO)
            }
            let mediaID = try Self.identifier(disk)
            guard
                request.mediaIdentifiers.isEmpty
                    || request.mediaIdentifiers[device] == mediaID
            else {
                throw AttachmentError.imageIdentityChanged
            }
            targets.append(Target(device: device, mediaID: mediaID, index: index))
        }
        guard let parent = targets.last, parent.device == request.device else {
            throw POSIXError(.EINVAL)
        }
        self.targets = targets
        self.parent = parent
        deadline = request.deadline
        force = request.force
        trace = request.trace
        self.session = session
        DASessionSetDispatchQueue(session, queue)
    }

    deinit { DASessionSetDispatchQueue(session, nil) }

    static func mediaIdentifiers(for devices: [String]) throws -> [String: UInt64] {
        guard let session = DASessionCreate(kCFAllocatorDefault) else { throw POSIXError(.ENOMEM) }
        var result: [String: UInt64] = [:]
        for device in devices {
            guard let disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, device) else {
                throw POSIXError(.ENXIO)
            }
            result[device] = try identifier(disk)
        }
        return result
    }

    func unmount() async throws {
        for target in targets { try await request(.unmount, target: target) }
    }
    func eject() async throws { try await request(.eject, target: parent) }

    private typealias Operation = DiskEjectionDiagnostics.Operation

    private func request(_ operation: Operation, target: Target) async throws {
        let cancellation = RequestCancellation()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                queue.async { [self] in
                    do {
                        // Resolve again: a reused BSD name must not select a different medium.
                        guard
                            let disk = DADiskCreateFromBSDName(
                                kCFAllocatorDefault, session, target.device),
                            try Self.identifier(disk) == target.mediaID
                        else { throw POSIXError(.ENXIO) }
                        guard ContinuousClock.now < deadline else { throw ProtocolError.timedOut }
                        guard cancellation.begin() else { throw CancellationError() }
                        let reply = Reply(
                            owner: self, operation: operation, targetIndex: target.index,
                            continuation: continuation)
                        let context = Unmanaged.passRetained(reply).toOpaque()
                        trace.record(.submitted, operation: operation, targetIndex: target.index)
                        switch operation {
                        case .unmount:
                            DADiskUnmount(
                                disk,
                                DADiskUnmountOptions(kDADiskUnmountOptionWhole)
                                    | (force ? DADiskUnmountOptions(kDADiskUnmountOptionForce) : 0),
                                Self.completed, context)
                        case .eject:
                            DADiskEject(
                                disk, DADiskEjectOptions(kDADiskEjectOptionDefault), Self.completed,
                                context)
                        }
                    } catch {
                        let (outcome, code) = DiskEjectionDiagnostics.failure(error)
                        trace.record(
                            .rejected, operation: operation, targetIndex: target.index,
                            outcome: outcome, errorCode: code)
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            // An issued DA request cannot be cancelled. Keep its callback alive.
            cancellation.cancel()
        }
    }

    private static func identifier(_ disk: DADisk) throws -> UInt64 {
        guard let description = DADiskCopyDescription(disk) as? [CFString: Any],
            description[kDADiskDescriptionMediaWholeKey] as? Bool == true
        else { throw POSIXError(.EINVAL) }
        let media = DADiskCopyIOMedia(disk)
        guard media != 0 else { throw POSIXError(.ENXIO) }
        defer { IOObjectRelease(media) }
        var id: UInt64 = 0
        guard IORegistryEntryGetRegistryEntryID(media, &id) == KERN_SUCCESS, id != 0 else {
            throw POSIXError(.ENXIO)
        }
        return id
    }

    private static let completed: DADiskUnmountCallback = { _, dissenter, context in
        guard let context else { return }
        let reply = Unmanaged<Reply>.fromOpaque(context).takeRetainedValue()
        if let dissenter {
            let status = DADissenterGetStatus(dissenter)
            let outcome: DiskEjectionDiagnostics.Outcome
            if reply.operation == .unmount && status == kDAReturnNotMounted {
                outcome = .alreadyUnmounted
            } else if ISCSIDiskArbitrationStatusIsBusy(status) {
                outcome = .busy
            } else {
                outcome = .failed
            }
            reply.owner.trace.record(
                .callback, operation: reply.operation, targetIndex: reply.targetIndex,
                status: UInt32(truncatingIfNeeded: status), outcome: outcome)
            if reply.operation == .unmount && status == kDAReturnNotMounted {
                reply.continuation.resume()
            } else if ISCSIDiskArbitrationStatusIsBusy(status) {
                reply.continuation.resume(throwing: POSIXError(.EBUSY))
            } else {
                reply.continuation.resume(
                    throwing: Failure(
                        status: status, detail: DADissenterGetStatusString(dissenter) as String?))
            }
        } else {
            reply.owner.trace.record(
                .callback, operation: reply.operation, targetIndex: reply.targetIndex,
                status: 0, outcome: .success)
            reply.continuation.resume()
        }
    }

    private final class Reply {
        let owner: DiskArbitrationEjectionHandle
        let operation: Operation
        let targetIndex: Int
        let continuation: CheckedContinuation<Void, any Error>
        init(
            owner: DiskArbitrationEjectionHandle, operation: Operation, targetIndex: Int,
            continuation: CheckedContinuation<Void, any Error>
        ) {
            self.owner = owner
            self.operation = operation
            self.targetIndex = targetIndex
            self.continuation = continuation
        }
    }

    private final class RequestCancellation: @unchecked Sendable {
        private let lock = NSLock()
        private var cancelled = false
        private var started = false
        func begin() -> Bool {
            lock.withLock {
                guard !cancelled, !started else { return false }
                started = true
                return true
            }
        }
        func cancel() { lock.withLock { cancelled = true } }
    }

    private struct Failure: LocalizedError {
        let status: DAReturn
        let detail: String?
        var errorDescription: String? {
            "Disk Arbitration (\(String(format: "0x%08x", status))): \(detail ?? "The disk could not be ejected.")"
        }
    }
}
