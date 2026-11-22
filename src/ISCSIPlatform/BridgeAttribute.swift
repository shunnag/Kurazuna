import Darwin
import Foundation

/// One system call against a mounted bridge, run on its own thread against a deadline, so a
/// stopped or unresponsive file system extension can't stall a confirmed forced release. At
/// the deadline the caller resumes with `timedOut`; the thread may stay blocked in the kernel
/// until the volume is released. Each forced attempt starts at most a few such calls.
enum BoundedCall {
    static let deadline = Duration.seconds(5)

    static func run<Value: Sendable>(
        deadline: Duration, timedOut: Value, _ call: @escaping @Sendable () -> Value
    ) async -> Value {
        let reply = Reply<Value>()
        return await withCheckedContinuation { continuation in
            reply.install(continuation)
            let timer = Task {
                do { try await Task.sleep(for: deadline) } catch { return }
                reply.finish(timedOut)
            }
            DispatchQueue.global(qos: .userInitiated).async {
                reply.finish(call())
                timer.cancel()
            }
        }
    }

    /// The first result wins; the continuation always resumes outside the lock.
    private final class Reply<Value: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Value, Never>?
        private var finished = false

        func install(_ continuation: CheckedContinuation<Value, Never>) {
            lock.withLock { self.continuation = continuation }
        }

        func finish(_ value: Value) {
            let waiter = lock.withLock { () -> CheckedContinuation<Value, Never>? in
                guard !finished else { return nil }
                finished = true
                defer { continuation = nil }
                return continuation
            }
            waiter?.resume(returning: value)
        }
    }
}

/// One extended-attribute read from a mounted bridge, bounded by `BoundedCall`.
enum BridgeAttributeRead: Sendable, Equatable {
    case value([UInt8])
    case failed(Int32)
    case timedOut

    static let deadline = BoundedCall.deadline

    static func bounded(path: String, name: String, capacity: Int) async -> Self {
        await bounded(path: path, name: name, capacity: capacity, deadline: deadline)
    }

    static func bounded(path: String, name: String, capacity: Int, deadline: Duration) async
        -> Self
    {
        await BoundedCall.run(deadline: deadline, timedOut: .timedOut) {
            read(path: path, name: name, capacity: capacity)
        }
    }

    static func read(path: String, name: String, capacity: Int) -> Self {
        var bytes = [UInt8](repeating: 0, count: max(0, capacity))
        let count = bytes.withUnsafeMutableBytes {
            getxattr(path, name, $0.baseAddress, $0.count, 0, XATTR_NOFOLLOW)
        }
        guard count >= 0 else { return .failed(errno) }
        return .value(Array(bytes.prefix(count)))
    }
}

/// One extended-attribute write to a mounted bridge, bounded by `BoundedCall`.
enum BridgeAttributeWrite: Sendable, Equatable {
    case written
    case failed(Int32)
    case timedOut

    static let deadline = BoundedCall.deadline

    static func bounded(path: String, name: String, value: Data) async -> Self {
        await bounded(path: path, name: name, value: value, deadline: deadline)
    }

    static func bounded(path: String, name: String, value: Data, deadline: Duration) async -> Self {
        await BoundedCall.run(deadline: deadline, timedOut: .timedOut) {
            write(path: path, name: name, value: value)
        }
    }

    static func write(path: String, name: String, value: Data) -> Self {
        let result = value.withUnsafeBytes {
            setxattr(path, name, $0.baseAddress, $0.count, 0, XATTR_NOFOLLOW)
        }
        return result == 0 ? .written : .failed(errno)
    }
}

/// Removing a forcibly released bridge's directory, bounded by `BoundedCall`: if a mount
/// appeared there again, the lookup could reach its file system extension.
enum BridgeDirectoryRemoval: Sendable, Equatable {
    case removed
    case failed(Int32)
    case timedOut

    static func bounded(path: String) async -> Self {
        await BoundedCall.run(deadline: BoundedCall.deadline, timedOut: .timedOut) {
            rmdir(path) == 0 ? .removed : .failed(errno)
        }
    }
}

/// One ordinary unmount(2) of a bridge, bounded by `BoundedCall`, so that its errno, and
/// above all EBUSY, is known exactly. The deadline is the one the umount command had.
enum BridgeUnmount: Sendable, Equatable {
    case unmounted
    case failed(Int32)
    case timedOut

    static let deadline = Duration.seconds(45)

    static func bounded(path: String) async -> Self {
        await BoundedCall.run(deadline: deadline, timedOut: .timedOut) {
            unmount(path, 0) == 0 ? .unmounted : .failed(errno)
        }
    }
}
