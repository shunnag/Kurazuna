import Darwin
import Foundation

/// Adopts an already exclusively locked descriptor. A duplicate can survive the owner's close
/// (for example across fork before exec), so release the shared flock explicitly in its owner.
final class FileLease: Sendable {
    private let descriptor: Int32
    private let ownerPID: pid_t

    init(lockedDescriptor: Int32) {
        descriptor = lockedDescriptor
        ownerPID = getpid()
    }

    func verifyOwner() throws {
        guard getpid() == ownerPID else { throw POSIXError(.ECHILD) }
    }

    deinit {
        // A forked child closing its copy must not unlock the still-active parent's lease.
        if getpid() == ownerPID {
            var result: Int32
            repeat { result = flock(descriptor, LOCK_UN) } while result < 0 && errno == EINTR
        }
        close(descriptor)
    }
}
