import Foundation
import ISCSICore
import ISCSINetwork

/// Trusted target control plane for an explicitly selected, exclusively owned raw LUN.
/// Preparation must bind its connected transport and continuously fenced backing incarnation
/// to the complete descriptor. A route label, successful CHAP or a PR snapshot is not that proof.
/// Distinct preparations must never alias a live transport or ownership lifecycle.
public protocol ReservedLUNSource: Sendable {
    /// The provider owns partial resources until it returns a preparation. It must cooperate
    /// with cancellation and this absolute deadline, and clean up partial transport acquisition
    /// on failure. The factory cancels and drains preparation; it cannot forcibly bound a provider
    /// that ignores cancellation. Cleanup/disconnect must preserve the external fence, including
    /// unresolved command pins, until independently authorized target retirement.
    func prepare(for descriptor: ConnectionDescriptor, deadline: ContinuousClock.Instant)
        async throws -> ReservedLUNPreparation
}

/// One transfer of a fresh connected byte stream, its real external fence and a dedicated durable
/// intent store. This object does not establish fencing authority; its trusted source does.
/// The factory performs login itself so preparation cannot substitute authentication or ISID.
public final class ReservedLUNPreparation: @unchecked Sendable {
    public typealias RecoveryControlFactory = @Sendable (UUID) throws -> any LUNRecoveryControl
    let descriptor: ConnectionDescriptor
    let transport: any ByteTransport
    let lease: any ContinuousStorageQuiescenceLease
    let store: any OwnedReservationIntentStore
    let makeRecoveryControl: RecoveryControlFactory?
    private let lock = NSLock()
    private var consumed = false

    public init(
        descriptor: ConnectionDescriptor, transport: any ByteTransport,
        lease: any ContinuousStorageQuiescenceLease, store: any OwnedReservationIntentStore,
        makeRecoveryControl: RecoveryControlFactory? = nil
    ) {
        self.descriptor = descriptor
        self.transport = transport
        self.lease = lease
        self.store = store
        self.makeRecoveryControl = makeRecoveryControl
    }

    /// Reuse fails before entering the new caller's cleanup scope. Consumption is permanent,
    /// including when the first claimant subsequently fails or is cancelled.
    func claim() throws {
        try lock.withLock {
            guard !consumed else { throw ProtocolError.invalidState }
            consumed = true
        }
    }
}
