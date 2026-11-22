import Foundation
import ISCSICore
import Testing

@testable import ISCSINetwork

/// A model of connection closure only; no producer drain or filesystem unmount proof.
@Test(arguments: [0, 1, 2, 3, 4])
func reservedExposedDiskCloseCannotBypassImmediateAbandonment(_ variant: Int) async throws {
    let store = IntentFixture()
    let (session, target) = try await reservedSession(store)
    let lease = ContinuousLeaseFixture()
    let reserved = try await ReservedRemoteDisk.acquire(
        session: session, lun: LogicalUnit(1), lease: lease, store: store)
    if variant > 0 {
        if variant == 3 { await target.failNextWrite() }
        if variant == 3 {
            await #expect(throws: ProtocolError.self) {
                try await reserved.disk.write(offset: 7, data: Data([0xAB, 0xCD]))
            }
        } else {
            try await reserved.disk.write(offset: 7, data: Data([0xAB, 0xCD]))
        }
        if variant == 2 || variant == 4 {
            await target.failNextSynchronization()
            await #expect(throws: ProtocolError.self) {
                try await reserved.disk.synchronize()
            }
            if variant == 4 { try await reserved.recoverSynchronizationFailure() }
        }
    }
    let evidence = reserved.disk.mutationEvidence
    let pins = lease.outstandingPins
    let intents = store.load()
    await reserved.disk.close()
    #expect(await target.logoutRequests == 0)
    #expect(await session.state == .closed)
    #expect(await target.actions == [0, 1])
    #expect(await target.hasReservation())
    #expect(store.load() == intents && intents.map(\.phase) == [.reserved])
    #expect(reserved.disk.mutationEvidence == evidence)
    #expect(lease.outstandingPins == pins)
    await reserved.close()
    #expect(await target.logoutRequests == 0)
}
