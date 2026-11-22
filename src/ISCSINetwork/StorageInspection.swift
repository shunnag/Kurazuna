import Foundation
import ISCSICore

/// An observation of one live connection. It is not a reservation or a recovery permission.
public struct SCSIStorageContinuity: Sendable, Equatable {
    public let instanceID: UUID
    public let initiatorName: String
    public let targetName: String
    public let initiatorSessionID: [UInt8]
    public let targetSessionHandle: UInt16
    public let targetPortalGroupTag: UInt16
    public let disruptionEpoch: UInt64
    public let admittedCommands: UInt64
    public let hasAdmittedDataAccess: Bool
    public let countersComplete: Bool
    public let isReady: Bool

    func continues(_ previous: Self) -> Bool {
        isReady && previous.isReady && countersComplete && previous.countersComplete
            && instanceID == previous.instanceID && initiatorName == previous.initiatorName
            && targetName == previous.targetName
            && initiatorSessionID == previous.initiatorSessionID
            && targetSessionHandle == previous.targetSessionHandle
            && targetPortalGroupTag == previous.targetPortalGroupTag
            && disruptionEpoch == previous.disruptionEpoch
            && admittedCommands >= previous.admittedCommands
    }
}

struct StorageInspectionTicket: Sendable, Equatable {
    let id: UUID
    let lun: LogicalUnit
    let initial: SCSIStorageContinuity
}

/// Real, non-mutating protocol information. Snapshots cannot prove continuous exclusion.
public struct SCSIStorageInspection: Sendable, Equatable {
    public let device: SCSIInquiry
    public let capacity: DiskCapacity
    public let identity: SCSILogicalUnitIdentity
    public let capabilities: SCSIReservationCapabilities
    public let keys: SCSIReservationKeys
    public let reservation: SCSIReservation
    public let fullStatus: SCSIReservationFullStatus
    public let initialContinuity: SCSIStorageContinuity
    public let finalContinuity: SCSIStorageContinuity

    public var establishesRecoveryAuthority: Bool { false }
}

extension DiskProbe {
    /// The complete query sequence excludes other commands on this connection. No registration,
    /// reservation, WRITE, synchronization, or retry that consumes Unit Attention is issued.
    public static func inspectStorage(session: ISCSISession, lun: LogicalUnit) async throws
        -> SCSIStorageInspection
    {
        try Task.checkCancellation()
        let ticket = try await session.beginStorageInspection(lun: lun)
        do {
            let result = try await storageBody(session: session, ticket: ticket)
            guard await session.finishStorageInspection(ticket, validating: result.finalContinuity)
            else {
                throw ProtocolError.invalidState
            }
            return result
        } catch {
            _ = await session.finishStorageInspection(ticket)
            throw error
        }
    }

    static func storageBody(session: ISCSISession, ticket: StorageInspectionTicket)
        async throws -> SCSIStorageInspection
    {
        func query(_ command: SCSICommand) async throws -> SCSIResult {
            try Task.checkCancellation()
            return try await session.executeForStorageInspection(command, ticket: ticket)
        }
        let inquiry = try await query(.inquiry())
        let device = try SCSIInquiry(data: inquiry.data)
        guard device.peripheralQualifier == 0, device.peripheralDeviceType == 0,
            device.responseDataFormat == 2
        else { throw ProtocolError.unsupported("storage inspection device") }
        let capacity: DiskCapacity
        do {
            let result = try await query(.readCapacity16())
            capacity = try DiskCapacity(readCapacity16: result.data)
        } catch let ProtocolError.scsiFailure(status, data) {
            guard status == 2, let sense = try? SCSISense(data: data), !sense.isDeferred,
                sense.isUnsupportedCommand
            else { throw ProtocolError.scsiFailure(status: status, sense: data) }
            let result = try await query(.readCapacity10())
            capacity = try DiskCapacity(readCapacity10: result.data)
        }
        let identification = try await query(.deviceIdentification())
        let identity = try SCSILogicalUnitIdentity(data: identification.data)
        let capabilityData = try await query(
            .persistentReservation(.capabilities, allocationLength: 8))
        let capabilities = try SCSIReservationCapabilities(data: capabilityData.data)
        let keyData = try await query(.persistentReservation(.keys))
        let keys = try SCSIReservationKeys(data: keyData.data)
        let reservationData = try await query(
            .persistentReservation(.reservation, allocationLength: 24))
        let reservation = try SCSIReservation(data: reservationData.data)
        let statusData = try await query(.persistentReservation(.fullStatus))
        let status = try SCSIReservationFullStatus(data: statusData.data)
        guard keys.generation == reservation.generation, keys.generation == status.generation,
            keys.keys.sorted() == status.registrations.map(\.key).sorted()
        else { throw ProtocolError.malformed("inconsistent reservation observations") }
        let holders = status.registrations.filter(\.isHolder)
        if let holder = reservation.holder {
            if let supported = capabilities.supportedTypes {
                guard supported.contains(holder.type) else {
                    throw ProtocolError.malformed("reservation contradicts capability mask")
                }
            }
            switch holder.type {
            case .writeExclusiveAllRegistrants, .exclusiveAccessAllRegistrants:
                guard !holders.isEmpty, holders.count == status.registrations.count,
                    holders.allSatisfy({ $0.type == holder.type })
                else { throw ProtocolError.malformed("inconsistent reservation holders") }
            default:
                guard holders.count == 1, holders[0].key == holder.key,
                    holders[0].type == holder.type
                else { throw ProtocolError.malformed("inconsistent reservation holder") }
            }
        } else {
            guard holders.isEmpty else {
                throw ProtocolError.malformed("unreported reservation holder")
            }
        }
        try Task.checkCancellation()
        guard let final = await session.storageContinuity, final.continues(ticket.initial) else {
            throw ProtocolError.invalidState
        }
        return SCSIStorageInspection(
            device: device, capacity: capacity, identity: identity,
            capabilities: capabilities, keys: keys, reservation: reservation, fullStatus: status,
            initialContinuity: ticket.initial, finalContinuity: final)
    }
}
