import Foundation
import ISCSICore

public struct DiskInformation: Sendable, Equatable {
    public let device: SCSIInquiry
    public let capacity: DiskCapacity
    public let isWriteProtected: Bool?

    public init(device: SCSIInquiry, capacity: DiskCapacity, isWriteProtected: Bool? = nil) {
        self.device = device
        self.capacity = capacity
        self.isWriteProtected = isWriteProtected
    }
}

public enum DiskProbeIssue: Error, Sendable, Equatable {
    case unavailable
    case unsupportedDevice(type: UInt8)
    case notReady
    case noMedia
    case accessRestricted
    case invalidInformation
    case commandFailed(status: UInt8)
}

extension DiskProbeIssue: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unavailable: "The logical unit is unavailable."
        case .unsupportedDevice: "This type of storage device is not supported."
        case .notReady: "The disk is not ready."
        case .noMedia: "No media is available in this device."
        case .accessRestricted: "Access to this disk is restricted."
        case .invalidInformation: "The disk information is invalid or incomplete."
        case .commandFailed(let status): "The disk returned an error (\(status))."
        }
    }
}

public struct LogicalUnitInspection: Sendable, Equatable {
    public let lun: LogicalUnit
    public let result: Result<DiskInformation, DiskProbeIssue>

    public init(lun: LogicalUnit, result: Result<DiskInformation, DiskProbeIssue>) {
        self.lun = lun
        self.result = result
    }
}

public enum DiskProbe {
    public static func diskInformation(session: ISCSISession, lun: LogicalUnit) async throws
        -> DiskInformation
    {
        do {
            let result = try await readOnly(.inquiry(), session: session, lun: lun)
            let device = try SCSIInquiry(data: result.data)
            guard device.peripheralQualifier == 0 else { throw DiskProbeIssue.unavailable }
            // DiskImages expects a random-access disk image. Tape, optical, RBC and zoned-only
            // devices need their own command sets and must not reach RemoteDisk through a URL.
            guard device.peripheralDeviceType == 0, device.responseDataFormat == 2 else {
                throw DiskProbeIssue.unsupportedDevice(type: device.peripheralDeviceType)
            }
            let capacity = try await capacity(session: session, lun: lun)
            let protection = try await writeProtection(session: session, lun: lun)
            return DiskInformation(
                device: device, capacity: capacity, isWriteProtected: protection)
        } catch let error as ProtocolError {
            // A local information error or SCSI status affects this LUN. Wire errors,
            // deadlines and disconnects fail the session and must retain that failure.
            guard await session.state == .ready, let issue = issue(for: error) else { throw error }
            throw issue
        }
    }

    public static func inspectLogicalUnits(session: ISCSISession) async throws
        -> [LogicalUnitInspection]
    {
        try Task.checkCancellation()
        let luns = try await logicalUnits(session: session)
        var inspections: [LogicalUnitInspection] = []
        for lun in luns {
            try Task.checkCancellation()
            do {
                let information = try await diskInformation(session: session, lun: lun)
                inspections.append(LogicalUnitInspection(lun: lun, result: .success(information)))
            } catch let issue as DiskProbeIssue {
                guard await session.state == .ready else { throw issue }
                inspections.append(LogicalUnitInspection(lun: lun, result: .failure(issue)))
            }
        }
        try Task.checkCancellation()
        return inspections
    }

    public static func capacity(session: ISCSISession, lun: LogicalUnit) async throws
        -> DiskCapacity
    {
        do {
            let result = try await readOnly(.readCapacity16(), session: session, lun: lun)
            return try DiskCapacity(readCapacity16: result.data)
        } catch let ProtocolError.scsiFailure(status, data) {
            guard status == 2, let sense = try? SCSISense(data: data), !sense.isDeferred,
                sense.isUnsupportedCommand
            else {
                throw ProtocolError.scsiFailure(status: status, sense: data)
            }
            let result = try await readOnly(.readCapacity10(), session: session, lun: lun)
            return try DiskCapacity(readCapacity10: result.data)
        }
    }

    public static func logicalUnits(session: ISCSISession) async throws -> [LogicalUnit] {
        let result = try await readOnly(
            .reportLUNs(allocationLength: 65_536), session: session, lun: LogicalUnit(0))
        return try LUNList.decode(result.data)
    }

    public static func blockLimits(session: ISCSISession, lun: LogicalUnit) async throws
        -> SCSIBlockLimits?
    {
        do {
            let result = try await readOnly(.blockLimits(), session: session, lun: lun)
            return try SCSIBlockLimits(data: result.data)
        } catch let ProtocolError.scsiFailure(status, data) {
            // Older targets may not implement this optional page. An error from a prior
            // operation, a wire failure, or any other device error must remain visible.
            guard await session.state == .ready, status == 2,
                let sense = try? SCSISense(data: data), !sense.isDeferred,
                sense.isUnsupportedCommand
            else { throw ProtocolError.scsiFailure(status: status, sense: data) }
            return nil
        }
    }

    /// The canonical logical-unit names from VPD page 83h, or nil when the device reports none
    /// that can be used: a page it rejects as an illegal request, a page without logical-unit
    /// names, or one that doesn't parse. A failed session still throws. Any other device
    /// error leaves the answer unknown: a not-ready device throws `notReady`, anything else
    /// `commandFailed`.
    public static func logicalUnitDesignator(session: ISCSISession, lun: LogicalUnit)
        async throws -> Data?
    {
        let result: SCSIResult
        do {
            result = try await readOnly(.deviceIdentification(), session: session, lun: lun)
        } catch let ProtocolError.scsiFailure(status, data) {
            guard await session.state == .ready else {
                throw ProtocolError.scsiFailure(status: status, sense: data)
            }
            guard status == 2, let sense = try? SCSISense(data: data), !sense.isDeferred else {
                throw DiskProbeIssue.commandFailed(status: status)
            }
            switch sense.key {
            case 5 where sense.additionalSenseCode == 0x25: throw DiskProbeIssue.unavailable
            case 5: return nil
            case 2, 6: throw DiskProbeIssue.notReady
            default: throw DiskProbeIssue.commandFailed(status: status)
            }
        }
        return (try? SCSILogicalUnitIdentity(data: result.data))?.canonicalBytes
    }

    /// Unsupported queries leave the state unknown; device and deferred errors stay visible.
    public static func writeProtection(session: ISCSISession, lun: LogicalUnit) async throws
        -> Bool?
    {
        for tenByte in [true, false] {
            for headerOnly in [false, true] {
                let command: SCSICommand =
                    tenByte
                    ? .modeSense10(headerOnly: headerOnly) : .modeSense6(headerOnly: headerOnly)
                do {
                    let result = try await readOnly(command, session: session, lun: lun)
                    let header =
                        try tenByte
                        ? SCSIModeHeader(modeSense10: result.data)
                        : SCSIModeHeader(modeSense6: result.data)
                    return header.isWriteProtected
                } catch let ProtocolError.scsiFailure(status, data) {
                    guard await session.state == .ready, status == 2,
                        let sense = try? SCSISense(data: data), !sense.isDeferred,
                        sense.isUnsupportedCommand
                    else { throw ProtocolError.scsiFailure(status: status, sense: data) }
                    // An unknown opcode cannot be fixed by changing the requested page.
                    if sense.additionalSenseCode == 0x20 { break }
                    // Invalid-field responses may reject all-pages but allow the header alone.
                }
            }
        }
        return nil
    }

    private static func issue(for error: ProtocolError) -> DiskProbeIssue? {
        switch error {
        case .malformed, .unsupported, .limitExceeded: return .invalidInformation
        case .scsiFailure(let status, let data):
            if status == 0x18 { return .accessRestricted }
            if status == 2, let sense = try? SCSISense(data: data), !sense.isDeferred {
                if sense.key == 2 {
                    return sense.additionalSenseCode == 0x3A ? .noMedia : .notReady
                }
                if sense.key == 5, sense.additionalSenseCode == 0x25, sense.qualifier == 0 {
                    return .unavailable
                }
            }
            return .commandFailed(status: status)
        default: return nil
        }
    }

    /// Only non-mutating commands may consume Unit Attention and retry. Writes are never retried.
    public static func readOnly(_ command: SCSICommand, session: ISCSISession, lun: LogicalUnit)
        async throws -> SCSIResult
    {
        guard command.direction != .write else { throw ProtocolError.invalidState }
        for attempt in 0..<3 {
            do { return try await session.execute(command, lun: lun) } catch let
                ProtocolError.scsiFailure(status, data)
            {
                guard attempt < 2, status == 2, let sense = try? SCSISense(data: data),
                    !sense.isDeferred, sense.isUnitAttention
                else {
                    throw ProtocolError.scsiFailure(status: status, sense: data)
                }
            }
        }
        throw ProtocolError.invalidState
    }
}
