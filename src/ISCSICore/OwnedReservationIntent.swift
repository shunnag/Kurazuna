import Foundation

/// Identification for an owned control operation, never permission to resume a saved session.
public struct OwnedReservationBinding: Codable, Sendable, Equatable {
    public let sessionID: UUID
    public let initiatorName: String
    public let targetName: String
    public let isid: [UInt8]
    public let tsih: UInt16
    public let portalGroup: UInt16
    public let relativeTargetPort: UInt16
    public let lun: LogicalUnit
    public let logicalUnitNames: Data
    public let blockCount: UInt64
    public let blockSize: UInt32
    public let quiescenceID: UUID

    public init(
        sessionID: UUID, initiatorName: String, targetName: String, isid: [UInt8],
        tsih: UInt16, portalGroup: UInt16, relativeTargetPort: UInt16,
        lun: LogicalUnit, logicalUnitNames: Data,
        blockCount: UInt64, blockSize: UInt32, quiescenceID: UUID
    ) throws {
        self.sessionID = sessionID
        self.initiatorName = initiatorName
        self.targetName = targetName
        self.isid = isid
        self.tsih = tsih
        self.portalGroup = portalGroup
        self.relativeTargetPort = relativeTargetPort
        self.lun = lun
        self.logicalUnitNames = logicalUnitNames
        self.blockCount = blockCount
        self.blockSize = blockSize
        self.quiescenceID = quiescenceID
        try validate()
    }

    public func validate() throws {
        guard isid.count == 6, tsih != 0, relativeTargetPort != 0, lun.wireBytes.count == 8,
            !initiatorName.isEmpty, initiatorName.utf8.count <= 223,
            !targetName.isEmpty, targetName.utf8.count <= 223,
            !logicalUnitNames.isEmpty, logicalUnitNames.count <= 65_535,
            blockCount > 0, blockSize >= 512, blockSize.nonzeroBitCount == 1,
            !blockCount.multipliedReportingOverflow(by: UInt64(blockSize)).overflow
        else { throw ProtocolError.malformed("owned reservation binding") }
    }
}

public struct OwnedReservationIntent: Codable, Sendable, Equatable {
    public enum Phase: String, Codable, Sendable {
        case prepared, registered, reserving, reserved, releasing, unregistering, released
    }

    public let id: UUID
    public let key: UInt64
    public let binding: OwnedReservationBinding
    public let revision: UInt64
    public let phase: Phase

    public init(id: UUID = UUID(), key: UInt64, binding: OwnedReservationBinding) throws {
        self.id = id
        self.key = key
        self.binding = binding
        revision = 0
        phase = .prepared
        try validate()
    }

    private init(previous: Self, phase: Phase) {
        id = previous.id
        key = previous.key
        binding = previous.binding
        revision = previous.revision + 1
        self.phase = phase
    }

    public func advancing(to next: Phase) throws -> Self {
        let phases: [Phase] = [
            .prepared, .registered, .reserving, .reserved, .releasing, .unregistering, .released,
        ]
        guard let index = phases.firstIndex(of: phase), index + 1 < phases.count,
            phases[index + 1] == next, revision < UInt64.max
        else { throw ProtocolError.invalidState }
        return Self(previous: self, phase: next)
    }

    public func validate() throws {
        try binding.validate()
        let phases: [Phase] = [
            .prepared, .registered, .reserving, .reserved, .releasing, .unregistering, .released,
        ]
        guard key != 0, phases.firstIndex(of: phase).map(UInt64.init) == revision else {
            throw ProtocolError.malformed("owned reservation intent")
        }
    }
}

/// Successful returns must represent durable publication. Implementations must serialize CAS,
/// retain uncertain records, and never infer live ownership from load(). No deletion is needed
/// for the bounded first lifecycle; an orphan requires a separate, explicit recovery policy.
public protocol OwnedReservationIntentStore: Sendable {
    func load() throws -> [OwnedReservationIntent]
    func insert(_ intent: OwnedReservationIntent) throws
    func advance(_ expected: OwnedReservationIntent, to next: OwnedReservationIntent) throws
}
