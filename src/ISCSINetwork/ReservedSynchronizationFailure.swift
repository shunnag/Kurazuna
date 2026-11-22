import Foundation

/// A live failure captured before the originating disk releases its I/O gate.
/// This is neither a saved recovery permit nor proof of filesystem durability.
public struct ReservedSynchronizationFailure: Error, Sendable {
    public let underlyingError: any Error
    private let access: ReservedDiskAccess
    private let origin: ReservedMutationOrigin
    private let incidentID: UUID
    private let evidenceGeneration: UInt64
    private let serviceGeneration: UInt64

    init(
        access: ReservedDiskAccess, incident: MutationIncident, evidence: MutationEvidence,
        error: any Error
    ) {
        self.access = access
        origin = access.origin
        incidentID = incident.id
        evidenceGeneration = evidence.generation
        serviceGeneration = evidence.serviceGeneration
        underlyingError = error
    }

    func validate(access expected: ReservedDiskAccess, evidence: MutationEvidence) throws {
        guard access === expected, origin == expected.origin,
            evidence.reservedOrigin == origin, evidence.incident?.id == incidentID,
            evidence.generation == evidenceGeneration,
            evidence.serviceGeneration == serviceGeneration,
            expected.generation == serviceGeneration
        else { throw MutationRecoveryIssue.wrongContext }
    }
}
