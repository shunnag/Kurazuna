import Foundation

/// Reserved metadata names. A disabled control must refuse writes, never store them as xattrs.
public enum LUNRecoveryControlAttributes {
    public static let command = "dev.soba.iscsi.validation.recovery.command"
    public static let status = "dev.soba.iscsi.validation.recovery.status"
    public static let maximumCommandBytes = 2048
    public static let maximumStatusBytes = 16_384
}

/// A local snapshot, not authentication, an ownership grant, or recovery eligibility.
public struct LUNRecoveryControlSnapshot: Sendable {
    public let liveVolumeID: UUID
    public let resourceIdentity: Data?
    public let failure: LUNImageVolume.SynchronizationRecoverySelection?
    public let isClosing: Bool
    public let isRecovering: Bool
}

/// An explicitly injected control plane. Implementations must authenticate every command,
/// bind one live owner and descriptor, consume incidents before awaiting, and retain outcomes.
/// They must not retain the volume or a task/closure that captures it.
public protocol LUNRecoveryControl: Sendable {
    var liveVolumeID: UUID { get }
    var resourceIdentity: Data { get }
    func status(for volume: LUNImageVolume) async throws -> Data
    func submit(_ command: Data, to volume: LUNImageVolume) async throws
}
