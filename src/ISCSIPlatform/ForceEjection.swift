import Foundation
import ISCSICore

/// A transient observation of the actual media, never a persisted BSD device name.
public struct DiskAttachmentIdentity: Sendable, Equatable {
    public let imageURL: URL
    public let device: String
    public let unmountDevices: [String]
    public let mediaIdentifiers: [String: UInt64]

    public init(
        imageURL: URL, device: String, unmountDevices: [String],
        mediaIdentifiers: [String: UInt64]
    ) {
        self.imageURL = imageURL
        self.device = device
        self.unmountDevices = unmountDevices
        self.mediaIdentifiers = mediaIdentifiers
    }
}

/// What one confirmed forced release acts on, observed while preparing its confirmation.
/// An earlier attempt may already have released some resources, so each part is optional;
/// a part absent here must still be absent, and a present one unchanged, when it is used.
/// Never persisted: a later attempt observes the resources again and needs new consent.
public struct ForcedReleaseIdentity: Sendable, Equatable {
    /// The inner disk image, if it was still attached.
    public let image: DiskAttachmentIdentity?
    /// Whether the outer bridge was mounted. A test backend that doesn't distinguish
    /// this reports it as mounted.
    let bridgeMounted: Bool
    /// The local media bound to a mounted block bridge. Keep this transient binding
    /// inside the confirmation; never persist consent.
    let bridgeResource: BlockMountResources.ForceIdentity?

    public init(image: DiskAttachmentIdentity?) {
        self.init(image: image, bridgeMounted: true, bridgeResource: nil)
    }

    init(
        image: DiskAttachmentIdentity?, bridgeMounted: Bool,
        bridgeResource: BlockMountResources.ForceIdentity?
    ) {
        self.image = image
        self.bridgeMounted = bridgeMounted
        self.bridgeResource = bridgeResource
    }
}

/// One-use confirmation bound to the resources observed for one disk. Only the coordinator
/// can create a request; recovery never recreates consent.
public struct ForceEjectionRequest: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let diskID: UUID
    public let displayName: String
    /// The connection to the server was interrupted, closed, or couldn't be read when the
    /// confirmation was prepared. A change in either direction requires a new confirmation.
    public let reportsLostConnection: Bool
    let descriptor: ConnectionDescriptor
    let bridgeURL: URL
    let release: ForcedReleaseIdentity
}
