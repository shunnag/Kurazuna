import FSKit
import Foundation
import ISCSICore
import ISCSIPlatform

struct BlockMountResourceBinding: Sendable, Equatable {
    let marker: BlockMountResource
    let mount: BlockMountIdentity
    let isWritable: Bool

    init(
        bsdName: String, blockSize: UInt64, physicalBlockSize: UInt64, blockCount: UInt64,
        isWritable: Bool, isRevoked: Bool = false, readHeader: () throws -> Data
    ) throws {
        guard !isRevoked, blockSize == BlockMountResource.logicalBlockSize,
            blockCount == BlockMountResource.mediaByteCount / BlockMountResource.logicalBlockSize,
            [UInt64(512), 4096].contains(physicalBlockSize),
            BlockMountIdentity.isValidBSDName(bsdName)
        else { throw POSIXError(.EINVAL) }
        marker = try BlockMountResource(header: readHeader())
        mount = try BlockMountIdentity(bsdName: bsdName, mountID: marker.reference.mountID)
        self.isWritable = isWritable
    }

    static func read(_ resource: FSBlockDeviceResource) throws -> Self {
        try Self(
            bsdName: resource.bsdName, blockSize: resource.blockSize,
            physicalBlockSize: resource.physicalBlockSize, blockCount: resource.blockCount,
            isWritable: resource.isWritable, isRevoked: resource.isRevoked
        ) {
            var header = Data(count: BlockMountResource.headerByteCount)
            let count = try header.withUnsafeMutableBytes {
                try resource.read(into: $0, startingAt: 0, length: $0.count)
            }
            guard count == header.count else { throw POSIXError(.EIO) }
            return header
        }
    }
}

/// The framework owns this read-only resource interface for the load's lifetime.
final class LoadedBlockResourceCheck: @unchecked Sendable {
    private let resource: FSBlockDeviceResource
    private let binding: BlockMountResourceBinding

    init(resource: FSBlockDeviceResource, binding: BlockMountResourceBinding) {
        self.resource = resource
        self.binding = binding
    }

    func check() throws {
        guard try BlockMountResourceBinding.read(resource) == binding, !resource.isRevoked else {
            throw POSIXError(.EIO)
        }
    }
}
