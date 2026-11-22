import CoreFoundation
import DiskArbitration
import Foundation
import IOKit
import ISCSICore

struct BlockResourceMedia: Sendable, Equatable {
    let device: String
    let identifier: UInt64

    init(device: String, identifier: UInt64, description: [String: Any]) throws {
        let suffix = device.dropFirst(9)
        guard device.hasPrefix("/dev/disk"), !suffix.isEmpty,
            suffix.utf8.allSatisfy({ (48...57).contains($0) }), identifier != 0,
            let whole = description[kDADiskDescriptionMediaWholeKey as String] as? NSNumber,
            CFGetTypeID(whole) == CFBooleanGetTypeID(), whole.boolValue,
            let writable = description[kDADiskDescriptionMediaWritableKey as String] as? NSNumber,
            CFGetTypeID(writable) == CFBooleanGetTypeID(), writable.boolValue,
            let size = description[kDADiskDescriptionMediaSizeKey as String] as? NSNumber,
            Self.integer(size) == BlockMountResource.mediaByteCount,
            let block = description[kDADiskDescriptionMediaBlockSizeKey as String] as? NSNumber,
            Self.integer(block) == BlockMountResource.logicalBlockSize
        else { throw AttachmentError.ownershipUnverified }
        self.device = device
        self.identifier = identifier
    }

    static func read(_ device: String) throws -> Self {
        guard let session = DASessionCreate(kCFAllocatorDefault),
            let disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, device),
            let description = DADiskCopyDescription(disk) as? [String: Any]
        else { throw POSIXError(.ENXIO) }
        let media = DADiskCopyIOMedia(disk)
        guard media != 0 else { throw POSIXError(.ENXIO) }
        defer { IOObjectRelease(media) }
        var identifier: UInt64 = 0
        guard IORegistryEntryGetRegistryEntryID(media, &identifier) == KERN_SUCCESS else {
            throw POSIXError(.ENXIO)
        }
        return try Self(device: device, identifier: identifier, description: description)
    }

    private static func integer(_ number: NSNumber) -> UInt64? {
        guard ["q", "Q", "i", "I", "l", "L", "s", "S"].contains(String(cString: number.objCType)),
            number.int64Value > 0
        else { return nil }
        return number.uint64Value
    }
}
