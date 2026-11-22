import FSKit
import Foundation

/// Metadata belongs to the temporary bridge namespace, never to sectors of the remote disk.
/// Caller serializes access with the volume's item lock; reclaim must retain these values.
struct LocalXattrs {
    static let maximumValueSize = 65_536
    static let maximumStorage = 16 * 1_048_576
    private var values: [ImageNode: [String: Data]] = [:]
    private var storage = 0

    func value(named name: String, on node: ImageNode) throws -> Data {
        guard let value = values[node]?[name] else { throw POSIXError(.ENOATTR) }
        return value
    }

    func names(on node: ImageNode) -> [String] { values[node]?.keys.sorted() ?? [] }

    mutating func set(
        _ value: Data?, named name: String, on node: ImageNode,
        policy: FSVolume.SetXattrPolicy
    ) throws {
        guard !name.isEmpty, name.utf8.count <= 255, !name.utf8.contains(0) else {
            throw POSIXError(.EINVAL)
        }
        let old = values[node]?[name]
        switch policy {
        case .alwaysSet: break
        case .mustCreate: guard old == nil else { throw POSIXError(.EEXIST) }
        case .mustReplace, .delete: guard old != nil else { throw POSIXError(.ENOATTR) }
        @unknown default: throw POSIXError(.EINVAL)
        }
        if policy == .delete {
            guard value == nil else { throw POSIXError(.EINVAL) }
            storage -= old!.count + name.utf8.count + 128
            values[node]?.removeValue(forKey: name)
            if values[node]?.isEmpty == true { values.removeValue(forKey: node) }
            return
        }
        guard let value else { throw POSIXError(.EINVAL) }
        guard value.count <= Self.maximumValueSize else { throw POSIXError(.E2BIG) }
        let increase = value.count - (old?.count ?? 0) + (old == nil ? name.utf8.count + 128 : 0)
        guard storage + increase <= Self.maximumStorage else { throw POSIXError(.ENOSPC) }
        values[node, default: [:]][name] = value
        storage += increase
    }
}
