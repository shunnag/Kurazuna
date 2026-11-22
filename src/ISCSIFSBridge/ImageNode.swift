import FSKit
import Foundation

enum ImageNode: Hashable, Sendable {
    case root, raw
    var directory: Bool { self == .root }
}

final class ImageItem: FSItem, @unchecked Sendable {
    let owner: UUID
    let node: ImageNode
    var directory: Bool { node.directory }

    init(owner: UUID, node: ImageNode) {
        self.owner = owner
        self.node = node
        super.init()
    }
}
