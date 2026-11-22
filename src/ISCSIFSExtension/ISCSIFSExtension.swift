import FSKit
import ISCSIFSBridge

@main
struct ISCSIFSExtension: UnaryFileSystemExtension {
    let fileSystem = ISCSIFileSystem()
}
