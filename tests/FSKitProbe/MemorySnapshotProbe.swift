import Darwin
import Foundation
import ISCSICore

enum MemorySnapshotProbe {
    static var enabled: Bool {
        ProcessInfo.processInfo.environment["ISCSI_TEST_MEMORY_CONTROL"] == "1"
    }

    static func verifyIfRequested(root: URL, image: URL) throws {
        guard enabled else { return }
        let bytes = try attribute(image: image, name: "dev.soba.iscsi.test.memory-control-info")
        guard let report = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
            report["memoryControl"] as? Bool == true,
            report["preloadedBytes"] as? UInt64 == 512 * 1_048_576,
            report["networkIOInReadWriteSyncCallbacks"] as? Bool == false,
            report["seedSHA256"] as? String
                == (try FixtureFileSystem.digest(of: root.appendingPathComponent("HFSPlus.cdr")))
        else { throw ProtocolError.malformed("memory control backend was not selected") }
        try bytes.write(to: root.appendingPathComponent("MemoryControlInfo.json"))
        print("MEMORY_CONTROL_INFO " + String(decoding: bytes, as: UTF8.self))
    }

    static func captureIfRequested(root: URL, image: URL, cutoff: UInt64) throws {
        guard enabled else { return }
        let name = "dev.soba.iscsi.test.memory-snapshot.\(cutoff)"
        let bytes = try attribute(image: image, name: name)
        guard let report = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
            let selected = report["selectedSyncNS"] as? UInt64,
            report["requestedCutoffNS"] as? UInt64 == cutoff, selected <= cutoff,
            report["networkIOInReadWriteSyncCallbacks"] as? Bool == false,
            report["productionRemoteDurabilityTest"] as? Bool == false
        else { throw ProtocolError.malformed("historical memory control snapshot") }
        try bytes.write(to: root.appendingPathComponent("MemoryControlSnapshot.json"))
        print("MEMORY_CONTROL_SNAPSHOT " + String(decoding: bytes, as: UTF8.self))
    }

    private static func attribute(image: URL, name: String) throws -> Data {
        var bytes = Data(count: 4096)
        let count = bytes.withUnsafeMutableBytes {
            getxattr(image.path, name, $0.baseAddress, $0.count, 0, 0)
        }
        guard count > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        bytes.count = count
        return bytes
    }
}
