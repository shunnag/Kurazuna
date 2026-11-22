import Darwin
import Foundation
import ISCSICore

enum HandlerControlProbe {
    static func captureIfRequested(
        root: URL, image: URL, beforeWrite: Bool, fullsyncReturned: UInt64? = nil
    ) throws {
        guard ProcessInfo.processInfo.environment["ISCSI_TEST_HANDLER_CONTROL"] == "1" else {
            return
        }
        var bytes = Data(count: 4096)
        let count = bytes.withUnsafeMutableBytes {
            getxattr(
                image.path, "dev.soba.iscsi.test.handler-control", $0.baseAddress, $0.count, 0, 0)
        }
        guard count > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        bytes.count = count
        guard var report = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
            report["readWriteHandler"] as? Bool == true,
            report["legacyReadWriteOperations"] as? Bool == false,
            let reads = report["readReplies"] as? Int, reads > 0
        else { throw ProtocolError.malformed("macOS27 handler control was not selected") }
        let phase = beforeWrite ? "BeforeWrite" : "AfterSnapshot"
        if let fullsyncReturned {
            report["fullsyncReturnedUptimeNS"] = fullsyncReturned
            report["countersCapturedAfterStableSnapshot"] = true
        }
        bytes = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        try bytes.write(to: root.appendingPathComponent("HandlerControl\(phase).json"))
        print("HANDLER_CONTROL \(phase) " + String(decoding: bytes, as: UTF8.self))
    }
}
