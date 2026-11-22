import Darwin
import Foundation
import ISCSICore

enum CallbackTraceProbe {
    static func captureIfRequested(
        root: URL, image: URL, beforeWrite: Bool, fullsyncReturned: UInt64? = nil
    ) throws {
        guard ProcessInfo.processInfo.environment["ISCSI_TEST_CALLBACK_TRACE"] == "1" else {
            return
        }
        var bytes = Data(count: 65_536)
        let count = bytes.withUnsafeMutableBytes {
            getxattr(
                image.path, "dev.soba.iscsi.test.callback-trace", $0.baseAddress, $0.count, 0, 0)
        }
        guard count > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        bytes.count = count
        guard var report = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
            report["explicitReplyHandlers"] as? Bool == true,
            report["timestampBeforeTraceLock"] as? Bool == true,
            report["includesReplyReturnEvents"] as? Bool == true,
            report["droppedEvents"] as? Int == 0,
            let events = report["events"] as? [[String: Any]]
        else { throw ProtocolError.malformed("bounded explicit callback trace was not selected") }
        if let fullsyncReturned {
            report["fullsyncReturnedUptimeNS"] = fullsyncReturned
            report["capturedAfterStableSnapshot"] = true
        }
        let phase = beforeWrite ? "BeforeWrite" : "AfterSnapshot"
        try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]).write(
            to: root.appendingPathComponent("CallbackTrace\(phase).json"))
        print("CALLBACK_TRACE \(phase) events=\(events.count), dropped=0")
    }
}
