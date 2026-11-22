import Darwin
import Foundation
import ISCSICore

@testable import ISCSIPlatform

/// Observe actual command replies without delaying them for file I/O. Save only
/// this fixture's inventory entries; unrelated images never enter the trace file.
final class AttachmentCommandTrace: @unchecked Sendable {
    private struct Row {
        let program: String
        let arguments: [String]
        let started: UInt64
        let completed: UInt64
        let data: Data?
        let error: String?
    }
    private let lock = NSLock()
    private var rows: [Row] = []
    private let root: URL

    init(root: URL) { self.root = root }

    func images() -> DiskImages {
        let root = root
        return DiskImages(
            run: { [self] program, arguments, timeout in
                let started = DispatchTime.now().uptimeNanoseconds
                do {
                    let data = try await SystemCommand.run(
                        program, arguments: arguments, timeout: timeout)
                    try append(
                        Row(
                            program: program, arguments: arguments, started: started,
                            completed: DispatchTime.now().uptimeNanoseconds, data: data, error: nil)
                    )
                    return data
                } catch {
                    try append(
                        Row(
                            program: program, arguments: arguments, started: started,
                            completed: DispatchTime.now().uptimeNanoseconds, data: nil,
                            error: String(describing: error)))
                    throw error
                }
            },
            fileSize: { url in
                guard url.standardizedFileURL.deletingLastPathComponent() == root else {
                    throw ProtocolError.invalidState
                }
                var status = stat()
                guard lstat(url.path, &status) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                guard status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                    status.st_uid == geteuid(), status.st_size >= 0
                else { throw POSIXError(.EINVAL) }
                return UInt64(status.st_size)
            })
    }

    private func append(_ row: Row) throws {
        try lock.withLock {
            guard rows.count < 256 else {
                throw ProtocolError.limitExceeded("fixture attachment trace")
            }
            rows.append(row)
        }
    }

    func save(name: String) throws {
        let records = try lock.withLock { rows }.map { row -> [String: Any] in
            var result: [String: Any] = [
                "program": row.program, "arguments": row.arguments,
                "startedNS": row.started, "completedNS": row.completed,
            ]
            if let error = row.error { result["error"] = error }
            if let data = row.data {
                if var plist = try? PropertyListSerialization.propertyList(from: data, format: nil)
                    as? [String: Any]
                {
                    if let images = plist["images"] as? [[String: Any]] {
                        plist["originalImageCount"] = images.count
                        plist["images"] = images.filter { image in
                            guard let path = image["image-path"] as? String else { return false }
                            return path.hasPrefix(root.path + "/")
                        }
                    }
                    result["plistBase64"] = try PropertyListSerialization.data(
                        fromPropertyList: plist, format: .binary, options: 0
                    ).base64EncodedString()
                } else {
                    result["stdoutBase64"] = data.base64EncodedString()
                }
            }
            return result
        }
        try JSONSerialization.data(withJSONObject: records, options: [.sortedKeys])
            .write(to: root.appendingPathComponent(name), options: .atomic)
    }
}
