import CryptoKit
import Darwin
import Foundation

/// A disposable APFS workload above the production FSKit/DiskImages stack.
enum SoakWorkload {
    struct FileProof: Codable, Sendable {
        let index: Int
        let name: String
        let length: Int
        let sha256: String
        let rounds: Int
        let bytesWritten: Int
        let renames: Int
    }

    struct Report: Codable, Sendable {
        let nonce: UUID
        let requestedSeconds: Int
        let elapsedMilliseconds: Int64
        let files: [FileProof]
    }

    private struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    private actor Progress {
        private var next = ContinuousClock.now.advanced(by: .seconds(30))
        private var rounds = 0
        private var bytes = 0

        func record(bytesWritten: Int) throws {
            rounds += 1
            bytes += bytesWritten
            guard ContinuousClock.now >= next else { return }
            next = ContinuousClock.now.advanced(by: .seconds(30))
            let data = try JSONSerialization.data(
                withJSONObject: ["rounds": rounds, "bytesWritten": bytes], options: .sortedKeys)
            FileHandle.standardOutput.write(Data("FSKIT_SOAK_PROGRESS ".utf8) + data + Data([10]))
        }
    }

    private struct Generator {
        var state: UInt64

        mutating func next() -> UInt64 {
            state ^= state << 13
            state ^= state >> 7
            state ^= state << 17
            return state
        }

        mutating func data(count: Int) -> Data {
            var result = Data(count: count)
            result.withUnsafeMutableBytes { (bytes: UnsafeMutableRawBufferPointer) in
                for index in 0..<count { bytes[index] = UInt8(truncatingIfNeeded: next()) }
            }
            return result
        }
    }

    static func run(at volume: URL, root: URL, nonce: UUID, seconds: Int) async throws -> Report {
        guard (60...3600).contains(seconds) else { throw Failure("Invalid soak duration") }
        let start = ContinuousClock.now
        let deadline = start.advanced(by: .seconds(seconds))
        let progress = Progress()
        let files = try await withThrowingTaskGroup(of: FileProof.self) { group in
            for index in 0..<4 {
                group.addTask {
                    try await worker(
                        index: index, volume: volume, nonce: nonce, deadline: deadline,
                        progress: progress)
                }
            }
            var results: [FileProof] = []
            for try await result in group { results.append(result) }
            return results.sorted { $0.index < $1.index }
        }
        let elapsed = start.duration(to: .now).components
        let milliseconds = elapsed.seconds * 1000 + elapsed.attoseconds / 1_000_000_000_000_000
        let report = Report(
            nonce: nonce, requestedSeconds: seconds, elapsedMilliseconds: milliseconds,
            files: files)
        guard milliseconds >= seconds * 1000,
            files.allSatisfy({ $0.rounds >= 7 && $0.renames >= 1 })
        else { throw Failure("Soak did not exercise every operation for the requested duration") }
        try verify(at: volume, report: report)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let output = root.appendingPathComponent("SoakReport.json")
        try encoder.encode(report).write(to: output, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: output.path)
        print(
            "PASS: four concurrent APFS workers, \(milliseconds) ms, full bytes, xattrs and renames"
        )
        return report
    }

    static func load(root: URL, nonce: UUID) throws -> Report {
        let data = try Data(contentsOf: root.appendingPathComponent("SoakReport.json"))
        guard data.count <= 16_384 else { throw Failure("Soak report exceeds limit") }
        let report = try JSONDecoder().decode(Report.self, from: data)
        guard report.nonce == nonce, (60...3600).contains(report.requestedSeconds),
            report.elapsedMilliseconds >= report.requestedSeconds * 1000,
            report.files.map(\.index) == [0, 1, 2, 3]
        else { throw Failure("Invalid soak report") }
        for file in report.files {
            guard
                [
                    name(index: file.index, nonce: nonce, alternate: false),
                    name(index: file.index, nonce: nonce, alternate: true),
                ].contains(file.name),
                file.length == 2 * 1_048_576 + 37 + file.index,
                file.sha256.count == 64,
                file.sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                file.rounds >= 7, file.renames >= 1, file.bytesWritten >= file.length
            else { throw Failure("Invalid soak file proof") }
        }
        return report
    }

    static func verify(at volume: URL, report: Report) throws {
        let names = try FileManager.default.contentsOfDirectory(atPath: volume.path)
            .filter { $0.hasPrefix("検証-") }
        guard Set(names) == Set(report.files.map(\.name)) else {
            throw Failure("Soak directory entries differ after renaming")
        }
        for proof in report.files {
            let url = volume.appendingPathComponent(proof.name)
            let file = try open(url)
            defer { try? file.close() }
            guard let bytes = try file.readToEnd(), bytes.count == proof.length,
                hash(bytes) == proof.sha256
            else { throw Failure("Soak file content differs: \(proof.index)") }
            let expected = Data("\(report.nonce.uuidString.lowercased()):\(proof.index)".utf8)
            var actual = Data(count: expected.count)
            let count = actual.withUnsafeMutableBytes {
                getxattr(url.path, "dev.soba.iscsi.validation", $0.baseAddress, $0.count, 0, 0)
            }
            guard count == expected.count, actual == expected else {
                throw Failure("Soak extended attribute differs: \(proof.index)")
            }
        }
        print("PASS: all four soak files and extended attributes match their independent report")
    }

    private static func worker(
        index: Int, volume: URL, nonce: UUID, deadline: ContinuousClock.Instant,
        progress: Progress
    ) async throws -> FileProof {
        var seed = UInt64(index + 1)
        for byte in nonce.uuidString.utf8 { seed = (seed ^ UInt64(byte)) &* 1_099_511_628_211 }
        var generator = Generator(state: seed == 0 ? 1 : seed)
        var expected = generator.data(count: 2 * 1_048_576 + 37 + index)
        var alternate = false
        var url = volume.appendingPathComponent(
            name(index: index, nonce: nonce, alternate: alternate))
        guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
            throw Failure("Cannot create soak file")
        }
        var file = try open(url, updating: true)
        defer { try? file.close() }
        try file.write(contentsOf: expected)
        let attribute = Data("\(nonce.uuidString.lowercased()):\(index)".utf8)
        let status = attribute.withUnsafeBytes {
            setxattr(
                url.path, "dev.soba.iscsi.validation", $0.baseAddress, $0.count, 0, XATTR_CREATE)
        }
        guard status == 0 else { throw posixFailure() }
        try fullSync(file)
        let lengths = [1, 511, 513, 4093, 4097, 65_573, 1_048_579]
        var rounds = 0
        var bytesWritten = expected.count
        var renames = 0
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            let length = lengths[rounds % lengths.count]
            let offset = Int(generator.next() % UInt64(expected.count - length + 1))
            let data = generator.data(count: length)
            try file.seek(toOffset: UInt64(offset))
            try file.write(contentsOf: data)
            expected.replaceSubrange(offset..<(offset + length), with: data)
            try fullSync(file)
            try file.seek(toOffset: 0)
            guard try file.readToEnd() == expected else {
                throw Failure("Concurrent soak readback differs: \(index), round \(rounds)")
            }
            rounds += 1
            bytesWritten += length
            if rounds.isMultiple(of: lengths.count) {
                try file.close()
                alternate.toggle()
                let replacement = volume.appendingPathComponent(
                    name(index: index, nonce: nonce, alternate: alternate))
                try FileManager.default.moveItem(at: url, to: replacement)
                url = replacement
                file = try open(url, updating: true)
                try fullSync(file)
                renames += 1
            }
            try await progress.record(bytesWritten: length)
            try await Task.sleep(for: .milliseconds(50))
        }
        try fullSync(file)
        try file.close()
        return FileProof(
            index: index, name: url.lastPathComponent, length: expected.count,
            sha256: hash(expected), rounds: rounds, bytesWritten: bytesWritten, renames: renames)
    }

    private static func name(index: Int, nonce: UUID, alternate: Bool) -> String {
        "検証-\(index)-\(nonce.uuidString.prefix(8))-\(alternate ? "b" : "a").bin"
    }

    private static func open(_ url: URL, updating: Bool = false) throws -> FileHandle {
        let file = try updating ? FileHandle(forUpdating: url) : FileHandle(forReadingFrom: url)
        guard fcntl(file.fileDescriptor, F_NOCACHE, 1) == 0 else {
            let error = posixFailure()
            try? file.close()
            throw error
        }
        return file
    }

    private static func fullSync(_ file: FileHandle) throws {
        try file.synchronize()
        guard fcntl(file.fileDescriptor, F_FULLFSYNC) == 0 else { throw posixFailure() }
    }

    private static func posixFailure() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
