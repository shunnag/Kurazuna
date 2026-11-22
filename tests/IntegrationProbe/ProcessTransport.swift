import Foundation
import ISCSICore
import ISCSINetwork

/// Test-only transport. The Python target never accesses files, devices or external servers.
final class ProcessTransport: ByteTransport, Sendable {
    private let process: Process
    private let input: FileHandle
    private let output: FileHandle
    private let readQueue = DispatchQueue(label: "dev.soba.iscsi.test.read")
    private let writeQueue = DispatchQueue(label: "dev.soba.iscsi.test.write")

    init(scriptPath: String) throws {
        process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", scriptPath, "--stdio-target"]
        let outgoing = Pipe()
        let incoming = Pipe()
        process.standardInput = outgoing
        process.standardOutput = incoming
        input = outgoing.fileHandleForWriting
        output = incoming.fileHandleForReading
        try process.run()
    }

    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            writeQueue.async { [input] in
                do {
                    try input.write(contentsOf: data)
                    continuation.resume()
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

    func receive(maximumLength: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            readQueue.async { [output] in
                do {
                    guard let data = try output.read(upToCount: maximumLength), !data.isEmpty else {
                        throw ProtocolError.connectionClosed
                    }
                    continuation.resume(returning: data)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

    func close() async {
        try? input.close()
        if process.isRunning { process.terminate() }
    }
}
