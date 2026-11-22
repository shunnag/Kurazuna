import Darwin
import Foundation
import ISCSICore

public enum SystemCommandError: Error, Sendable, Equatable {
    case failed(program: String, status: Int32, detail: String)
    case timedOut(program: String)
}

public enum SystemCommand {
    /// Arguments are passed directly. Completion waits for child termination and capture cleanup.
    public static func run(_ executable: String, arguments: [String], timeout: TimeInterval = 45)
        async throws -> Data
    {
        guard timeout.isFinite, (0.05...120).contains(timeout) else {
            throw ProtocolError.invalidState
        }
        try Task.checkCancellation()
        let job = try CommandJob(executable: executable, arguments: arguments)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { job.start($0, timeout: timeout) }
        } onCancel: {
            job.stop(with: CancellationError())
        }
    }
}

private final class CommandPipe: @unchecked Sendable {
    let reader: FileHandle
    let writer: FileHandle

    init() throws {
        var descriptors: [Int32] = [0, 0]
        guard pipe(&descriptors) == 0 else { throw Self.error() }
        do {
            for descriptor in descriptors {
                guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else { throw Self.error() }
            }
            let flags = fcntl(descriptors[0], F_GETFL)
            guard flags >= 0, fcntl(descriptors[0], F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw Self.error()
            }
        } catch {
            close(descriptors[0])
            close(descriptors[1])
            throw error
        }
        reader = FileHandle(fileDescriptor: descriptors[0], closeOnDealloc: true)
        writer = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true)
    }

    static func error() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}

/// All Process state, reads, deadlines and cancellation transitions run on one serial queue.
private final class CommandJob: @unchecked Sendable {
    private let queue = DispatchQueue(label: "dev.soba.iscsi.command", qos: .userInitiated)
    private let process = Process()
    private let pipes: [CommandPipe]
    private let program: String
    private var sources: [DispatchSourceRead] = []
    private var ended: Set<Int> = []
    private var closed: Set<Int> = []
    private var output = Data()
    private var errorOutput = Data()
    private var byteCounts = [0, 0]
    private var continuation: CheckedContinuation<Data, any Error>?
    private var failure: (any Error)?
    private var launched = false
    private var exited = false
    private var status: Int32 = 0
    private var pendingResult: Result<Data, any Error>?
    private var timer: DispatchWorkItem?
    private var escalation: DispatchWorkItem?

    init(executable: String, arguments: [String]) throws {
        program = URL(fileURLWithPath: executable).lastPathComponent
        pipes = try [CommandPipe(), CommandPipe()]
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipes[0].writer
        process.standardError = pipes[1].writer
    }

    func start(_ continuation: CheckedContinuation<Data, any Error>, timeout: TimeInterval) {
        queue.async { [self] in
            self.continuation = continuation
            if failure != nil {
                finish()
                return
            }
            for index in pipes.indices {
                let source = DispatchSource.makeReadSource(
                    fileDescriptor: pipes[index].reader.fileDescriptor, queue: queue)
                source.setEventHandler { [weak self] in self?.read(index) }
                source.setCancelHandler { [self] in
                    try? pipes[index].reader.close()
                    closed.insert(index)
                    completeIfClosed()
                }
                sources.append(source)
                source.resume()
            }
            process.terminationHandler = { [weak self] child in
                let status = child.terminationStatus
                self?.queue.async { [weak self] in self?.didExit(status) }
            }
            do {
                try process.run()
                launched = true
            } catch {
                failure = error
                exited = true
            }
            // Only the child's copies may keep the pipe writers alive.
            for pipe in pipes { try? pipe.writer.close() }
            if failure != nil {
                finish()
                return
            }
            let timer = DispatchWorkItem { [weak self] in
                guard let self else { return }
                stopOnQueue(SystemCommandError.timedOut(program: program))
            }
            self.timer = timer
            queue.asyncAfter(deadline: .now() + timeout, execute: timer)
        }
    }

    func stop(with error: any Error) {
        queue.async { [self] in stopOnQueue(error) }
    }

    private func stopOnQueue(_ error: any Error) {
        guard pendingResult == nil else { return }
        if failure == nil { failure = error }
        for source in sources { source.cancel() }
        if !launched || exited {
            if continuation != nil { finish() }
            return
        }
        if process.isRunning { process.terminate() }
        guard escalation == nil else { return }
        let escalation = DispatchWorkItem { [weak self] in
            guard let self, pendingResult == nil, !exited, process.isRunning else { return }
            _ = kill(process.processIdentifier, SIGKILL)
        }
        self.escalation = escalation
        queue.asyncAfter(deadline: .now() + 2, execute: escalation)
    }

    private func read(_ index: Int) {
        guard pendingResult == nil, failure == nil, !ended.contains(index) else { return }
        var bytes = [UInt8](repeating: 0, count: 8192)
        // Yield between bounded batches so a noisy child cannot starve its deadline.
        for _ in 0..<16 {
            let count = Darwin.read(pipes[index].reader.fileDescriptor, &bytes, bytes.count)
            if count > 0 {
                guard byteCounts[index] <= 1_048_576 - count else {
                    stopOnQueue(
                        ProtocolError.limitExceeded(
                            index == 0 ? "command output" : "command error output"))
                    return
                }
                byteCounts[index] += count
                if index == 0 {
                    output.append(contentsOf: bytes.prefix(count))
                } else {
                    errorOutput.append(
                        contentsOf: bytes.prefix(min(count, 4096 - errorOutput.count)))
                }
            } else if count == 0 {
                ended.insert(index)
                sources[index].cancel()
                if exited, ended.count == pipes.count { finish() }
                return
            } else if errno == EINTR {
                continue
            } else if errno == EAGAIN || errno == EWOULDBLOCK {
                return
            } else {
                stopOnQueue(CommandPipe.error())
                return
            }
        }
    }

    private func didExit(_ status: Int32) {
        self.status = status
        exited = true
        if failure != nil || ended.count == pipes.count { finish() }
    }

    private func finish() {
        guard pendingResult == nil else { return }
        timer?.cancel()
        timer = nil
        escalation?.cancel()
        escalation = nil
        process.terminationHandler = nil
        if let failure {
            pendingResult = .failure(failure)
        } else if status != 0 {
            pendingResult = .failure(
                SystemCommandError.failed(
                    program: program, status: status,
                    detail: String(decoding: errorOutput, as: UTF8.self)))
        } else {
            pendingResult = .success(output)
        }
        for pipe in pipes { try? pipe.writer.close() }
        if sources.isEmpty {
            for index in pipes.indices {
                try? pipes[index].reader.close()
                closed.insert(index)
            }
        } else {
            for source in sources { source.cancel() }
        }
        completeIfClosed()
    }

    private func completeIfClosed() {
        guard let result = pendingResult, let continuation, closed.count == pipes.count else {
            return
        }
        self.continuation = nil
        sources.removeAll()
        continuation.resume(with: result)
    }
}
