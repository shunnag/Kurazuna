import FSKit
import Foundation
import ISCSICore
import ISCSIFSBridge
import ISCSINetwork

private enum SensePhase: String {
    case unsupported20, unsupported24, inquiryAttention, capacityAttention
    case notReady, noMedia, unavailable
    case read, write, synchronize, close

    var key: UInt8 {
        switch self {
        case .unsupported20, .unsupported24, .unavailable: 5
        case .inquiryAttention, .capacityAttention: 6
        case .notReady, .noMedia: 2
        default: 7
        }
    }
    var asc: UInt8 {
        switch self {
        case .unsupported20: 0x20
        case .unsupported24: 0x24
        case .inquiryAttention, .capacityAttention: 0x29
        case .notReady: 0x04
        case .noMedia: 0x3A
        case .unavailable: 0x25
        default: 0x27
        }
    }
}

enum DeferredSenseProbe {
    static func run(portal: String, credentials: CHAPCredentials?) async throws {
        let env = ProcessInfo.processInfo.environment
        guard let phase = env["ISCSI_TEST_SENSE_PHASE"].flatMap(SensePhase.init(rawValue:)),
            let response = env["ISCSI_TEST_SENSE_RESPONSE"].flatMap({ UInt8($0, radix: 16) }),
            [UInt8(0x70), 0x71, 0x72, 0x73].contains(response)
        else { throw ProtocolError.invalidState }
        let source = try Portal(portal)
        guard source.host == "127.0.0.1" else { throw ProtocolError.invalidState }
        let connection = try await SessionConnector.connect(
            portal: source,
            configuration: LoginConfiguration(
                initiatorName: "iqn.2026-10.test:sense-probe",
                targetName: "iqn.2026-10.test:memory", credentials: credentials),
            timeout: .seconds(5))
        let session = connection.session
        let lun = try LogicalUnit(0)
        let deferred = response == 0x71 || response == 0x73
        let sense =
            response == 0x70 || response == 0x71
            ? Data([response, 0, phase.key, 0, 0, 0, 0, 6, 0, 0, 0, 0, phase.asc, 0])
            : Data([response, phase.key, phase.asc, 0, 0, 0, 0, 0])
        var volume: LUNImageVolume?
        do {
            var error: (any Error)?
            var value = 0
            do {
                switch phase {
                case .unsupported20, .unsupported24, .capacityAttention:
                    value = Int(try await DiskProbe.capacity(session: session, lun: lun).byteCount)
                case .inquiryAttention:
                    value = try await DiskProbe.readOnly(.inquiry(), session: session, lun: lun)
                        .data.count
                case .notReady, .noMedia, .unavailable:
                    _ = try await DiskProbe.diskInformation(session: session, lun: lun)
                case .read, .write, .synchronize, .close:
                    let information = try await DiskProbe.diskInformation(
                        session: session, lun: lun)
                    guard information.capacity.byteCount == 65_536 else {
                        throw ProtocolError.invalidState
                    }
                    let disk = RemoteDisk(
                        session: session, lun: lun, capacity: information.capacity, readOnly: false)
                    let image = LUNImageVolume(disk: disk, identifier: UUID())
                    volume = image
                    let (item, _) = try await (image as any FSVolume.Operations).lookupItem(
                        named: FSFileName(string: LUNImageVolume.imageName),
                        inDirectory: image.rootItem)
                    switch phase {
                    case .read: _ = try await disk.read(offset: 0, length: 512)
                    case .write:
                        _ = try await image.write(
                            contents: Data(repeating: 0xA5, count: 512), to: item, at: 0)
                    case .synchronize:
                        // The target must see no WRITE; count one as acknowledged, unflushed.
                        try UnsynchronizedWrite.mark(disk)
                        try await image.synchronize(flags: .wait)
                    case .close:
                        try await image.openItem(item, modes: .write)
                        try UnsynchronizedWrite.mark(disk)
                        try await image.closeItem(item, modes: [])
                    default: throw ProtocolError.invalidState
                    }
                }
            } catch let caught { error = caught }
            let outcome: String
            switch phase {
            case .unsupported20, .unsupported24, .inquiryAttention, .capacityAttention:
                if deferred {
                    guard error as? ProtocolError == .scsiFailure(status: 2, sense: sense) else {
                        throw ProtocolError.malformed(
                            "deferred sense concealed by retry or fallback")
                    }
                    outcome = "original-sense"
                } else {
                    guard error == nil, value == (phase == .inquiryAttention ? 36 : 65_536) else {
                        throw ProtocolError.malformed("current sense recovery")
                    }
                    outcome = "recovered"
                }
            case .notReady, .noMedia, .unavailable:
                if deferred {
                    guard error as? ProtocolError == .scsiFailure(status: 2, sense: sense) else {
                        throw ProtocolError.malformed("original deferred disk error")
                    }
                } else {
                    let expected: DiskProbeIssue =
                        phase == .notReady ? .notReady : phase == .noMedia ? .noMedia : .unavailable
                    guard error as? DiskProbeIssue == expected else {
                        throw ProtocolError.malformed("current disk issue classification")
                    }
                }
                outcome = deferred ? "original-sense" : phase.rawValue
            case .read:
                guard error as? ProtocolError == .scsiFailure(status: 2, sense: sense) else {
                    throw ProtocolError.malformed("remote read sense preservation")
                }
                outcome = "original-sense"
            case .write, .synchronize, .close:
                guard (error as? POSIXError)?.code == (deferred ? .EIO : .EROFS) else {
                    throw ProtocolError.malformed("deferred filesystem error classification")
                }
                outcome = deferred ? "EIO" : "EROFS"
            }
            if deferred {
                guard await session.state == .failed else { throw ProtocolError.invalidState }
                if let volume {
                    guard
                        try await volume.xattr(
                            named: FSFileName(
                                string: ConnectionDescriptor.connectionStateAttributeName),
                            of: volume.rootItem) == DiskConnectionState.interrupted.encoded
                    else { throw ProtocolError.invalidState }
                }
                do {
                    _ = try await session.execute(.testUnitReady(), lun: lun)
                    throw ProtocolError.malformed("I/O admitted after a deferred error")
                } catch ProtocolError.invalidState {}
                await session.close()
            } else {
                guard await session.state == .ready else { throw ProtocolError.invalidState }
                try await session.logout()
            }
            await volume?.shutdown()
            let result: [String: Any] = [
                "response": String(format: "%02x", response),
                "phase": phase.rawValue, "outcome": outcome, "value": value,
                "noFSKitMountUsed": true, "sessionClosed": await session.state == .closed,
                "failureLatched": deferred,
            ]
            print(
                "SENSE_RESULT "
                    + String(
                        decoding: try JSONSerialization.data(
                            withJSONObject: result, options: [.sortedKeys]), as: UTF8.self))
        } catch {
            await volume?.shutdown()
            await session.closeGracefully()
            throw error
        }
    }
}
