#if DEBUG
    import FSKit
    import Foundation
    import ISCSICore
    import ISCSINetwork

    @testable import ISCSIFSBridge

    /// Real TCP and the default45-second mount deadline, without a kernel mount.
    enum MountCompletionProbe {
        static func run(portal: String) async throws {
            let portal = try Portal(portal)
            let environment = ProcessInfo.processInfo.environment
            guard portal.host == "127.0.0.1", portal.port > 1024,
                let mode = environment["ISCSI_TEST_MOUNT_COMPLETION_MODE"],
                ["abandoned", "mounted"].contains(mode),
                let token = environment["ISCSI_TEST_MOUNT_COMPLETION_NONCE"],
                let nonce = UUID(uuidString: token), nonce.uuidString.lowercased() == token
            else { throw ProtocolError.malformed("private mount completion fixture") }
            let configuration = try LoginConfiguration(
                initiatorName: "iqn.2026-10.test:mount-completion-" + token,
                targetName: "iqn.2026-10.test:fskit-" + token,
                isid: [0x80, 0x53, 0x4f, 0x42, 0x41, 7])
            let connection = try await SessionConnector.connect(
                portal: portal, configuration: configuration)
            let session = connection.session
            let information = try await DiskProbe.diskInformation(
                session: session, lun: LogicalUnit(0))
            guard information.capacity.blockSize == 512,
                information.capacity.byteCount == 65536
            else {
                await session.close()
                throw ProtocolError.malformed("private mount completion capacity")
            }
            let disk = RemoteDisk(
                session: session, lun: try LogicalUnit(0), capacity: information.capacity,
                readOnly: true)
            let descriptor = try ConnectionDescriptor(
                profileID: nonce, portal: portal, initiatorName: configuration.initiatorName,
                targetName: configuration.targetName!, lun: LogicalUnit(0), readOnly: true,
                isid: configuration.isid)
            let controller = ResourceController { _, _ in
                LUNImageVolume(disk: disk, identifier: nonce)
            }
            do {
                let clock = ContinuousClock()
                let start = clock.now
                let volume = try await controller.load(descriptor, readOnly: true)
                let expected = Data((0..<512).map { UInt8($0 % 251) })
                guard try await disk.read(offset: 0, length: 512) == expected else {
                    throw ProtocolError.malformed("initial mount completion read")
                }
                if mode == "mounted" {
                    try await activate(volume)
                    try await volume.completeMount()
                }
                try emit("MOUNT_COMPLETION_READY", ["mode": mode, "nonce": token])
                let survived: Bool
                if mode == "mounted" {
                    try await clock.sleep(for: .seconds(50))
                    guard await disk.connectionState() == .connected,
                        try await disk.read(offset: 0, length: 512) == expected
                    else { throw ProtocolError.malformed("established mount expired") }
                    survived = true
                } else {
                    let until = start.advanced(by: .seconds(50))
                    while await disk.connectionState() != .closed {
                        guard clock.now < until else { throw ProtocolError.timedOut }
                        try await clock.sleep(for: .milliseconds(20))
                    }
                    do {
                        try await activate(volume)
                        throw ProtocolError.malformed("expired volume activated")
                    } catch let error as ProtocolError {
                        guard error == .timedOut else { throw error }
                    }
                    survived = false
                }
                let duration = start.duration(to: clock.now).components
                let elapsed = Double(duration.seconds) + Double(duration.attoseconds) / 1e18
                guard elapsed >= (survived ? 50 : 44), elapsed < 55 else {
                    throw ProtocolError.malformed("mount completion deadline timing")
                }
                try await controller.unload(descriptor)
                guard await disk.connectionState() == .closed else {
                    throw ProtocolError.malformed("mount completion final shutdown")
                }
                try emit(
                    "MOUNT_COMPLETION_RESULT",
                    [
                        "mode": mode, "nonce": token, "elapsedSeconds": elapsed,
                        "productionMountDeadlineSeconds": 45,
                        "mountedCallbacksDelivered": survived, "survivedPastDeadline": survived,
                        "finalConnectionClosed": true, "realNetworkFramework": true,
                        "injectedClock": false, "actualFSKitMount": false,
                    ])
            } catch {
                try? await controller.unload(descriptor)
                await session.close()
                throw error
            }
        }

        private static func activate(_ volume: LUNImageVolume) async throws {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                volume.activateRoot { root, error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else if root != nil {
                        continuation.resume()
                    } else {
                        continuation.resume(throwing: ProtocolError.invalidState)
                    }
                }
            }
        }

        private static func emit(_ name: String, _ values: [String: Any]) throws {
            let data = try JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
            FileHandle.standardOutput.write(Data((name + " ").utf8) + data + Data([10]))
        }
    }
#endif
