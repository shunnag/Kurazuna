#if ISCSI_FSKIT_CACHE_DIAGNOSTIC
    import FSKit
    import Foundation
    import ISCSICore
    import Testing

    @testable import ISCSIFSBridge

    private final class CacheEvents: @unchecked Sendable {
        private let lock = NSLock()
        private var events: [VolumeLifecycleDiagnostics.Event] = []
        func record(_ event: VolumeLifecycleDiagnostics.Event) {
            lock.withLock { events.append(event) }
        }
        var values: [VolumeLifecycleDiagnostics.Event] { lock.withLock { events } }
    }

    private actor CacheDisk: ImageDisk {
        let capacity: DiskCapacity
        let isReadOnly: Bool
        private var state = DiskConnectionState.connected
        private var failure: (any Error)?
        private var holdSync = false
        private var holdState = false
        private var syncReply: CheckedContinuation<Void, Never>?
        private var stateReply: CheckedContinuation<Void, Never>?
        private(set) var operations: [String] = []
        var syncHeld: Bool { syncReply != nil }
        var stateHeld: Bool { stateReply != nil }

        init(readOnly: Bool = false) throws {
            var bytes = Array(repeating: UInt8(0), count: 8)
            bytes.put(UInt32(8191), at: 0)
            bytes.put(UInt32(512), at: 4)
            capacity = try DiskCapacity(readCapacity10: Data(bytes))
            isReadOnly = readOnly
        }
        func arm(_ error: any Error, hold: Bool = false) {
            failure = error
            holdSync = hold
        }
        func holdNextSync() { holdSync = true }
        func holdNextState() { holdState = true }
        func interrupt() { state = .interrupted }
        func releaseSync() {
            syncReply?.resume()
            syncReply = nil
            holdSync = false
        }
        func releaseState() {
            stateReply?.resume()
            stateReply = nil
        }
        func read(offset: Int64, length: Int) async throws -> Data {
            operations.append("read")
            return Data(repeating: 0, count: length)
        }
        func write(offset: Int64, data: Data) async throws {
            operations.append("write:\(data.count)")
        }
        func synchronize() async throws {
            operations.append("sync")
            if holdSync { await withCheckedContinuation { syncReply = $0 } }
            if let failure {
                self.failure = nil
                throw failure
            }
        }
        func close() async {
            operations.append("close")
            state = .closed
        }
        func connectionState() async -> DiskConnectionState {
            let snapshot = state
            if holdState {
                holdState = false
                await withCheckedContinuation { stateReply = $0 }
            }
            return snapshot
        }
    }

    private func waitForCache(_ condition: @Sendable () async -> Bool) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while !(await condition()) {
            guard clock.now < deadline else { throw ProtocolError.timedOut }
            try await clock.sleep(for: .milliseconds(2))
        }
    }

    private actor CloseStart {
        private var reply: CheckedContinuation<Void, Never>?
        var waiting: Bool { reply != nil }
        func wait() async { await withCheckedContinuation { reply = $0 } }
        func release() {
            reply?.resume()
            reply = nil
        }
    }

    @Suite struct DataCacheDiagnosticTests {
        @Test(arguments: [FSVolume.DataCacheMode.none, .readWithCache, .readWriteWithCache])
        func everyRequestGrantsNoCacheWithOneLifecycleOwner(_ mode: FSVolume.DataCacheMode)
            async throws
        {
            let disk = try CacheDisk()
            let events = CacheEvents()
            let volume = LUNImageVolume(
                disk: disk, identifier: UUID(), lifecycleObserver: events.record)
            let object: AnyObject = volume
            #expect(object is any FSVolume.DataCacheHandler)
            #expect(!(object is any FSVolume.OpenCloseOperations))
            #expect(!volume.isDataCacheInhibited)
            #expect(!volume.responds(to: NSSelectorFromString("openItem:withModes:replyHandler:")))
            #expect(
                !volume.responds(to: NSSelectorFromString("closeItem:keepingModes:replyHandler:")))
            #expect(
                volume.responds(
                    to: NSSelectorFromString("openItem:modes:cacheMode:context:replyHandler:")))
            #expect(
                volume.responds(
                    to: NSSelectorFromString("upgradeItem:cacheMode:context:replyHandler:")))
            #expect(volume.responds(to: NSSelectorFromString("closeItem:context:replyHandler:")))
            #expect(
                try await volume.negotiateCacheOpen(volume.imageItem, modes: .read, cacheMode: mode)
                    == .noCache)
            #expect(
                try await volume.negotiateCacheUpgrade(volume.imageItem, cacheMode: mode)
                    == .noCache)
            await volume.finishCacheClose(volume.imageItem)
            let grants = events.values.filter {
                $0.operation == .cacheGrant && $0.phase == .finished
            }
            #expect(
                grants.count == 2 && grants.allSatisfy { $0.flags == 0 && $0.outcome == .success })
            #expect(!events.values.contains { $0.operation == .open || $0.operation == .close })
            // A writable image opened by a reader still receives one conservative
            // final barrier: upgrade does not tell us whether access became writable.
            #expect(await disk.operations == ["sync"])
        }

        @Test func invalidAccessDoesNotGrantCachingOrReachTheDisk() async throws {
            let disk = try CacheDisk(readOnly: true)
            let volume = LUNImageVolume(disk: disk, identifier: UUID())
            let foreign = LUNImageVolume(disk: disk, identifier: UUID())
            await #expect(throws: POSIXError(.ESTALE)) {
                try await volume.negotiateCacheOpen(
                    foreign.imageItem, modes: .read, cacheMode: .none)
            }
            await #expect(throws: POSIXError(.EISDIR)) {
                try await volume.negotiateCacheOpen(
                    volume.rootItem, modes: .write, cacheMode: .readWriteWithCache)
            }
            await #expect(throws: POSIXError(.EROFS)) {
                try await volume.negotiateCacheOpen(
                    volume.imageItem, modes: .write, cacheMode: .readWriteWithCache)
            }
            await #expect(throws: POSIXError(.EBADF)) {
                try await volume.negotiateCacheUpgrade(
                    volume.imageItem, cacheMode: .readWriteWithCache)
            }
            await #expect(throws: POSIXError(.ESTALE)) {
                try await volume.negotiateCacheUpgrade(foreign.imageItem, cacheMode: .none)
            }
            #expect(await disk.operations.isEmpty)
        }

        @Test func readOnlyImageAndDirectoryCloseDoNotAddWriteBarriers() async throws {
            let disk = try CacheDisk(readOnly: true)
            let volume = LUNImageVolume(disk: disk, identifier: UUID())
            _ = try await volume.negotiateCacheOpen(
                volume.rootItem, modes: .read, cacheMode: .readWithCache)
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .read, cacheMode: .readWithCache)
            _ = try await volume.negotiateCacheUpgrade(
                volume.imageItem, cacheMode: .readWriteWithCache)
            await volume.finishCacheClose(volume.rootItem)
            await volume.finishCacheClose(volume.imageItem)
            #expect(await disk.operations.isEmpty)
        }

        @Test func onlyFinalCloseEndsTheNewLifecycleAndUpgradeIsNotAWriterCount() async throws {
            let disk = try CacheDisk()
            let volume = LUNImageVolume(disk: disk, identifier: UUID())
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .write, cacheMode: .none)
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .read, cacheMode: .readWithCache)
            // DataCacheHandler has no remaining-modes notification for writer exit
            // while this reader remains. No old last-writer callback is synthesized.
            _ = try await volume.negotiateCacheUpgrade(
                volume.imageItem, cacheMode: .readWriteWithCache)
            #expect(await disk.operations.isEmpty)
            await volume.finishCacheClose(volume.imageItem)
            await volume.finishCacheClose(volume.imageItem)
            #expect(await disk.operations == ["sync"])
            await #expect(throws: POSIXError(.EBADF)) {
                try await volume.negotiateCacheUpgrade(volume.imageItem, cacheMode: .none)
            }
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .read, cacheMode: .none)
            await volume.finishCacheClose(volume.imageItem)
            #expect(await disk.operations == ["sync", "sync"])
        }

        @Test(arguments: [POSIXErrorCode.EIO, .ETIMEDOUT, .ECANCELED])
        func firstFinalCloseFailureSurvivesErrorlessCompletion(_ code: POSIXErrorCode) async throws
        {
            let disk = try CacheDisk()
            let events = CacheEvents()
            let volume = LUNImageVolume(
                disk: disk, identifier: UUID(), lifecycleObserver: events.record)
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .write, cacheMode: .none)
            await disk.arm(POSIXError(code))
            await volume.finishCacheClose(volume.imageItem)
            await volume.finishCacheClose(volume.imageItem)
            await #expect(throws: POSIXError(code)) {
                try await volume.negotiateCacheOpen(
                    volume.imageItem, modes: .read, cacheMode: .none)
            }
            await #expect(throws: POSIXError(code)) {
                try await volume.negotiateCacheUpgrade(
                    volume.imageItem, cacheMode: .readWriteWithCache)
            }
            await #expect(throws: POSIXError(code)) { try await volume.synchronize(flags: .wait) }
            await #expect(throws: POSIXError(code)) {
                try await volume.write(contents: Data([1]), to: volume.imageItem, at: 0)
            }
            await #expect(throws: POSIXError(code)) {
                try await volume.readChunks(
                    from: volume.imageItem, at: 0, length: 1, bufferLength: 1
                ) { _, _ in }
            }
            let state = try await volume.xattr(
                named: FSFileName(string: ConnectionDescriptor.connectionStateAttributeName),
                of: volume.imageItem)
            #expect(state == DiskConnectionState.interrupted.encoded)
            #expect(await disk.operations == ["sync"])
            let failures = events.values.filter {
                $0.operation == .cacheClose && $0.phase == .finished
                    && $0.errorCode == Int(code.rawValue)
            }
            #expect(failures.count == 2)
            #expect(failures[0].outcome == (code == .ECANCELED ? .cancelled : .posix))
        }

        @Test func aKnownBackendFaultRejectsOpenAndUpgradeWithoutAnotherDataRequest() async throws {
            let disk = try CacheDisk()
            let volume = LUNImageVolume(disk: disk, identifier: UUID())
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .read, cacheMode: .none)
            await disk.interrupt()
            await #expect(throws: POSIXError(.EIO)) {
                try await volume.negotiateCacheOpen(
                    volume.imageItem, modes: .read, cacheMode: .none)
            }
            await #expect(throws: POSIXError(.EIO)) {
                try await volume.negotiateCacheUpgrade(
                    volume.imageItem, cacheMode: .readWriteWithCache)
            }
            #expect(await disk.operations.isEmpty)
        }

        @Test func chunkedWritesKeepTheirTargetBarrierBeforeTheSuccessfulReply() async throws {
            let disk = try CacheDisk()
            let volume = LUNImageVolume(disk: disk, identifier: UUID())
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .read, cacheMode: .none)
            _ = try await volume.negotiateCacheUpgrade(
                volume.imageItem, cacheMode: .readWriteWithCache)
            await disk.holdNextSync()
            let write = Task {
                try await volume.write(
                    contents: Data(repeating: 7, count: 2_097_153), to: volume.imageItem, at: 0)
            }
            do {
                try await waitForCache { await disk.syncHeld }
                #expect(
                    await disk.operations == ["write:1048576", "write:1048576", "write:1", "sync"])
                let close = Task { await volume.finishCacheClose(volume.imageItem) }
                try await waitForCache { await volume.queuedIOCount == 1 }
                await disk.releaseSync()
                #expect(try await write.value == 2_097_153)
                await close.value
                #expect(
                    await disk.operations == [
                        "write:1048576", "write:1048576", "write:1", "sync", "sync",
                    ])
            } catch {
                await disk.releaseSync()
                _ = try? await write.value
                throw error
            }
        }

        @Test func finalCloseIsSharedWhilePendingAndDoesNotShutDownTheVolume() async throws {
            let disk = try CacheDisk()
            let events = CacheEvents()
            let volume = LUNImageVolume(
                disk: disk, identifier: UUID(), lifecycleObserver: events.record)
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .write, cacheMode: .none)
            await disk.holdNextSync()
            let first = Task { await volume.finishCacheClose(volume.imageItem) }
            do {
                try await waitForCache { await disk.syncHeld }
                let second = Task { await volume.finishCacheClose(volume.imageItem) }
                try await waitForCache {
                    events.values.filter { $0.operation == .cacheClose && $0.phase == .begin }.count
                        == 2
                }
                first.cancel()
                await disk.releaseSync()
                await first.value
                await second.value
                #expect(await disk.operations == ["sync"])
                let closes = events.values.filter {
                    $0.operation == .cacheClose && $0.phase == .finished
                }
                #expect(closes.count == 2)
                #expect(Set(closes.map(\.requestID)).count == 2)
            } catch {
                await disk.releaseSync()
                await first.value
                throw error
            }
        }

        @Test func closeRacingShutdownCompletesWithoutASecondShutdownOrLostFailure() async throws {
            let disk = try CacheDisk()
            let events = CacheEvents()
            let volume = LUNImageVolume(
                disk: disk, identifier: UUID(), lifecycleObserver: events.record)
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .write, cacheMode: .none)
            await disk.holdNextSync()
            let close = Task { await volume.finishCacheClose(volume.imageItem) }
            do {
                try await waitForCache { await disk.syncHeld }
                await volume.unmount()
                try await volume.deactivate(options: FSDeactivateOptions(rawValue: 0))
                await disk.releaseSync()
                await close.value
                #expect(await disk.operations == ["sync", "close"])
                #expect(
                    events.values.filter { $0.operation == .shutdown && $0.phase == .begin }.count
                        == 1)
                #expect(
                    events.values.filter {
                        $0.operation == .cacheClose && $0.phase == .finished && $0.errorCode == 5
                    }.count == 1)
            } catch {
                await disk.releaseSync()
                await close.value
                throw error
            }
        }

        @Test func finalBarrierFailureBlocksAlreadyQueuedIOBeforeReleasingTheGate() async throws {
            let disk = try CacheDisk()
            let volume = LUNImageVolume(disk: disk, identifier: UUID())
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .write, cacheMode: .none)
            await disk.arm(POSIXError(.EIO), hold: true)
            let close = Task { await volume.finishCacheClose(volume.imageItem) }
            var pending: [Task<Void, any Error>] = []
            do {
                try await waitForCache { await disk.syncHeld }
                pending.append(
                    Task {
                        _ = try await volume.readChunks(
                            from: volume.imageItem, at: 0, length: 1, bufferLength: 1
                        ) { _, _ in }
                    })
                pending.append(
                    Task {
                        _ = try await volume.write(contents: Data([1]), to: volume.imageItem, at: 0)
                    })
                pending.append(Task { try await volume.synchronize(flags: .wait) })
                try await waitForCache { await volume.queuedIOCount == 3 }
                await disk.releaseSync()
                await close.value
                for task in pending {
                    await #expect(throws: POSIXError(.EIO)) { try await task.value }
                }
                // The backend intentionally stays connected and would accept
                // further requests. The volume must preserve the failed barrier
                // BEFORE any queued operation can reach that backend.
                #expect(await disk.operations == ["sync"])
            } catch {
                await disk.releaseSync()
                await close.value
                for task in pending { _ = try? await task.value }
                throw error
            }
        }

        @Test func aCallerCancelledBeforeCloseStillCompletesOneFinalBarrier() async throws {
            let disk = try CacheDisk()
            let volume = LUNImageVolume(disk: disk, identifier: UUID())
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .write, cacheMode: .none)
            let start = CloseStart()
            let close = Task {
                await start.wait()
                #expect(Task.isCancelled)
                await volume.finishCacheClose(volume.imageItem)
            }
            do {
                try await waitForCache { await start.waiting }
                close.cancel()
                await start.release()
                await close.value
                #expect(await disk.operations == ["sync"])
            } catch {
                await start.release()
                await close.value
                throw error
            }
        }

        @Test(arguments: [false, true])
        func aReopenWaitsForFinalCloseAndCannotClearItsFailure(_ fail: Bool) async throws {
            let disk = try CacheDisk()
            let events = CacheEvents()
            let volume = LUNImageVolume(
                disk: disk, identifier: UUID(), lifecycleObserver: events.record)
            _ = try await volume.negotiateCacheOpen(
                volume.imageItem, modes: .write, cacheMode: .none)
            if fail {
                await disk.arm(POSIXError(.EIO), hold: true)
            } else {
                await disk.holdNextSync()
            }
            let close = Task { await volume.finishCacheClose(volume.imageItem) }
            var reopen: Task<FSVolume.KernelCacheCoherencyType, any Error>?
            do {
                try await waitForCache { await disk.syncHeld }
                let next = Task {
                    try await volume.negotiateCacheOpen(
                        volume.imageItem, modes: .read, cacheMode: .none)
                }
                reopen = next
                try await waitForCache {
                    events.values.filter { $0.operation == .cacheOpen && $0.phase == .begin }.count
                        == 2
                }
                #expect(
                    events.values.filter { $0.operation == .cacheGrant && $0.phase == .finished }
                        .count == 1)
                await disk.releaseSync()
                await close.value
                if fail {
                    await #expect(throws: POSIXError(.EIO)) { try await next.value }
                    #expect(await disk.operations == ["sync"])
                } else {
                    #expect(try await next.value == .noCache)
                    await volume.finishCacheClose(volume.imageItem)
                    #expect(await disk.operations == ["sync", "sync"])
                }
            } catch {
                await disk.releaseSync()
                await close.value
                if let reopen { _ = try? await reopen.value }
                throw error
            }
        }

        @Test(arguments: [false, true])
        func shutdownOrCancellationDuringOpenStateQueryCannotGrantCache(_ cancel: Bool) async throws
        {
            let disk = try CacheDisk()
            let volume = LUNImageVolume(disk: disk, identifier: UUID())
            await disk.holdNextState()
            let open = Task {
                try await volume.negotiateCacheOpen(
                    volume.imageItem, modes: .read, cacheMode: .none)
            }
            do {
                try await waitForCache { await disk.stateHeld }
                if cancel { open.cancel() } else { await volume.shutdown() }
                await disk.releaseState()
                await #expect(throws: POSIXError(cancel ? .ECANCELED : .EIO)) {
                    try await open.value
                }
            } catch {
                await disk.releaseState()
                _ = try? await open.value
                throw error
            }
        }
    }
#else
    import FSKit
    import Foundation
    import Testing

    @testable import ISCSIFSBridge

    @Test func productionVolumeKeepsTheLegacyLifecycleAndSelectors() throws {
        let volume = LUNImageVolume(disk: try MemoryDisk(), identifier: UUID())
        let object: AnyObject = volume
        #expect(object is any FSVolume.OpenCloseOperations)
        #expect(volume.responds(to: NSSelectorFromString("openItem:withModes:replyHandler:")))
        #expect(volume.responds(to: NSSelectorFromString("closeItem:keepingModes:replyHandler:")))
        if #available(macOS 27.0, *) {
            #expect(!(object is any FSVolume.DataCacheHandler))
            #expect(
                !volume.responds(
                    to: NSSelectorFromString("openItem:modes:cacheMode:context:replyHandler:")))
            #expect(!volume.responds(to: NSSelectorFromString("closeItem:context:replyHandler:")))
        }
    }
#endif
