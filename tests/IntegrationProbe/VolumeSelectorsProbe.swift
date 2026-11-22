#if DEBUG
    import FSKit
    import Foundation
    import ISCSICore
    import ISCSIFSBridge
    import ObjectiveC

    private actor SelectorMemoryDisk: ImageDisk {
        let capacity: DiskCapacity
        let isReadOnly = true
        init() throws {
            var reply = [UInt8](repeating: 0, count: 32)
            reply.put(UInt64(7), at: 0)
            reply.put(UInt32(512), at: 8)
            capacity = try DiskCapacity(readCapacity16: Data(reply))
        }
        func read(offset: Int64, length: Int) -> Data { Data(count: length) }
        func write(offset: Int64, data: Data) throws { throw POSIXError(.EROFS) }
        func synchronize() {}
        func close() {}
        func connectionState() -> DiskConnectionState { .connected }
    }

    /// Inspects public Objective-C callbacks without mounting or creating task options.
    enum VolumeSelectorsProbe {
        static func run() throws {
            let volume = LUNImageVolume(disk: try SelectorMemoryDisk(), identifier: UUID())
            var count: UInt32 = 0
            let methods = class_copyMethodList(LUNImageVolume.self, &count)
            defer { free(methods) }
            let own = (0..<Int(count)).compactMap { index -> String? in
                guard let methods else { return nil }
                return NSStringFromSelector(method_getName(methods[index]))
            }
            let selectors = [
                "activateWithOptions:replyHandler:", "mountWithOptions:replyHandler:",
                "unmountWithReplyHandler:", "synchronizeWithFlags:replyHandler:",
                "deactivateWithOptions:replyHandler:",
            ]
            let rows = selectors.map { name in
                [
                    "selector": name, "responds": volume.responds(to: NSSelectorFromString(name)),
                    "implementedByVolume": own.contains(name),
                ] as [String: Any]
            }
            let value: [String: Any] = [
                "OS": ProcessInfo.processInfo.operatingSystemVersionString,
                "commonProtocolPresent": NSProtocolFromString("FSVolumeCommonOperations") != nil,
                "operationsProtocolPresent": NSProtocolFromString("FSVolumeOperations") != nil,
                "callbacks": rows, "mountedResources": 0, "networkConnections": 0,
                "taskOptionsCreated": false,
            ]
            let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
            print("VOLUME_SELECTORS " + String(decoding: data, as: UTF8.self))
        }
    }
#endif
