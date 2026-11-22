import ISCSICore

#if DEBUG
    @testable import ISCSINetwork
#else
    import ISCSINetwork
#endif

enum UnsynchronizedWrite {
    /// Counts one write as sent and acknowledged without sending it, so that the next flush
    /// has something to make durable and is sent: a disk that wrote nothing since its last GOOD
    /// flush doesn't send one (see SynchronizationCoverage). For probes of a flush's own
    /// outcome whose target must see no WRITE.
    static func mark(_ disk: RemoteDisk) throws {
        #if DEBUG
            disk.coverage.endMutation(disk.coverage.beginMutation(epoch: 0))
        #else
            throw ProtocolError.unsupported("flush probe without a debug build")
        #endif
    }
}
