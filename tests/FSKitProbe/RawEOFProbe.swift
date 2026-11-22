import Darwin
import Foundation
import ISCSICore

/// Read-only checks of a private ordinary file or the raw file in a verified bridge.
enum RawEOFProbe {
    static let controlSize = 512 * 1024 + 1536

    static func controlData() -> Data {
        Data(
            (0..<controlSize).map { index in
                UInt8(truncatingIfNeeded: (index * 37) ^ (index >> 7) ^ (index >> 15) ^ 19)
            })
    }

    static func validate(_ image: URL, expected: Data) throws {
        guard expected.count > 65_537 else {
            throw ProtocolError.malformed("raw EOF expected contents too small")
        }
        var reads = 0
        var mappedTailBytes = 0
        let cases = [
            (0, 1), (expected.count - 1, 1), (expected.count - 1, 4096),
            (expected.count - 511, 65_537), (expected.count - 4093, 65_537),
            (expected.count - 16_385, 32_771), (expected.count, 0), (expected.count, 1),
            (expected.count, 65_537), (expected.count + 1, 4096),
            (expected.count + 4097, 65_537),
        ]
        for noCache in [false, true] {
            let file = open(image.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            guard file >= 0 else { throw systemError() }
            var opened = true
            defer { if opened { _ = Darwin.close(file) } }
            var information = stat()
            guard fstat(file, &information) == 0 else { throw systemError() }
            guard information.st_mode & S_IFMT == S_IFREG,
                information.st_size == off_t(expected.count)
            else { throw ProtocolError.malformed("raw EOF file type or capacity") }
            if noCache {
                guard fcntl(file, F_NOCACHE, 1) == 0 else { throw systemError() }
            }
            mappedTailBytes = try checkMapping(file, expected: expected)
            for (index, request) in cases.enumerated() {
                let (offset, length) = request
                let count = min(length, max(0, expected.count - offset))
                let sentinel = UInt8(truncatingIfNeeded: index * 17 + (noCache ? 0x51 : 0xA5))
                var bytes = [UInt8](repeating: sentinel, count: length + 32)
                let result = bytes.withUnsafeMutableBytes { buffer in
                    pread(file, buffer.baseAddress!.advanced(by: 16), length, off_t(offset))
                }
                guard result >= 0 else { throw systemError() }
                guard result == count,
                    bytes.prefix(16).allSatisfy({ $0 == sentinel }),
                    bytes.suffix(from: 16 + count).allSatisfy({ $0 == sentinel })
                else { throw ProtocolError.malformed("raw EOF byte count or buffer canary") }
                if count > 0 {
                    guard
                        Data(bytes[16..<(16 + count)])
                            == expected.subdata(
                                in: offset..<(offset + count))
                    else { throw ProtocolError.malformed("raw EOF returned contents") }
                }
                reads += 1
            }
            _ = try checkMapping(file, expected: expected)
            let closed = Darwin.close(file)
            opened = false
            guard closed == 0 else { throw systemError() }
        }
        let report: [String: Any] = [
            "imageBytes": expected.count, "preadCases": reads,
            "cacheModes": ["default", "F_NOCACHE requested"],
            "mmapChecks": 4, "mmapTailBytesPerCheck": mappedTailBytes,
            "returnedContentsMatch": true, "callerBufferCanariesIntact": true,
            "mmapTailZero": true,
        ]
        let output = try JSONSerialization.data(withJSONObject: report, options: .sortedKeys)
        print("RAW_EOF_RESULT " + String(decoding: output, as: UTF8.self))
    }

    private static func checkMapping(_ file: Int32, expected: Data) throws -> Int {
        let page = Int(getpagesize())
        let start = ((expected.count - 1) / page) * page
        let valid = expected.count - start
        guard let mapping = mmap(nil, page, PROT_READ, MAP_PRIVATE, file, off_t(start)),
            mapping != MAP_FAILED
        else { throw systemError() }
        var mapped = true
        defer { if mapped { _ = munmap(mapping, page) } }
        let bytes = UnsafeRawBufferPointer(start: mapping, count: page)
        guard Data(bytes.prefix(valid)) == expected.suffix(valid),
            bytes.suffix(from: valid).allSatisfy({ $0 == 0 })
        else { throw ProtocolError.malformed("raw EOF mmap contents or zero-filled tail") }
        let removed = munmap(mapping, page)
        mapped = false
        guard removed == 0 else { throw systemError() }
        return page - valid
    }

    private static func systemError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
