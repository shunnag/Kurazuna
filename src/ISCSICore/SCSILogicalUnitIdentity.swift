import Foundation

/// Names advertised for a logical unit, not a medium/content generation or an access lease.
public struct SCSILogicalUnitIdentity: Sendable, Equatable {
    public struct Designator: Sendable, Hashable {
        public enum Kind: UInt8, Sendable {
            case vendor = 1
            case eui = 2
            case naa = 3
            case name = 8
            case uuid = 10
        }
        public let kind: Kind
        public let codeSet: UInt8
        public let identifier: Data
    }

    public let designators: [Designator]
    /// An observed LIO FILEIO encoding quirk; this does not authenticate the peer.
    public let usedLIOFileIOTerminalNullCompatibility: Bool
    /// The corresponding Linux IBLOCK profile; neither name proves a backing incarnation.
    public let usedLIOBlockIOTerminalNullCompatibility: Bool

    public init(data: Data) throws {
        guard data.count <= Int(UInt16.max) else {
            throw ProtocolError.limitExceeded("device identification page")
        }
        let bytes = Array(data)
        guard bytes.count >= 4, bytes[0] == 0, bytes[1] == 0x83 else {
            throw ProtocolError.malformed("device identification header")
        }
        let end = 4 + Int(bytes.uint16(at: 2))
        guard end <= bytes.count else {
            throw ProtocolError.malformed("truncated device identification page")
        }
        var cursor = 4
        var names: Set<Designator> = []
        var usedLIOFileIOCompatibility = false
        var usedLIOBlockIOCompatibility = false
        while cursor < end {
            guard end - cursor >= 4 else {
                throw ProtocolError.malformed("device identification descriptor")
            }
            let length = Int(bytes[cursor + 3])
            guard length <= end - cursor - 4 else {
                throw ProtocolError.malformed("truncated device identification descriptor")
            }
            let association = (bytes[cursor + 1] >> 4) & 3
            if association == 0, let kind = Designator.Kind(rawValue: bytes[cursor + 1] & 15) {
                let codeSet = bytes[cursor] & 15
                let payload = Array(bytes[(cursor + 4)..<(cursor + 4 + length)])
                let identifier = try Self.identifier(kind: kind, codeSet: codeSet, bytes: payload)
                names.insert(Designator(kind: kind, codeSet: codeSet, identifier: identifier))
                if kind == .vendor, codeSet == 2, payload.last == 0 {
                    switch Self.lioTerminalNullBackend(payload) {
                    case .fileIO: usedLIOFileIOCompatibility = true
                    case .blockIO: usedLIOBlockIOCompatibility = true
                    case nil: break
                    }
                }
            }
            cursor += 4 + length
        }
        // Target/port names and a vendor-specific descriptor alone do not name this LU.
        guard !names.isEmpty else { throw ProtocolError.unsupported("logical unit identity") }
        guard
            !(usedLIOFileIOCompatibility || usedLIOBlockIOCompatibility)
                || names.contains(where: { $0.kind == .naa })
        else {
            throw ProtocolError.malformed("LIO logical unit identity without NAA")
        }
        usedLIOFileIOTerminalNullCompatibility = usedLIOFileIOCompatibility
        usedLIOBlockIOTerminalNullCompatibility = usedLIOBlockIOCompatibility
        designators = names.sorted {
            if $0.kind.rawValue != $1.kind.rawValue { return $0.kind.rawValue < $1.kind.rawValue }
            if $0.codeSet != $1.codeSet { return $0.codeSet < $1.codeSet }
            return $0.identifier.lexicographicallyPrecedes($1.identifier)
        }
    }

    /// Ordered, length-delimited encoding; descriptor order and redundant names are immaterial.
    public var canonicalBytes: Data {
        var bytes: [UInt8] = [1, 0, 0]
        bytes.put(UInt16(designators.count), at: 1)
        for name in designators {
            bytes += [name.kind.rawValue, name.codeSet, 0, 0]
            bytes.put(UInt16(name.identifier.count), at: bytes.count - 2)
            bytes += name.identifier
        }
        return Data(bytes)
    }

    private static func identifier(kind: Designator.Kind, codeSet: UInt8, bytes: [UInt8]) throws
        -> Data
    {
        switch kind {
        case .vendor:
            guard [1, 2].contains(codeSet), bytes.count > 8,
                bytes.prefix(8).allSatisfy({ (0x20...0x7E).contains($0) }),
                bytes.prefix(8).contains(where: { $0 != 0x20 }),
                codeSet != 2 || bytes.allSatisfy({ (0x20...0x7E).contains($0) })
                    || lioTerminalNullBackend(bytes) != nil
            else { throw ProtocolError.malformed("vendor logical unit designator") }
        case .eui:
            guard codeSet == 1, [8, 12, 16].contains(bytes.count) else {
                throw ProtocolError.malformed("EUI logical unit designator")
            }
        case .naa:
            guard codeSet == 1, let first = bytes.first,
                ([2, 3, 5].contains(first >> 4) && bytes.count == 8)
                    || (first >> 4 == 6 && bytes.count == 16)
            else { throw ProtocolError.malformed("NAA logical unit designator") }
        case .uuid:
            guard codeSet == 1, bytes.count == 18, bytes[0] >> 4 == 1 else {
                throw ProtocolError.malformed("UUID logical unit designator")
            }
            return Data(bytes.dropFirst(2))
        case .name:
            guard codeSet == 3, !bytes.isEmpty, bytes.count % 4 == 0,
                let end = bytes.firstIndex(of: 0), end > 0,
                bytes[end...].allSatisfy({ $0 == 0 }),
                let name = String(bytes: bytes[..<end], encoding: .utf8),
                !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
            else { throw ProtocolError.malformed("SCSI logical unit name") }
            if name.hasPrefix("eui.") {
                guard [16, 24, 32].contains(name.utf8.count - 4),
                    name.utf8.dropFirst(4).allSatisfy(Self.isHex)
                else { throw ProtocolError.malformed("EUI logical unit name") }
            } else if name.hasPrefix("naa.") {
                guard [16, 32].contains(name.utf8.count - 4),
                    name.utf8.dropFirst(4).allSatisfy(Self.isHex)
                else { throw ProtocolError.malformed("NAA logical unit name") }
                let digits = Array(name.utf8.dropFirst(4))
                guard
                    (digits.count == 16 && [UInt8(50), 51, 53].contains(digits[0]))
                        || (digits.count == 32 && digits[0] == 54)
                else { throw ProtocolError.malformed("NAA logical unit name authority") }
            } else if name.hasPrefix("iqn."),
                let split = name.range(of: ",L,0x", options: .backwards)
            {
                let node = name[..<split.lowerBound]
                let suffix = name[split.upperBound...]
                guard node.utf8.count > 4, node.utf8.count <= 223,
                    !node.contains(","), (1...16).contains(suffix.utf8.count),
                    suffix.utf8.allSatisfy(Self.isHex)
                else { throw ProtocolError.malformed("iSCSI logical unit name") }
                try validateIQNNode(node)
            } else {
                throw ProtocolError.unsupported("SCSI logical unit name format")
            }
            return Data(bytes[..<end])
        }
        return Data(bytes)
    }

    private enum LIOTerminalNullBackend { case fileIO, blockIO }

    private static func lioTerminalNullBackend(_ bytes: [UInt8]) -> LIOTerminalNullBackend? {
        // Linux SPC emits the same terminal NUL for both fixed backend model names.
        // Keep all raw bytes in the identity; this does not declare SPC conformance.
        let fileIO = Array("LIO-ORG FILEIO:".utf8)
        let blockIO = Array("LIO-ORG IBLOCK:".utf8)
        let backend: LIOTerminalNullBackend
        let prefix: [UInt8]
        if bytes.starts(with: fileIO) {
            backend = .fileIO
            prefix = fileIO
        } else if bytes.starts(with: blockIO) {
            backend = .blockIO
            prefix = blockIO
        } else {
            return nil
        }
        guard bytes.count == prefix.count + 36 + 1, bytes.last == 0 else { return nil }
        let serial = bytes.dropFirst(prefix.count).dropLast()
        guard
            serial.enumerated().allSatisfy({ index, byte in
                if [8, 13, 18, 23].contains(index) { return byte == 45 }
                return (48...57).contains(byte) || (97...102).contains(byte)
            })
        else { return nil }
        return backend
    }

    private static func isHex(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) || (65...70).contains(byte) || (97...102).contains(byte)
    }

    private static func validateIQNNode(_ node: Substring) throws {
        let bytes = Array(node.utf8)
        // Explicit normalized ASCII profile. Unicode stringprep is not inferred or applied
        // to a peer's identity; unsupported forms never become a different accepted name.
        guard
            bytes.allSatisfy({
                (97...122).contains($0) || (48...57).contains($0)
                    || [UInt8(45), 46, 58].contains($0)
            })
        else { throw ProtocolError.unsupported("iSCSI name character profile") }
        guard bytes.count >= 13, bytes[8] == 45, bytes[11] == 46,
            bytes[4..<8].allSatisfy({ (48...57).contains($0) }),
            bytes[9..<11].allSatisfy({ (48...57).contains($0) }),
            let year = Int(String(decoding: bytes[4..<8], as: UTF8.self)), year > 0,
            let month = Int(String(decoding: bytes[9..<11], as: UTF8.self)),
            (1...12).contains(month)
        else { throw ProtocolError.malformed("iSCSI qualified name date") }
        let authority = node.dropFirst(12).split(separator: ":", omittingEmptySubsequences: false)[
            0]
        let labels = authority.split(separator: ".", omittingEmptySubsequences: false)
        func letterOrDigit(_ byte: UInt8) -> Bool {
            (97...122).contains(byte) || (48...57).contains(byte)
        }
        guard
            labels.allSatisfy({ label in
                let characters = Array(label.utf8)
                return (1...63).contains(characters.count)
                    && characters.first.map(letterOrDigit) == true
                    && characters.last.map(letterOrDigit) == true
                    && characters.allSatisfy({ letterOrDigit($0) || $0 == 45 })
            })
        else { throw ProtocolError.malformed("iSCSI qualified name authority") }
    }
}
