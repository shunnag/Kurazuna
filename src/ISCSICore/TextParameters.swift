import Foundation

/// An ordered list: discovery replies legitimately repeat TargetName and TargetAddress.
public struct TextParameters: Sendable, Equatable {
    /// Independent of the byte limit: short entries also consume strings and array storage.
    public static let maximumEntryCount = 16_384

    public struct Entry: Sendable, Equatable {
        public let key: String
        public let value: String

        public init(_ key: String, _ value: String) {
            self.key = key
            self.value = value
        }
    }

    public let entries: [Entry]

    public init(_ entries: [Entry]) throws {
        guard entries.count <= Self.maximumEntryCount else {
            throw ProtocolError.limitExceeded("text entries")
        }
        for entry in entries {
            guard !entry.key.isEmpty, entry.key.utf8.count <= 63,
                entry.key.utf8.allSatisfy({ (33...126).contains($0) && $0 != 61 }),
                !entry.value.utf8.contains(0)
            else { throw ProtocolError.malformed("text parameter") }
        }
        self.entries = entries
    }

    public init(data: Data) throws {
        guard data.count <= 1_048_576 else { throw ProtocolError.limitExceeded("text response") }
        guard data.isEmpty || data.last == 0 else {
            throw ProtocolError.malformed("unterminated text parameter")
        }
        // Count before split/map allocates a slice and two strings for every entry.
        var count = 0
        for byte in data where byte == 0 {
            count += 1
            guard count <= Self.maximumEntryCount else {
                throw ProtocolError.limitExceeded("text entries")
            }
        }
        let entries = try data.split(separator: 0, omittingEmptySubsequences: false)
            .dropLast().map { bytes -> Entry in
                guard let text = String(bytes: bytes, encoding: .utf8),
                    let equals = text.firstIndex(of: "=")
                else { throw ProtocolError.malformed("text parameter encoding") }
                return Entry(String(text[..<equals]), String(text[text.index(after: equals)...]))
            }
        try self.init(entries)
    }

    public func encoded() -> Data {
        Data(entries.flatMap { Array("\($0.key)=\($0.value)".utf8) + [0] })
    }

    public func uniqueValue(for key: String) throws -> String? {
        let matches = entries.filter { $0.key == key }
        guard matches.count <= 1 else { throw ProtocolError.malformed("duplicate \(key)") }
        return matches.first?.value
    }
}
