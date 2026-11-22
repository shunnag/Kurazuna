import CryptoKit
import Foundation

/// CHAP's mandated MD5 is used only for legacy iSCSI authentication, never for integrity.
public enum CHAP {
    public static func response(identifier: UInt8, secret: String, challenge: String) throws
        -> String
    {
        let bytes = try decodeBinary(challenge)
        // A peer's challenge may be shorter than MD5's 16-byte response. RFC 1994
        // requires a nonempty value; RFC 7143 caps its decoded length at 1024 bytes.
        // LoginMachine independently generates 32 random bytes for our mutual challenge.
        guard (1...1024).contains(bytes.count) else {
            throw ProtocolError.malformed("CHAP challenge length")
        }
        var input = Data([identifier])
        input.append(contentsOf: secret.utf8)
        input.append(bytes)
        return "0x" + Insecure.MD5.hash(data: input).map { String(format: "%02x", $0) }.joined()
    }

    public static func decodeBinary(_ text: String) throws -> Data {
        guard text.utf8.count <= 4096 else { throw ProtocolError.limitExceeded("CHAP challenge") }
        if text.hasPrefix("0x") || text.hasPrefix("0X") {
            let digits = Array(text.dropFirst(2).utf8)
            guard digits.count % 2 == 0 else { throw ProtocolError.malformed("CHAP hexadecimal") }
            func nibble(_ byte: UInt8) throws -> UInt8 {
                switch byte {
                case 48...57: byte - 48
                case 65...70: byte - 55
                case 97...102: byte - 87
                default: throw ProtocolError.malformed("CHAP hexadecimal")
                }
            }
            var result = Data()
            for offset in stride(from: 0, to: digits.count, by: 2) {
                result.append(try nibble(digits[offset]) << 4 | nibble(digits[offset + 1]))
            }
            return result
        }
        if text.hasPrefix("0b") || text.hasPrefix("0B"),
            let data = Data(base64Encoded: String(text.dropFirst(2)))
        {
            return data
        }
        throw ProtocolError.malformed("CHAP binary encoding")
    }
}

/// Deliberately not Codable or CustomStringConvertible: credentials never enter profiles or logs.
public struct CHAPCredentials: Sendable {
    public let username: String
    public let targetUsername: String?
    private let password: String
    private let targetPassword: String?

    public init(
        username: String, password: String, targetUsername: String? = nil,
        targetPassword: String? = nil
    ) throws {
        guard !username.isEmpty, username.utf8.count <= 223,
            !username.utf8.contains(0), (12...1024).contains(password.utf8.count)
        else { throw ProtocolError.malformed("CHAP credentials") }
        guard (targetUsername == nil) == (targetPassword == nil) else {
            throw ProtocolError.malformed("mutual CHAP credentials")
        }
        if let targetUsername, let targetPassword {
            guard !targetUsername.isEmpty, targetUsername.utf8.count <= 223,
                targetUsername.utf8.allSatisfy({ $0 >= 32 && $0 != 127 }),
                (12...1024).contains(targetPassword.utf8.count), password != targetPassword
            else { throw ProtocolError.malformed("mutual CHAP credentials") }
        }
        self.username = username
        self.password = password
        self.targetUsername = targetUsername
        self.targetPassword = targetPassword
    }

    func response(identifier: UInt8, challenge: String) throws -> String {
        try CHAP.response(identifier: identifier, secret: password, challenge: challenge)
    }

    func verifyTarget(username: String, response: String, identifier: UInt8, challenge: String)
        throws
    {
        guard username == targetUsername, let targetPassword,
            let received = try? CHAP.decodeBinary(response), received.count == 16
        else { throw ProtocolError.authenticationFailed }
        let expected = try CHAP.decodeBinary(
            CHAP.response(identifier: identifier, secret: targetPassword, challenge: challenge))
        let reflected = try CHAP.decodeBinary(
            self.response(identifier: identifier, challenge: challenge))
        var difference: UInt8 = 0
        var reflectionDifference: UInt8 = 0
        for index in 0..<16 {
            difference |= received[index] ^ expected[index]
            reflectionDifference |= received[index] ^ reflected[index]
        }
        guard difference == 0, reflectionDifference != 0 else {
            throw ProtocolError.authenticationFailed
        }
    }
}
