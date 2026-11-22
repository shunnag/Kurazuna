import CryptoKit
import Foundation
import ISCSICore

extension ServerProfile {
    /// Binds a mount to the exact configured endpoint and credential references that
    /// authorized it. Copied credentials for a selected endpoint keep this original binding.
    public var connectionSettingsBinding: Data {
        get throws {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            return Data(SHA256.hash(data: Data([1]) + (try encoder.encode(self))))
        }
    }
}
