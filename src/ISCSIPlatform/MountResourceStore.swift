import Foundation
import ISCSICore
import Security

public protocol MountResourceStore: Sendable {
    func save(_ descriptor: ConnectionDescriptor) async throws -> ConnectionResourceReference
    func resolve(_ reference: ConnectionResourceReference) async throws -> ConnectionDescriptor
    func remove(_ reference: ConnectionResourceReference) async throws
}

/// The mount, disk image, and bridge directory are already absent. Only removal
/// of the connection metadata failed; keep the journal so recovery can retry it.
public struct MountResourceCleanupError: Error, Sendable {
    public let underlying: any Error

    public init(underlying: any Error) {
        self.underlying = underlying
    }
}

extension MountResourceStore {
    public func descriptor(for url: URL) async throws -> ConnectionDescriptor {
        if let reference = try? ConnectionResourceReference(url: url) {
            let descriptor = try await resolve(reference)
            try reference.validate(descriptor)
            return descriptor
        }
        let supplied = try ConnectionDescriptor(resourceURL: url)
        // Anonymous full URLs remain available to unsigned command-line probes. A URL
        // alone cannot authorize selecting saved CHAP credentials, including legacy
        // accounts without a credential UUID. Never recreate metadata from this input.
        guard supplied.chapUsername != nil else { return supplied }
        let reference = try ConnectionResourceReference(descriptor: supplied)
        let stored = try await resolve(reference)
        try reference.validate(stored)
        guard stored == supplied else { throw ProtocolError.malformed("mount resource binding") }
        return stored
    }
}

/// Public metadata uses its own service, never the CHAP credential service. Records are
/// immutable and remain available until the app proves both mount and image are absent.
public actor KeychainMountResourceStore: MountResourceStore {
    private let accessGroup: String?
    private let identity: ApplicationIdentity

    public init(accessGroup: String?, identity: ApplicationIdentity = .current) {
        self.accessGroup = accessGroup
        self.identity = identity
    }

    public static func sharedForCurrentBundle() -> KeychainMountResourceStore {
        KeychainMountResourceStore(
            accessGroup: Bundle.main.object(forInfoDictionaryKey: "ISCSISharedKeychainAccessGroup")
                as? String)
    }

    public func save(_ descriptor: ConnectionDescriptor) throws -> ConnectionResourceReference {
        let reference = try ConnectionResourceReference(descriptor: descriptor)
        let data = try Self.encode(descriptor)
        var item = try query(reference)
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDuplicateItem {
            guard try resolve(reference) == descriptor else {
                throw ProtocolError.malformed("mount resource binding")
            }
        } else if status != errSecSuccess {
            throw Self.error(status)
        }
        return reference
    }

    public func resolve(_ reference: ConnectionResourceReference) throws -> ConnectionDescriptor {
        var query = try query(reference)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw Self.error(status) }
        guard let data = result as? Data else {
            throw ProtocolError.malformed("mount resource data")
        }
        return try Self.decode(data, reference: reference)
    }

    public func remove(_ reference: ConnectionResourceReference) throws {
        // A mismatched/corrupted item is evidence, not a disposable matching record.
        do { _ = try resolve(reference) } catch let error as NSError
            where error.domain == NSOSStatusErrorDomain && error.code == Int(errSecItemNotFound)
        { return }
        let status = SecItemDelete(try query(reference) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.error(status)
        }
    }

    static func encode(_ descriptor: ConnectionDescriptor) throws -> Data {
        let data = Data(try descriptor.resourceURL.absoluteString.utf8)
        guard data.count <= 4096 else { throw ProtocolError.limitExceeded("mount resource data") }
        // Only metadata that the extension can fully decode may be published.
        _ = try decode(data, reference: ConnectionResourceReference(descriptor: descriptor))
        return data
    }

    static func decode(_ data: Data, reference: ConnectionResourceReference) throws
        -> ConnectionDescriptor
    {
        guard data.count <= 4096, let value = String(data: data, encoding: .utf8),
            let url = URL(string: value), url.absoluteString == value
        else { throw ProtocolError.malformed("mount resource data") }
        let descriptor = try ConnectionDescriptor(resourceURL: url)
        try reference.validate(descriptor)
        return descriptor
    }

    private func query(_ reference: ConnectionResourceReference) throws -> [String: Any] {
        try Self.query(reference, accessGroup: accessGroup, identity: identity)
    }

    static func query(
        _ reference: ConnectionResourceReference, accessGroup: String?,
        identity: ApplicationIdentity
    ) throws -> [String: Any] {
        guard let accessGroup, identity.permitsKeychainGroup(accessGroup) else {
            throw error(errSecMissingEntitlement)
        }
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: identity.bundleIdentifier + ".mount-resource",
            kSecAttrAccount as String: reference.account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
        ]
    }

    private static func error(_ status: OSStatus) -> NSError {
        NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
}
