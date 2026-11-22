import CryptoKit
import Foundation

public enum LUNImagePresentation: String, Sendable, Codable {
    case raw, udsp
}

/// Public connection metadata. Passwords and CHAP responses are never serialized in resource URLs.
public struct ConnectionDescriptor: Sendable, Equatable, Codable {
    public static let scheme = "iscsi-fskit"
    public let profileID: UUID
    public let portal: Portal
    public let initiatorName: String
    public let targetName: String
    public let lun: LogicalUnit
    public let readOnly: Bool
    public let chapUsername: String?
    public let targetCHAPUsername: String?
    public let credentialID: UUID?
    public let isid: [UInt8]
    public let mountID: UUID?
    public let imagePresentation: LUNImagePresentation
    public let portalGroupTag: UInt16?
    public let settingsBinding: Data?

    public init(
        profileID: UUID, portal: Portal, initiatorName: String, targetName: String,
        lun: LogicalUnit, readOnly: Bool, chapUsername: String? = nil, isid: [UInt8],
        mountID: UUID? = nil, credentialID: UUID? = nil,
        imagePresentation: LUNImagePresentation = .raw, targetCHAPUsername: String? = nil,
        portalGroupTag: UInt16? = nil, settingsBinding: Data? = nil
    ) throws {
        _ = try LoginConfiguration(initiatorName: initiatorName, targetName: targetName, isid: isid)
        if let chapUsername {
            guard !chapUsername.isEmpty, chapUsername.utf8.count <= 223,
                chapUsername.utf8.allSatisfy({ $0 >= 32 && $0 != 127 })
            else { throw ProtocolError.malformed("CHAP username") }
        }
        guard credentialID == nil || chapUsername != nil else {
            throw ProtocolError.malformed("credential reference without CHAP")
        }
        if let targetCHAPUsername {
            guard chapUsername != nil, !targetCHAPUsername.isEmpty,
                targetCHAPUsername.utf8.count <= 223,
                targetCHAPUsername.utf8.allSatisfy({ $0 >= 32 && $0 != 127 })
            else { throw ProtocolError.malformed("mutual CHAP username") }
        }
        guard settingsBinding == nil || settingsBinding?.count == 32 else {
            throw ProtocolError.malformed("connection settings binding")
        }
        self.profileID = profileID
        self.portal = portal
        self.initiatorName = initiatorName
        self.targetName = targetName
        self.lun = lun
        self.readOnly = readOnly
        self.chapUsername = chapUsername
        self.targetCHAPUsername = targetCHAPUsername
        self.credentialID = credentialID
        self.isid = isid
        self.mountID = mountID
        self.imagePresentation = imagePresentation
        self.portalGroupTag = portalGroupTag
        self.settingsBinding = settingsBinding
    }

    public var resourceURL: URL {
        get throws {
            var components = URLComponents()
            components.scheme = Self.scheme
            components.host = portal.host.contains(":") ? "[\(portal.host)]" : portal.host
            components.port = Int(portal.port)
            components.path = "/\(profileID.uuidString.lowercased())"
            var items = [
                URLQueryItem(name: "initiator", value: initiatorName),
                URLQueryItem(name: "target", value: targetName),
                URLQueryItem(name: "lun", value: "0x" + lun.addressKey),
                URLQueryItem(name: "readOnly", value: readOnly ? "1" : "0"),
                URLQueryItem(name: "isid", value: isid.map { String(format: "%02x", $0) }.joined()),
            ]
            if let chapUsername { items.append(URLQueryItem(name: "chap", value: chapUsername)) }
            if let targetCHAPUsername {
                items.append(URLQueryItem(name: "targetCHAP", value: targetCHAPUsername))
            }
            if let portalGroupTag {
                items.append(URLQueryItem(name: "portalGroup", value: String(portalGroupTag)))
            }
            if let credentialID {
                items.append(
                    URLQueryItem(name: "credential", value: credentialID.uuidString.lowercased()))
            }
            if let mountID {
                items.append(URLQueryItem(name: "mount", value: mountID.uuidString.lowercased()))
            }
            if imagePresentation == .udsp {
                items.append(URLQueryItem(name: "image", value: "udsp"))
            }
            components.queryItems = items
            if let settingsBinding {
                components.queryItems?.append(
                    URLQueryItem(
                        name: "settings",
                        value: settingsBinding.map { String(format: "%02x", $0) }.joined()))
            }
            guard let url = components.url else {
                throw ProtocolError.malformed("resource URL host")
            }
            return url
        }
    }

    public init(resourceURL: URL) throws {
        guard resourceURL.absoluteString.utf8.count <= 4096,
            let c = URLComponents(url: resourceURL, resolvingAgainstBaseURL: false),
            c.scheme == Self.scheme, c.user == nil, c.password == nil, c.fragment == nil,
            let host = c.host, let port = c.port, (1...65_535).contains(port),
            c.percentEncodedPath == c.path,
            let profileID = UUID(uuidString: String(c.path.dropFirst())),
            c.path == "/\(String(c.path.dropFirst()))",
            let items = c.queryItems
        else { throw ProtocolError.malformed("iSCSI resource URL") }
        var values: [String: String] = [:]
        let keys: Set<String> = [
            "initiator", "target", "lun", "readOnly", "chap", "isid", "mount", "credential",
            "image", "targetCHAP", "portalGroup", "settings",
        ]
        for item in items {
            guard keys.contains(item.name), let value = item.value, values[item.name] == nil else {
                throw ProtocolError.malformed("resource URL parameter")
            }
            values[item.name] = value
        }
        guard let initiator = values["initiator"], let target = values["target"],
            let lunText = values["lun"],
            let readOnly = values["readOnly"], ["0", "1"].contains(readOnly),
            let isidText = values["isid"], isidText.utf8.count == 12
        else { throw ProtocolError.malformed("resource URL fields") }
        let isid = try CHAP.decodeBinary("0x" + isidText)
        let presentation: LUNImagePresentation
        if let value = values["image"] {
            guard value == "udsp" else {
                throw ProtocolError.malformed("resource image presentation")
            }
            presentation = .udsp
        } else {
            presentation = .raw
        }
        let credentialID: UUID?
        if let text = values["credential"] {
            guard let id = UUID(uuidString: text) else {
                throw ProtocolError.malformed("credential reference")
            }
            credentialID = id
        } else {
            credentialID = nil
        }
        let portalGroupTag: UInt16?
        if let text = values["portalGroup"] {
            guard let tag = UInt16(text), String(tag) == text else {
                throw ProtocolError.malformed("resource portal group")
            }
            portalGroupTag = tag
        } else {
            portalGroupTag = nil
        }
        let mountID: UUID?
        if let text = values["mount"] {
            guard let id = UUID(uuidString: text) else {
                throw ProtocolError.malformed("resource mount identity")
            }
            mountID = id
        } else {
            mountID = nil
        }
        let lun: LogicalUnit
        let settingsBinding: Data?
        if let text = values["settings"] {
            guard text.utf8.count == 64,
                text.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
            else {
                throw ProtocolError.malformed("connection settings binding")
            }
            settingsBinding = try CHAP.decodeBinary("0x" + text)
        } else {
            settingsBinding = nil
        }
        if lunText.hasPrefix("0x") {
            lun = try LogicalUnit(addressKey: String(lunText.dropFirst(2)))
        } else if let number = UInt16(lunText), String(number) == lunText {
            lun = try LogicalUnit(number)
        } else {
            throw ProtocolError.malformed("resource URL LUN")
        }
        let unbracketed =
            host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        try self.init(
            profileID: profileID, portal: Portal(host: unbracketed, port: UInt16(port)),
            initiatorName: initiator, targetName: target, lun: lun,
            readOnly: readOnly == "1", chapUsername: values["chap"], isid: [UInt8](isid),
            mountID: mountID, credentialID: credentialID, imagePresentation: presentation,
            targetCHAPUsername: values["targetCHAP"], portalGroupTag: portalGroupTag,
            settingsBinding: settingsBinding)
    }

    public func assigningMountID(_ id: UUID) throws -> ConnectionDescriptor {
        try ConnectionDescriptor(
            profileID: profileID, portal: portal, initiatorName: initiatorName,
            targetName: targetName, lun: lun, readOnly: readOnly, chapUsername: chapUsername,
            isid: isid, mountID: id, credentialID: credentialID,
            imagePresentation: imagePresentation, targetCHAPUsername: targetCHAPUsername,
            portalGroupTag: portalGroupTag, settingsBinding: settingsBinding)
    }

    public static let identityAttributeName = "dev.soba.iscsi.resource-id"
    public static let connectionStateAttributeName = "dev.soba.iscsi.connection-state"
    public static let sourceBlockSizeAttributeName = "dev.soba.iscsi.source-block-size"
    public static let connectionRouteAttributeName = "dev.soba.iscsi.connection-route"
    /// Write-only control. Writing `abandonRecoveryControlValue` stops reconnecting: waiting
    /// I/O fails at once and no further login is attempted. It is never readable.
    public static let connectionControlAttributeName = "dev.soba.iscsi.connection-control"
    public static let abandonRecoveryControlValue = Data("abandon".utf8)
    /// The same request for a read-only volume, where the kernel refuses every attribute write
    /// (EROFS) before the extension sees it. Reading this name, which is never listed, stops
    /// reconnecting and returns `abandonRecoveryControlValue`; a writable volume doesn't have
    /// it (ENOATTR), so it can only be asked for deliberately.
    public static let readOnlyConnectionControlAttributeName =
        "dev.soba.iscsi.connection-control.read-only"
    public var resourceIdentity: Data {
        get throws { Data(SHA256.hash(data: Data(try resourceURL.absoluteString.utf8))) }
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        guard string.utf8.count <= 4096, let url = URL(string: string) else {
            throw ProtocolError.malformed("persisted resource URL")
        }
        try self.init(resourceURL: url)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(resourceURL.absoluteString)
    }
}
