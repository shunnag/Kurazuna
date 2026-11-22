import Foundation

/// Immutable evidence produced after login and disk inspection. Consumers must also
/// verify the mounted namespace, current connection health and descriptor ownership.
public struct ConnectionRouteReport: Codable, Sendable, Equatable {
    public static let maximumEncodedLength = 65_536
    public let version: Int
    public let resourceIdentity: Data
    public let connectedPortal: Portal
    public let contactedPortals: [Portal]
    public let permanentRedirects: [PermanentPortalRedirect]
    public let creationOrder: UInt64

    public init(
        resourceIdentity: Data, connectedPortal: Portal, contactedPortals: [Portal],
        permanentRedirects: [PermanentPortalRedirect], creationOrder: UInt64
    ) throws {
        guard resourceIdentity.count == 32, creationOrder > 0,
            (1...5).contains(contactedPortals.count), permanentRedirects.count <= 4,
            contactedPortals.last?.isSameEndpoint(as: connectedPortal) == true
        else { throw ProtocolError.malformed("mounted connection route") }
        var checked: [Portal] = []
        for portal in contactedPortals {
            guard !checked.contains(where: { $0.isSameEndpoint(as: portal) }) else {
                throw ProtocolError.malformed("mounted connection route loop")
            }
            checked.append(portal)
        }
        var sources: [Portal] = []
        for redirect in permanentRedirects {
            guard !sources.contains(where: { $0.isSameEndpoint(as: redirect.source) }),
                let index = contactedPortals.firstIndex(where: {
                    $0.isSameEndpoint(as: redirect.source)
                }),
                index + 1 < contactedPortals.count,
                redirect.destinations.contains(where: {
                    $0.isSameEndpoint(as: contactedPortals[index + 1])
                })
            else { throw ProtocolError.malformed("mounted permanent redirect path") }
            sources.append(redirect.source)
        }
        version = 1
        self.resourceIdentity = resourceIdentity
        self.connectedPortal = connectedPortal
        self.contactedPortals = contactedPortals
        self.permanentRedirects = permanentRedirects
        self.creationOrder = creationOrder
    }

    public func validate(for descriptor: ConnectionDescriptor) throws {
        guard resourceIdentity == (try descriptor.resourceIdentity),
            contactedPortals.first?.isSameEndpoint(as: descriptor.portal) == true
        else { throw ProtocolError.malformed("mounted connection route identity") }
    }

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        guard data.count <= Self.maximumEncodedLength else {
            throw ProtocolError.limitExceeded("mounted connection route")
        }
        return data
    }

    public init(data: Data, descriptor: ConnectionDescriptor) throws {
        guard data.count <= Self.maximumEncodedLength else {
            throw ProtocolError.limitExceeded("mounted connection route")
        }
        self = try JSONDecoder().decode(Self.self, from: data)
        try validate(for: descriptor)
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard try c.decode(Int.self, forKey: .version) == 1 else {
            throw ProtocolError.unsupported("mounted connection route version")
        }
        try self.init(
            resourceIdentity: c.decode(Data.self, forKey: .resourceIdentity),
            connectedPortal: c.decode(Portal.self, forKey: .connectedPortal),
            contactedPortals: c.decode([Portal].self, forKey: .contactedPortals),
            permanentRedirects: c.decode(
                [PermanentPortalRedirect].self, forKey: .permanentRedirects),
            creationOrder: c.decode(UInt64.self, forKey: .creationOrder))
    }
}
