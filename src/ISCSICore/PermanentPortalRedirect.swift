import Foundation

/// A permanent login redirect, scoped to a profile and login target by its settings owner.
/// It never changes the configured endpoint or the identity used to obtain credentials.
public struct PermanentPortalRedirect: Codable, Sendable, Equatable {
    public let source: Portal
    public let destinations: [Portal]

    public init(source: Portal, destinations: [Portal]) throws {
        guard !destinations.isEmpty, destinations.count <= 16 else {
            throw ProtocolError.limitExceeded("permanent redirect addresses")
        }
        var unique: [Portal] = []
        for portal in destinations where !source.isSameEndpoint(as: portal) {
            if !unique.contains(where: { $0.isSameEndpoint(as: portal) }) { unique.append(portal) }
        }
        guard !unique.isEmpty else { throw ProtocolError.malformed("permanent redirect loop") }
        self.source = source
        self.destinations = unique
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            source: values.decode(Portal.self, forKey: .source),
            destinations: values.decode([Portal].self, forKey: .destinations))
    }

    public func preferring(_ portal: Portal) throws -> Self {
        guard destinations.contains(where: { $0.isSameEndpoint(as: portal) }) else {
            throw ProtocolError.invalidState
        }
        return try Self(
            source: source,
            destinations: [portal] + destinations.filter { !$0.isSameEndpoint(as: portal) })
    }
}
