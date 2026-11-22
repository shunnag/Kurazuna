import Foundation
import ISCSICore
import ISCSIPlatform
import Security

enum MutualCredentialProbe {
    static func run(mode: String, nonce: UUID, use: CredentialContext.Use = .connection)
        async throws
    {
        let context = CredentialContext(
            profileID: nonce, portal: try Portal("127.0.0.1:3260"),
            username: "credential-probe-mac-" + nonce.uuidString.lowercased(), credentialID: nonce,
            targetUsername: "credential-probe-server-" + nonce.uuidString.lowercased(), use: use)
        let store = KeychainCredentialStore.sharedForCurrentBundle()
        let destination = CredentialContext(
            profileID: nonce, portal: try Portal("127.0.0.1:3271"), username: context.username,
            credentialID: nonce, targetUsername: context.targetUsername)
        let oneWaySource = CredentialContext(
            profileID: nonce, portal: context.portal,
            username: context.username, credentialID: nonce)
        let oneWayDestination = CredentialContext(
            profileID: nonce, portal: destination.portal,
            username: context.username, credentialID: nonce)
        let password =
            (use == .discovery ? "discovery-initiator-" : "initiator-")
            + nonce.uuidString.lowercased()
        let targetPassword =
            (use == .discovery ? "discovery-target-" : "target-") + nonce.uuidString.lowercased()
        switch mode {
        case "--mutual-credentials-write":
            try await store.save(
                password: password, targetPassword: targetPassword, context: context)
            print("PASS: disposable mutual credential pair saved in the shared Keychain")
        case "--mutual-credentials-check":
            let credentials = try await store.credentials(context: context)
            guard credentials.targetUsername == context.targetUsername else {
                throw ProtocolError.malformed("restored mutual credential identity")
            }
            try validate(credentials, password: password, targetPassword: targetPassword)
            let other = CredentialContext(
                profileID: nonce, portal: context.portal,
                username: context.username, credentialID: nonce, targetUsername: "other-server",
                use: use)
            try await requireMissing(store, context: other)
            print(
                "PASS: another process restored both secrets and verified both CHAP directions; changed identity has no credential"
            )
        case "--mutual-credentials-copy":
            try await store.copyCredentials(from: context, to: destination)
            try await store.save(password: password, context: oneWaySource)
            try await store.copyCredentials(from: oneWaySource, to: oneWayDestination)
            print(
                "PASS: mutual credential pair copied inside the Keychain to the selected endpoint")
        case "--mutual-credentials-check-copy":
            let credentials = try await store.credentials(context: destination)
            try validate(credentials, password: password, targetPassword: targetPassword)
            try validate(
                try await store.credentials(context: oneWayDestination),
                password: password, targetPassword: targetPassword)
            let altered = CredentialContext(
                profileID: nonce, portal: try Portal("127.0.0.1:3272"),
                username: context.username, credentialID: nonce,
                targetUsername: context.targetUsername)
            try await requireMissing(store, context: altered)
            let alteredOneWay = CredentialContext(
                profileID: nonce, portal: altered.portal,
                username: context.username, credentialID: nonce)
            try await requireMissing(store, context: alteredOneWay)
            print(
                "PASS: another process verified the copied one-way CHAP secret and endpoint binding"
            )
            print(
                "PASS: another process verified both copied secrets; a changed endpoint has no credential"
            )
        case "--mutual-credentials-remove":
            if use == .connection {
                try await store.remove(context: oneWaySource)
                try await store.remove(context: oneWayDestination)
                try await store.remove(context: destination)
                try await requireMissing(store, context: oneWaySource)
                try await requireMissing(store, context: oneWayDestination)
                try await requireMissing(store, context: destination)
            }
            try await store.remove(context: context)
            try await requireMissing(store, context: context)
            print("PASS: disposable mutual credential pair removed")
        default: throw ProtocolError.malformed("mutual credential probe mode")
        }
    }

    private static func requireMissing(_ store: KeychainCredentialStore, context: CredentialContext)
        async throws
    {
        do {
            _ = try await store.credentials(context: context)
            throw ProtocolError.malformed("unexpected credential item")
        } catch let error as NSError
            where error.domain == NSOSStatusErrorDomain && error.code == Int(errSecItemNotFound)
        {
            return
        }
    }

    static func validate(
        _ credentials: CHAPCredentials, password: String, targetPassword: String
    ) throws {
        let isid: [UInt8] = [0x80, 9, 8, 7, 6, 5]
        func reply(_ flags: UInt8, _ sequence: UInt32, _ entries: [TextParameters.Entry]) throws
            -> PDU
        {
            var header = Array(repeating: UInt8(0), count: 48)
            header[0] = 0x23
            header[1] = flags
            header.replaceSubrange(8..<14, with: isid)
            header.put(UInt16(1), at: 14)
            header.put(UInt32(1), at: 16)
            header.put(sequence, at: 24)
            header.put(UInt32(1), at: 28)
            header.put(UInt32(32), at: 32)
            return try PDU(header: header, data: TextParameters(entries).encoded())
        }
        var machine = LoginMachine(
            configuration: try LoginConfiguration(
                initiatorName: "iqn.2026-10.dev.soba:credential-probe", credentials: credentials,
                isid: isid))
        _ = try machine.start()
        _ = try machine.accept(reply(0, 0, [.init("AuthMethod", "CHAP")]))
        let challenge = "0x000102030405060708090a0b0c0d0e0f"
        guard
            let answer = try machine.accept(
                reply(
                    0, 1, [.init("CHAP_A", "5"), .init("CHAP_I", "7"), .init("CHAP_C", challenge)]))
        else {
            throw ProtocolError.invalidState
        }
        let text = try TextParameters(data: answer.data)
        guard
            try text.uniqueValue(for: "CHAP_R")
                == CHAP.response(identifier: 7, secret: password, challenge: challenge)
        else {
            throw ProtocolError.malformed("restored CHAP response")
        }
        if credentials.targetUsername == nil {
            guard try text.uniqueValue(for: "CHAP_I") == nil,
                try text.uniqueValue(for: "CHAP_C") == nil
            else {
                throw ProtocolError.malformed("unexpected mutual CHAP challenge")
            }
            return
        }
        guard
            try text.uniqueValue(for: "CHAP_R")
                == CHAP.response(identifier: 7, secret: password, challenge: challenge),
            let identifier = try text.uniqueValue(for: "CHAP_I").flatMap(UInt8.init),
            let peerChallenge = try text.uniqueValue(for: "CHAP_C"),
            let targetUsername = credentials.targetUsername
        else { throw ProtocolError.malformed("restored CHAP response") }
        let result = try CHAP.response(
            identifier: identifier, secret: targetPassword, challenge: peerChallenge)
        guard
            let offer = try machine.accept(
                reply(0x81, 2, [.init("CHAP_N", targetUsername), .init("CHAP_R", result)]))
        else {
            throw ProtocolError.invalidState
        }
        let selected = try TextParameters(data: offer.data).entries.map {
            ["HeaderDigest", "DataDigest"].contains($0.key)
                ? TextParameters.Entry($0.key, "None") : $0
        }
        _ = try machine.accept(reply(0x87, 3, selected))
        guard machine.isComplete else { throw ProtocolError.authenticationFailed }
    }
}
