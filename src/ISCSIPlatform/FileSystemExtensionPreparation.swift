import Foundation

/// A bounded post-install registration workaround. It does not change the user's
/// enablement choice, remove another copy, or certify that mounting will succeed.
public enum FileSystemExtensionPreparation {
    public enum Outcome: Sendable, Equatable { case deferred, alreadyAttempted, submitted }
    enum Stage: String, Sendable { case application, module }

    public static func prepare(
        applicationURL: URL, supportURL: URL, identity: ApplicationIdentity = .current,
        permitted: @escaping @Sendable () async -> Bool
    ) async throws -> Outcome {
        try await prepare(
            supportURL: supportURL,
            capture: {
                try ExtensionRegistrationIdentity.capture(
                    applicationURL: applicationURL, identity: identity)
            },
            permitted: permitted,
            run: { stage, snapshot in
                let executable: String
                let arguments: [String]
                switch stage {
                case .application:
                    executable =
                        "/System/Library/Frameworks/CoreServices.framework/Versions/A/"
                        + "Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"
                    arguments = ["-f", snapshot.application.path]
                case .module:
                    executable = "/usr/bin/pluginkit"
                    arguments = ["-a", snapshot.module.path]
                }
                _ = try await SystemCommand.run(executable, arguments: arguments, timeout: 5)
            })
    }

    static func prepare(
        supportURL: URL,
        capture: @escaping @Sendable () throws -> ExtensionRegistrationIdentity,
        permitted: @escaping @Sendable () async -> Bool,
        run: @escaping @Sendable (Stage, ExtensionRegistrationIdentity) async throws -> Void
    ) async throws -> Outcome {
        try Task.checkCancellation()
        guard await permitted() else { return .deferred }
        let snapshot = try await Task.detached(priority: .userInitiated) { try capture() }.value
        try Task.checkCancellation()
        guard await permitted() else { return .deferred }
        guard let attempt = try ExtensionRegistrationAttempt.claim(snapshot, in: supportURL) else {
            return .alreadyAttempted
        }
        do {
            for stage in [Stage.application, .module] {
                try Task.checkCancellation()
                guard await permitted() else { throw POSIXError(.EBUSY) }
                let current = try await Task.detached(priority: .userInitiated) { try capture() }
                    .value
                try Task.checkCancellation()
                guard current == snapshot else { throw POSIXError(.ESTALE) }
                guard await permitted() else { throw POSIXError(.EBUSY) }
                try Task.checkCancellation()
                try await run(stage, snapshot)
                try attempt.append(stage.rawValue + "-registered")
            }
            let final = try await Task.detached(priority: .userInitiated) { try capture() }.value
            try Task.checkCancellation()
            guard final == snapshot else { throw POSIXError(.ESTALE) }
            try attempt.append("complete")
            return .submitted
        } catch {
            // A failed command may already have changed OS registration. Keep the claim.
            try? attempt.append(error is CancellationError ? "cancelled" : "failed")
            throw error
        }
    }
}
