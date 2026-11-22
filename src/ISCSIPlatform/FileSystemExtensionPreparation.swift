import AppKit
import FSKit
import Foundation

/// Prepares the running installation while preserving the user’s extension enablement choice.
public enum FileSystemExtensionPreparation {
    public enum Outcome: Sendable, Equatable { case deferred, alreadyAttempted, submitted }
    enum Stage: String, Sendable { case application, module }

    public static func prepare(
        applicationURL: URL, supportURL: URL, identity: ApplicationIdentity = .current,
        permitted: @escaping @Sendable () async -> Bool
    ) async throws -> Outcome {
        guard !isReadOnlyInstallation(applicationURL) else { return .deferred }
        return try await prepare(
            supportURL: supportURL,
            capture: {
                try ExtensionRegistrationIdentity.capture(
                    applicationURL: applicationURL, identity: identity)
            },
            permitted: permitted, run: register)
    }

    public static func isReadOnlyInstallation(_ application: URL) -> Bool {
        (try? application.resourceValues(forKeys: [.volumeIsReadOnlyKey]).volumeIsReadOnly) == true
    }

    private static let lsregister =
        "/System/Library/Frameworks/CoreServices.framework/Versions/A/"
        + "Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"

    private static func register(_ stage: Stage, _ snapshot: ExtensionRegistrationIdentity)
        async throws
    {
        switch stage {
        case .application:
            _ = try await SystemCommand.run(
                lsregister, arguments: ["-f", "-R", snapshot.application.path], timeout: 5)
        case .module:
            _ = try await SystemCommand.run(
                "/usr/bin/pluginkit", arguments: ["-a", snapshot.module.path], timeout: 5)
        }
    }

    /// Called only after the user selects the running copy. Startup never unregisters another app.
    public static func useRunningCopy(
        applicationURL: URL, identity: ApplicationIdentity = .current,
        permitted: @escaping @Sendable () async -> Bool
    ) async throws {
        func checkPermission() async throws {
            try Task.checkCancellation()
            guard await permitted() else { throw POSIXError(.EBUSY) }
            guard !isReadOnlyInstallation(applicationURL) else { throw POSIXError(.EROFS) }
        }
        func capture() throws -> ExtensionRegistrationIdentity {
            try ExtensionRegistrationIdentity.capture(
                applicationURL: applicationURL, identity: identity)
        }
        func registrations() async throws -> [FileSystemExtensionRegistration] {
            try await FSClient.shared.installedExtensions.filter {
                $0.bundleIdentifier == identity.extensionBundleIdentifier
            }.map {
                FileSystemExtensionRegistration(
                    bundleIdentifier: $0.bundleIdentifier, moduleURL: $0.url,
                    isEnabled: $0.isEnabled)
            }
        }
        try await checkPermission()
        let current = try capture()
        let modules = try await registrations()
        let state = FileSystemExtensionAvailability.evaluate(
            modules, applicationURL: applicationURL, identity: identity)
        guard state != .ready, state != .disabled else { return }
        if state == .differentCopy, let module = modules.first {
            let other = try ExtensionRegistrationIdentity.conflictingApplication(
                module.moduleURL, current: current)
            let running = NSRunningApplication.runningApplications(
                withBundleIdentifier: identity.bundleIdentifier)
            guard
                running.allSatisfy({
                    $0.processIdentifier == ProcessInfo.processInfo.processIdentifier
                })
            else {
                throw POSIXError(.EBUSY)
            }
            let latest = try await registrations()
            guard latest.count == 1, latest[0].moduleURL == module.moduleURL,
                try ExtensionRegistrationIdentity.conflictingApplication(
                    module.moduleURL, current: current) == other,
                try capture() == current
            else { throw POSIXError(.ESTALE) }
            try await checkPermission()
            _ = try await SystemCommand.run(lsregister, arguments: ["-u", other.path], timeout: 5)
        }
        for stage in [Stage.application, .module] {
            try await checkPermission()
            guard try capture() == current else { throw POSIXError(.ESTALE) }
            try await register(stage, current)
        }
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
