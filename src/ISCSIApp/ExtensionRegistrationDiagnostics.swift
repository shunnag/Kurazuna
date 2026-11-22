import Darwin
import Foundation
import ISCSIPlatform
import OSLog

/// Records the app's existing query without logging paths, descriptions or credentials.
enum ExtensionRegistrationDiagnostics {
    private static let logger = Logger(
        subsystem: "dev.soba.iscsi", category: "ExtensionRegistration")

    static func preparationStarted(_ id: UUID) {
        logger.notice(
            "FSKitRegistration preparation=\(id.uuidString, privacy: .public) event=begin")
    }

    static func preparationCompleted(
        _ id: UUID, outcome: FileSystemExtensionPreparation.Outcome
    ) {
        let value: String
        switch outcome {
        case .deferred: value = "deferred"
        case .alreadyAttempted: value = "already-attempted"
        case .submitted: value = "submitted"
        }
        logger.notice(
            "FSKitRegistration preparation=\(id.uuidString, privacy: .public) event=\(value, privacy: .public)"
        )
    }

    static func preparationFailed(_ id: UUID, error: any Error) {
        let fields = failureFields(error)
        logger.error(
            "FSKitRegistration preparation=\(id.uuidString, privacy: .public) event=failed \(fields, privacy: .public)"
        )
    }

    static func started(_ id: UUID) {
        let build =
            Int(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "") ?? 0
        logger.notice(
            "FSKitRegistration query=\(id.uuidString, privacy: .public) event=begin pid=\(ProcessInfo.processInfo.processIdentifier) uid=\(geteuid()) build=\(build)"
        )
    }

    static func completed(_ id: UUID, assessment: FileSystemExtensionAssessment) {
        let fields = registrationFields(assessment)
        logger.notice(
            "FSKitRegistration query=\(id.uuidString, privacy: .public) event=complete \(fields, privacy: .public)"
        )
    }

    static func failed(_ id: UUID, error: any Error) {
        let fields = failureFields(error)
        logger.error(
            "FSKitRegistration query=\(id.uuidString, privacy: .public) event=failed \(fields, privacy: .public)"
        )
    }

    static func checkFailed(_ id: UUID, error: any Error) {
        let fields = failureFields(error)
        logger.error(
            "FSKitRegistration check=\(id.uuidString, privacy: .public) event=unavailable \(fields, privacy: .public)"
        )
    }

    static func registrationFields(_ assessment: FileSystemExtensionAssessment) -> String {
        let state: String
        switch assessment.availability {
        case .unavailable: state = "unavailable"
        case .disabled: state = "disabled"
        case .differentCopy: state = "different-copy"
        case .ready: state = "ready"
        }
        return
            "state=\(state) own=\(assessment.matchingModuleCount) enabled=\(assessment.enabledMatchingModuleCount) "
            + "expectedIdentity=\(assessment.expectedIdentity != nil ? 1 : 0) registeredIdentity=\(assessment.registeredIdentity != nil ? 1 : 0) "
            + "expectedDevice=\(assessment.expectedIdentity?.device ?? 0) expectedInode=\(assessment.expectedIdentity?.inode ?? 0) "
            + "registeredDevice=\(assessment.registeredIdentity?.device ?? 0) registeredInode=\(assessment.registeredIdentity?.inode ?? 0)"
    }

    static func failureFields(_ error: any Error) -> String {
        if error is CancellationError { return "domain=cancellation code=0" }
        let error = error as NSError
        let knownDomains = [
            NSCocoaErrorDomain, NSPOSIXErrorDomain, "FSKitErrorDomain",
            "com.apple.extensionKit.errorDomain",
        ]
        let domain = knownDomains.contains(error.domain) ? error.domain : "other"
        return "domain=\(domain) code=\(error.code)"
    }
}
