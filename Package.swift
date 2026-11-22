// swift-tools-version: 6.0

import Foundation
import PackageDescription

// The product supports macOS 27 or later on Apple silicon. The data-cache diagnostic
// remains an explicit opt-in; production keeps the OpenCloseOperations contract.
let cacheDiagnostic = ProcessInfo.processInfo.environment["ISCSI_FSKIT_CACHE_DIAGNOSTIC"] == "1"
let cacheDiagnosticSettings: [SwiftSetting] =
    cacheDiagnostic ? [.define("ISCSI_FSKIT_CACHE_DIAGNOSTIC")] : []
let ioDiagnostic = ProcessInfo.processInfo.environment["ISCSI_IO_DIAGNOSTICS"] == "1"
let ioDiagnosticSettings: [SwiftSetting] = ioDiagnostic ? [.define("ISCSI_IO_DIAGNOSTICS")] : []

let package = Package(
    name: "Kurazuna",
    platforms: [.macOS("27.0")],
    products: [
        .library(name: "ISCSICore", targets: ["ISCSICore"]),
        .library(name: "ISCSINetwork", targets: ["ISCSINetwork"]),
        .library(name: "ISCSIFSBridge", targets: ["ISCSIFSBridge"]),
        .library(name: "ISCSIPlatform", targets: ["ISCSIPlatform"]),
        .executable(name: "iscsi", targets: ["ISCSIControl"]),
    ],
    targets: [
        .target(name: "ISCSICore", path: "src/ISCSICore", swiftSettings: ioDiagnosticSettings),
        .target(name: "ISCSINetwork", dependencies: ["ISCSICore"], path: "src/ISCSINetwork"),
        .executableTarget(
            name: "ISCSIControl", dependencies: ["ISCSICore", "ISCSINetwork"],
            path: "src/ISCSIControl"),
        .testTarget(
            name: "ISCSICoreTests", dependencies: ["ISCSICore"], path: "tests/ISCSICoreTests"),
        .testTarget(
            name: "ISCSINetworkTests",
            dependencies: ["ISCSINetwork", "ISCSICore", "ISCSIFSBridge", "ISCSIPlatform"],
            path: "tests/ISCSINetworkTests", swiftSettings: cacheDiagnosticSettings),
        .executableTarget(
            name: "TCPTransportObservationProbe", dependencies: ["ISCSICore", "ISCSINetwork"],
            path: "tests/TCPTransportObservationProbe"),
        .executableTarget(
            name: "ISCSIIntegrationProbe",
            dependencies: ["ISCSICore", "ISCSINetwork", "ISCSIFSBridge", "ISCSIPlatform"],
            path: "tests/IntegrationProbe"),
        .executableTarget(
            name: "ISCSIFSKitProbe",
            dependencies: ["ISCSICore", "ISCSINetwork", "ISCSIPlatform", "FSKitNativeDiagnostics"],
            path: "tests/FSKitProbe"),
        .target(name: "FSKitNativeDiagnostics", path: "tests/FSKitNativeDiagnostics"),
        .target(
            name: "ISCSIFSBridge", dependencies: ["ISCSICore", "ISCSINetwork", "ISCSIPlatform"],
            path: "src/ISCSIFSBridge", swiftSettings: cacheDiagnosticSettings),
        .target(
            name: "ISCSIMemoryControlSupport",
            dependencies: ["ISCSICore", "ISCSINetwork", "ISCSIFSBridge"],
            path: "tests/MemoryControlSupport"),
        .testTarget(
            name: "ISCSIFSBridgeTests",
            dependencies: ["ISCSIFSBridge", "ISCSIMemoryControlSupport"],
            path: "tests/ISCSIFSBridgeTests", swiftSettings: cacheDiagnosticSettings),
        .systemLibrary(name: "ISCSIPlatformNative", path: "src/ISCSIPlatformNative"),
        .target(
            name: "ISCSIPlatform", dependencies: ["ISCSICore", "ISCSIPlatformNative"],
            path: "src/ISCSIPlatform"),
        .testTarget(
            name: "ISCSIPlatformTests", dependencies: ["ISCSIPlatform", "FSKitNativeDiagnostics"],
            path: "tests/ISCSIPlatformTests"),
        .target(
            name: "ISCSIAppModel", dependencies: ["ISCSICore", "ISCSINetwork", "ISCSIPlatform"],
            path: "src/ISCSIApp",
            exclude: [
                "ISCSIApp.swift", "MainView.swift", "ServerEditor.swift",
                "ConfirmationEscapeHandler.swift", "ServerRemovalConfirmation.swift",
                "ReadOnlyConnectionConfirmation.swift",
                "ErrorAcknowledgement.swift", "AppDelegate.swift",
                "Localizable.xcstrings",
                "ja.lproj", "en.lproj",
            ]),
        .testTarget(
            name: "ISCSIAppModelTests",
            dependencies: ["ISCSIAppModel", "ISCSIPlatform", "ISCSICore", "ISCSINetwork"],
            path: "tests/ISCSIAppModelTests"),
    ]
)
