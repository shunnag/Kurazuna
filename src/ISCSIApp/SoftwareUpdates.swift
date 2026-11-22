#if KURAZUNA_UPDATES
    import Combine
    import Foundation
    import Sparkle

    @MainActor final class SoftwareUpdates: NSObject, ObservableObject, SPUUpdaterDelegate {
        @Published private(set) var canCheck = false
        @Published private(set) var automaticChecks = false
        @Published private(set) var automaticDownloads = false
        private(set) var updatePrepared = false
        private weak var model: AppModel?
        private lazy var controller = SPUStandardUpdaterController(
            startingUpdater: false, updaterDelegate: self, userDriverDelegate: nil)

        func start(for model: AppModel) {
            guard self.model == nil else { return }
            self.model = model
            let updater = controller.updater
            updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheck)
            updater.publisher(for: \.automaticallyChecksForUpdates).assign(to: &$automaticChecks)
            updater.publisher(for: \.automaticallyDownloadsUpdates).assign(to: &$automaticDownloads)
            controller.startUpdater()
        }

        func check() { controller.checkForUpdates(nil) }

        func setAutomaticChecks(_ enabled: Bool) {
            controller.updater.automaticallyChecksForUpdates = enabled
        }

        func setAutomaticDownloads(_ enabled: Bool) {
            controller.updater.automaticallyDownloadsUpdates = enabled
        }

        func updater(
            _ updater: SPUUpdater, shouldProceedWithUpdate item: SUAppcastItem,
            updateCheck: SPUUpdateCheck
        ) throws {
            guard model?.canInstallSoftwareUpdate == true else {
                throw NSError(
                    domain: "Kurazuna.SoftwareUpdate", code: 1,
                    userInfo: [
                        NSLocalizedDescriptionKey: String(
                            localized:
                                "Finish any disk operations and eject your disks before updating Kurazuna."
                        )
                    ])
            }
        }

        // Disk state can change between discovering an update and installing it.
        func updaterShouldRelaunchApplication(_ updater: SPUUpdater) -> Bool {
            model?.canInstallSoftwareUpdate == true
        }

        func updater(_ updater: SPUUpdater, didExtractUpdate item: SUAppcastItem) {
            updatePrepared = true
        }

        func updater(
            _ updater: SPUUpdater, willInstallUpdateOnQuit item: SUAppcastItem,
            immediateInstallationBlock: @escaping () -> Void
        ) -> Bool {
            updatePrepared = true
            return false
        }
    }
#endif
