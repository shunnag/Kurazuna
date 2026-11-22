export CLANG_MODULE_CACHE_PATH := $(CURDIR)/.cache/clang
export SWIFTPM_MODULECACHE_OVERRIDE := $(CURDIR)/.cache/swift

.PHONY: build run test storage-check app-project app-build app-build-release app-build-signed app-build-signed-release app-install-signed app-install-signed-release app-verify-signature app-verify-signature-release app-preview test-ui integration integration-tcp build-release-probe fskit-preflight fskit-preflight-release integration-fskit-fixture integration-fskit integration-fskit-write integration-fskit-release integration-lio integration-lio-release lint
build:
	swift build --disable-sandbox

STORAGE_RESERVE_GIB ?= 50
STORAGE_REQUIRED_GIB ?= 5
.PHONY: storage-check
storage-check:
	python3 scripts/check-storage.py --reserve-gib $(STORAGE_RESERVE_GIB) --required-gib $(STORAGE_REQUIRED_GIB)
# Direct integration/test goals also check space when they do not depend on build.
build test run app-project app-preview: | storage-check

app-project:
	xcodegen generate
app-build: app-project
	xcodebuild -project Kurazuna.xcodeproj -scheme Kurazuna -configuration Debug -destination 'platform=macOS,arch=arm64' -derivedDataPath build/DerivedData CODE_SIGNING_ALLOWED=NO OTHER_SWIFT_FLAGS=-disable-sandbox build
.PHONY: app-build-release
app-build-release: app-project
	xcodebuild -project Kurazuna.xcodeproj -scheme Kurazuna -configuration Release -destination 'platform=macOS,arch=arm64' -derivedDataPath build/DerivedData CODE_SIGNING_ALLOWED=NO OTHER_SWIFT_FLAGS=-disable-sandbox build
app-build-signed: app-project
	bash scripts/build-signed-app.sh
	python3 scripts/verify-signed-app.py
# The Release configuration (dev.soba.iscsi.kurazuna, kurazuna) with Apple Development signing, in
# build/SignedRelease. Installed as ~/Applications/Kurazuna.app beside the development app.
.PHONY: app-build-signed-release app-verify-signature-release app-install-signed-release
app-build-signed-release: app-project
	bash scripts/build-signed-app.sh release
	python3 scripts/verify-signed-app.py --edition release
app-verify-signature-release:
	python3 scripts/verify-signed-app.py --edition release
app-install-signed-release: app-build-signed-release
	python3 scripts/install-signed-app.py --edition release
app-verify-signature:
	python3 scripts/verify-signed-app.py
app-install-signed: app-build-signed
	python3 scripts/install-signed-app.py
app-preview: app-project
	xcodebuild -project Kurazuna.xcodeproj -scheme ISCSIPreview -configuration Debug -destination 'platform=macOS,arch=arm64' -derivedDataPath build/Preview CODE_SIGNING_ALLOWED=NO OTHER_SWIFT_FLAGS=-disable-sandbox build
UI_TEST_DERIVED_DATA ?= build/UITests
UI_TEST_RESULT_BUNDLE ?= build/UITestResults/$(shell date +%Y%m%d-%H%M%S).xcresult
.PHONY: test-ui
test-ui: STORAGE_REQUIRED_GIB=10
test-ui: app-project | storage-check
	mkdir -p "$(dir $(UI_TEST_RESULT_BUNDLE))"
	python3 scripts/test-ui.py --derived-data "$(UI_TEST_DERIVED_DATA)" --result-bundle "$(UI_TEST_RESULT_BUNDLE)"
run:
	swift run --disable-sandbox iscsi $(ARGS)
test:
	swift test --disable-sandbox
integration: build
	python3 -u scripts/test-integration.py
integration-tcp: build | storage-check
	python3 -u scripts/test-integration.py --loopback
build-release-probe: | storage-check
	swift build --disable-sandbox -c release -Xswiftc -enable-testing --product ISCSIFSKitProbe
	swift build --disable-sandbox -c release -Xswiftc -enable-testing --product iscsi
fskit-preflight-release: build-release-probe
	ISCSI_TEST_APP=release python3 -u scripts/test-fskit.py --preflight-only
integration-fskit-release: build-release-probe | storage-check
	ISCSI_TEST_APP=release python3 -u scripts/test-fskit.py
integration-lio-release: build-release-probe | storage-check
	ISCSI_TEST_APP=release python3 -u scripts/test-lio.py
fskit-preflight: build
	python3 -u scripts/test-fskit.py --preflight-only
integration-fskit-fixture: build | storage-check
	python3 -u scripts/test-fskit.py --fixture-only
integration-fskit: build | storage-check
	python3 -u scripts/test-fskit.py
integration-fskit-write: build | storage-check
	python3 -u scripts/test-fskit.py --read-write
integration-lio: build | storage-check
	python3 -u scripts/test-lio.py
lint:
	xcrun swift-format lint --strict --recursive Package.swift src tests
	xcrun clang-format --dry-run --Werror tests/FSKitNativeDiagnostics/FSKitNativeDiagnostics.c tests/FSKitNativeDiagnostics/include/FSKitNativeDiagnostics.h
	xcrun clang -std=c11 -Wall -Wextra -Werror -I tests/FSKitNativeDiagnostics/include -fsyntax-only tests/FSKitNativeDiagnostics/FSKitNativeDiagnostics.c
	xcrun clang-format --dry-run --Werror src/ISCSIPlatformNative/DiskArbitrationStatus.h
	xcrun clang -std=c11 -Wall -Wextra -Werror -x c -include src/ISCSIPlatformNative/DiskArbitrationStatus.h -fsyntax-only /dev/null
