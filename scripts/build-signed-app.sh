#!/bin/bash
set -euo pipefail

# Usage: build-signed-app.sh [development|release]
# development (the default) builds the Debug configuration into build/Signed; release builds
# the Release configuration into build/SignedRelease. Both use Apple Development signing.
edition=${1-development}
case $edition in
    development)
        configuration=Debug
        derived_data=build/Signed
        ;;
    release)
        configuration=Release
        derived_data=build/SignedRelease
        ;;
    *)
        echo 'Usage: build-signed-app.sh [development|release]' >&2
        exit 2
        ;;
esac
if (($# > 1)); then
    echo 'Usage: build-signed-app.sh [development|release]' >&2
    exit 2
fi

development_team=${ISCSI_DEVELOPMENT_TEAM:-FQTM2788K5}
if [[ ! $development_team =~ ^[A-Z0-9]{10}$ ]]; then
    echo 'Set ISCSI_DEVELOPMENT_TEAM to your 10-character Apple Developer team ID.' >&2
    exit 2
fi

build_command=(xcodebuild)
case ${ISCSI_ALLOW_PROVISIONING_UPDATES:-0} in
    0) ;;
    1) build_command+=(-allowProvisioningUpdates) ;;
    *)
        echo 'ISCSI_ALLOW_PROVISIONING_UPDATES must be 0 or 1.' >&2
        exit 2
        ;;
esac

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
python3 scripts/check-storage.py --required-gib 8

# Updating Apple Developer signing assets is an explicit opt-in. Extension activation and
# notarization remain separate from building the signed app.
exec "${build_command[@]}" \
    -project Kurazuna.xcodeproj \
    -scheme Kurazuna \
    -configuration "$configuration" \
    -destination 'platform=macOS,arch=arm64' \
    -derivedDataPath "$derived_data" \
    CODE_SIGN_STYLE=Automatic \
    CODE_SIGN_IDENTITY='Apple Development' \
    DEVELOPMENT_TEAM="$development_team" \
    OTHER_SWIFT_FLAGS=-disable-sandbox \
    build
