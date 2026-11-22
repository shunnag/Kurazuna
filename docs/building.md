# Building and testing

Use an Apple silicon Mac running macOS 27 or later, Xcode with the macOS 27 SDK, XcodeGen 2.44 or later, and Python 3. Select your Xcode installation with `DEVELOPER_DIR` if needed.

```sh
make build
make test
make lint
make app-build-release
```

The Release app is written to `build/DerivedData/Build/Products/Release/Kurazuna.app`. This build verifies compilation and resources. Running the file-system extension also requires signing. For a preview of the interface with sample data, use `make app-preview`. The English and Japanese UI suite runs with `make test-ui` in a logged-in desktop session with Xcode UI automation enabled.

## Signing

The Xcode project is generated from `project.yml`. The app and its embedded extension need explicit App IDs for your team. Enable the FSKit Module capability on the extension, and grant the app and extension the same Keychain group. If you build a fork, set the team and bundle identifiers in `project.yml`, match them in `src/ISCSIPlatform/ApplicationIdentity.swift` and `scripts/application_identity.py`, and generate the project again. Developer and release builds use separate identifiers, shared groups, settings directories, and FSKit short names.

Choose the Kurazuna scheme in Xcode for the app. For the development-signed Release configuration use `make app-build-signed-release` and `make app-install-signed-release`. The installer checks the app and its extension and installs them together in `~/Applications`. Enable Kurazuna under General → Login Items & Extensions → By Category → File System Extensions.

## Real-target tests

`scripts/test-fskit.py` exercises the installed module with a disposable target. `scripts/test-lio.py` creates a fresh Linux target VM with Lima for interoperability tests. Read their `--help` before running them. The signed validation probe needs a separate development App ID (`scripts/validation-probe-signing.py`) and a local development profile permitting the test device and the app’s shared Keychain group. Use `make fskit-preflight-release` to verify the selected Release module before mounting a fixture. Unit tests, a valid signature, or a successful preflight alone do not exercise a mounted disk.

To test recovery after a five-minute outage, run `make build-release-probe`, then run `ISCSI_TEST_APP=release python3 scripts/test-lio-recovery.py --scenarios R9`. The command creates a dedicated Linux target and verifies data against the target’s storage after reconnecting.

## Publishing signed updates

The Release app uses Sparkle 2.10.1. Both the update ZIP and `appcast.xml` are signed with the app’s Ed25519 key. The official Sparkle and third-party notices ship in `config/Sparkle-LICENSE.txt`. For a fork, change the feed URL, public key and release destination before distribution, and create your own Keychain signing identity using Sparkle’s `generate_keys`.

For Kurazuna releases, increment `CURRENT_PROJECT_VERSION`, archive and notarize the app with Developer ID, staple the ticket, and create the ZIP with `ditto -c -k --sequesterRsrc --keepParent Kurazuna.app <archive.zip>`. Use the tools from the pinned Sparkle distribution on the signing Mac. For example, to sign beta 1:

```sh
python3 scripts/make-appcast.py Kurazuna-1.0-beta.1.zip \
  --tag v1.0-beta.1 --display-version '1.0 beta 1' --tools /path/to/Sparkle/bin
```

The script reads the public key and build from the archived app, checks its extension, signs and verifies the ZIP, then signs and verifies the feed. Upload the ZIP to the specified GitHub release before publishing the generated `appcast.xml` on `main`. Future releases should use new build numbers and versioned asset URLs.
