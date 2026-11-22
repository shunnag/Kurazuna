#!/usr/bin/env python3
"""Check development signatures, profiles, and the app/FSKit keychain contract."""

import argparse
import datetime
import fnmatch
import os
import plistlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from application_identity import DEVELOPMENT, IDENTITIES, identity_for_bundle


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*arguments):
    return subprocess.run(arguments, check=True, capture_output=True).stdout


def verify_nested_code_teams(bundle, team):
    # Deep verification accepts ad-hoc signed debug dylibs, which hardened
    # runtime library validation rejects when the main executable has a team.
    macho_magic = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                   b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                   b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
    for path in sorted(bundle.rglob("*")):
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(4) not in macho_magic:
                continue
        result = subprocess.run(["codesign", "-d", "--verbose=4", str(path)],
                                check=True, capture_output=True, text=True)
        teams = [line.removeprefix("TeamIdentifier=") for line in result.stderr.splitlines()
                 if line.startswith("TeamIdentifier=")]
        require(teams == [team],
                f"{path.relative_to(bundle)}: code signature team differs; runtime library validation would reject it")


def inspect_bundle(bundle, identifier, team, group, extension, provisioning_udid=None):
    run("codesign", "--verify", "--deep", "--strict", str(bundle))
    verify_nested_code_teams(bundle, team)
    info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
    executable = info.get("CFBundleExecutable")
    require(isinstance(executable, str) and executable not in ("", ".", "..")
            and Path(executable).name == executable,
            f"{identifier}: CFBundleExecutable must name a file in Contents/MacOS")
    binary = bundle / "Contents/MacOS" / executable
    require(binary.is_file() and not binary.is_symlink(),
            f"{identifier}: main executable is missing or is not a regular file: {binary}")
    require(binary.stat().st_mode & 0o111 and os.access(binary, os.X_OK),
            f"{identifier}: main executable is not executable: {binary}")
    version = info.get("CFBundleVersion")
    require(isinstance(version, str) and bool(version.strip()),
            f"{identifier}: CFBundleVersion is missing or empty")
    signed = plistlib.loads(run("codesign", "-d", "--entitlements", "-", "--xml", str(bundle)))
    profile = plistlib.loads(run(
        "security", "cms", "-D", "-i", str(bundle / "Contents/embedded.provisionprofile")
    ))
    allowed = profile["Entitlements"]
    app_identifier = f"{team}.{identifier}"
    require(info["CFBundleIdentifier"] == identifier, f"{identifier}: bundle ID differs")
    require(profile["TeamIdentifier"] == [team], f"{identifier}: profile team differs")
    require(signed.get("com.apple.developer.team-identifier") == team,
            f"{identifier}: signature team differs")
    require(signed.get("com.apple.application-identifier") == app_identifier,
            f"{identifier}: application identifier prefix differs from team")
    require(fnmatch.fnmatchcase(app_identifier, allowed["com.apple.application-identifier"]),
            f"{identifier}: profile does not permit the application identifier")
    require(allowed.get("com.apple.developer.team-identifier") == team,
            f"{identifier}: profile entitlement team differs")
    require(signed.get("keychain-access-groups") == [group],
            f"{identifier}: shared keychain entitlement differs")
    require(info.get("ISCSISharedKeychainAccessGroup") == group,
            f"{identifier}: shared keychain Info.plist value differs")
    require(any(fnmatch.fnmatchcase(group, pattern)
                for pattern in allowed.get("keychain-access-groups", [])),
            f"{identifier}: profile does not permit the shared keychain group")
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    require(profile["CreationDate"] <= now < profile["ExpirationDate"],
            f"{identifier}: profile is not currently valid")
    if provisioning_udid is not None:
        devices = profile.get("ProvisionedDevices", [])
        require(isinstance(devices, list) and all(isinstance(device, str) for device in devices),
                f"{identifier}: profile device list is invalid")
        require(profile.get("ProvisionsAllDevices") is True
                or any(device.casefold() == provisioning_udid.casefold() for device in devices),
                f"{identifier}: target device is not listed in the embedded provisioning profile")

    with tempfile.TemporaryDirectory(prefix="iscsi-signing-certificate-") as directory:
        certificate_prefix = str(Path(directory) / "signer")
        run("codesign", "-d", f"--extract-certificates={certificate_prefix}", str(bundle))
        certificate = Path(certificate_prefix + "0").read_bytes()
        require(certificate in profile["DeveloperCertificates"],
                f"{identifier}: signing certificate is not in the profile")

    if extension:
        require(signed.get("com.apple.developer.fskit.fsmodule") is True,
                f"{identifier}: FSKit entitlement is missing")
        require(allowed.get("com.apple.developer.fskit.fsmodule") is True,
                f"{identifier}: profile does not permit FSKit")
        require(signed.get("com.apple.security.app-sandbox") is True,
                f"{identifier}: extension sandbox entitlement is missing")
        require(signed.get("com.apple.security.network.client") is True,
                f"{identifier}: outgoing network entitlement is missing")
        require(info["EXAppExtensionAttributes"]["EXExtensionPointIdentifier"]
                == "com.apple.fskit.fsmodule", f"{identifier}: extension point differs")

    print(f"Verified {identifier}: {profile['Name']}, expires {profile['ExpirationDate']} UTC")
    return version


def inspect_identity(app, edition=None):
    app_info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    identity = identity_for_bundle(app_info.get("CFBundleIdentifier"))
    require(edition is None or edition == identity.edition,
            "Application edition differs from the requested edition")
    extension_info = plistlib.loads(
        (app / "Contents/Extensions/ISCSIFSExtension.appex/Contents/Info.plist").read_bytes())
    require(extension_info.get("CFBundleIdentifier") == identity.extension_identifier,
            "FSKit bundle ID differs from the application edition")
    for info in (app_info, extension_info):
        # Existing release builds predate the explicit edition key.
        require(info.get("ISCSIApplicationEdition", "release") == identity.edition,
                "Application and extension editions differ")
    require(extension_info.get("EXAppExtensionAttributes", {}).get("FSShortName") == identity.file_system_type,
            "FSKit short name differs from the application edition")
    return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path,
                        help="Default: the signed build of --edition (build/Signed for development, "
                             "build/SignedRelease for release)")
    parser.add_argument("--edition", choices=IDENTITIES,
                        help="Require this edition; otherwise accept either known bundle ID")
    parser.add_argument("--team", default=os.environ.get("ISCSI_DEVELOPMENT_TEAM", "FQTM2788K5"))
    parser.add_argument("--provisioning-udid",
                        help="Require both profiles to permit this target device; use the provisioning UDID for Apple silicon Macs")
    arguments = parser.parse_args()
    if arguments.app is None:
        arguments.app = Path(IDENTITIES[arguments.edition or DEVELOPMENT.edition].signed_product)
    require(re.fullmatch(r"[A-Z0-9]{10}", arguments.team), "Invalid Apple Developer team ID")
    if arguments.provisioning_udid is not None:
        require(re.fullmatch(r"[A-Fa-f0-9]+(?:-[A-Fa-f0-9]+)*", arguments.provisioning_udid)
                and 16 <= len(arguments.provisioning_udid.replace("-", "")) <= 40,
                "Invalid target provisioning UDID")
    identity = inspect_identity(arguments.app, arguments.edition)
    extension = arguments.app / "Contents/Extensions/ISCSIFSExtension.appex"
    group = f"{arguments.team}.{identity.keychain_group_suffix}"
    app_version = inspect_bundle(arguments.app, identity.bundle_identifier, arguments.team, group, False,
                                 arguments.provisioning_udid)
    extension_version = inspect_bundle(extension,
                                       identity.extension_identifier, arguments.team, group, True,
                                       arguments.provisioning_udid)
    require(app_version == extension_version, "App and FSKit extension build numbers differ")
    print(f"App and extension build numbers match: {app_version}")
    print(f"Shared keychain group matches: {group}")
    if arguments.provisioning_udid is not None:
        print("Target device is permitted by both provisioning profiles.")
    print("Signature checks do not establish extension activation or runtime keychain access.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"Signing verification failed: {error}", file=sys.stderr)
        sys.exit(1)
