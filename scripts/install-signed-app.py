#!/usr/bin/env python3
"""Install the verified signed app in ~/Applications without launching it.

--edition development (the default) installs build/Signed's Kurazuna Development.app;
--edition release installs build/SignedRelease's Kurazuna.app. Each replaces only its own app.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

from application_identity import DEVELOPMENT, IDENTITIES

ROOT = Path(__file__).resolve().parents[1]
# The edition being installed; main() selects it before any other step.
IDENTITY = DEVELOPMENT
LSREGISTER = "/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister"


def run(arguments):
    return subprocess.run(list(map(str, arguments)), check=True, timeout=60)


def check_storage():
    run(["python3", ROOT / "scripts/check-storage.py", "--required-gib", "0.3"])


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify(app):
    run(["python3", ROOT / "scripts/verify-signed-app.py", "--app", app,
         "--edition", IDENTITY.edition,
         "--provisioning-udid", provisioning_udid()])


def provisioning_udid():
    hardware = json.loads(subprocess.check_output(
        ["/usr/sbin/system_profiler", "SPHardwareDataType", "-json"],
        text=True, timeout=20))
    entries = hardware.get("SPHardwareDataType") if isinstance(hardware, dict) else None
    device = (entries[0].get("provisioning_UDID")
              if isinstance(entries, list) and entries and isinstance(entries[0], dict) else None)
    require(isinstance(device, str)
            and re.fullmatch(r"[A-Fa-f0-9]+(?:-[A-Fa-f0-9]+)*", device)
            and 16 <= len(device.replace("-", "")) <= 40,
            "Cannot determine this Mac's provisioning UDID; no app was installed")
    return device


def register_installed(app):
    run([LSREGISTER, "-f", "-R", app])
    # Registering the host alone did not consistently register its FSKit extension
    # after replacement. Add this exact bundle without changing user enablement.
    run(["/usr/bin/pluginkit", "-a", app / "Contents/Extensions/ISCSIFSExtension.appex"])


def registered_applications():
    probe = '''import Foundation
import CoreServices
var failure: Unmanaged<CFError>?
let values = LSCopyApplicationURLsForBundleIdentifier(BUNDLE_IDENTIFIER as CFString, &failure)?.takeRetainedValue() as? [URL] ?? []
let code = failure.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0
let data = try JSONSerialization.data(withJSONObject: ["paths": values.map { $0.path }, "error": code])
print(String(decoding: data, as: UTF8.self))
'''.replace("BUNDLE_IDENTIFIER", json.dumps(IDENTITY.bundle_identifier))
    query = subprocess.run(["xcrun", "swift", "-module-cache-path", str(ROOT / ".cache/swift-registration"),
                            "-e", probe], check=True, capture_output=True, text=True, timeout=60)
    state = json.loads(query.stdout)
    require(state["error"] in (0, -10814), "Launch Services could not verify the build registration")
    return {Path(path).resolve() for path in state["paths"]}


def unregister_source(source):
    if source.resolve() not in registered_applications():
        print("Build app registration is already absent (verified through Launch Services)")
        return
    # Only remove a registration that the public API actually reports.
    subprocess.run([LSREGISTER, "-u", str(source)], capture_output=True, text=True, timeout=60)
    require(source.resolve() not in registered_applications(),
            "The build app remains registered")


def verify_registration(source, installed):
    """Confirm the final registration, repairing rediscovery at most three times."""
    source = source.resolve()
    installed = installed.resolve()
    confirmations = 0
    repairs = 0
    while confirmations < 2:
        registrations = registered_applications()
        if source not in registrations and installed in registrations:
            confirmations += 1
            continue
        require(repairs < 3, "Application registration did not remain at the installed app")
        require(not subprocess.check_output(["/sbin/mount", "-t", IDENTITY.file_system_type]).strip(),
                "An iSCSI disk became active before updating application registration.")
        # Keep a valid installed registration before removing a rediscovered build.
        # No bundle copy, global database reset, or delay is needed for this repair.
        register_installed(installed)
        if source in registrations:
            unregister_source(source)
        repairs += 1
        confirmations = 0


def bundle_contents(folder):
    entries = {".": ("directory", folder.stat().st_mode & 0o7777)}
    for path in folder.rglob("*"):
        name = str(path.relative_to(folder))
        if path.is_symlink():
            entries[name] = ("symlink", os.readlink(path))
        elif path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(1_048_576):
                    digest.update(chunk)
            entries[name] = ("file", path.stat().st_mode & 0o7777, digest.hexdigest())
        elif path.is_dir():
            entries[name] = ("directory", path.stat().st_mode & 0o7777)
        else:
            raise RuntimeError(f"Unsupported entry in application bundle: {path}")
    return entries


def exchange_bundles(staged, installed):
    """Keep the installed path present while exchanging two complete local bundles."""
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    exchange = library.renamex_np
    exchange.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    exchange.restype = ctypes.c_int
    # Public Darwin stdio.h: RENAME_SWAP. Do not fall back to removing the installed path.
    if exchange(os.fsencode(staged), os.fsencode(installed), 0x00000002) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(installed))


def main(argv=()):
    """Install one edition. Tests call main() for the development default."""
    global IDENTITY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edition", choices=IDENTITIES, default=DEVELOPMENT.edition)
    parser.add_argument("--source", type=Path, help="Install this signed app, e.g. a Developer ID export.")
    arguments = parser.parse_args(list(argv))
    IDENTITY = IDENTITIES[arguments.edition]
    check_storage()
    source = arguments.source or ROOT / IDENTITY.signed_product
    applications = Path.home() / "Applications"
    installed = applications / (IDENTITY.application_name + ".app")
    require(source.resolve() != installed.resolve(), "The source must differ from the installed app")
    require(not subprocess.check_output(["/sbin/mount", "-t", IDENTITY.file_system_type]).strip(),
            "Eject iSCSI disks before replacing their active extension.")
    require(not installed.is_symlink(), "The installed app must not be a symbolic link")
    if installed.exists():
        require(installed.stat().st_uid == os.getuid(), "The installed app belongs to another user")
        info = plistlib.loads((installed / "Contents/Info.plist").read_bytes())
        require(info["CFBundleIdentifier"] == IDENTITY.bundle_identifier,
                "A different app occupies the destination")
        executable = installed / "Contents/MacOS" / info["CFBundleExecutable"]
        processes = subprocess.check_output(["/bin/ps", "-axo", "comm="], text=True).splitlines()
        require(str(executable) not in [line.strip() for line in processes],
                "Quit iSCSI before installing a new build.")
    verify(source)
    if installed.exists() and bundle_contents(source) == bundle_contents(installed):
        verify(installed)
        registrations = registered_applications()
        if source.resolve() in registrations or installed.resolve() not in registrations:
            require(not subprocess.check_output(["/sbin/mount", "-t", IDENTITY.file_system_type]).strip(),
                    "An iSCSI disk became active before updating application registration.")
        if source.resolve() in registrations:
            register_installed(installed)
            unregister_source(source)
        elif installed.resolve() not in registrations:
            register_installed(installed)
        verify_registration(source, installed)
        print(f"{IDENTITY.edition.capitalize()} build is already installed; bundle unchanged: {installed}")
        return
    applications.mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=".iscsi-install-", dir=applications))
    retain_stage = False
    try:
        stage = directory / (IDENTITY.application_name + ".app")
        run(["ditto", source, stage])
        verify(stage)
        version = plistlib.loads((stage / "Contents/Info.plist").read_bytes())["CFBundleVersion"]
        replaced = False
        had_previous = installed.exists()
        try:
            require(not subprocess.check_output(["/sbin/mount", "-t", IDENTITY.file_system_type]).strip(),
                    "An iSCSI disk became active while the build was being staged.")
            if had_previous:
                exchange_bundles(stage, installed)
            else:
                stage.rename(installed)
            replaced = True
            # Xcode auto-registers its build product. Nonrecursive unregister is intentional:
            # a recursive package scan failed with -10814 on the validation Mac.
            register_installed(installed)
            unregister_source(source)
            # Unregistering once can succeed before Launch Services rediscovers
            # Xcode's build product. Keep final verification inside the rollback.
            verify_registration(source, installed)
        except BaseException:
            if replaced:
                try:
                    if had_previous:
                        exchange_bundles(stage, installed)
                        register_installed(installed)
                    else:
                        installed.rename(stage)
                except BaseException as rollback_error:
                    # The stage may hold the only previous copy. Leave it recoverable.
                    retain_stage = True
                    raise RuntimeError(
                        f"Installation rollback failed. Keep both bundles and inspect {directory}"
                    ) from rollback_error
            raise
    finally:
        if not retain_stage:
            shutil.rmtree(directory)
    print(f"Installed {IDENTITY.edition} build {version}: {installed}")


if __name__ == "__main__":
    main(sys.argv[1:])
