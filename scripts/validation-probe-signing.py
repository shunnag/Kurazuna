"""Keep command-only validation bundles separate from the graphical product's identity."""
from datetime import datetime, timezone
from functools import lru_cache
import fnmatch
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess

IDENTIFIER = 'dev.soba.iscsi.Validation'
DISPLAY_NAME = 'iSCSI Validation'


def validate_profile(profile, team, group, certificate, device, now):
    """Require the exact validation App ID; a product or wildcard profile is not a substitute."""
    allowed = profile.get('Entitlements', {})
    if (profile.get('TeamIdentifier') != [team]
            or profile.get('ApplicationIdentifierPrefix') != [team]
            or allowed.get('com.apple.application-identifier') != f'{team}.{IDENTIFIER}'
            or allowed.get('com.apple.developer.team-identifier') != team):
        raise ValueError('A profile for the explicit validation App ID and current team is required')
    if 'OSX' not in profile.get('Platform', []):
        raise ValueError('The validation profile must permit macOS')
    if not any(fnmatch.fnmatchcase(group, pattern)
               for pattern in allowed.get('keychain-access-groups', [])):
        raise ValueError('The validation profile does not permit the product shared Keychain group')
    if certificate not in profile.get('DeveloperCertificates', []):
        raise ValueError('The validation profile does not permit the existing extension signer')
    if not profile.get('CreationDate') or not profile.get('ExpirationDate'):
        raise ValueError('The validation profile has no validity interval')
    if not profile['CreationDate'] <= now < profile['ExpirationDate']:
        raise ValueError('The validation profile is not currently valid')
    if (profile.get('ProvisionsAllDevices') is not True
            and device.casefold() not in [d.casefold() for d in profile.get('ProvisionedDevices', [])]):
        raise ValueError('The validation profile does not permit this Mac')


@lru_cache(maxsize=1)
def provisioning_udid():
    data = json.loads(subprocess.check_output(
        ['system_profiler', 'SPHardwareDataType', '-json'], text=True, timeout=20))
    value = data['SPHardwareDataType'][0].get('provisioning_UDID', '')
    if not (isinstance(value, str) and re.fullmatch(r'[a-fA-F0-9]+(?:-[a-fA-F0-9]+)*', value)
            and 16 <= len(value.replace('-', '')) <= 40):
        raise ValueError('Cannot determine this Mac\'s provisioning UDID')
    return value


def select_profile(team, group, certificate):
    supplied = os.environ.get('ISCSI_VALIDATION_PROFILE')
    if supplied:
        candidates = [Path(supplied).expanduser().resolve(strict=True)]
    else:
        candidates = []
        for directory in [Path.home() / 'Library/Developer/Xcode/UserData/Provisioning Profiles',
                          Path.home() / 'Library/MobileDevice/Provisioning Profiles']:
            if directory.is_dir():
                candidates.extend(p for p in directory.iterdir()
                                  if p.suffix in ('.provisionprofile', '.mobileprovision') and p.is_file())
    device = provisioning_udid()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    matches = []
    for path in candidates:
        result = subprocess.run(['security', 'cms', '-D', '-i', str(path)],
                                capture_output=True, timeout=15)
        try:
            result.check_returncode()
            profile = plistlib.loads(result.stdout)
            validate_profile(profile, team, group, certificate, device, now)
        except (subprocess.CalledProcessError, plistlib.InvalidFileException, ValueError, TypeError):
            if supplied:
                raise ValueError('ISCSI_VALIDATION_PROFILE is not a valid profile for this validation bundle')
            continue
        matches.append((profile['ExpirationDate'], path))
    if not matches:
        raise ValueError(f'Create a Mac development profile for {IDENTIFIER} with the existing signer, '
                         f'this Mac and shared group {group}; set ISCSI_VALIDATION_PROFILE to its path')
    return max(matches, key=lambda item: (item[0], str(item[1])))[1]


def probe_info(original, binary_name):
    """Derive the validation bundle's Info.plist from the product app's Info.plist.

    ISCSIUsesBlockResources selects the mount source that SystemAttachmentBackend
    passes to `mount -F`. The product extension declares FSSupportsBlockResources, and
    mount(8) then builds an FSBlockDeviceResource from any source string, so a
    resource URL fails in fskitd ("Probing resource: No such file or directory")
    before the extension runs. Carry the product's choice so the probe mounts the
    same local marker device that the app mounts.
    """
    info = {key: original[key] for key in ('CFBundleVersion', 'CFBundleShortVersionString',
            'ISCSISharedKeychainAccessGroup', 'LSMinimumSystemVersion')}
    if 'ISCSIUsesBlockResources' in original:
        if not isinstance(original['ISCSIUsesBlockResources'], bool):
            raise ValueError('ISCSIUsesBlockResources in the product Info.plist must be a Boolean')
        info['ISCSIUsesBlockResources'] = original['ISCSIUsesBlockResources']
    info.update(CFBundleIdentifier=IDENTIFIER, CFBundleExecutable=binary_name,
                CFBundleDevelopmentRegion='en', CFBundleName=DISPLAY_NAME,
                CFBundleDisplayName=DISPLAY_NAME, CFBundlePackageType='APPL', LSUIElement=True,
                NSLocalNetworkUsageDescription='Connect to disposable storage servers to validate iSCSI.')
    return info


def prepare_bundle(bundle, application, binary_name, profile):
    """Prepare metadata and resources only; the caller copies and signs its own CLI executable."""
    original = plistlib.loads((application / 'Contents/Info.plist').read_bytes())
    contents = bundle / 'Contents'
    (contents / 'MacOS').mkdir(parents=True)
    info = probe_info(original, binary_name)
    resources = contents / 'Resources'
    localized = resources / 'ja.lproj'
    localized.mkdir(parents=True)
    (localized / 'InfoPlist.strings').write_text(
        '"NSLocalNetworkUsageDescription" = "iSCSIの検証用ディスクに接続します。";\n')
    icon = application / 'Contents/Resources/AppIcon.icns'
    if icon.is_file():
        shutil.copy2(icon, resources / icon.name)
        info['CFBundleIconFile'] = icon.name
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    shutil.copy2(profile, contents / 'embedded.provisionprofile')
    entitlements = plistlib.loads(subprocess.check_output(
        ['codesign', '-d', '--entitlements', '-', '--xml', str(application)], stderr=subprocess.DEVNULL))
    team = entitlements['com.apple.developer.team-identifier']
    entitlements['com.apple.application-identifier'] = f'{team}.{IDENTIFIER}'
    return contents / 'MacOS' / binary_name, entitlements
