#!/usr/bin/env python3
"""Check free space before allocating build, fixture, archive, or VM data."""

import argparse
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import uuid

GIB = 1024**3


def gib_bytes(value):
    try:
        number = Decimal(value)
        if not number.is_finite() or number < 0:
            raise ValueError
        return int((number * GIB).to_integral_value(rounding=ROUND_CEILING))
    except (InvalidOperation, ValueError):
        raise argparse.ArgumentTypeError("GiB must be finite and nonnegative") from None


def enough_space(free_bytes, required_bytes, reserve_bytes):
    return free_bytes >= required_bytes + reserve_bytes


def mounted_volume(path):
    """Use the path's actual filesystem device, including APFS volume groups.

    A parent walk with ismount() can reach the System volume from a Data path
    when their stat device numbers agree. Never infer UUID from that walk.
    This is a checked snapshot, not a reservation against remounts or writers.
    """
    before = path.stat()

    def device():
        result = subprocess.run(["/bin/df", "-P", str(path)], check=True,
                                capture_output=True, env=os.environ | {"LC_ALL": "C"})
        if len(result.stdout) > 16384:
            raise ValueError("filesystem device output is too large")
        lines = result.stdout.decode("utf-8", "strict").splitlines()
        fields = lines[1].split(maxsplit=5) if len(lines) == 2 else []
        if len(fields) != 6 or not re.fullmatch(r"/dev/disk[0-9]+(?:s[0-9]+){0,2}", fields[0]):
            raise ValueError("cannot identify mounted disk device")
        return fields[0], fields[5]

    original, original_mount = device()
    result = subprocess.run(["/usr/sbin/diskutil", "info", "-plist", original],
                            check=True, capture_output=True)
    if len(result.stdout) > 65536:
        raise ValueError("mounted volume metadata is too large")
    volume = plistlib.loads(result.stdout)
    if (type(volume) is not dict or volume.get("DeviceIdentifier") != original[5:]
            or ('DeviceNode' in volume and volume['DeviceNode'] != original)
            or ('Mounted' in volume and volume['Mounted'] is not True)):
        raise ValueError("mounted volume device does not match")
    mount = volume.get("MountPoint")
    if (type(mount) is not str or mount != original_mount or not mount.startswith("/")
            or str(PurePosixPath(mount)) != mount or ".." in PurePosixPath(mount).parts):
        raise ValueError("invalid volume mount point")
    identity = volume.get("VolumeUUID")
    if type(identity) is not str or str(uuid.UUID(identity)).upper() != identity.upper():
        raise ValueError("invalid mounted volume UUID")
    final_device = device()
    after = path.stat()
    if final_device != (original, original_mount) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise ValueError("allocation filesystem changed during inspection")
    return volume


def project_usage(root, maximum_entries=50000):
    """Conservative accounting for one owned storage tree, without following links.

    Callers include all possible growth in required_bytes. This snapshot does
    not reserve space against other writers or replace a VM allocation plan.
    """
    root = Path(root)
    if root != root.resolve(strict=True) or not root.is_dir():
        raise ValueError('project budget root must be a canonical directory')
    original = root.lstat()
    device = original.st_dev
    used, entries = 0, 0
    def account(info):
        nonlocal used, entries
        entries += 1
        if entries > maximum_entries:
            raise ValueError('project inventory entry limit')
        if info.st_dev != device:
            raise ValueError('project inventory crosses a mounted filesystem')
        used += max(info.st_size, info.st_blocks * 512)
    def visit(directory, depth):
        if depth > 64:
            raise ValueError('project inventory depth limit')
        account(os.fstat(directory))
        with os.scandir(directory) as children:
            for child in children:
                info = os.stat(child.name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    handle = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                     | os.O_CLOEXEC, dir_fd=directory)
                    try:
                        current = os.fstat(handle)
                        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                            raise ValueError('project directory changed during inventory')
                        visit(handle, depth + 1)
                    finally:
                        os.close(handle)
                else:
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise ValueError('project inventory contains a link or special file')
                    account(info)
    handle = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(handle)
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
            raise ValueError('project root changed during inventory')
        visit(handle, 0)
    finally:
        os.close(handle)
    return used, entries


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--required-gib", type=gib_bytes, default=0,
                        help="estimated maximum additional allocation, including temporary copies")
    parser.add_argument("--reserve-gib", type=gib_bytes, default=50 * GIB,
                        help="free space retained after allocation (default: 50 GiB)")
    parser.add_argument("--expected-volume-uuid",
                        help="require this mounted volume; prevents fallback to internal storage")
    parser.add_argument("--project-budget-root", type=Path,
                        help="account only this owned directory; allocation path must be inside it")
    parser.add_argument("--project-budget-bytes", type=int,
                        help="maximum project usage including the requested additional allocation")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        path = args.path.resolve(strict=True)
        if not path.is_dir():
            raise ValueError("path must be an existing directory")
        if args.expected_volume_uuid:
            volume = mounted_volume(path)
            if volume.get("VolumeUUID", "").upper() != args.expected_volume_uuid.upper():
                raise ValueError("mounted volume UUID does not match")
            if volume.get("WritableVolume") is not True:
                raise ValueError("volume is not writable")
        free = shutil.disk_usage(path).free
        ok = enough_space(free, args.required_gib, args.reserve_gib)
        report = dict(path=str(path), freeBytes=free, requiredBytes=args.required_gib,
                      reserveBytes=args.reserve_gib,
                      projectedFreeBytes=free - args.required_gib, sufficient=ok)
        if args.expected_volume_uuid:
            report.update(volumeUUID=volume['VolumeUUID'], volumeDevice=volume['DeviceIdentifier'],
                          volumeMountPoint=volume['MountPoint'])
        if args.project_budget_root is not None or args.project_budget_bytes is not None:
            if (args.project_budget_root is None or args.project_budget_bytes is None
                    or args.project_budget_bytes <= 0):
                raise ValueError('both positive project budget and root are required')
            root = args.project_budget_root
            if not path.is_relative_to(root):
                raise ValueError('allocation path is outside the project budget root')
            used, entries = project_usage(root)
            projected = used + args.required_gib
            ok = ok and projected <= args.project_budget_bytes
            report.update(projectBudgetRoot=str(root), projectUsedBytes=used,
                          projectEntries=entries, projectBudgetBytes=args.project_budget_bytes,
                          projectedProjectBytes=projected, sufficient=ok)
        if args.json:
            print(json.dumps(report))
        else:
            print(f"Storage {'OK' if ok else 'STOP'}: {path}; free {free / GIB:.1f} GiB, "
                  f"additional allocation {args.required_gib / GIB:.1f} GiB, "
                  f"reserve {args.reserve_gib / GIB:.1f} GiB")
        return 0 if ok else 1
    except (OSError, ValueError, subprocess.SubprocessError, plistlib.InvalidFileException) as error:
        print(f"Storage STOP: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
