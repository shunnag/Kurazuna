"""Bounded sparse copies of disposable, Linux-owned 3 TiB filesystem images."""

import errno
import hashlib
import os
import sys

BYTE_COUNT = 3 * 1024 ** 4
MAX_DATA_BYTES = 1024 ** 3


def validate(path):
    assert path.is_file() and not path.is_symlink()
    assert path.stat().st_size == BYTE_COUNT
    assert path.stat().st_blocks * 512 <= MAX_DATA_BYTES


def blank(path):
    assert BYTE_COUNT <= 16 * 1048576 or sys.platform == "linux"
    with path.open("xb", buffering=0) as image:
        image.truncate(BYTE_COUNT)
    path.chmod(0o600)
    validate(path)


def ranges(file):
    cursor = total = count = 0
    while cursor < BYTE_COUNT:
        try:
            start = os.lseek(file.fileno(), cursor, os.SEEK_DATA)
        except OSError as error:
            if error.errno == errno.ENXIO:
                break
            raise
        end = os.lseek(file.fileno(), start, os.SEEK_HOLE)
        assert cursor <= start < end <= BYTE_COUNT
        total += end - start
        count += 1
        assert total <= MAX_DATA_BYTES and count <= 4096
        yield start, end
        cursor = end


def fingerprint(path):
    validate(path)
    digest = hashlib.sha256(BYTE_COUNT.to_bytes(8, "big"))
    total = count = 0
    with path.open("rb", buffering=0) as source:
        for start, end in ranges(source):
            digest.update(start.to_bytes(8, "big") + (end - start).to_bytes(8, "big"))
            cursor = start
            while cursor < end:
                size = min(1048576, end - cursor)
                contents = os.pread(source.fileno(), size, cursor)
                assert len(contents) == size
                digest.update(contents)
                cursor += size
            total += end - start
            count += 1
    return dict(byteCount=BYTE_COUNT, scannedDataBytes=total, extentCount=count,
                allocatedBytes=path.stat().st_blocks * 512, sparseContentSHA256=digest.hexdigest(),
                extraSyncIssued=False)


def copy(source, destination):
    """Copy logical data extents only; never call fsync on the observed source."""
    validate(source)
    blank(destination)
    with source.open("rb", buffering=0) as incoming, destination.open("r+b", buffering=0) as outgoing:
        for start, end in ranges(incoming):
            cursor = start
            while cursor < end:
                size = min(1048576, end - cursor)
                data = os.pread(incoming.fileno(), size, cursor)
                assert len(data) == size
                assert os.pwrite(outgoing.fileno(), data, cursor) == size
                cursor += size
    result = fingerprint(destination)
    assert result["sparseContentSHA256"] == fingerprint(source)["sparseContentSHA256"]
    return result
