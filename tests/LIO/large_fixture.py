"""Small, deterministic contents of a disposable 3 TiB sparse LUN."""

import errno
import hashlib
import os
import sys

BYTE_COUNT = 3 * 1024 ** 4
BOUNDARY = (1 << 32) * 512
REGION_BYTES = 4096
OFFSETS = (8 * 1048576, BOUNDARY - REGION_BYTES, BOUNDARY, BYTE_COUNT - REGION_BYTES)


def regions(nonce):
    values = []
    for index, offset in enumerate(OFFSETS):
        before = bytearray([0xA0 + index]) * REGION_BYTES
        marker = f"Sparse LIO {nonce} region {index}\n".encode()
        before[:len(marker)] = marker
        after = bytearray([0x51 + index]) * REGION_BYTES
        if index == 2:
            after[17:54] = bytes([0x5A]) * 37
        values.append((offset, bytes(before), bytes(after)))
    return values


def create(path, nonce):
    # macOS may allocate an extended regular file eagerly. Large creation is
    # deliberately restricted to the disposable Linux target, never the host.
    assert BYTE_COUNT <= 16 * 1048576 or sys.platform == "linux"
    with path.open("xb", buffering=0) as output:
        output.truncate(BYTE_COUNT)
        for offset, before, _ in regions(nonce):
            assert os.pwrite(output.fileno(), before, offset) == len(before)
    path.chmod(0o600)
    assert path.stat().st_size == BYTE_COUNT
    assert path.stat().st_blocks * 512 < 16 * 1048576


def verify(path, nonce, written):
    """Read every allocated extent and check all other bytes there are zero.

    SEEK_HOLE describes logical zero regions, not physically persisted storage.
    No fsync or other extra flush is issued by this observer.
    """
    assert path.stat().st_size == BYTE_COUNT
    allocated = path.stat().st_blocks * 512
    assert allocated < 16 * 1048576, "Unexpected allocation in sparse test fixture"
    expected_regions = [(offset, after if written else before)
                        for offset, before, after in regions(nonce)]
    extents = []
    with path.open("rb", buffering=0) as source:
        for offset, expected in expected_regions:
            assert os.pread(source.fileno(), len(expected), offset) == expected
        cursor = total = 0
        while cursor < BYTE_COUNT:
            try:
                start = os.lseek(source.fileno(), cursor, os.SEEK_DATA)
            except OSError as error:
                if error.errno == errno.ENXIO:
                    break
                raise
            end = os.lseek(source.fileno(), start, os.SEEK_HOLE)
            assert cursor <= start < end <= BYTE_COUNT
            total += end - start
            assert total <= 16 * 1048576 and len(extents) < 128
            expected = bytearray(end - start)
            for offset, contents in expected_regions:
                left, right = max(start, offset), min(end, offset + len(contents))
                if left < right:
                    expected[left - start:right - start] = contents[left - offset:right - offset]
            actual = os.pread(source.fileno(), end - start, start)
            assert actual == expected, "Unexpected bytes outside the intended sparse regions"
            extents.append(dict(offset=start, length=end - start, sha256=hashlib.sha256(actual).hexdigest()))
            cursor = end
    return dict(byteCount=BYTE_COUNT, allocatedBytes=allocated, scannedDataBytes=total,
                mode="written" if written else "original", allAllocatedBytesMatch=True,
                zeroHolesReportedBySeekHole=True, extraSyncIssued=False, extents=extents)
