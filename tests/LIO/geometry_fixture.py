"""Validate an OS-created, disposable 512 MiB GPT image with 4 KiB sectors.

This reads the two GPT copies before LIO exports the image. It never rewrites
partition metadata or accepts a block device.
"""

import os
import stat
import struct
import zlib

BLOCK_SIZE = 4096
BYTE_COUNT = 512 * 1048576


def validate(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_size == BYTE_COUNT
        last = BYTE_COUNT // BLOCK_SIZE - 1

        def header(lba, alternate):
            raw = bytearray(os.pread(fd, BLOCK_SIZE, lba * BLOCK_SIZE))
            assert len(raw) == BLOCK_SIZE and raw[:8] == b"EFI PART"
            revision, size, checksum, reserved = struct.unpack_from("<IIII", raw, 8)
            assert revision == 0x10000 and 92 <= size <= BLOCK_SIZE and reserved == 0
            struct.pack_into("<I", raw, 16, 0)
            assert zlib.crc32(raw[:size]) == checksum
            current, other, first, end = struct.unpack_from("<QQQQ", raw, 24)
            assert (current, other) == (lba, alternate) and 6 <= first <= end <= last - 5
            array_lba, count, entry_size, array_crc = struct.unpack_from("<QIII", raw, 72)
            assert count == 128 and entry_size == 128
            length = count * entry_size
            assert 2 <= array_lba and array_lba * BLOCK_SIZE + length <= last * BLOCK_SIZE
            array_end = array_lba + (length + BLOCK_SIZE - 1) // BLOCK_SIZE - 1
            assert array_end < first if lba == 1 else array_lba > end
            entries = os.pread(fd, length, array_lba * BLOCK_SIZE)
            assert len(entries) == length and zlib.crc32(entries) == array_crc
            ranges = []
            for index in range(count):
                entry = entries[index * entry_size:(index + 1) * entry_size]
                if entry[:16] != bytes(16):
                    start, stop = struct.unpack_from("<QQ", entry, 32)
                    assert first <= start <= stop <= end
                    ranges.append((start, stop))
            assert ranges
            ranges.sort()
            assert all(a[1] < b[0] for a, b in zip(ranges, ranges[1:]))
            return bytes(raw[56:72]), first, end, entries

        assert os.pread(fd, 8, 512) != b"EFI PART"
        assert header(1, last) == header(last, 1)
        return dict(byteCount=BYTE_COUNT, blockSize=BLOCK_SIZE, bothGPTCopiesValid=True)
    finally:
        os.close(fd)
