# Compatibility and known issues

Kurazuna uses FSKit to expose a LUN as a fixed-length disk image. macOS attaches that image and mounts its partitions using its own file-system drivers. One host must have exclusive access to a writable disk.

## Beta 1 (build 202)

On an Apple silicon Mac running macOS 27.3 beta (26C5047e), we installed the Developer ID–signed and notarized app from the distribution ZIP. The installed FSKit extension mounted an APFS disk through a CHAP-authenticated connection. We wrote and flushed data, ejected the disk, and verified the contents against the target’s storage.

On a separate Debian Linux LIO target, the same extension passed four APFS tests. Each test checked the final contents against a snapshot of the target.

| Interruption | Result in this run |
| --- | --- |
| Five seconds of packet loss during I/O | The TCP connection survived and the disk completed its writes. |
| Five minutes of packet loss while idle | The disk reconnected about 16 seconds after traffic resumed. Reads, writes and a normal eject succeeded. |
| Three TCP resets during writes with mutual CHAP | Both peers authenticated on each new connection. All three interrupted 24 MiB files matched their expected contents. |
| Server’s mutual CHAP secret changed during an outage | Kurazuna refused the server’s new proof and stopped writes. Confirmed Force Eject released the disk. Previously synchronized data matched the snapshot. |

On a second Linux target implementation, TGT 1.0.85, build 202 passed 18 mounts and normal ejections: six each for APFS, ExFAT and Mac OS Extended (Journaled). Each format was tested both read-only and read/write with 512-byte logical blocks (with and without CHAP) and with 4096-byte logical blocks using a 512-byte-unit partition layout. The target snapshots preserved the read-only images and the data written by the app.

## Earlier development builds

| Target | Observed behavior before the first beta |
| --- | --- |
| Linux LIO and TGT | The development build mounted APFS, ExFAT, and journaled HFS+ read-only and read/write. Native 4Kn GPT disks mounted read-only and rejected a read/write connection. A development-signed Release build passed the LIO/TGT connection checks. |
| Windows Server 2025 x86-64 evaluation, iSCSI Target Server | The signed probe exercised the product extension for reads, writes, synchronization, reconnection, verification against stored data, and ejection. The ordinary graphical app was not tested against this target. |
| Windows Server ARM Insider Preview and FreeBSD CTL | Results from protocol tests apply to those targets and builds only. A mounted file-system test on those configurations is pending. |

When the network disappears, Kurazuna tries to log in again and checks the identity, capacity, block size, and write protection of the responding disk. A disk whose write or synchronization cannot complete stops accepting writes. A normal ejection may fail for a stopped, writable disk. Confirm **Force Eject** to release it.

During a five-minute outage test, an earlier development build showed Connected and then returned a write error. The disk required Force Eject. Other runs recovered successfully. The cause of this observation remains open.

Tests with disposable virtual targets do not cover physical NAS firmware, loss of power to a target or Mac, or days of continuous I/O.
