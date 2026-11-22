#!/usr/bin/env python3
"""Real-target fault injection for transport recovery (RecoveringSession).

Creates one disposable Lima Debian VM with a kernel LIO target (scripts/test-lio.py), mounts
APFS through the installed signed app's FSKit extension via the production
AttachmentCoordinator (ISCSIFSKitProbe --recovery-lio-loopback), injects faults inside the
VM and checks, independently of the initiator:

- the wire (RecoveryWireAudit): logins, revalidation before I/O, flush ordering per
  connection, redo of interrupted writes, and no mutation after a latch or a replaced LUN;
- the target's backing store (snapshots attached read-only on this Mac) against the probe's
  write ledger: every version whose synchronization returned must be present.

Faults run inside the VM: iptables DROP of tcp/3260 on lo (both directions), `ss -K`,
`systemctl restart rtslib-fb-targetctl` with a saved configuration, and a sysrq reboot.
The Lima port forward relays each guest connection through its guest agent; a dial left
pending during a blackhole would deliver a login the initiator already abandoned once the
DROP is removed. Pending dials (SYN-SENT) to :3260 are therefore aborted just before each
heal, as a real network would never complete a connection the initiator closed.

R13 (not in the default order) stalls one connection in the audit forwarder on this Mac
instead: it forwards only the first part of one target PDU (R13-datain, R13-response) or of
one initiator Data-Out (R13-dataout) and then nothing more in either direction, without ending
either side, so that the initiator's own transport deadline must end the connection (see
scenario_r13). R13-dataout also stops reading from the initiator, so that its sends block.

Sleep and wake (--scenarios SLEEP) are prepared but refused unless --allow-sleep is given:
the Mac running this must be a dedicated test host, because the scenario puts it to sleep
(`pmset sleepnow`) and needs `sudo -n pmset relative wake` to wake it. The Lima VM sleeps with
the host, so the scenario checks the initiator's side only: that the recovery window counts
awake time (a sleep longer than WINDOW must not expire it), that the disk returns to connected
after wake without application errors, and that acknowledged synchronizations survive.
With --manual-sleep a person sleeps and wakes the Mac instead; the prompt prints the deadline
(--sleep-wait-minutes). The workload keeps running through every maintenance DarkWake and
is stopped, and the disk ejected, only at a full wake with the screen unlocked (SleepWatch):
the eject's last step removes a Keychain item, which the Keychain refuses while the screen is
locked (MountResourceCleanupError, APP043).

Mutual CHAP (R3-mutual, R2-mutual, R4-mutual; each runs only when named, see mutual_variant):
R3's and R2's bodies, and a target whose mutual secret changes during an outage (R4-mutual),
with a disposable pair of random secrets per scenario (mutual_credentials). They exist only in
this process's memory, the guest's ACL and the probe's Keychain item: the configurator and the
probe read them on stdin, never from a command line or a file, and the scenario's evidence is
searched for them before they are dropped (secret_mentions). The wire audit then checks both
CHAP proofs of every Normal login (RecoveryWireAudit.expect_mutual_chap).
"""

from contextlib import contextmanager
import argparse
import collections
import datetime
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import random
import re
import secrets
import select
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lio_interop", ROOT / "scripts/test-lio.py")
lio = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lio)
fixture = lio.fixture
login_audit = lio.login_audit
run = lio.run

SCENARIOS = ("R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13",
             "SLEEP")
DEFAULT_ORDER = ("R3", "R1", "R2", "R4", "R9", "R5", "R10", "R7", "R11", "R12", "R8", "R6")
SECOND = 1_000_000_000
WINDOW = 120  # SessionRecovery.defaultRecoveryWindow, awake seconds
# R13's variants and their digests: header and data digests shift the cut of a Data-In or a
# Data-Out; a Response is cut inside its header either way.
R13_VARIANTS = (("datain", "CRC32C"), ("response", "None"), ("dataout", "CRC32C"))


def r13_variants(name):
    """The (variant, digest) rows a --scenarios name selects: datain and response for R13, one
    variant for R13-<variant> (any case); None for any other name. R13-dataout is only chosen
    by name: on this Mac its stall ends by the command deadline (see scenario_r13)."""
    name = name.upper()
    if name == "R13":
        return [row for row in R13_VARIANTS if row[0] != "dataout"]
    return [row for row in R13_VARIANTS if name == "R13-" + row[0].upper()] or None


# Mutual CHAP variants (mutual_bodies).
MUTUAL_VARIANTS = ("R3-mutual", "R2-mutual", "R4-mutual")


def mutual_variant(name):
    """The mutual CHAP variant a --scenarios name selects (any case), or None. They run only by
    name: neither the default order nor R2, R3 or R4 includes them."""
    return next((variant for variant in MUTUAL_VARIANTS if variant.upper() == name.upper()), None)


# The CHAP names of the disposable target's ACL (tests/LIO/configure.py) and of the probe's
# credential (FSKitProbe.saveFixtureCredential); only the secrets are disposable.
MUTUAL_USERNAME = "test-user"
MUTUAL_TARGET_USERNAME = "test-server"


def chap_secret(avoid=()):
    """A disposable CHAP secret: 32 hexadecimal characters from the system's CSPRNG (within the
    product's 12 to 1024 bytes and LIO's limit), different from each of `avoid`."""
    while True:
        value = secrets.token_hex(16)
        if value not in avoid:
            return value


def mutual_credentials():
    """A scenario's mutual CHAP pair, a different secret each way. Keep it in memory only."""
    password = chap_secret()
    return dict(username=MUTUAL_USERNAME, password=password,
                targetUsername=MUTUAL_TARGET_USERNAME, targetPassword=chap_secret((password,)))


SECRET_SCAN_CHUNK = 1048576


def secret_mentions(values, paths):
    """The files among `paths` (directories are walked, symbolic links skipped) that contain any
    of `values`, as strings. Only names are returned; what matched is never printed. A file
    that cannot be read is listed as unreadable."""
    needles = [value.encode() for value in values if value]
    overlap = max((len(needle) for needle in needles), default=1) - 1
    found = []
    files = []
    for path in map(Path, paths):
        if path.is_symlink() or not path.exists():
            continue
        if path.is_dir():
            for directory, names, file_names in os.walk(path):
                names[:] = [n for n in names if not (Path(directory) / n).is_symlink()]
                files.extend(Path(directory) / n for n in file_names)
        else:
            files.append(path)
    files = [path for path in files if not path.is_symlink() and path.is_file()]
    for path in files:
        try:
            with open(path, "rb") as stream:
                tail = b""
                while chunk := stream.read(SECRET_SCAN_CHUNK):
                    window = tail + chunk
                    if any(needle in window for needle in needles):
                        found.append(str(path))
                        break
                    tail = window[-overlap:] if overlap else b""
        except OSError as error:
            found.append(f"{path} (unreadable: {error.strerror})")
    return dict(files=len(files), found=found)


def run_log_path():
    """The file this process's standard output is written to (a nohup log), or None."""
    try:
        sys.stdout.flush()
        if not stat.S_ISREG(os.fstat(sys.stdout.fileno()).st_mode):
            return None
        path = fcntl.fcntl(sys.stdout.fileno(), fcntl.F_GETPATH, bytes(1024))
        return path.rstrip(b"\0").decode() or None
    except (OSError, ValueError, AttributeError):
        return None

# MARK: CRC32C


def _crc_table():
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        table.append(value)
    return table


_CRC_TABLE = _crc_table()


def crc32c(data):
    """Table-driven CRC32C; checked against the bitwise reference before any use."""
    crc = 0xFFFFFFFF
    table = _CRC_TABLE
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return struct.pack("<I", crc ^ 0xFFFFFFFF)


def check_crc32c():
    generator = random.Random(7)
    for size in (0, 1, 3, 47, 48, 512, 4099, 65536):
        data = bytes(generator.getrandbits(8) for _ in range(size))
        assert crc32c(data) == lio.crc_fixture.crc32c(data), "Fast CRC32C differs from the reference"
    # RFC 3720 B.4 test vector: 32 bytes of zeros.
    assert crc32c(bytes(32)) == bytes.fromhex("aa36918a"), "CRC32C test vector differs"


# MARK: Wire audit


IO_OPCODES = {0x28: "READ10", 0x88: "READ16", 0x2A: "WRITE10", 0x8A: "WRITE16",
              0x35: "SYNC10", 0x91: "SYNC16"}
WRITE_OPCODES = (0x2A, 0x8A)
SYNC_OPCODES = (0x35, 0x91)
LSOF = "/usr/sbin/lsof"


def socket_queued(stream):
    """Bytes the kernel holds in `stream`'s receive buffer (FIONREAD), or None if the socket
    is gone. Nothing is read."""
    try:
        value = fcntl.ioctl(stream.fileno(), termios.FIONREAD, struct.pack("i", 0))
        return struct.unpack("i", value)[0]
    except (OSError, ValueError):
        return None


def initiator_socket(initiator_port, forwarder_port, runner=subprocess.run):
    """The initiator's end of one loopback connection to the forwarder as the kernel lists it
    (lsof, read-only): `seen`, its TCP `state`, and its kernel `sendQueue` and `receiveQueue`
    in bytes, with the owning `pid`; or `error`. The forwarder's own end has the same ports
    the other way round and is told apart by its name. lsof lists only sockets a process
    still holds: once the initiator closes its end, it is gone from the listing even while
    its kernel keeps the connection (FIN_WAIT_1 behind unsent bytes)."""
    if initiator_port is None or forwarder_port is None:
        return dict(error="no ports")
    name = f"127.0.0.1:{initiator_port}->127.0.0.1:{forwarder_port}"
    try:
        result = runner([LSOF, "-nP", "-T", "qs", "-FpfnT", f"-iTCP:{initiator_port}"],
                        capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        return dict(error=type(error).__name__)
    if result.returncode not in (0, 1):
        return dict(error=f"lsof exit {result.returncode}")
    rows, pid, row = [], None, None
    for line in result.stdout.splitlines():
        if line.startswith("p"):
            pid, row = int(line[1:]), None
        elif line.startswith("f"):
            row = dict(pid=pid)
            rows.append(row)
        elif row is not None and line.startswith("n"):
            row["name"] = line[1:]
        elif row is not None and line.startswith("T") and "=" in line:
            key, _, value = line[1:].partition("=")
            row[key] = value
    match = next((row for row in rows if row.get("name") == name), None)
    if match is None:
        return dict(seen=False)
    try:
        queues = dict(sendQueue=int(match["QS"]), receiveQueue=int(match["QR"]))
    except (KeyError, ValueError):
        queues = dict(sendQueue=None, receiveQueue=None)
    return dict(seen=True, pid=match["pid"], state=match.get("ST"), **queues)


def dataout_handed(drained, pdu, digests):
    """What the initiator had handed its kernel of the Data-Out burst a `dataout` stall cut,
    from the bytes drained after its close (plain data; the bytes are not kept).

    `drained` starts with the rest of the cut frame (pdu: frameBytes, forwardedBytes,
    dataLength, tag, final), then frames follow. `dataBytes` counts the burst's data in whole
    frames, the cut frame's included once it is whole; `final` is True once the burst's last
    Data-Out (F bit) is among them. A burst whose last Data-Out never arrived was not handed
    over whole: the initiator's sends had not finished it."""
    rest = pdu["frameBytes"] - pdu["forwardedBytes"]
    result = dict(drainedBytes=len(drained), cutFrameWhole=len(drained) >= rest, frames=0,
                  dataBytes=0, final=False, lastBufferOffset=None, otherFrames=0,
                  partialBytes=0, error=None)
    if len(drained) < rest:
        result["partialBytes"] = len(drained)
        return result
    result.update(dataBytes=pdu["dataLength"], final=bool(pdu.get("final")),
                  lastBufferOffset=pdu.get("bufferOffset"))
    tag = bytes.fromhex(pdu["tag"])
    offset = rest
    while len(drained) - offset >= 48:
        header = drained[offset:offset + 48]
        try:
            _, length, _, size, _, _ = login_audit.frame_layout(header, True, *digests)
        except Exception as error:
            result["error"] = (error.args[0] if type(error) is login_audit.AuditError
                               and error.args else type(error).__name__)
            break
        if len(drained) - offset < size:
            break
        if header[0] & 0x3F == 5 and header[16:20] == tag:
            result["frames"] += 1
            result["dataBytes"] += length
            result["lastBufferOffset"] = int.from_bytes(header[40:44], "big")
            result["final"] = result["final"] or bool(header[1] & 0x80)
        else:
            result["otherFrames"] += 1
        offset += size
    result["partialBytes"] = len(drained) - offset
    return result


class _ErrorList(list):
    """The base proxy reports a refused target connection as an error. During a restart or a
    reboot the Lima forward disappears with the guest listener; record such refusals with
    their time instead, and judge them against the declared faults."""

    def __init__(self, audit):
        super().__init__()
        self.audit = audit

    def append(self, value):
        if value == "TARGET_CONNECTION_FAILED":
            self.audit.note_target_connect_failure()
            return
        super().append(value)


class RecoveryWireAudit(lio.WireAudit):
    """Observes recovery traffic per connection without changing forwarded bytes.

    The base audit's global write/flush counters, single-Logout rule and fatal transport,
    partial-frame and incomplete-login conditions model one healthy session. Here each TCP
    connection is modeled on its own, and every abrupt end must fall inside a fault window
    declared by the harness. `recovery_report()` replaces the base login and Logout coverage
    checks; a scenario fails on any violation it lists.
    """

    GRACE_NS = 90 * SECOND
    # TCP connections accepted per scenario (a budget, unlike the forwarder's concurrent
    # bounds). Each costs a few KiB here and a row in wire.json. See R10_CONNECTIONS_PER_MINUTE.
    MAXIMUM_CONNECTIONS = 4096
    EVENT_LIMIT = 20000  # The most recent events are kept; older ones are counted.
    VIOLATION_LIMIT = 256  # Any violation fails the scenario; the rest are counted.

    def __init__(self, expected_digests):
        super().__init__()
        # The base proxy appends TARGET_CONNECTION_FAILED while it holds self.lock, and
        # _ErrorList records it through note_target_connect_failure(), which takes the lock
        # again. A plain Lock self-deadlocked the accept thread on the first refused target
        # connection (R4-staged, first run), so every later reconnect hung in the proxy.
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.errors = _ErrorList(self)
        self.maximum_connections = self.MAXIMUM_CONNECTIONS
        self.expected_digests = expected_digests
        self.faults = []
        self.events = collections.deque(maxlen=self.EVENT_LIMIT)
        self.events_dropped = 0
        self.infos = []
        self.violations = []
        self.violations_dropped = 0
        self.normal_isid = None
        self.normal_logins = []
        self.login_rejections = []
        self.connect_failures = []
        # Per WRITE, only what the redo check needs: records stay in their connection's
        # info["unsynced"] until a GOOD flush covers them; a covered WRITE leaves only its
        # (connection, sentNS) point here, per (lba, blocks), and only while no other covered
        # WRITE of that range is both on a later connection and sent later. The full log
        # this replaces stopped at 400000 WRITEs, about 100 minutes into a soak.
        self.synced_ranges = {}
        self.no_mutation_after = None
        self.closing = False
        # Transport stalls (R13): the armed one, every one armed (plain data, reported), and
        # the (initiator, target) sockets of each stalled connection for release_stall().
        self.stall_plan = None
        self.stalls = []
        self.stall_streams = {}
        # How a held `dataout` stall sees the initiator's end of its connection (replaceable).
        self.socket_probe = initiator_socket
        # Mutual CHAP (expect_mutual_chap): the scenario's pair, in memory only, and whether
        # every Normal login must carry the mutual exchange.
        self._credentials = None
        self.mutual_expected = False

    # Mutual CHAP

    def expect_mutual_chap(self, credentials):
        """From now on each new connection's login state checks both CHAP proofs (initiator and
        target) against `credentials` (username, password, targetUsername, targetPassword),
        which stays in memory only, and every Normal login that completes must have carried
        the mutual exchange. Call it after the harness's own discovery, which is anonymous: a
        login checked this way must use CHAP."""
        with self.lock:
            self._credentials = dict(credentials)
            self.mutual_expected = True

    def change_target_secret(self, secret):
        """The target's mutual secret from now on (R4-mutual), so that a proof the target makes
        with it verifies here: then a login that ends after it was ended by the initiator."""
        with self.lock:
            self._credentials = dict(self._credentials, targetPassword=secret)

    def forget_credentials(self):
        with self.lock:
            self._credentials = None

    def _login_credentials(self, session_type):
        # LoginAudit calls this while it holds its own lock: read the reference only, never
        # self.lock (mutual_report takes self.lock and then a login state's lock).
        credentials = self._credentials
        if credentials is None:
            raise login_audit.AuditError("OBSERVER_FAILED")
        return credentials

    def mutual_report(self):
        """Per Normal login attempt (a connection that sent a Normal login request), whether it
        carried the mutual exchange: plain booleans and times, never CHAP values.

        `mutual` is True when the initiator's challenge (CHAP_I, CHAP_C) went to the target and
        both proofs (CHAP_N, CHAP_R) verified; `complete` when the login reached full feature
        phase. `refusedAfterTargetProof` lists attempts whose initiator ended its side,
        unrejected and incomplete, after the target's proof verified (or a fault cut them then).
        """
        with self.lock:
            states = [(info, info.get("loginAudit")) for info in self.infos]
            expected = self.mutual_expected
        rows = []
        for info, state in states:
            if state is None:
                continue
            summary = state.summary()  # Outside self.lock: it takes the state's own lock.
            if summary["sessionType"] != "Normal":
                continue
            ends = info["ends"]
            rows.append(dict(
                connection=info["id"], openedNS=info["openedNS"], closedNS=info["closedNS"],
                initiatorEndNS=ends["toTarget"]["ns"] if "toTarget" in ends else None,
                readyNS=info["readyNS"], checked=state.provider is not None,
                initiatorChallenge=summary["initiatorChallengeBytes"] is not None,
                initiatorProof=summary["initiatorProofVerified"],
                targetProof=summary["targetProofVerified"],
                mutual=summary["mutualProofsVerified"], complete=bool(info["ready"]),
                rejected=info["rejected"] is not None,
                observationFailed=info["observationFailed"]))
        completed = [row for row in rows if row["complete"]]
        refused = [row for row in rows if row["targetProof"] and not row["complete"]
                   and not row["rejected"] and row["initiatorEndNS"] is not None]
        return dict(expected=expected, attempts=len(rows), logins=len(completed),
                    mutualLogins=sum(row["mutual"] for row in completed),
                    loginsWithoutMutual=sum(not row["mutual"] for row in completed),
                    refusedAfterTargetProof=[row["connection"] for row in refused],
                    rows=rows[-256:])

    def connections_opened_since(self, ns):
        """Connections the initiator opened at or after `ns`, whatever they sent."""
        with self.lock:
            return [info["id"] for info in self.infos if info["openedNS"] >= ns]

    # Harness declarations

    def fault_start(self, kind, start_ns, **detail):
        with self.lock:
            fault = dict(kind=kind, startNS=start_ns, endNS=None, **detail)
            self.faults.append(fault)
            self._event("fault-start", fault=kind)
            return fault

    def fault_end(self, fault, end_ns, **detail):
        with self.lock:
            fault["endNS"] = end_ns
            fault.update(detail)
            self._event("fault-end", fault=fault["kind"])

    def forbid_mutation_after(self, ns, reason):
        with self.lock:
            if self.no_mutation_after is None or ns < self.no_mutation_after[0]:
                self.no_mutation_after = (ns, reason)

    def note_target_connect_failure(self):
        with self.lock:
            self.connect_failures.append(time.monotonic_ns())
            self._event("target-connect-failed")

    def _event(self, event, **detail):
        if len(self.events) == self.events.maxlen:
            self.events_dropped += 1
        self.events.append(dict(ns=time.monotonic_ns(), event=event, **detail))

    def _in_fault(self, start_ns, end_ns):
        for fault in self.faults:
            fault_end = (fault["endNS"] or time.monotonic_ns()) + self.GRACE_NS
            if fault["startNS"] <= end_ns and start_ns <= fault_end:
                return True
        return False

    def _violation(self, code, info=None, **detail):
        if len(self.violations) < self.VIOLATION_LIMIT:
            self.violations.append(dict(code=code, ns=time.monotonic_ns(),
                                        connection=info["id"] if info else None, **detail))
        else:
            self.violations_dropped += 1

    def _synced(self, write):
        """Keep the Pareto front of (connection, sentNS) of covered WRITEs per range: some
        covered WRITE is on a later connection and sent later than a given one exactly when
        a point of the front is."""
        point = (write["connection"], write["sentNS"])
        front = self.synced_ranges.setdefault((write["lba"], write["blocks"]), [])
        if any(c >= point[0] and s >= point[1] for c, s in front):
            return
        front[:] = [(c, s) for c, s in front if not (point[0] >= c and point[1] >= s)]
        front.append(point)

    def unsynced_writes(self):
        """WRITE records no GOOD flush on their connection has covered, in send order."""
        with self.lock:
            return sorted((write for info in self.infos for write in info["unsynced"]),
                          key=lambda write: (write["sentNS"], write["connection"]))

    # Per-connection model

    def _info(self, connection):
        with self.lock:
            info = connection.get("info")
            if info is None:
                info = dict(id=len(self.infos) + 1, openedNS=time.monotonic_ns(), closedNS=None,
                            ends={}, sessionType=None, isid=None, tsih=None, rejected=None,
                            ready=False, readyNS=None, logoutNS=None, logoutReplied=False,
                            commands={}, nops={}, targetNops={}, writesSent=0, writesGood=0,
                            syncsSent=0, syncsGood=0, readsSent=0, inquiryGood=False,
                            capacityGood=False, preIO=[], firstIONS=None, unsynced=[],
                            observationFailed=None, deviceErrors=[], partialFrame=False,
                            stalled=False)
                connection["info"] = info
                self.infos.append(info)
                for stall in self.stalls:
                    if stall["connection"] is not None and stall["nextConnection"] is None:
                        stall["nextConnection"] = dict(id=info["id"], openedNS=info["openedNS"])
            return info

    def observe(self, header, connection, to_target, body):
        info = connection["info"]
        opcode = header[0] & 0x3F
        now = time.monotonic_ns()
        if opcode in (3, 0x23):
            if opcode == 3 and info["isid"] is None:
                info["isid"] = bytes(header[8:14]).hex()
                info["tsih"] = int.from_bytes(header[14:16], "big")
            if opcode == 0x23 and (header[36] or header[37]):
                with self.lock:
                    rejection = dict(ns=now, connection=info["id"], statusClass=header[36],
                                     statusDetail=header[37],
                                     responseISID=bytes(header[8:14]).hex())
                    info["rejected"] = rejection
                    if len(self.login_rejections) < 1024:
                        self.login_rejections.append(rejection)
                    self._event("login-rejected", connection=info["id"],
                                status="%02x%02x" % (header[36], header[37]))
                return
            if "loginAudit" not in connection:
                with self.lock:
                    # Unreachable while the proxy's connection budget (a harness error) is
                    # the same number: every login state belongs to an accepted connection.
                    if len(self.login_states) >= self.maximum_connections:
                        raise login_audit.AuditError("LOGIN_CONNECTION_LIMIT")
                    # With mutual CHAP expected the state checks both proofs (and CHAP itself).
                    provider = self._login_credentials if self._credentials is not None else None
                    connection["loginAudit"] = login_audit.LoginAudit(provider, info["id"])
                    info["loginAudit"] = connection["loginAudit"]
                    self.login_states.append(connection["loginAudit"])
            state = connection["loginAudit"]
            finalized = state.observe(header, to_target, body)
            summary = state.summary()
            connection["normal"] = summary["sessionType"] == "Normal"
            connection["header"] = summary["headerDigest"] == "CRC32C"
            connection["data"] = summary["dataDigest"] == "CRC32C"
            connection["ready"] = state.ready
            info["sessionType"] = summary["sessionType"]
            if finalized:
                with self.lock:
                    info["ready"] = True
                    info["readyNS"] = now
                    if connection["normal"]:
                        self.normal_digests.append((connection["header"], connection["data"]))
                        if (connection["header"], connection["data"]) != self.expected_digests:
                            self._violation("DIGEST_POLICY", info)
                        if self.normal_isid is None:
                            self.normal_isid = info["isid"]
                        elif info["isid"] != self.normal_isid:
                            self._violation("ISID_CHANGED", info, isid=info["isid"])
                        if info["tsih"] != 0:
                            self._violation("LOGIN_NOT_REINSTATEMENT", info, tsih=info["tsih"])
                        if self.mutual_expected and not summary["mutualProofsVerified"]:
                            self._violation("LOGIN_WITHOUT_MUTUAL_CHAP", info)
                        self.normal_logins.append(dict(ns=now, connection=info["id"]))
                    self._event("login", connection=info["id"], sessionType=info["sessionType"])
            return
        if not connection["ready"]:
            raise login_audit.AuditError("FRAME_BEFORE_LOGIN")
        tag = bytes(header[16:20])
        transfer_tag = bytes(header[20:24])
        with self.lock:
            if to_target and opcode == 0 and tag != b"\xff" * 4:
                if len(body) > 64 or tag in info["nops"] or len(info["nops"]) >= 4:
                    raise login_audit.AuditError("OBSERVER_FAILED")
                info["nops"][tag] = bytes(body)
                self.nop_out += 1
            elif to_target and opcode == 0:
                if info["targetNops"].pop(transfer_tag, None) != bytes(header[8:16]) or body:
                    raise login_audit.AuditError("OBSERVER_FAILED")
                self.target_nop_out += 1
            elif not to_target and opcode == 0x20 and tag != b"\xff" * 4:
                if info["nops"].pop(tag, None) != body:
                    raise login_audit.AuditError("OBSERVER_FAILED")
                self.nop_replies += 1
            elif not to_target and opcode == 0x20 and transfer_tag != b"\xff" * 4:
                if body or len(info["targetNops"]) >= 4:
                    raise login_audit.AuditError("OBSERVER_FAILED")
                info["targetNops"][transfer_tag] = bytes(header[8:16])
                self.target_nop_in += 1
            elif to_target and opcode == 6:
                if info["logoutNS"] is not None:
                    raise login_audit.AuditError("LOGOUT_REQUEST")
                info["logoutNS"] = now
                self.logouts += 1
                self._event("logout", connection=info["id"])
            elif not to_target and opcode == 0x26:
                if info["logoutNS"] is None or info["logoutReplied"] or header[2] != 0 or body:
                    raise login_audit.AuditError("LOGOUT_RESPONSE")
                info["logoutReplied"] = True
                self.logout_replies += 1
            elif to_target and opcode == 1:
                self._command(info, header, tag, now)
            elif not to_target and (opcode == 0x21 or (opcode == 0x25 and header[1] & 1)):
                self._response(info, opcode, header, body, tag, now)
            elif not to_target and opcode == 0x32:
                self._event("async-message", connection=info["id"], event=header[36])
            elif not to_target and opcode == 0x3F:
                self._event("reject", connection=info["id"], reason=header[2])

    def _command(self, info, header, tag, now):
        cdb = bytes(header[32:48])
        command = cdb[0]
        if tag in info["commands"] or len(info["commands"]) >= 256:
            raise login_audit.AuditError("OBSERVER_FAILED")
        record = dict(opcode=command, sentNS=now, connection=info["id"], status=None)
        if command in (0x28, 0x2A, 0x88, 0x8A):
            wide = command in (0x88, 0x8A)
            record["lba"] = int.from_bytes(cdb[2:10] if wide else cdb[2:6], "big")
            record["blocks"] = int.from_bytes(cdb[10:14] if wide else cdb[7:9], "big")
        if command == 0x12:
            record["evpd"] = cdb[1] & 1
        if command == 0x9E:
            record["serviceAction"] = cdb[1] & 31
        info["commands"][tag] = record
        for index, stall in enumerate(self.stalls):
            cut = stall["command"]
            if (stall["redo"] is None and cut is not None and info["id"] > stall["connection"]
                    and command == cut["opcode"] and record.get("lba") == cut["lba"]
                    and record.get("blocks") == cut["blocks"]):
                # The command whose PDU was cut, sent again on a later connection.
                stall["redo"] = dict(connection=info["id"], sentNS=now, status=None,
                                     responseNS=None)
                record["stallRedo"] = index
        if command in IO_OPCODES and info["firstIONS"] is None:
            info["firstIONS"] = now
            if not (info["inquiryGood"] and info["capacityGood"]):
                self._violation("IO_BEFORE_REVALIDATION", info, opcode=command,
                                preIO=list(info["preIO"]))
        elif command not in IO_OPCODES and info["firstIONS"] is None and len(info["preIO"]) < 32:
            info["preIO"].append(command)
        if command in WRITE_OPCODES + SYNC_OPCODES and self.no_mutation_after is not None \
                and now > self.no_mutation_after[0]:
            self._violation("MUTATION_AFTER_LATCH", info, opcode=command,
                            reason=self.no_mutation_after[1])
        if command in WRITE_OPCODES:
            info["writesSent"] += 1
            self.writes += 1
            self.write_bytes += int.from_bytes(header[20:24], "big")
            record["synced"] = False
            info["unsynced"].append(record)
        elif command in SYNC_OPCODES:
            info["syncsSent"] += 1
            if info["writesGood"] != info["writesSent"]:
                self._violation("FLUSH_BEFORE_WRITE_COMPLETION", info,
                                writesSent=info["writesSent"], writesGood=info["writesGood"])
            record["coversWrites"] = info["writesSent"]
        elif command in (0x28, 0x88):
            info["readsSent"] += 1
            self.reads += 1
            self.read_bytes += int.from_bytes(header[20:24], "big")

    def _response(self, info, opcode, header, body, tag, now):
        record = info["commands"].pop(tag, None)
        if record is None:
            return
        good = header[2] == 0 and header[3] == 0
        record["status"] = "good" if good else "error"
        record["responseNS"] = now
        if "stallRedo" in record:
            self.stalls[record["stallRedo"]]["redo"].update(status=record["status"],
                                                            responseNS=now)
        command = record["opcode"]
        if good:
            if command in WRITE_OPCODES:
                info["writesGood"] += 1
                self.acknowledged_writes += 1
            elif command in SYNC_OPCODES:
                info["syncsGood"] += 1
                self.flushes += 1
                remaining = []
                for write in info["unsynced"]:
                    if write["status"] == "good" and write["sentNS"] < record["sentNS"]:
                        write["synced"] = True
                        write["syncedNS"] = now
                        self._synced(write)
                    else:
                        remaining.append(write)
                info["unsynced"] = remaining
            elif command == 0x12 and not record.get("evpd"):
                info["inquiryGood"] = True
            elif command == 0x25 or (command == 0x9E and record.get("serviceAction") == 0x10):
                info["capacityGood"] = True
        else:
            error = dict(ns=now, opcode=command, response=header[2], status=header[3])
            if opcode == 0x21 and header[3] == 2 and len(body) >= 2:
                length = int.from_bytes(body[:2], "big")
                sense = body[2:2 + length]
                if len(sense) >= 14 and sense[0] & 0x7F in (0x70, 0x71):
                    error.update(senseKey=sense[2] & 15, asc=sense[12], ascq=sense[13])
                elif len(sense) >= 4 and sense[0] & 0x7F in (0x72, 0x73):
                    error.update(senseKey=sense[1] & 15, asc=sense[2], ascq=sense[3])
            if len(info["deviceErrors"]) < 64:
                info["deviceErrors"].append(error)
            if len(self.device_errors) < 256:
                self.device_errors.append(dict(connection=info["id"], **error))
            self._event("device-error", connection=info["id"], opcode=command,
                        status=header[3], senseKey=error.get("senseKey"),
                        asc=error.get("asc"), ascq=error.get("ascq"))

    def forward(self, source, destination, connection, to_target):
        info = self._info(connection)
        direction = "toTarget" if to_target else "toInitiator"
        pending = bytearray()
        end = "eof"
        try:
            while True:
                if connection.get("stall") is not None:
                    if to_target and connection["stall"]["kind"] == "dataout":
                        end = self._hold(source, connection, len(pending))
                    else:
                        end = self._discard(source, connection, to_target, len(pending))
                    pending.clear()
                    break
                if info["observationFailed"] and pending:
                    destination.sendall(pending)
                    pending.clear()
                if not select.select([source], [], [], .1)[0]:
                    continue
                data = source.recv(self._read_size(connection, pending, to_target))
                if not data:
                    if connection.get("stall") is not None:
                        end = self._discard(source, connection, to_target, len(pending))
                        pending.clear()
                    break
                pending.extend(data)
                if connection.get("stall") is not None:
                    continue
                if info["observationFailed"]:
                    destination.sendall(pending)
                    pending.clear()
                    continue
                while len(pending) >= 48:
                    if to_target and "dataoutWatch" in connection:
                        cut = self._dataout_cut(pending, connection, info)
                        if cut == 0:
                            break  # The bytes up to the cut have not all arrived.
                        if cut is not None:
                            # The target never receives the cut frame whole: not observed.
                            destination.sendall(pending[:cut])
                            self._stall_started(connection["stall"], destination, source)
                            del pending[:cut]
                            break
                    cut = None
                    try:
                        policy = (connection["ready"], connection["header"], connection["data"])
                        size = login_audit.frame_layout(pending, *policy)[3]
                        if len(pending) < size:
                            break
                        body, checked_header, checked_data = login_audit.validate_frame(
                            pending[:size], *policy, crc32c)
                        if "loginAudit" in connection:
                            connection["loginAudit"].checked_digests(checked_header, checked_data)
                        with self.lock:
                            self.digest_checks["header"] += int(checked_header)
                            self.digest_checks["data"] += int(checked_data)
                        if connection.get("stall") is not None:
                            break  # The other direction stalled this connection.
                        if self.stall_plan is not None and not to_target:
                            cut = self._stall_cut(pending[:48], connection, info, size, body)
                        if cut is None:
                            # The initiator never receives a cut frame whole: not observed.
                            self.observe(pending[:48], connection, to_target, body)
                    except Exception as error:
                        code = error.args[0] if (type(error) is login_audit.AuditError
                                                 and error.args) else type(error).__name__
                        with self.lock:
                            info["observationFailed"] = code
                            self._violation("OBSERVATION_FAILED", info, detail=str(code),
                                            direction=direction)
                        destination.sendall(pending)
                        pending.clear()
                        break
                    if cut is not None:
                        destination.sendall(pending[:cut])
                        self._stall_started(connection["stall"], source, destination)
                        del pending[:cut]
                        break
                    if connection.get("stall") is not None:
                        break
                    destination.sendall(pending[:size])
                    del pending[:size]
            if pending:
                with self.lock:
                    info["partialFrame"] = True
                destination.sendall(pending)
                pending.clear()
        except OSError as error:
            end = "oserror:" + (error.strerror or type(error).__name__)
        finally:
            with self.lock:
                info["ends"][direction] = dict(ns=time.monotonic_ns(), how=end,
                                               closing=self.closing)
                if len(info["ends"]) == 2:
                    info["closedNS"] = max(value["ns"] for value in info["ends"].values())
                stall = connection.get("stall")
                side = "initiatorEnd" if to_target else "targetEnd"
                if stall is not None and stall[side] is None:
                    stall[side] = dict(ns=info["ends"][direction]["ns"], how=end,
                                       afterRelease=stall["released"] is not None)
            if "loginAudit" in connection:
                connection["loginAudit"].close()
            # A stalled connection never passes the target's end on: only the initiator's own
            # deadline may end its side. The initiator's end still reaches the target.
            if to_target or connection.get("stall") is None:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

    # Transport stalls (R13)

    STALL_KINDS = ("datain", "response", "dataout")
    # `dataout` cuts only a burst of this many bytes or more (the product's MaxBurstLength), so
    # that what the initiator still has to send exceeds what the clamped buffers hold.
    DATAOUT_MINIMUM_BURST = 262144
    # The cut forwards at most this much of the Data-Out's data (half of a shorter segment).
    # LIO took the whole 256 KiB burst as one Data-Out; cut at half (20261116-185051), the
    # rest (131,076 B) fit the buffers and the send completed.
    DATAOUT_CUT_DATA = 4096
    HOLD_POLL_SECONDS = 0.05  # How often a held stall reads the kernel's receive queue.
    HOLD_PROBE_SECONDS = 0.15  # How often it lists the initiator's socket (lsof takes ~60 ms).
    HOLD_SAMPLES = 64  # Changes kept of each series a held stall records.
    DRAIN_KEEP = 4 * 1048576  # Bytes drained after the initiator's close that are parsed.
    DRAIN_SECONDS = 30

    def arm_stall(self, kind):
        """Cut the next matching PDU on a ready Normal connection, then stall there.

        `datain`: a Data-In of a READ, after its header (and header digest) and half of its
        data segment. `response`: the SCSI Response of a WRITE, in the middle of its 48-byte
        header. Either leaves the initiator inside a PDU. From the cut on, nothing more is
        forwarded on that connection in either direction: both relays keep reading and drop
        what they read, and the target's end of the connection is never passed on, so only
        the initiator can end its side. The initiator's end is passed on to the target.

        `dataout`: the initiator's first Data-Out for an R2T that solicits at least
        DATAOUT_MINIMUM_BURST bytes of a WRITE, after its header (and header digest) and
        DATAOUT_CUT_DATA bytes of its data (half of a shorter data segment), sent on to the
        target. From the R2T on, the initiator's relay
        reads exactly up to the end of each frame or the cut, so it takes in nothing past the
        cut. From the cut on, the initiator's relay reads nothing at all (_hold) until the
        kernel no longer lists the initiator's end of the connection, then drains it; the
        target's relay reads and drops, and the target's end is never passed on.

        Returns the record (plain data), which gains `startNS` once the cut was sent."""
        assert kind in self.STALL_KINDS, kind
        with self.lock:
            assert self.stall_plan is None, "a stall is already armed"
            record = dict(kind=kind, armedNS=time.monotonic_ns(), connection=None,
                          flaggedNS=None, startNS=None, startWall=None, pdu=None,
                          command=None, discarded=dict(toTarget=0, toInitiator=0),
                          initiatorEnd=None, targetEnd=None, nextConnection=None, redo=None,
                          released=None, r2t=None, hold=None)
            self.stall_plan = record
            self.stalls.append(record)
            self._event("stall-armed", kind=kind)
            return record

    def disarm_stall(self):
        """Forget an armed stall that no PDU triggered; True if one was armed."""
        with self.lock:
            armed, self.stall_plan = self.stall_plan is not None, None
            return armed

    def _stall_cut(self, header, connection, info, size, body):
        """Bytes of this target frame to send before its connection stalls, or None."""
        if not (connection["ready"] and connection["normal"]):
            return None
        opcode = header[0] & 0x3F
        with self.lock:
            plan = self.stall_plan
            if plan is None:
                return None
            record = info["commands"].get(bytes(header[16:20]))
            if plan["kind"] == "dataout":
                desired = int.from_bytes(header[44:48], "big")
                if (opcode == 0x31 and record is not None and record["opcode"] in WRITE_OPCODES
                        and desired >= self.DATAOUT_MINIMUM_BURST):
                    # Set before the R2T is forwarded: the initiator's relay reads exactly
                    # from now on, so it can't take in bytes past the cut (_read_size).
                    connection["dataoutWatch"] = dict(
                        plan=plan, tag=bytes(header[16:20]), transferTag=bytes(header[20:24]),
                        offset=int.from_bytes(header[40:44], "big"), length=desired,
                        ns=time.monotonic_ns())
                return None  # The R2T itself is forwarded whole and observed.
            if plan["kind"] == "datain":
                if opcode != 0x25 or record is None or record["opcode"] not in (0x28, 0x88) \
                        or len(body) < 2:
                    return None
                cut = 48 + (4 if connection["header"] else 0) + len(body) // 2
            else:
                if opcode != 0x21 or record is None or record["opcode"] not in WRITE_OPCODES:
                    return None
                cut = 24
            self.stall_plan = None
            plan.update(
                connection=info["id"], flaggedNS=time.monotonic_ns(),
                pdu=dict(opcode=opcode, tag=bytes(header[16:20]).hex(), dataLength=len(body),
                         frameBytes=size, forwardedBytes=cut),
                command=dict(opcode=record["opcode"], lba=record.get("lba"),
                             blocks=record.get("blocks"), sentNS=record["sentNS"]))
            info["stalled"] = True
            # Set before the cut is sent: the other relay stops forwarding at once, so nothing
            # the initiator sends in reaction to the cut can reach the target.
            connection["stall"] = plan
            self._event("stall", connection=info["id"], kind=plan["kind"])
            return cut

    def _stall_started(self, stall, target, initiator):
        with self.lock:
            stall["startNS"] = time.monotonic_ns()
            stall["startWall"] = time.time()
            self.stall_streams[stall["connection"]] = (initiator, target)

    @staticmethod
    def _watched(header, watch):
        """The Data-Out a `dataout` watch cuts: the first one for its R2T."""
        return (header[0] & 0x3F == 5 and bytes(header[16:20]) == watch["tag"]
                and bytes(header[20:24]) == watch["transferTag"]
                and int.from_bytes(header[40:44], "big") == watch["offset"])

    def _read_size(self, connection, pending, to_target):
        """How many bytes a relay may read. While an armed `dataout` stall watches this
        connection, the initiator's relay reads exactly to the end of the current frame, or to
        the cut, so that the bytes past the cut stay in the kernel's socket buffers."""
        watch = connection.get("dataoutWatch") if to_target else None
        if (watch is None or watch["plan"] is not self.stall_plan
                or connection["info"]["observationFailed"]):
            return 65536
        if len(pending) < 48:
            return 48 - len(pending)
        try:
            start, length, _, size, _, _ = login_audit.frame_layout(
                pending, connection["ready"], connection["header"], connection["data"])
        except Exception:
            return 65536  # forward() reports the frame.
        end = start + self._cut_data(length) if self._watched(pending, watch) else size
        return max(1, min(65536, end - len(pending)))

    def _cut_data(self, length):
        """How much of a watched Data-Out's data the cut forwards."""
        return min(length // 2, self.DATAOUT_CUT_DATA)

    def _dataout_cut(self, pending, connection, info):
        """For the watched Data-Out at the front of `pending`: 0 until the bytes up to its cut
        (its header, header digest and _cut_data of its data) have arrived, then the cut, once
        the stall took the connection. None for any other frame, or if the stall was disarmed
        meanwhile (then the frame is forwarded whole)."""
        watch = connection.get("dataoutWatch")
        if watch is None or info["observationFailed"] or not self._watched(pending, watch):
            return None
        try:
            start, length, _, size, _, _ = login_audit.frame_layout(
                pending, connection["ready"], connection["header"], connection["data"])
        except Exception:
            return None  # forward() reports the frame.
        cut = start + self._cut_data(length)
        if len(pending) < cut:
            return 0
        header = bytes(pending[:48])
        with self.lock:
            connection.pop("dataoutWatch", None)
            plan = self.stall_plan
            if plan is not watch["plan"]:
                return None
            self.stall_plan = None
            record = info["commands"].get(watch["tag"])
            plan.update(
                connection=info["id"], flaggedNS=time.monotonic_ns(),
                pdu=dict(opcode=5, tag=watch["tag"].hex(), dataLength=length, frameBytes=size,
                         forwardedBytes=cut, bufferOffset=watch["offset"],
                         dataSN=int.from_bytes(header[36:40], "big"),
                         final=bool(header[1] & 0x80)),
                command=record and dict(opcode=record["opcode"], lba=record.get("lba"),
                                        blocks=record.get("blocks"), sentNS=record["sentNS"]),
                r2t=dict(transferTag=watch["transferTag"].hex(), bufferOffset=watch["offset"],
                         desiredLength=watch["length"], forwardedNS=watch["ns"]))
            info["stalled"] = True
            # Set before the cut is sent: the target's relay stops forwarding at once.
            connection["stall"] = plan
            self._event("stall", connection=info["id"], kind=plan["kind"])
            return cut

    def _hold(self, source, connection, beyond):
        """A `dataout` stall's initiator relay: read nothing, so that the initiator's sends
        fill the kernel's socket buffers and block, until the initiator closes its end.

        Every HOLD_POLL_SECONDS it reads the receive queue the kernel holds for the forwarder
        (FIONREAD, never the bytes), and every HOLD_PROBE_SECONDS it lists the initiator's end
        of the connection (self.socket_probe, lsof). Its close can't be seen on the wire: its
        FIN waits behind the bytes this relay doesn't read. The close is the first listing,
        after one that showed the socket ESTABLISHED, in which it is gone or in another state;
        a socket error or a release ends the hold too. Then it reads what the initiator had
        handed its kernel (at most DRAIN_SECONDS) and records what that was (dataout_handed);
        the bytes themselves are not kept. Returns how this side ended."""
        stall = connection["stall"]
        hold = dict(initiatorPort=None, forwarderPort=None, readBeyondCut=beyond, queued=[],
                    lastGrowthNS=None, maximumQueued=None, samples=[], observed=False,
                    aliveNS=None, closedNS=None, closedHow=None, probeErrors=[],
                    drainedBytes=0, drainEnd=None, handed=None)
        with self.lock:
            stall["hold"] = hold
        try:
            hold["forwarderPort"] = source.getsockname()[1]
            hold["initiatorPort"] = source.getpeername()[1]
        except (OSError, TypeError, IndexError):
            pass  # A socket pair in the tests has no ports.
        probe_due = 0
        while True:
            now = time.monotonic_ns()
            queued = socket_queued(source)
            with self.lock:
                if queued is not None and queued != hold["maximumQueued"]:
                    if len(hold["queued"]) < self.HOLD_SAMPLES:
                        hold["queued"].append(dict(ns=now, bytes=queued))
                    if hold["maximumQueued"] is None or queued > hold["maximumQueued"]:
                        hold["maximumQueued"], hold["lastGrowthNS"] = queued, now
                released = stall["released"] is not None
            if queued is None or released:
                hold["closedHow"] = "released" if released else "socket-closed"
                break
            try:
                error = source.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            except OSError as failure:
                error = failure.errno or errno.EBADF
            if error:
                with self.lock:
                    hold.update(closedNS=now, closedHow="socket-error:"
                                + errno.errorcode.get(error, str(error)))
                break
            if now >= probe_due:
                # The close lies after the start of the last listing that showed the socket
                # (aliveNS) and before the end of the first that didn't (closedNS).
                sample = self.socket_probe(hold["initiatorPort"], hold["forwarderPort"])
                done = time.monotonic_ns()
                probe_due = done + int(self.HOLD_PROBE_SECONDS * SECOND)
                with self.lock:
                    if "error" in sample:
                        if len(hold["probeErrors"]) < self.HOLD_SAMPLES:
                            hold["probeErrors"].append(dict(ns=now, error=sample["error"]))
                        sample = None
                    elif sample.get("state") == "ESTABLISHED":
                        hold.update(observed=True, aliveNS=now)
                    elif hold["observed"]:
                        hold.update(closedNS=done, closedHow=(
                            f"state:{sample.get('state')}" if sample.get("seen") else "gone"))
                    if sample is not None and len(hold["samples"]) < self.HOLD_SAMPLES and (
                            not hold["samples"] or any(
                                hold["samples"][-1].get(key) != sample.get(key)
                                for key in ("seen", "state", "sendQueue", "receiveQueue"))):
                        hold["samples"].append(dict(ns=now, **sample))
                    if hold["closedNS"] is not None:
                        break
            time.sleep(self.HOLD_POLL_SECONDS)
        kept, total, end = bytearray(), 0, "eof"
        limit = time.monotonic() + self.DRAIN_SECONDS
        try:
            while True:
                if time.monotonic() >= limit:
                    end = "drain-timeout"
                    break
                if not select.select([source], [], [], .1)[0]:
                    continue
                data = source.recv(65536)
                if not data:
                    break
                total += len(data)
                kept.extend(data[:max(0, self.DRAIN_KEEP - len(kept))])
        except (OSError, ValueError) as error:
            end = "oserror:" + (getattr(error, "strerror", None) or type(error).__name__)
        handed = dataout_handed(bytes(kept), stall["pdu"],
                                (connection["header"], connection["data"]))
        with self.lock:
            hold.update(drainedBytes=total, drainEnd=end, handed=handed)
            stall["discarded"]["toTarget"] += beyond + total
        return end  # forward() records the end, for the stall too.

    def _discard(self, source, connection, to_target, dropped):
        """A stalled connection's relay: read and drop until this side ends. Returns how."""
        stall = connection["stall"]
        end = "eof"
        try:
            while True:
                if not select.select([source], [], [], .1)[0]:
                    continue
                data = source.recv(65536)
                if not data:
                    break
                dropped += len(data)
        except (OSError, ValueError) as error:
            end = "oserror:" + (getattr(error, "strerror", None) or type(error).__name__)
        with self.lock:
            stall["discarded"]["toTarget" if to_target else "toInitiator"] += dropped
        return end  # forward() records the end, for the stall too.

    def release_stall(self, reason):
        """End a stall its initiator did not end: shut both sockets of the connection down.

        The scenario's escape hatch, so that a product that never gives up does not hold the
        cleanup for the recovery window. Ends recorded afterwards say so (afterRelease)."""
        with self.lock:
            stall = next((s for s in reversed(self.stalls) if s["startNS"] is not None), None)
            if stall is None or stall["released"] is not None:
                return False
            stall["released"] = dict(ns=time.monotonic_ns(), reason=reason)
            streams = self.stall_streams.get(stall["connection"], ())
        for stream in streams:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        return True

    # The base proxy calls these after closing every connection. Recovery coverage is judged
    # by recovery_report(), which each scenario must pass.
    def validate_logins(self, require_sessions=False):
        pass

    def validate_logouts(self):
        pass

    def recovery_report(self, *, latched=False):
        mutual = self.mutual_report()
        with self.lock:
            violations = list(self.violations)
            connections = []
            now = time.monotonic_ns()
            for info in self.infos:
                closed = info["closedNS"] or now
                abrupt = []
                if not info["ready"] and info["rejected"] is None:
                    abrupt.append("incomplete-login")
                if info["ready"] and not info["logoutReplied"]:
                    abrupt.append("no-logout")
                if info["partialFrame"]:
                    abrupt.append("partial-frame")
                if info["stalled"]:
                    abrupt.append("stalled")
                for direction, value in info["ends"].items():
                    if value["how"] != "eof" and not value["closing"]:
                        abrupt.append(direction + "-" + value["how"])
                explained = self._in_fault(info["openedNS"], closed)
                if abrupt and not explained:
                    violations.append(dict(code="UNEXPLAINED_ABRUPT_END", connection=info["id"],
                                           abrupt=abrupt))
                if info["rejected"] is not None and not self._in_fault(info["openedNS"], closed):
                    violations.append(dict(code="UNEXPLAINED_LOGIN_REJECTION",
                                           connection=info["id"], rejected=info["rejected"]))
                connections.append(dict(
                    id=info["id"], sessionType=info["sessionType"], openedNS=info["openedNS"],
                    closedNS=info["closedNS"], readyNS=info["readyNS"], isid=info["isid"],
                    rejected=info["rejected"], logoutReplied=info["logoutReplied"],
                    writesSent=info["writesSent"], writesGood=info["writesGood"],
                    syncsSent=info["syncsSent"], syncsGood=info["syncsGood"],
                    readsSent=info["readsSent"], preIO=["%02x" % value for value in info["preIO"]],
                    firstIONS=info["firstIONS"], abrupt=abrupt, explained=explained,
                    observationFailed=info["observationFailed"],
                    deviceErrors=info["deviceErrors"][:8], ends=info["ends"]))
            for failure in self.connect_failures:
                if not self._in_fault(failure, failure):
                    violations.append(dict(code="UNEXPLAINED_TARGET_CONNECT_FAILURE", ns=failure))
            # Writes that reached a connection that then died without a GOOD flush covering
            # them must be sent again, with the same range, on a later connection and flushed
            # there, unless the disk latched (then nothing may be sent again).
            unsynced = self.unsynced_writes()
            redone, not_redone = 0, []
            for write in unsynced:
                later = any(c > write["connection"] and s > write["sentNS"]
                            for c, s in self.synced_ranges.get((write["lba"], write["blocks"]), ()))
                if later:
                    redone += 1
                elif len(not_redone) < 64:
                    not_redone.append(dict(connection=write["connection"], lba=write["lba"],
                                           blocks=write["blocks"], status=write["status"],
                                           sentNS=write["sentNS"]))
            if not_redone and not latched:
                violations.append(dict(code="INTERRUPTED_WRITE_NOT_REDONE", count=len(not_redone),
                                       examples=not_redone[:8]))
            normal = [c for c in connections if c["sessionType"] == "Normal" and c["readyNS"]]
            return dict(
                violations=violations, connections=connections, faults=list(self.faults),
                normalLogins=len(normal), reconnects=max(0, len(normal) - 1),
                loginRejections=list(self.login_rejections),
                loginStatuses=sorted({"%02x%02x" % (r["statusClass"], r["statusDetail"])
                                      for r in self.login_rejections}),
                targetConnectFailures=len(self.connect_failures),
                unsyncedWrites=len(unsynced), redoneWrites=redone, notRedone=not_redone,
                writes=self.writes, flushes=self.flushes, reads=self.reads,
                writeBytes=self.write_bytes, readBytes=self.read_bytes,
                deviceErrors=self.device_errors[:64], digestChecks=dict(self.digest_checks),
                nopOut=self.nop_out, nopReplies=self.nop_replies, logouts=self.logouts,
                logoutReplies=self.logout_replies, violationsDropped=self.violations_dropped,
                harnessErrors=list(self.harness_errors), eventsDropped=self.events_dropped,
                noMutationAfter=self.no_mutation_after, stalls=[dict(s) for s in self.stalls],
                mutualCHAP=mutual, events=list(self.events)[-2000:])


# MARK: Probe


class HarnessError(Exception):
    """The harness itself failed (for example a forwarder bound tripped), not the product.

    It stops the scenario body at once; what happens afterwards is not product evidence."""

    def __init__(self, row):
        self.row = row
        super().__init__(" ".join(str(row.get(key)) for key in ("code", "limit", "wallTime")
                                  if row.get(key) is not None))


class ProbeSession:
    """The interactive probe: JSON commands on stdin, RECOVERY_* events on stdout."""

    LOUD = ("STATE", "STATE_SLOW", "IO_ERROR", "IO_SLOW", "COORDINATOR", "READY", "ABANDONED",
            "EJECT_STARTED", "EJECT_FINISHED", "INVALID_EVENT")
    EVENT_LIMIT = 200000

    def __init__(self, arguments, log_path):
        self.arguments = list(map(str, arguments))
        self.log = open(log_path, "w")
        self.condition = threading.Condition()
        self.results = {}
        self.events = []
        self.states = []
        self.ready = None
        self.eof = False
        self.next_id = 1
        # Harness errors stop the scenario body's waits while `abortable`; the harness clears
        # it before its own cleanup (stop, eject, exit), which must still be able to wait.
        self.harness_errors = []
        self.abortable = True
        self.exit_result = None
        print("RUN:", " ".join(self.arguments), flush=True)
        self.process = subprocess.Popen(self.arguments, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        for raw in iter(self.process.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            stamp = time.monotonic_ns()
            self.log.write(f"{stamp} {line}\n")
            self.log.flush()
            if line.startswith("RECOVERY_"):
                kind, _, payload = line.partition(" ")
                kind = kind[len("RECOVERY_"):]
                try:
                    value = json.loads(payload) if payload else {}
                except json.JSONDecodeError:
                    value = dict(raw=payload)
                with self.condition:
                    if kind == "RESULT":
                        self.results[value.get("id")] = value
                    elif kind == "READY":
                        self.ready = value
                    elif kind == "STATE":
                        self.states.append((value["uptimeNS"], value["state"]))
                    if len(self.events) < self.EVENT_LIMIT:
                        self.events.append((kind, value))
                    elif not any(row["code"] == "PROBE_EVENT_LIMIT" for row in self.harness_errors):
                        # A dropped IO_ERROR would let a scenario pass unseen.
                        self.harness_errors.append(dict(
                            code="PROBE_EVENT_LIMIT", limit=self.EVENT_LIMIT,
                            monotonicNS=time.monotonic_ns(),
                            wallTime=time.strftime("%Y-%m-%dT%H:%M:%S%z")))
                        print("HARNESS ERROR:", json.dumps(self.harness_errors[-1]), flush=True)
                    self.condition.notify_all()
                if kind in self.LOUD:
                    print(f"PROBE {kind} {payload[:400]}", flush=True)
            else:
                print("PROBE:", line[:2000], flush=True)
        with self.condition:
            self.eof = True
            self.condition.notify_all()

    def on_harness_error(self, row):
        """A WireAudit harness listener: stop the scenario body's waits."""
        with self.condition:
            self.harness_errors.append(row)
            self.condition.notify_all()

    def _aborting(self):
        # Caller holds self.condition.
        return self.harness_errors[0] if self.abortable and self.harness_errors else None

    def _raise_if_aborting(self):
        # Caller holds self.condition.
        row = self._aborting()
        if row is not None:
            raise HarnessError(row)

    def sleep(self, seconds):
        """Like time.sleep, but a harness error ends it at once with HarnessError."""
        deadline = time.monotonic() + seconds
        with self.condition:
            while True:
                self._raise_if_aborting()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                self.condition.wait(remaining)

    def wait_ready(self, timeout=240):
        with self.condition:
            ready = self.condition.wait_for(
                lambda: self.ready is not None or self.eof or self._aborting(), timeout)
            self._raise_if_aborting()
            if not ready:
                raise TimeoutError("Probe did not become ready")
            if self.ready is None:
                raise RuntimeError("Probe exited before it was ready")
            return self.ready

    def supply_secrets(self, credentials):
        """The probe's first stdin line in a `-mutual-chap` mode, before any command: the mutual
        CHAP pair as JSON (RecoveryProbe.suppliedSecrets). Nothing of it is printed or logged."""
        with self.condition:
            assert self.next_id == 1, "the secrets must come before any command"
        line = json.dumps(dict(password=credentials["password"],
                               targetPassword=credentials["targetPassword"])) + "\n"
        self.process.stdin.write(line.encode())
        self.process.stdin.flush()

    def send(self, cmd, **fields):
        with self.condition:
            identifier = self.next_id
            self.next_id += 1
        line = json.dumps(dict(id=identifier, cmd=cmd, **fields)) + "\n"
        self.process.stdin.write(line.encode())
        self.process.stdin.flush()
        return identifier

    def wait(self, identifier, timeout):
        with self.condition:
            done = self.condition.wait_for(
                lambda: identifier in self.results or self.eof or self._aborting(), timeout)
            self._raise_if_aborting()
            if identifier in self.results:
                return self.results.pop(identifier)
            if not done:
                raise TimeoutError(f"Probe command {identifier} did not finish in {timeout}s")
            raise RuntimeError("Probe exited before answering")

    def poll(self, identifier):
        with self.condition:
            return self.results.pop(identifier, None)

    def command(self, cmd, timeout=120, **fields):
        return self.wait(self.send(cmd, **fields), timeout)

    def state(self):
        with self.condition:
            return self.states[-1][1] if self.states else None

    def wait_state(self, wanted, since_ns, timeout):
        """First state event in `wanted` at or after since_ns; also the current state."""
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                self._raise_if_aborting()
                for stamp, value in self.states:
                    if stamp >= since_ns and value in wanted:
                        return stamp, value
                if self.states and self.states[-1][1] in wanted and self.states[-1][0] < since_ns:
                    return since_ns, self.states[-1][1]
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.eof:
                    return None
                self.condition.wait(min(remaining, 1))

    def events_of(self, kind, since_ns=0):
        with self.condition:
            return [value for name, value in self.events
                    if name == kind and value.get("uptimeNS", 0) >= since_ns]

    def close(self, timeout=60):
        with self.condition:
            self.abortable = False  # Closing is cleanup; it must still wait for the probe.
        try:
            if self.process.poll() is None and not self.eof:
                result = self.command("exit", timeout=timeout)
                self.exit_result = result
                print("PROBE exit:", json.dumps(result), flush=True)
            self.process.wait(timeout=timeout)
        finally:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
            self.thread.join(timeout=10)
            self.log.close()
        return self.process.returncode


# MARK: Faults


class Faults:
    """Fault injection inside the disposable guest (sudo inside the VM only)."""

    def __init__(self, vm, nonce, audit, record):
        self.vm = vm
        self.nonce = nonce
        self.audit = audit
        self.record = record
        self.active = None

    def sudo(self, script, timeout=60):
        return self.vm.shell("sudo", "sh", "-c", script, capture_output=True, text=True,
                             timeout=timeout)

    def blackhole(self):
        assert self.active is None
        before = time.monotonic_ns()
        fault = self.audit.fault_start("blackhole", before)
        self.sudo("iptables -N ISCSI_FAULT 2>/dev/null; "
                  "iptables -C INPUT -j ISCSI_FAULT 2>/dev/null || iptables -I INPUT 1 -j ISCSI_FAULT; "
                  "iptables -F ISCSI_FAULT; "
                  "iptables -A ISCSI_FAULT -i lo -p tcp --dport 3260 -j DROP; "
                  "iptables -A ISCSI_FAULT -i lo -p tcp --sport 3260 -j DROP")
        after = time.monotonic_ns()
        fault.update(appliedNS=after)
        self.active = fault
        self.record("blackhole", startNS=before, appliedNS=after)
        return fault

    def heal(self):
        fault = self.active
        assert fault is not None and fault["kind"] == "blackhole"
        before = time.monotonic_ns()
        result = self.sudo(
            "pending=$(ss -Htn state syn-sent '( dport = :3260 )' | wc -l); "
            "ss -K -Htn state syn-sent '( dport = :3260 )' >/dev/null; "
            "iptables -F ISCSI_FAULT; echo $pending")
        after = time.monotonic_ns()
        killed = int(result.stdout.split()[-1]) if result.stdout.split() else -1
        self.audit.fault_end(fault, after, healStartNS=before, abortedPendingDials=killed)
        self.active = None
        self.record("heal", startNS=before, endNS=after, abortedPendingDials=killed,
                    outageSeconds=(after - fault["appliedNS"]) / SECOND)
        return dict(startNS=before, endNS=after, abortedPendingDials=killed,
                    outageNS=after - fault["appliedNS"])

    def reset(self):
        before = time.monotonic_ns()
        fault = self.audit.fault_start("reset", before)
        result = self.sudo("n=$(ss -Htn '( sport = :3260 or dport = :3260 )' | wc -l); "
                           "ss -K -Htn '( sport = :3260 or dport = :3260 )' >/dev/null; echo $n")
        after = time.monotonic_ns()
        killed = int(result.stdout.split()[-1]) if result.stdout.split() else -1
        self.audit.fault_end(fault, after, sockets=killed)
        self.record("reset", startNS=before, endNS=after, sockets=killed)
        return dict(startNS=before, endNS=after, sockets=killed)

    def target_restart(self):
        self.vm.configure("save", self.nonce, "auto", capture_output=True, text=True)
        before = time.monotonic_ns()
        fault = self.audit.fault_start("target-restart", before)
        self.sudo("systemctl restart rtslib-fb-targetctl", timeout=120)
        after = time.monotonic_ns()
        self.audit.fault_end(fault, after)
        self.vm.configure("save", self.nonce, "clear", capture_output=True, text=True)
        status = json.loads(self.vm.configure("status", self.nonce, capture_output=True,
                                              text=True).stdout)
        self.record("target-restart", startNS=before, endNS=after, status=status)
        return dict(startNS=before, endNS=after, status=status)

    def change_target_secret(self, secret):
        """Sets the target's mutual CHAP secret (tests/LIO/configure.py rekey-mutual). The secret
        goes on stdin, never on the command line, and is never printed."""
        before = time.monotonic_ns()
        status = json.loads(self.vm.configure(
            "rekey-mutual", self.nonce, input=json.dumps(dict(targetPassword=secret)) + "\n",
            capture_output=True, text=True).stdout)
        after = time.monotonic_ns()
        self.record("target-secret-changed", startNS=before, endNS=after,
                    sessions=status.get("sessionCount"))
        return dict(startNS=before, endNS=after, status=status)

    def restage(self, stage):
        """One step of a staged configuration restore (tests/LIO/configure.py restage)."""
        before = time.monotonic_ns()
        status = json.loads(self.vm.configure("restage", self.nonce, stage, capture_output=True,
                                              text=True).stdout)
        after = time.monotonic_ns()
        self.record("restage", stage=stage, startNS=before, endNS=after,
                    targets=status["targets"])
        return dict(stage=stage, startNS=before, endNS=after, status=status)

    def boot_id(self, timeout=8):
        try:
            result = subprocess.run(
                ["limactl", "shell", "--workdir=/tmp", self.vm.name, "cat",
                 "/proc/sys/kernel/random/boot_id"],
                capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    def crash(self, root, snapshot_name):
        """sysrq-b: immediate reboot without syncing the guest's page cache (LIO fileio with
        write-back caching keeps acknowledged but unflushed writes there). The configuration is
        restored explicitly after a snapshot of the backing file at the crash point."""
        self.vm.configure("save", self.nonce, "manual", capture_output=True, text=True)
        before_boot = self.boot_id()
        assert before_boot
        self.sudo("echo 1 > /proc/sys/kernel/sysrq")
        crash_ns = time.monotonic_ns()
        fault = self.audit.fault_start("reboot", crash_ns)
        trigger = subprocess.Popen(
            ["limactl", "shell", "--workdir=/tmp", self.vm.name, "sudo", "sh", "-c",
             "echo b > /proc/sysrq-trigger"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            trigger.wait(timeout=5)
        except subprocess.TimeoutExpired:
            trigger.kill()
            trigger.wait(timeout=10)
        deadline = time.monotonic() + 180
        after_boot = None
        while time.monotonic() < deadline:
            after_boot = self.boot_id()
            if after_boot and after_boot != before_boot:
                break
            time.sleep(0.5)
        assert after_boot and after_boot != before_boot, "Guest did not reboot"
        booted_ns = time.monotonic_ns()
        self.vm.shell("mkdir", "-m", "700", "-p", self.vm.staging)
        self.vm.stage_configuration()
        self.record("rebooted", bootedNS=booted_ns, seconds=(booted_ns - crash_ns) / SECOND)
        status = json.loads(self.vm.configure("status", self.nonce, capture_output=True,
                                              text=True).stdout)
        assert not status["targets"], "The crash snapshot requires the export to be absent"
        self.vm.configure("snapshot", self.nonce, timeout=60, capture_output=True, text=True)
        snapshot_ns = time.monotonic_ns()
        self.vm.copy(self.vm.name + ":" + self.vm.staging + "/" + self.nonce + "-snapshot.img",
                     root / snapshot_name)
        self.vm.shell("rm", "--", self.vm.staging + "/" + self.nonce + "-snapshot.img")
        restored = json.loads(self.vm.configure("restore", self.nonce, capture_output=True,
                                                text=True).stdout)
        restored_ns = time.monotonic_ns()
        self.audit.fault_end(fault, restored_ns)
        self.record("reboot", crashNS=crash_ns, bootedNS=booted_ns, snapshotNS=snapshot_ns,
                    restoredNS=restored_ns, bootIDs=[before_boot, after_boot])
        return dict(crashNS=crash_ns, bootedNS=booted_ns, snapshotNS=snapshot_ns,
                    restoredNS=restored_ns, restored=restored, status=status)


# MARK: Host observations


def extension_processes():
    output = subprocess.run(["/bin/ps", "-axo", "pid=,%cpu=,rss=,etime=,comm="],
                            capture_output=True, text=True, timeout=20).stdout
    rows = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) == 5 and parts[4].endswith("ISCSIFSExtension"):
            rows.append(dict(pid=int(parts[0]), cpu=float(parts[1]), rssKiB=int(parts[2]),
                             etime=parts[3]))
    return rows


class Sampler:
    def __init__(self, interval=15):
        self.interval = interval
        self.rows = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        while not self.stop.is_set():
            try:
                self.rows.append(dict(ns=time.monotonic_ns(), processes=extension_processes()))
            except Exception as error:  # Observation only.
                self.rows.append(dict(ns=time.monotonic_ns(), error=str(error)))
            self.stop.wait(self.interval)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(timeout=30)


LOG_PREDICATE = (
    'process == "kernel" AND (eventMessage CONTAINS[c] "apfs" OR eventMessage CONTAINS[c] "disk" '
    'OR eventMessage CONTAINS[c] "fskit" OR eventMessage CONTAINS[c] "I/O") '
    'OR subsystem BEGINSWITH "com.apple.FSKit" OR process == "ISCSIFSExtension" '
    'OR subsystem == "dev.soba.iscsi" OR process CONTAINS "diskimages" '
    'OR subsystem BEGINSWITH "com.apple.DiskImages"')


def guest_epoch(vm_name, runner=subprocess.run):
    """The guest's own clock, so its journal can be cut at the scenario start; None if the
    guest doesn't answer."""
    try:
        result = runner(["limactl", "shell", "--workdir=/tmp", vm_name, "date", "+%s"],
                        capture_output=True, text=True, timeout=30, check=False)
        return int(result.stdout.strip()) if result.returncode == 0 else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


GUEST_LOG_LINES = 20000


def collect_guest_logs(vm_name, since_epoch, destination, runner=subprocess.run):
    """Target-side evidence (read-only): the guest kernel ring buffer, and the kernel and
    target-unit journal since `since_epoch` (guest clock), which keeps LIO's messages after
    the ring buffer wrapped or a guest reboot. Not the full journal: it holds sudo command
    lines. A failure here is recorded, never raised."""
    since = f"@{int(since_epoch)}" if since_epoch is not None else "-6h"
    commands = dict(
        dmesg=("guest-dmesg.txt", ["sudo", "dmesg", "--time-format", "iso"]),
        journal=("guest-journal.txt", [
            "sudo", "journalctl", "--no-pager", "-o", "short-iso-precise", "--since", since,
            "-n", str(GUEST_LOG_LINES), "_TRANSPORT=kernel", "+",
            "_SYSTEMD_UNIT=rtslib-fb-targetctl.service", "+",
            "UNIT=rtslib-fb-targetctl.service"]))
    record = dict(since=since)
    for key, (name, command) in commands.items():
        row = dict(file=name)
        full = ["limactl", "shell", "--workdir=/tmp", vm_name, *command]
        try:
            with open(destination / name, "wb") as output:
                result = runner(full, stdout=output, stderr=subprocess.STDOUT, timeout=60,
                                check=False)
            row["exit"] = result.returncode
        except subprocess.TimeoutExpired:
            row["unavailable"] = "TimeoutExpired"
        except Exception as error:
            row["unavailable"] = f"{type(error).__name__}: {error}"
        record[key] = row
    return record


def merged_harness_errors(audit, session):
    """Harness errors of the forwarder (audit) and the probe reader (session), oldest first."""
    rows, seen = [], set()
    for row in list(getattr(audit, "harness_errors", [])) + list(
            getattr(session, "harness_errors", [])):
        if id(row) not in seen:
            seen.add(id(row))
            rows.append(row)
    return sorted(rows, key=lambda row: row["monotonicNS"])


def collect_logs(start_wall, destination):
    """System log lines for the scenario's interval (read-only). Returns error-like lines."""
    start = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_wall - 5))
    with open(destination, "w") as output:
        try:
            subprocess.run(["/usr/bin/log", "show", "--style", "compact", "--start", start,
                            "--predicate", LOG_PREDICATE], stdout=output,
                           stderr=subprocess.STDOUT, timeout=600)
        except subprocess.TimeoutExpired:
            output.write("log show timed out\n")
    keys = ("i/o error", "eio", "errno 5", "error 5", "error:5", "timed out", "timeout", "failed",
            "failure", "abort", "panic", "not responding", "unresponsive", "busy", "corrupt")
    benign = ("error (null)", "error: (null)", "err=0", "error 0")
    lines = []
    total = 0
    with open(destination, errors="replace") as source:
        for line in source:
            total += 1
            lowered = line.lower()
            if any(key in lowered for key in keys) and not any(key in lowered for key in benign):
                lines.append(line.rstrip()[:400])
    return dict(file=str(destination), lines=total, matching=len(lines), examples=lines[:120])


# MARK: Host sleep and screen lock


SLEEP_MINIMUM_SECONDS = 30  # Time asleep, in all, before a wake counts.
SLEEP_GAP_SECONDS = 2  # Wall time gained over awake time between two polls that is a sleep.
SLEEP_WAIT_MINUTES = 60  # Default --sleep-wait-minutes: for the person to sleep this Mac.
WAKE_UNLOCK_MINUTES = 30  # After the sleep, for a full wake with the screen unlocked.
CLEANUP_UNLOCK_MINUTES = 30  # In cleanup, for an unlocked screen to retry a refused eject.
UNLOCKED_EJECT_ATTEMPTS = 12  # Retries, 5 s apart, once unlocked: the Keychain may lag.
POWER_LOG_RECHECK_SECONDS = 10  # `pmset -g log` takes about 2 s; read it at most this often.
GRAPHICS_CAPABILITY = 0x2  # kIOPMSystemCapabilityGraphics: a maintenance DarkWake lacks it.
POWER_LOG_KINDS = ("Sleep", "DarkWake", "Wake")


def wall_clock(seconds):
    """A wall time for the timeline: local, with its offset."""
    return datetime.datetime.fromtimestamp(seconds).astimezone().isoformat(timespec="seconds")


def short_clock(seconds):
    return time.strftime("%H:%M:%S", time.localtime(seconds))


def _ioreg(arguments, runner):
    return plistlib.loads(runner(["/usr/sbin/ioreg", *arguments, "-a"], capture_output=True,
                                 timeout=10, check=True).stdout)


def host_power_state(runner=subprocess.run):
    """This Mac's wake and console state, read without sudo; a value that can't be read is None.

    `fullWake`: IOPMrootDomain's "System Capabilities" include Graphics. A maintenance DarkWake
    runs without the display: `pmset -g log` shows it as DarkWake [CDNP] and a full wake as
    Wake [CDNVA] (V is the display), and `pmset -g systemstate` lists the same capabilities.
    `locked`: the screen of this user's console session is locked (CGSSessionScreenIsLocked in
    IOConsoleUsers, or IOConsoleLocked), or this user has no session on the console. The data
    protection Keychain refuses the eject's last step while it is (APP043).
    """
    state = dict(capabilities=None, fullWake=None, clamshellClosed=None, locked=None)
    errors = []
    try:
        rows = _ioreg(["-r", "-n", "IOPMrootDomain", "-d1"], runner)
        domain = rows[0] if isinstance(rows, list) else rows
        capabilities = domain.get("System Capabilities")
        if isinstance(capabilities, int):
            state.update(capabilities=capabilities,
                         fullWake=bool(capabilities & GRAPHICS_CAPABILITY))
        state["clamshellClosed"] = domain.get("AppleClamshellState")
    except (OSError, subprocess.SubprocessError, ValueError, LookupError, AttributeError,
            TypeError) as error:
        errors.append(f"IOPMrootDomain: {type(error).__name__}")
    try:
        root = _ioreg(["-n", "Root", "-d1"], runner)
        console = [user for user in root.get("IOConsoleUsers") or []
                   if user.get("kCGSSessionOnConsoleKey")
                   and user.get("kCGSSessionUserIDKey") == os.getuid()]
        state["locked"] = (not console or bool(root.get("IOConsoleLocked"))
                           or any(user.get("CGSSessionScreenIsLocked") for user in console))
    except (OSError, subprocess.SubprocessError, ValueError, LookupError, AttributeError,
            TypeError) as error:
        errors.append(f"Root: {type(error).__name__}")
    if errors:
        state["error"] = "; ".join(errors)
    return state


def power_log(since_wall, runner=subprocess.run):
    """The system's own record of sleeps and wakes from `since_wall` on (`pmset -g log`, no
    sudo), as (wall, kind, text) per Sleep, DarkWake and Wake entry; None if unreadable.

    A full wake, also a DarkWake that became one ("DarkWake to FullWake"), is logged as Wake.
    """
    try:
        output = runner(["/usr/bin/pmset", "-g", "log"], capture_output=True, text=True,
                        errors="replace", timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    rows = []
    for line in output.splitlines():
        head, tab, text = line.partition("\t")
        fields = head.split()
        kind = " ".join(fields[3:])
        if not tab or kind not in POWER_LOG_KINDS:
            continue  # Also "Wake Requests", whose kind spans two words.
        try:
            stamp = datetime.datetime.strptime(" ".join(fields[:3]),
                                               "%Y-%m-%d %H:%M:%S %z").timestamp()
        except ValueError:
            continue
        if stamp >= since_wall - 1:
            rows.append((stamp, kind, " ".join(text.split())[:200]))
    return rows


def wait_for_unlock(deadline, pause, state=host_power_state, wall=time.time, prompt=None):
    """Polls every 2 s until this user's screen is unlocked; the wall time it was seen
    unlocked, or None at `deadline` (wall time)."""
    prompted = False
    while True:
        if state().get("locked") is False:
            return wall()
        if wall() >= deadline:
            return None
        if prompt and not prompted:
            print(prompt, flush=True)
            prompted = True
        pause(2)


def keychain_refused(outcome):
    """An eject that failed only in its last step, removing the mount resource Keychain item.
    The data protection Keychain refuses it while the screen is locked
    (errSecInteractionNotAllowed); the product then keeps the disk's record for a retry and,
    by design, refuses the forced path for it (recoveryRequired; APP043)."""
    return "MountResourceCleanupError" in str(outcome.get("error") or "")


class SleepWatch:
    """Follows this Mac through a sleep, from the harness's clocks and the host's own state.

    time.monotonic() stands still while the Mac sleeps and wall time doesn't, so wall time
    gained over awake time between two polls is time asleep. A maintenance DarkWake runs this
    process with the lid closed and the screen locked: the disk may reconnect there, but the
    Keychain still refuses the eject's last step. The 2026-11-16 run ejected at such a DarkWake
    and failed with MountResourceCleanupError (errSecInteractionNotAllowed). The wait therefore
    ends only at a full wake (host_power_state) with this user's screen unlocked, once the
    system's power log, when it has an entry, agrees that the last wake was a full one.
    """

    def __init__(self, record, pause, state=host_power_state, wall=time.time,
                 awake_ns=time.monotonic_ns, log=power_log):
        self.record = record
        self.pause = pause
        self.state = state
        self.wall = wall
        self.awake_ns = awake_ns
        self.log = log
        self.sleeps = []
        self.dark_wakes = []
        self.full_wakes = []
        self.full_wake = None  # The full wake after a sleep, while it lasts.
        self.unlocked = None  # The first poll of that full wake with the screen unlocked.
        self.observed = None  # The last raw host state; each change is recorded.
        self.log_check = None
        self.slept = 0.0
        self.started_wall = None
        self.unlock_by = None
        self.outcome = None

    def wait(self, sleep_by, minimum=SLEEP_MINIMUM_SECONDS,
             unlock_seconds=WAKE_UNLOCK_MINUTES * 60, requested=0):
        """Polls every second. Returns "ready"; or "no-sleep" when the Mac hasn't slept
        `minimum` seconds by `sleep_by` (wall time); or "no-full-wake" or "locked" when, after
        the sleep, it wasn't fully awake with the screen unlocked by `unlock_by`: `unlock_seconds`
        after the later of the first poll after the sleep and the requested wake."""
        start_wall, start_ns = self.wall(), self.awake_ns()
        self.started_wall = start_wall
        last_wall, last_ns = start_wall, start_ns
        self._observe(self.state(), None, start_ns, start_wall, start_ns)
        while True:
            self.pause(1)
            now_wall, now_ns = self.wall(), self.awake_ns()
            gap = (now_wall - last_wall) - (now_ns - last_ns) / SECOND
            self.slept = (now_wall - start_wall) - (now_ns - start_ns) / SECOND
            segment = None
            if gap >= SLEEP_GAP_SECONDS:
                # The sleep lies between these two polls: within a second of each estimate.
                segment = dict(startWall=wall_clock(last_wall), endWall=wall_clock(now_wall),
                               seconds=round(gap, 1), beforeNS=last_ns, afterNS=now_ns,
                               startEpoch=last_wall)
                self.sleeps.append(segment)
            if self.slept >= minimum and self.unlock_by is None:
                first = self.sleeps[0]["startEpoch"] if self.sleeps else now_wall
                self.unlock_by = max(now_wall, first + requested) + unlock_seconds
                self.record("woke", sleptSeconds=round(self.slept, 1),
                            unlockBy=wall_clock(self.unlock_by))
                print(f"WOKE: this Mac slept {round(self.slept)} s; waiting until "
                      f"{short_clock(self.unlock_by)} for it to be fully awake with its screen "
                      "unlocked before the workload stops and the disk is ejected", flush=True)
            self._observe(self.state(), segment, last_ns, now_wall, now_ns)
            last_wall, last_ns = now_wall, now_ns
            if self.slept < minimum:
                if now_wall >= sleep_by:
                    return self._finish("no-sleep")
                continue
            # Readiness first: the deadline may have passed while this process was asleep.
            if self.full_wake and self.unlocked and self._confirmed(now_wall):
                return self._finish("ready")
            if now_wall >= self.unlock_by:
                return self._finish("locked" if self.full_wake else "no-full-wake")

    def _observe(self, state, segment, before_ns, now_wall, now_ns):
        full, locked = state.get("fullWake"), state.get("locked")
        raw = {key: state.get(key) for key in ("capabilities", "locked", "clamshellClosed",
                                               "error")}
        if raw != self.observed:
            self.record("host-state", wall=wall_clock(now_wall), **raw)
            self.observed = raw
        if segment is not None:
            segment.update(wake="full" if full else "dark" if full is False else "unknown",
                           screenLocked=locked)
            self.record("asleep", **{key: segment[key] for key in (
                "startWall", "endWall", "seconds", "beforeNS", "afterNS", "wake",
                "screenLocked")})
            self.full_wake = self.unlocked = self.log_check = None
            if full is False:
                self.dark_wakes.append(wall_clock(now_wall))
                self.record("dark-wake", wall=wall_clock(now_wall),
                            capabilities=state.get("capabilities"), screenLocked=locked,
                            clamshellClosed=state.get("clamshellClosed"))
        if full is None:
            self.unlocked = None  # A poll that couldn't read the state is never ready.
            return
        if full is False:
            self.full_wake = self.unlocked = None
            return
        if self.full_wake is None and self.sleeps:
            # Since the poll before: a DarkWake can turn into a full wake without a sleep.
            self.full_wake = dict(wall=wall_clock(now_wall), ns=now_ns, sinceNS=before_ns,
                                  capabilities=state.get("capabilities"))
            self.full_wakes.append(self.full_wake)
            self.record("full-wake", wall=self.full_wake["wall"], sinceNS=before_ns,
                        capabilities=state.get("capabilities"), screenLocked=locked)
            if locked is not False:
                by = f" by {short_clock(self.unlock_by)}" if self.unlock_by else ""
                print(f"UNLOCK NOW: this Mac is awake but its screen is locked; unlock it{by}. "
                      "The workload keeps running until then.", flush=True)
        if self.full_wake is None:
            return
        if locked is False and self.unlocked is None:
            self.unlocked = dict(wall=wall_clock(now_wall), ns=now_ns)
            self.record("unlocked", wall=self.unlocked["wall"],
                        afterFullWakeSeconds=round((now_ns - self.full_wake["ns"]) / SECOND, 1))
        elif locked is not False:
            self.unlocked = None

    def _confirmed(self, now_wall):
        """The power log agrees that the last wake was a full one, or has no entry to judge by
        (recorded as agrees=None). Read at most every POWER_LOG_RECHECK_SECONDS."""
        check = self.log_check
        if check is not None and now_wall - check["at"] < POWER_LOG_RECHECK_SECONDS:
            return check["agrees"] is not False
        rows = self.log(self.started_wall)
        last = rows[-1] if rows else None
        agrees = None if last is None else last[1] == "Wake"
        self.log_check = dict(at=now_wall, agrees=agrees)
        self.record("power-log", agrees=agrees, entries=None if rows is None else len(rows),
                    last=last and dict(wall=wall_clock(last[0]), kind=last[1], text=last[2]))
        return agrees is not False

    def _finish(self, outcome):
        self.outcome = outcome
        self.record("sleep-wait", outcome=outcome, sleptSeconds=round(self.slept, 1),
                    darkWakes=len(self.dark_wakes),
                    fullWake=self.full_wake and self.full_wake["wall"],
                    unlocked=self.unlocked and self.unlocked["wall"])
        return outcome

    def summary(self):
        return dict(
            outcome=self.outcome, sleptSeconds=round(self.slept, 1),
            sleeps=[{key: segment.get(key) for key in (
                "startWall", "endWall", "seconds", "wake", "screenLocked")}
                for segment in self.sleeps[:32]],
            darkWakes=self.dark_wakes[:32],
            fullWakes=[wake["wall"] for wake in self.full_wakes[:8]],
            fullWake=self.full_wake and self.full_wake["wall"],
            unlocked=self.unlocked and self.unlocked["wall"],
            unlockBy=self.unlock_by and wall_clock(self.unlock_by),
            powerLogAgrees=self.log_check and self.log_check["agrees"])


def wake_reconnects(states, since_ns, sleeps, full_since_ns):
    """Each reconnect from `since_ns` on, from the probe's state samples (stamped on the
    harness's awake clock): the wake it followed (a DarkWake, or the full wake from
    `full_since_ns` on), when it began relative to the first poll after that wake's sleep
    (slightly negative if before that poll), and how long it took."""
    cycles, began = [], None
    for stamp, value in states:
        if stamp < since_ns:
            continue
        if value == "reconnecting" and began is None:
            began = stamp
        elif value == "connected" and began is not None:
            cycles.append((began, stamp))
            began = None
    if began is not None:
        cycles.append((began, None))
    rows = []
    for start, end in cycles[:16]:
        # A state stamped at the last poll before a sleep happened before that sleep.
        before = [segment for segment in sleeps if segment["beforeNS"] < start]
        segment = before[-1] if before else None
        rows.append(dict(
            afterSleep=len(before) or None,
            wake="full" if full_since_ns is not None and start >= full_since_ns
            else segment and segment.get("wake"),
            afterWakeSeconds=segment and round((start - segment["afterNS"]) / SECOND, 3),
            reconnectSeconds=None if end is None else round((end - start) / SECOND, 3)))
    full = [row for row in rows if row["wake"] == "full"]
    return dict(reconnects=rows, reconnectSeconds=rows[0]["reconnectSeconds"] if rows else None,
                reconnectingAfterWakeSeconds=rows[0]["afterWakeSeconds"] if rows else None,
                afterFullWake=dict(reconnected=bool(full),
                                   reconnectSeconds=full[0]["reconnectSeconds"] if full else None,
                                   afterWakeSeconds=full[0]["afterWakeSeconds"] if full else None),
                states=[value for stamp, value in states if stamp >= since_ns][:24])


def inventory_leftovers(inventory):
    """What the probe's own last inventory shows left that the file system can't: a
    coordinator record, a journal record, the mount resource Keychain item."""
    if not inventory:
        return []
    left = []
    if inventory.get("disks"):
        left.append("a coordinator record")
    if inventory.get("journalEntries") != 0:
        left.append(f"journal records ({inventory.get('journalEntries')})")
    if inventory.get("keychainItem") != "absent":
        left.append(f"the mount resource Keychain item ({inventory.get('keychainItem')})")
    return left


# MARK: Scenario framework


class ScenarioFailure(AssertionError):
    pass


class Context:
    def __init__(self, harness, name, root, nonce, session, audit, faults, logs):
        self.harness = harness
        self.name = name
        self.root = root
        self.nonce = nonce
        self.session = session
        self.audit = audit
        self.faults = faults
        self.logs = logs
        self.failures = []
        # Failures checked after a harness error: consequences of a broken harness until
        # shown otherwise, so they are kept apart from product failures in result.json.
        self.failures_after_harness_error = []
        self.notes = []
        self.measurements = {}
        self.timeline = []
        self.ledgers = []
        self.files = []
        self.snapshots = []
        self.final_strict = ["fullfsync", "fsync"]
        self.latched = False
        self.ejected = False
        self.running_workloads = set()
        self.started_ns = time.monotonic_ns()
        # Mutual CHAP scenarios: the pair (in memory only), and whether the body expects the
        # initiator to refuse a target's proof (R4-mutual); any other refusal fails.
        self.credentials = None
        self.target_refusals_expected = False
        # Measurements the body takes from the system log once the runner has collected it
        # (R9: measure_idle_premise); each takes the log's path. They never judge the run.
        self.system_log_checks = []

    def record(self, kind, **detail):
        row = dict(ns=time.monotonic_ns(), kind=kind, **detail)
        self.timeline.append(row)
        print("TIMELINE", self.name, json.dumps(row), flush=True)

    def harness_errors(self):
        return merged_harness_errors(self.audit, self.session)

    def check(self, condition, message, at_ns=None):
        """`at_ns` dates an observation made earlier than the check (a wire violation)."""
        if not condition:
            first = self.harness_errors()
            at_ns = time.monotonic_ns() if at_ns is None else at_ns
            if first and at_ns >= first[0]["monotonicNS"]:
                self.failures_after_harness_error.append(message)
                print("FAIL (after a harness error):", self.name, message, flush=True)
            else:
                self.failures.append(message)
                print("FAIL:", self.name, message, flush=True)
        return condition

    def note(self, message):
        self.notes.append(message)
        print("NOTE:", self.name, message, flush=True)

    def run_system_log_checks(self, path):
        """The body's measurements from the collected system log, into self.measurements. One
        that breaks leaves a note and changes nothing else."""
        for log_check in self.system_log_checks:
            try:
                log_check(path)
            except Exception as error:
                self.note(f"system log check failed: {type(error).__name__}: {error}")

    def seconds(self, start_ns, end_ns):
        return None if start_ns is None or end_ns is None else round((end_ns - start_ns) / SECOND, 3)

    def sleep(self, seconds):
        self.session.sleep(seconds)

    def start_workload(self, label, writers=("fullfsync", "fsync"), readers=1, raw=True, pause=20):
        result = self.session.command("workload-start", timeout=120, label=label,
                                      writers=list(writers), readers=readers, rawReader=raw,
                                      pauseMS=pause)
        if not result.get("ok"):
            raise ScenarioFailure("workload-start failed: " + json.dumps(result))
        self.running_workloads.add(label)
        self.record("workload-start", label=label)
        return result

    def stop_workload(self, label, timeout=300, expect_clean=True):
        result = self.session.command("workload-stop", timeout=timeout + 30, label=label,
                                      timeoutSeconds=timeout)
        self.running_workloads.discard(label)
        self.record("workload-stop", label=label, steps=result.get("steps"),
                    errors=result.get("errors"), stuck=result.get("stuck"))
        if result.get("ledger"):
            self.ledgers.append(result["ledger"])
        stats = result.get("stats", {})
        self.measurements.setdefault("workload", {})[label] = dict(
            steps=result.get("steps"), errors=result.get("errors"),
            readMismatches=result.get("readMismatches"), stuck=result.get("stuck"),
            writerFailures=result.get("writerFailures"),
            maximumMS={key: round(value.get("maximumMS", 0), 1) for key, value in stats.items()},
            counts={key: value.get("count") for key, value in stats.items()},
            errorList=result.get("errorList", [])[:16])
        self.check(not result.get("stuck"), f"workload {label} threads did not stop")
        self.check(result.get("readMismatches", 0) == 0,
                   f"workload {label} read back data that differs from an acknowledged version")
        if expect_clean:
            self.check(result.get("errors", 0) == 0,
                       f"workload {label} saw application-visible errors: "
                       + json.dumps(result.get("errorList", [])[:4]))
        return result

    def workload_steps(self, label):
        return self.session.command("workload-status", timeout=60, label=label).get("steps", [])

    def wait_progress(self, label, before, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            steps = self.workload_steps(label)
            if steps and all(after > previous for after, previous in zip(steps, before)):
                return steps
            self.session.sleep(1)
        return None

    def eject(self, timeout=300):
        began = time.monotonic_ns()
        result = self.session.command("eject", timeout=timeout + 60, timeoutSeconds=timeout)
        self.record("eject", status=result.get("status"), elapsedMS=result.get("elapsedMS"),
                    error=result.get("error"))
        if result.get("status") == "succeeded" and result.get("remainingDisks") == 0:
            self.ejected = True
        result["harnessSeconds"] = self.seconds(began, time.monotonic_ns())
        return result

    def force_eject(self, retry_seconds=0):
        """The forced path refuses (recoveryRequired) while an earlier, timed-out ejection's
        Disk Arbitration request is still pending. With `retry_seconds`, ask again every 2 s;
        `attempts` records each refusal relative to the first request."""
        began = time.monotonic_ns()
        attempts = []
        while True:
            result = self.session.command("force-eject", timeout=600)
            attempts.append(dict(atSeconds=self.seconds(began, time.monotonic_ns()),
                                 status=result.get("status"), error=result.get("error"),
                                 state=self.session.state()))
            pending = "recoveryRequired" in str(result.get("error"))
            if (result.get("status") == "succeeded" or not pending
                    or time.monotonic_ns() - began > retry_seconds * SECOND):
                break
            self.session.sleep(2)
        self.record("force-eject", status=result.get("status"), elapsedMS=result.get("elapsedMS"),
                    error=result.get("error"), attempts=len(attempts))
        if result.get("status") == "succeeded" and result.get("remainingDisks") == 0:
            self.ejected = True
        result["attempts"] = attempts
        return result

    def cleanup_eject(self, state=host_power_state, wall=time.time,
                      unlock_seconds=CLEANUP_UNLOCK_MINUTES * 60):
        """Ejects a disk the scenario body left attached: normally; after a refused last step
        (keychain_refused) normally again once the screen is unlocked, never forced; after any
        other failure through the forced path."""
        self.note("scenario body left the disk attached; ejecting normally")
        outcome = self.eject(timeout=300)
        if outcome.get("status") != "succeeded" and keychain_refused(outcome):
            outcome = self.eject_when_unlocked(outcome, state, wall, unlock_seconds)
        if outcome.get("status") != "succeeded" and not keychain_refused(outcome):
            self.note("normal eject failed in cleanup; force ejecting")
            self.force_eject(retry_seconds=240)
        return outcome

    def eject_when_unlocked(self, refused, state=host_power_state, wall=time.time,
                            unlock_seconds=CLEANUP_UNLOCK_MINUTES * 60):
        """After an eject refused in its last step, retries the normal eject once this user's
        screen is unlocked, for at most `unlock_seconds`; a few times more if the Keychain
        still refuses (it may lag the unlock). The forced path would be refused by design."""
        deadline = wall() + unlock_seconds
        locked = state().get("locked")
        self.note("the normal eject in cleanup failed only in its last step, removing the mount "
                  f"resource Keychain item (screen locked: {locked}): "
                  f"{str(refused.get('error'))[:240]}. Retrying the normal eject once the "
                  f"screen is unlocked, until {short_clock(deadline)}; not forcing")
        attempts, unlocked, outcome = [], None, refused
        prompt = (f"UNLOCK NOW: the disk's eject needs this Mac's screen unlocked; unlock it by "
                  f"{short_clock(deadline)} (cleanup of {self.name}).")
        while True:
            seen = wait_for_unlock(deadline, self.session.sleep, state, wall, prompt)
            if seen is None:
                break
            if unlocked is None:
                unlocked = seen
                self.record("cleanup-unlocked", wall=wall_clock(seen))
            outcome = self.eject(timeout=300)
            attempts.append(dict(wall=wall_clock(wall()), status=outcome.get("status"),
                                 error=outcome.get("error")))
            if (outcome.get("status") == "succeeded" or not keychain_refused(outcome)
                    or len(attempts) >= UNLOCKED_EJECT_ATTEMPTS or wall() >= deadline):
                break
            self.session.sleep(5)
        self.measurements["cleanupEject"] = dict(
            firstError=refused.get("error"), screenLockedAtFirst=locked,
            unlockBy=wall_clock(deadline), unlocked=unlocked and wall_clock(unlocked),
            attempts=attempts[:16], status=outcome.get("status"))
        if outcome.get("status") == "succeeded":
            self.note("the normal eject succeeded in cleanup after the screen was unlocked")
        elif keychain_refused(outcome):
            self.note("the Keychain still refused the eject's last step"
                      + ("" if unlocked else ": the screen stayed locked")
                      + "; the disk's record and Keychain item are left to the fixture recovery")
        return outcome

    def inventory(self):
        return self.session.command("inventory", timeout=120)

    def require_clean_inventory(self, label):
        inventory = self.inventory()
        self.measurements["inventory-" + label] = inventory
        self.check(not inventory.get("disks"), f"{label}: a coordinator record remains")
        self.check(inventory.get("journalEntries") == 0, f"{label}: a journal record remains")
        self.check(not inventory.get("mounts"), f"{label}: a mount remains: {inventory.get('mounts')}")
        self.check(not inventory.get("images"), f"{label}: an attached image remains")
        self.check(not inventory.get("markerFiles"), f"{label}: a block marker remains")
        self.check(inventory.get("keychainItem") == "absent",
                   f"{label}: mount resource Keychain item {inventory.get('keychainItem')}")
        self.check(not inventory.get("bridgeDirectoryExists"), f"{label}: the bridge directory remains")
        return inventory

    def outage_metrics(self, fault, heal, label):
        """Reconnect timing from the probe's state samples and the wire."""
        start = fault["appliedNS"] if "appliedNS" in fault else fault["startNS"]
        states = [(stamp, value) for stamp, value in self.session.states if stamp >= fault["startNS"]]
        first_reconnecting = next((s for s, v in states if v == "reconnecting"), None)
        healed = heal["endNS"] if heal else None
        connected = next((s for s, v in states if v == "connected" and healed and s >= healed), None)
        logins = [row["ns"] for row in self.audit.normal_logins if row["ns"] >= fault["startNS"]]
        after_heal = [ns for ns in logins if healed and ns >= heal["startNS"]]
        metrics = dict(
            outageSeconds=self.seconds(start, healed),
            toReconnectingSeconds=self.seconds(start, first_reconnecting),
            stateSequence=[v for _, v in states][:24],
            reconnectedAfterHealSeconds=self.seconds(healed, connected),
            firstLoginAfterHealSeconds=self.seconds(heal["startNS"], after_heal[0]) if after_heal else None,
            normalLoginsSinceFault=len(logins),
            abortedPendingDials=heal.get("abortedPendingDials") if heal else None)
        self.measurements.setdefault("outages", []).append(dict(label=label, **metrics))
        return metrics

    def wait_record(self, prefix, since_ns, timeout):
        """When the coordinator's record, which the app's disk list shows, began with `prefix`
        (for example "reconnecting/"), at or after since_ns; None if it didn't in time."""
        deadline = time.monotonic() + timeout
        while True:
            for value in self.session.events_of("COORDINATOR", since_ns):
                if str(value.get("record", "")).startswith(prefix):
                    return value["uptimeNS"]
            if time.monotonic() >= deadline:
                return None
            self.session.sleep(0.5)

    def wait_force_offered(self, shown_ns, label, timeout=40):
        """Polls the coordinator, as the disk list would, until it offers Force Eject for the
        reconnecting disk. The offer waits for AttachedDisk.forcedReleaseReconnectingDelay
        (10 s) of uninterrupted reconnecting, so a blip never shows it."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.session.command("can-force", timeout=30).get("canPrepare"):
                offered = time.monotonic_ns()
                waited = self.seconds(shown_ns, offered) if shown_ns else None
                self.measurements.setdefault("forceOffer", {})[label] = dict(
                    afterShownReconnectingSeconds=waited)
                self.check(waited is None or waited >= OFFER_DELAY - 1,
                           f"{label}: Force Eject was offered {waited} s after the disk list "
                           f"showed reconnecting, before the {OFFER_DELAY} s delay")
                return offered
            self.session.sleep(1)
        self.check(False, f"{label}: Force Eject was never offered for the reconnecting disk")
        return None

    def wait_connected(self, since_ns, timeout, label):
        hit = self.session.wait_state({"connected"}, since_ns, timeout)
        self.check(hit is not None, f"{label}: the disk did not return to connected within {timeout}s"
                   f" (state {self.session.state()})")
        return hit

    def snapshot(self, name):
        self.harness.vm.configure("snapshot", self.nonce, timeout=60, capture_output=True,
                                  text=True)
        destination = self.root / name
        self.harness.vm.copy(self.harness.vm.name + ":" + self.harness.vm.staging + "/"
                             + self.nonce + "-snapshot.img", destination)
        self.harness.vm.shell("rm", "--", self.harness.vm.staging + "/" + self.nonce
                              + "-snapshot.img")
        destination.chmod(0o600)
        self.record("snapshot", image=name)
        return destination

    def verify(self, image, cutoff_ns=None, grace_ns=0, strict=("fullfsync", "fsync"),
               files=None, label="final", recent_ns=None):
        spec_name = f"Verify-{label}.json"
        (self.root / spec_name).write_text(json.dumps(dict(
            image=image.name, ledgers=self.ledgers, cutoffNS=cutoff_ns, graceNS=grace_ns,
            recentNS=recent_ns, strictSyncs=list(strict),
            files=files if files is not None else self.files)) + "\n")
        result = subprocess.run([self.harness.probe, "--verify-recovery-snapshot", spec_name,
                                 str(self.root), self.nonce], capture_output=True, text=True,
                                timeout=300)
        print(result.stdout, end="", flush=True)
        if result.returncode:
            print(result.stderr, end="", flush=True)
        report_path = self.root / spec_name.replace(".json", "-result.json")
        report = json.loads(report_path.read_text()) if report_path.exists() else None
        summary = dict(label=label, passed=result.returncode == 0 and bool(report)
                       and report["passed"], failureCount=report and report["failureCount"],
                       failures=report and report["failures"][:8],
                       observations=report and report["observations"][:16],
                       counts=[ledger["counts"] for ledger in (report or {}).get("ledgers", [])],
                       files=(report or {}).get("files"))
        self.snapshots.append(summary)
        self.check(summary["passed"], f"snapshot {label} verification failed: "
                   + json.dumps(summary["failures"])[:800])
        return summary


class Harness:
    def __init__(self, vm, probe, binary_dir, logs, digest_override=None):
        self.vm = vm
        self.probe = probe
        self.binary_dir = binary_dir
        self.logs = logs
        self.digest_override = digest_override
        self.results = []
        self.stop = False

    def resources_remain(self, root, result, inventory=None):
        """Mounts, attached images or connection records in the fixture's journal remain.

        Listing mounts can block on a stuck file system; a hang counts as remaining. The
        probe's own last `inventory`, if given, adds what only it can see: a coordinator record
        and the mount resource Keychain item. It describes the state before any recovery, so
        only the first check passes it."""
        left = inventory_leftovers(inventory)
        if left:
            result.setdefault("observations", []).append(
                "the probe's inventory at the end shows " + ", ".join(left))
            return True
        for attempt in range(3):
            try:
                return fixture.resources_remain(root, records=True)
            except subprocess.TimeoutExpired as error:
                result.setdefault("observations", []).append(
                    f"resource listing hung: {' '.join(map(str, error.cmd))} > {error.timeout}s")
                time.sleep(10)
        return True

    def release_leftovers(self, root, nonce, result, inventory=None,
                          unlock_seconds=CLEANUP_UNLOCK_MINUTES * 60, state=host_power_state,
                          wall=time.time, pause=time.sleep):
        """Recovers what a scenario left with the probe's own recovery; whether anything still
        remains afterwards. A recovery ends with the same Keychain step as an eject, so with
        the screen locked it first waits up to `unlock_seconds` for an unlock."""
        if not self.resources_remain(root, result, inventory):
            return False
        result["passed"] = False
        result.setdefault("errors", []).append("fixture resources remain after scenario")
        if unlock_seconds > 0 and state().get("locked") is not False:
            deadline = wall() + unlock_seconds
            seen = wait_for_unlock(deadline, pause, state, wall, prompt=(
                "UNLOCK NOW: the fixture's recovery needs this Mac's screen unlocked; unlock "
                f"it by {short_clock(deadline)}."))
            result.setdefault("observations", []).append(
                "recovery waited for an unlocked screen: "
                + (f"unlocked at {wall_clock(seen)}" if seen else "still locked; recovering"))
        try:
            run([self.probe, "--recover-fixture", root, nonce], timeout=300)
        except Exception as error:
            result["errors"].append("recover-fixture: " + str(error))
        if self.resources_remain(root, result):
            # A stopped disk refuses the normal eject; take the forced path from a new
            # owner process, as the app does after its confirmation.
            try:
                run([self.probe, "--force-recover-fixture", root, nonce], timeout=300)
                result["errors"].append("resources needed --force-recover-fixture")
            except Exception as error:
                result["errors"].append("force-recover-fixture: " + str(error))
        return self.resources_remain(root, result)

    def scenario(self, name, body, digest="CRC32C", chap=True, read_only=False, clamp=False,
                 mutual=False):
        """`clamp`: the forwarder's sockets toward the initiator get small receive buffers
        (ClampedForwarder; R13-dataout). `mutual`: mutual CHAP with a disposable pair of random
        secrets (mutual_credentials), checked on the wire for every Normal login; the evidence
        is searched for the secrets before they are dropped."""
        assert not (mutual and (read_only or not chap)), "mutual CHAP is a read-write CHAP mode"
        if self.digest_override:
            digest = self.digest_override
        nonce = str(uuid.uuid4())
        parent = ROOT / "build/FSKitFixtures"
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix=f"iSCSI-FSKit-{nonce}-", dir=parent)).resolve()
        logs = self.logs / name
        logs.mkdir()
        start_wall = time.time()
        credentials = mutual_credentials() if mutual else None
        result = dict(scenario=name, nonce=nonce, root=str(root), digest=digest, chap=chap,
                      mutualCHAP=mutual, readOnly=read_only, passed=False)
        print(f"\n===== SCENARIO {name}: digest={digest} CHAP={chap} mutualCHAP={mutual} "
              f"readOnly={read_only} root={root}", flush=True)
        configured = False
        context = None
        session = opened_session = None
        audit = None
        guest_since = guest_epoch(self.vm.name)
        try:
            fixture.write_fixture_manifest(root, "apfs")
            run([self.probe, "--prepare-fixture", root, nonce], timeout=180)
            image = root / fixture.FIXTURE_IMAGES["apfs"]
            original = hashlib.sha256(image.read_bytes()).hexdigest()
            self.vm.copy(image, self.vm.name + ":" + self.vm.staging + "/" + nonce + ".img")
            configured = True
            setup_export(self.vm, nonce, digest, chap, original, credentials)
            self.vm.wait_for_target()
            audit = RecoveryWireAudit(lio.expected_normal_digests("lio", digest))
            forwarder = []
            owner = ClampedForwarder() if clamp else None
            with recovery_proxy(audit, self.vm.port, forwarder, owner=owner) as address:
                environment = dict(os.environ,
                                   ISCSI_INITIATOR_NAME="iqn.2026-10.dev.soba:lio-probe-" + nonce)
                discovery = run([self.binary_dir / "iscsi", "discover", address], env=environment,
                                capture_output=True, text=True)
                assert "iqn.2026-10.dev.soba:lio-" + nonce in discovery.stdout
                if credentials is not None:
                    # After the anonymous discovery above: every later login must be mutual.
                    audit.expect_mutual_chap(credentials)
                mode = ("--recovery-lio-loopback"
                        + ("-mutual-chap" if mutual else "-chap" if chap else "")
                        + ("-readonly" if read_only else ""))
                session = opened_session = ProbeSession(
                    [self.probe, mode, address, root, nonce], logs / "probe.log")
                if credentials is not None:
                    session.supply_secrets(credentials)
                # A forwarder bound that trips stops the body's waits at once (HarnessError)
                # instead of leaving the initiator to run into its recovery window.
                audit.add_harness_listener(session.on_harness_error)
                ready = session.wait_ready()
                print("READY", json.dumps(ready), flush=True)
                assert ready.get("readOnly") == read_only, "The probe mounted another access mode"
                faults = None
                context = Context(self, name, root, nonce, session, audit, None, logs)
                context.credentials = credentials
                if owner is not None:
                    context.measurements["clamp"] = owner.clamp  # Filled in as it accepts.
                faults = Faults(self.vm, nonce, audit, context.record)
                context.faults = faults
                try:
                    if mutual:
                        require_mutual_first_login(context)
                    body(context)
                except HarnessError as error:
                    context.note(f"a harness error stopped the scenario body: {error}")
                except ScenarioFailure as error:
                    context.failures.append(str(error))
                except Exception as error:
                    context.failures.append(f"{type(error).__name__}: {error}")
                    traceback.print_exc()
                finally:
                    # The cleanup below must still wait for the probe after a harness error.
                    session.abortable = False
                    if faults.active is not None:
                        context.note("healing a blackhole left active by the scenario body")
                        faults.heal()
                for label in sorted(context.running_workloads):
                    context.note(f"stopping workload {label} left running by the scenario body")
                    context.stop_workload(label, timeout=200, expect_clean=False)
                if not context.ejected and session.process.poll() is None:
                    context.cleanup_eject()
                if session.process.poll() is None:
                    context.require_clean_inventory("end")
                code = session.close()
                session = None
                context.check(code == 0, f"probe exited with {code}")
                if mutual:
                    # The probe removes the mutual pair from the Keychain once no disk remains.
                    exit_result = opened_session.exit_result or {}
                    context.check(exit_result.get("credentialRemoved") is True,
                                  "the probe did not remove the mutual CHAP credential: "
                                  + json.dumps(exit_result)[:300])
                audit.closing = True
            report = audit.recovery_report(latched=context.latched)
            if mutual:
                check_mutual_logins(context, report["mutualCHAP"])
            if forwarder:
                # The proxy forces closed a connection whose target side never ended. That is
                # expected only for a connection a declared fault cut (its target-side TCP
                # outlived the blackhole or reset); every other connection must have ended
                # naturally (EOF both ways).
                forced = [c for c in report["connections"]
                          if not c["ends"] or any(v["how"] != "eof" for v in c["ends"].values())]
                result.setdefault("observations", []).append(
                    "forwarder lifecycle: " + ", ".join(forwarder) + "; forced connections: "
                    + json.dumps([dict(id=c["id"], explained=c["explained"],
                                       ends={k: v["how"] for k, v in c["ends"].items()})
                                  for c in forced])[:600])
                def cut_by_fault(connection):
                    # The initiator closed its side during (or within GRACE_NS after) a fault.
                    end = connection["ends"].get("toTarget")
                    return end is not None and end["how"] == "eof" and any(
                        f["startNS"] <= end["ns"] <= (f["endNS"] or end["ns"]) + audit.GRACE_NS
                        for f in audit.faults)

                context.check(set(forwarder) == {"FORCED_TRANSPORT_CLOSE"} and forced
                              and all(cut_by_fault(c) for c in forced),
                              "forwarder lifecycle failures not explained by a declared fault: "
                              + ", ".join(forwarder))
            (logs / "wire.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
            for violation in report["violations"]:
                context.check(False, "wire: " + json.dumps(violation, default=str)[:600],
                              at_ns=violation.get("ns"))
            context.measurements["wire"] = {key: report[key] for key in (
                "normalLogins", "reconnects", "loginStatuses", "targetConnectFailures",
                "unsyncedWrites", "redoneWrites", "writes", "flushes", "reads", "writeBytes",
                "digestChecks", "nopOut", "nopReplies", "logouts", "logoutReplies")}
            context.measurements["wire"]["deviceErrors"] = [
                {k: v for k, v in error.items() if k in ("opcode", "status", "senseKey", "asc", "ascq")}
                for error in report["deviceErrors"][:16]]
            context.measurements["wire"]["connections"] = [
                dict(id=c["id"], type=c["sessionType"], preIO=c["preIO"], abrupt=c["abrupt"],
                     rejected=c["rejected"], writes=c["writesSent"], syncs=c["syncsGood"])
                for c in report["connections"]][:64]
            final = context.snapshot("Final.img")
            context.verify(final, strict=context.final_strict, label="final")
            status = json.loads(self.vm.configure("status", nonce, capture_output=True,
                                                  text=True).stdout)
            context.measurements["targetStatus"] = status
            context.check(not status["sessions"], "a target session remains after the scenario")
            result["passed"] = not context.failures and not context.harness_errors()
        except Exception as error:
            traceback.print_exc()
            result.setdefault("errors", []).append(f"{type(error).__name__}: {error}")
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception as error:
                    result.setdefault("errors", []).append("probe close: " + str(error))
            if audit is not None and not (logs / "wire.json").exists():
                try:
                    report = audit.recovery_report(latched=bool(context and context.latched))
                    (logs / "wire.json").write_text(
                        json.dumps(report, indent=2, default=str) + "\n")
                except Exception as error:
                    result.setdefault("errors", []).append("wire report: " + str(error))
            if context is not None:
                result.update(failures=context.failures,
                              failuresAfterHarnessError=context.failures_after_harness_error,
                              notes=context.notes,
                              measurements=context.measurements, timeline=context.timeline,
                              snapshots=context.snapshots)
            harness_errors = merged_harness_errors(audit, opened_session)
            if harness_errors:
                # Not product evidence: the harness broke the transport it was observing.
                result["harnessErrors"] = harness_errors
                result["passed"] = False
            try:
                result["systemLog"] = collect_logs(start_wall, logs / "system.log")
            except Exception as error:
                result["systemLog"] = dict(error=str(error))
            if context is not None and context.system_log_checks:
                # Into context.measurements, which the result already holds; no verdict.
                context.run_system_log_checks(logs / "system.log")
            try:
                result["guestLogs"] = collect_guest_logs(self.vm.name, guest_since, logs)
            except Exception as error:
                result["guestLogs"] = dict(error=f"{type(error).__name__}: {error}")
            measured = context.measurements if context is not None else {}
            # A cleanup that already waited out its unlock bound isn't waited for again.
            waited = measured.get("cleanupEject")
            if self.release_leftovers(
                    root, nonce, result, measured.get("inventory-end"),
                    unlock_seconds=0 if waited and not waited.get("unlocked")
                    else CLEANUP_UNLOCK_MINUTES * 60):
                self.vm.safe_to_stop = False
                self.stop = True
                result["errors"].append("STUCK: resources remain; VM retained, later scenarios skipped")
            elif configured:
                try:
                    for _ in range(60):
                        status = json.loads(self.vm.configure(
                            "status", nonce, capture_output=True, text=True).stdout)
                        if not status["sessions"] and not status["sessionCount"]:
                            break
                        time.sleep(1)
                    self.vm.configure("remove", nonce)
                except Exception as error:
                    # The guest fixture state is not as expected; later setups would refuse it.
                    result.setdefault("errors", []).append("target remove: " + str(error))
                    self.stop = True
            if credentials is not None:
                scan_for_secrets(result, credentials, logs, root, audit, context)
            if result.get("errors"):
                result["passed"] = False
            result["verdict"] = ("pass" if result["passed"] else
                                 "harness-error" if harness_errors else "fail")
            text = json.dumps(result, indent=2, default=str) + "\n"
            if credentials is not None:
                withheld = any(value in text for value in scenario_secrets(credentials))
                if withheld:
                    text = json.dumps(dict(scenario=name, passed=False, verdict="fail", errors=[
                        "result withheld: it contained a scenario secret"]), indent=2) + "\n"
                    result.update(passed=False, verdict="fail")
                credentials.clear()  # Nothing of the pair is kept past this scenario.
            (logs / "result.json").write_text(text)
            if result["passed"]:
                fixture.remove_empty_mounts(root)
                shutil.rmtree(root)
            else:
                print("Fixture retained for diagnosis:", root, flush=True)
            print(f"===== {result['verdict'].upper()}: {name}", flush=True)
            self.results.append(result)
        return result


# R13-dataout's forwarder sockets toward the initiator. Without them the loopback kernel takes
# in more than a Data-Out burst can be, so the initiator's sends never block: measured on this
# Mac (2026-11-16) with plain sockets, 278,188 to 359,704 B before the sender blocked, and an
# NWConnection sender finished a whole 262,144 B burst; a 256 KiB burst is at most 263,936 B
# on the wire. A listener's SO_RCVBUF of 1 to 48 KiB became 116,696 B at accept (52 and
# 56 KiB became 120,720 and 124,744 B, 60 KiB 64,384 B), and with loopback's 16 KiB segments
# the forwarder's queue reached 123,008 to 196,332 B whatever SO_RCVBUF was; with a smaller
# TCP_MAXSEG it stopped about 32 segments past SO_RCVBUF. With 32 KiB and 1 KiB segments the
# forwarder's queue stopped at 57 to 66 KB and a plain-socket sender's buffer at its size
# (146,988 B): 204,372 to 212,532 B in all; an NWConnection test sender sending 8 KiB frames
# then blocked and its own 15 s timer fired. A 16 KiB SO_RCVBUF made the sender pause 5 s at
# times (not investigated; perhaps the sender's silly-window avoidance against the larger
# window it saw first). The extension itself was not held up by any of these clamps: see
# scenario_r13. Its forwarder queue reached 64,860 to 65,492 B with 32 KiB and 1 KiB segments
# (20261116-185051, -185451) and 12,184 to 40,960 B with the values below (-190033), while
# its socket held 49,152 to 196,872 B.
CLAMP_LISTEN_RECEIVE_BUFFER = 61440  # The smallest value tried that stayed small at accept.
# Each accepted initiator connection. With 24 KiB and 512 B segments the forwarder's queue
# stopped at 16,480 B and grew to 40,960 B by 10.5 s, with no pauses (plain sockets).
CLAMP_RECEIVE_BUFFER = 24576
CLAMP_SEGMENT = 512  # TCP_MAXSEG of each accepted connection: the window's growth step.


class ClampedForwarder(lio.lifecycle.Forwarder):
    """The forwarder's owner with small receive buffers toward the initiator (R13-dataout).

    The listener gets CLAMP_LISTEN_RECEIVE_BUFFER before it listens; each accepted initiator
    connection gets CLAMP_RECEIVE_BUFFER and CLAMP_SEGMENT as the base proxy adopts it. The
    sockets toward the target are unchanged. A socket option that fails is recorded, not
    raised: the accept loop must go on."""

    def __init__(self):
        super().__init__(socket_factory=socket.socket, thread_factory=threading.Thread)
        self.clamp = dict(listener=None, accepted=[], failures=[])

    def _apply(self, stream, options):
        applied = {}
        for name, level, option, value in options:
            try:
                stream.setsockopt(level, option, value)
                applied[name] = stream.getsockopt(level, option)
            except OSError as error:
                if len(self.clamp["failures"]) < 16:
                    self.clamp["failures"].append(f"{name}: {error.strerror or error}")
        return applied

    def new_socket(self, *, listener=False):
        stream = super().new_socket(listener=listener)
        if listener:
            self.clamp["listener"] = self._apply(stream, (
                ("receiveBuffer", socket.SOL_SOCKET, socket.SO_RCVBUF,
                 CLAMP_LISTEN_RECEIVE_BUFFER),))
        return stream

    def adopt(self, stream):
        adopted = super().adopt(stream)
        if adopted:
            applied = self._apply(stream, (
                ("receiveBuffer", socket.SOL_SOCKET, socket.SO_RCVBUF, CLAMP_RECEIVE_BUFFER),
                ("segment", socket.IPPROTO_TCP, socket.TCP_MAXSEG, CLAMP_SEGMENT)))
            if len(self.clamp["accepted"]) < 256:
                self.clamp["accepted"].append(applied)
        return adopted


def setup_export(vm, nonce, digest, chap, original, credentials=None):
    """Exports the fixture (tests/LIO/configure.py setup). With `credentials` (mutual CHAP) both
    secrets go on the configurator's stdin ("mutual-stdin"), never on its command line."""
    if credentials is None:
        return vm.configure("setup", nonce, digest, "yes" if chap else "no", "512", original)
    line = json.dumps(dict(password=credentials["password"],
                           targetPassword=credentials["targetPassword"])) + "\n"
    return vm.configure("setup", nonce, digest, "mutual-stdin", "512", original, input=line,
                        text=True)


@contextmanager
def recovery_proxy(audit, port, failures, *, resources=None, owner=None):
    """The base proxy, reporting its forwarder lifecycle failures into `failures` instead of
    failing the scenario before the wire report and the media checks run. A bound that trips
    is reported at once through audit.harness_failure (see Harness.scenario)."""
    resources = {} if resources is None else resources
    try:
        with audit.proxy(port, resources=resources, owner=owner) as address:
            yield address
    except AssertionError as error:
        if str(error) != "Forwarder lifecycle evidence invalid":
            raise
        failures.extend(sorted(resources["owner"].failures))
        if list(audit.errors):
            raise AssertionError(f"wire audit errors: {list(audit.errors)[:8]}") from error


# MARK: Scenarios


def short_outage(c, seconds):
    c.start_workload(c.name)
    c.sleep(8)
    fault = c.faults.blackhole()
    c.sleep(seconds)
    heal = c.faults.heal()
    # Count progress from the heal. Steps that finished before the DROP took hold once stood in
    # for I/O resumed after it, so the outage metrics were taken before a stalled connection was
    # replaced (R1 at 20261111-140029: EOF 1.39 s and a new login 3.53 s after the heal).
    before = c.workload_steps(c.name)
    hit = c.wait_connected(heal["endNS"] - 1, 150, "after heal")
    progressed = c.wait_progress(c.name, before, timeout=90)
    c.check(progressed is not None, "the workload made no progress after the outage")
    metrics = c.outage_metrics(fault, heal, f"{seconds}s blackhole")
    c.sleep(10)
    c.stop_workload(c.name)
    eject = c.eject()
    c.check(eject.get("status") == "succeeded", "normal eject failed: " + json.dumps(eject))
    c.measurements["eject"] = eject
    return metrics, hit, fault


def scenario_r1(c):
    _, _, fault = short_outage(c, 5)
    # Decide from every Normal login the audit saw after the fault, once the disk is ejected:
    # a connection that stalled during the blackhole can be replaced after the outage metrics.
    logins = [row["ns"] for row in c.audit.normal_logins if row["ns"] >= fault["startNS"]]
    c.measurements["normalLoginsSinceFaultAtEnd"] = len(logins)
    if logins:
        c.note(f"the connection was replaced after the 5 s blackhole: {len(logins)} new login(s), "
               f"the first {c.seconds(fault['endNS'], logins[0])} s after the heal")
    else:
        c.note("TCP survived the 5 s blackhole; no reconnect was needed")


def scenario_r2(c):
    metrics, _, _ = short_outage(c, 40)
    c.check(metrics["normalLoginsSinceFault"] >= 1, "no new session (same ISID) after a 40 s outage")
    c.check(metrics["toReconnectingSeconds"] is not None, "the disk never reported reconnecting")


def scenario_r3(c):
    c.start_workload(c.name)
    c.sleep(5)
    resets = []
    for index in range(3):
        before_bytes = c.audit.write_bytes
        request = c.session.send("file-write", label=f"{c.name}-large{index}", bytes=24 * 1048576,
                                 sync="fullfsync")
        deadline = time.monotonic() + 60
        while c.audit.write_bytes - before_bytes < 6 * 1048576 and time.monotonic() < deadline:
            time.sleep(0.05)
        in_flight = c.audit.write_bytes - before_bytes
        reset = c.faults.reset()
        reset["writeBytesBeforeReset"] = in_flight
        result = c.session.wait(request, 300)
        reset["largeWrite"] = {key: result.get(key) for key in (
            "ok", "writeErrno", "syncErrno", "writeMS", "syncMS")}
        resets.append(reset)
        c.check(result.get("ok"), f"large write {index} failed across a reset: {json.dumps(result)}")
        if result.get("ok"):
            c.files.append(dict(name=result["name"], sha256=result["sha256"], required=True))
        c.wait_connected(reset["endNS"], 150, f"after reset {index}")
        c.sleep(5)
    c.measurements["resets"] = resets
    c.check(any(r["sockets"] > 0 for r in resets), "no socket was reset")
    c.sleep(5)
    c.stop_workload(c.name)
    eject = c.eject()
    c.check(eject.get("status") == "succeeded", "normal eject failed: " + json.dumps(eject))


def scenario_r4(c):
    c.start_workload(c.name)
    c.sleep(8)
    before = c.workload_steps(c.name)
    restart = c.faults.target_restart()
    c.wait_connected(restart["endNS"] - 1, 150, "after target restart")
    progressed = c.wait_progress(c.name, before, timeout=120)
    c.check(progressed is not None, "the workload made no progress after the restart")
    c.measurements["restart"] = dict(
        seconds=c.seconds(restart["startNS"], restart["endNS"]),
        wwnPreserved=[s["wwn"] for s in restart["status"]["stores"]])
    fault = dict(kind="target-restart", startNS=restart["startNS"], appliedNS=restart["startNS"])
    heal = dict(startNS=restart["endNS"], endNS=restart["endNS"])
    c.outage_metrics(fault, heal, "target restart")
    c.sleep(10)
    c.stop_workload(c.name)
    eject = c.eject()
    c.check(eject.get("status") == "succeeded", "normal eject failed: " + json.dumps(eject))


def staged_restore(c, stages):
    """Runs `stages` [(stage, seconds after it)] inside one declared fault."""
    start = time.monotonic_ns()
    fault = c.audit.fault_start("staged-restore", start)
    steps = []
    for stage, hold in stages:
        steps.append(c.faults.restage(stage))
        c.sleep(hold)
    end = time.monotonic_ns()
    c.audit.fault_end(fault, end)
    return fault, start, end, steps


def rejections_since(c, start):
    return [dict(seconds=c.seconds(start, r["ns"]),
                 status="%02x%02x" % (r["statusClass"], r["statusDetail"]))
            for r in c.audit.login_rejections if r["ns"] >= start]


def scenario_r4_staged(c):
    """A restore that passes through an unknown target (LIO answers 0301), 0202 and 0201,
    with less than 30 s of authorization rejections."""
    c.start_workload(c.name)
    c.sleep(8)
    before = c.workload_steps(c.name)
    fault, start, end, steps = staged_restore(c, [
        ("clear", 4), ("placeholder", 16), ("no-acl", 10), ("no-chap", 10), ("full", 0)])
    c.wait_connected(end - 1, 150, "after the staged restore")
    progressed = c.wait_progress(c.name, before, timeout=120)
    c.check(progressed is not None, "the workload made no progress after the staged restore")
    rejections = rejections_since(c, start)
    c.measurements["stagedRestore"] = dict(
        stages=[dict(stage=s["stage"], atSeconds=c.seconds(start, s["startNS"])) for s in steps],
        rejections=rejections, refusedConnections=len(
            [t for t in c.audit.connect_failures if t >= start]))
    c.outage_metrics(dict(kind="staged-restore", startNS=start, appliedNS=start),
                     dict(startNS=end, endNS=end), "staged restore")
    c.sleep(10)
    c.stop_workload(c.name)
    eject = c.eject()
    c.check(eject.get("status") == "succeeded", "normal eject failed: " + json.dumps(eject))


def scenario_r4_auth(c):
    """Authorization keeps failing for more than 30 s: the disk stops and never logs in again."""
    c.start_workload(c.name)
    c.sleep(8)
    start = time.monotonic_ns()
    fault = c.audit.fault_start("authorization-loss", start)
    c.faults.restage("clear")
    c.faults.restage("no-acl")
    hit = c.session.wait_state({"interrupted"}, start, 110)
    rejections = rejections_since(c, start)
    latched_ns = hit[0] if hit else None
    c.check(hit is not None, f"authorization failures did not stop the disk (state {c.session.state()})")
    c.faults.restage("no-chap")
    c.faults.restage("full")
    restored = time.monotonic_ns()
    c.audit.fault_end(fault, restored)
    if latched_ns:
        c.audit.forbid_mutation_after(latched_ns, "authorization failures")
    c.latched = True
    first = next((r for r in c.audit.login_rejections if r["ns"] >= start), None)
    errors = c.session.events_of("IO_ERROR", start)
    c.measurements["authorizationLoss"] = dict(
        rejections=rejections[:20], rejectionCount=len(rejections),
        latchedAfterFirstRejectionSeconds=c.seconds(first["ns"], latched_ns) if first and latched_ns else None,
        latchedAfterStartSeconds=c.seconds(start, latched_ns),
        firstErrors=[{k: e.get(k) for k in ("operation", "errno", "elapsedMS")} for e in errors[:6]])
    c.check(bool(rejections) and all(r["status"] in ("0201", "0202") for r in rejections),
            f"unexpected login statuses: {rejections[:6]}")
    # RecoveringSession retries 0201/0202 for SessionRecovery.authorizationRetryLimit (30 s)
    # before it stops the disk; an earlier stop means the rejection wasn't recognised as one.
    if first and latched_ns:
        c.check(len(rejections) >= 3 and latched_ns - first["ns"] >= 29 * SECOND,
                f"the disk stopped {c.seconds(first['ns'], latched_ns)} s after the first "
                f"authorization rejection ({len(rejections)} rejections), before the 30 s limit")
    c.sleep(20)
    logins = [row for row in c.audit.normal_logins if row["ns"] >= restored]
    c.check(not logins, "the stopped disk logged in again after the configuration was restored")
    c.stop_workload(c.name, timeout=120, expect_clean=False)
    eject = c.eject(timeout=300)
    c.measurements["normalEject"] = {k: eject.get(k) for k in ("status", "error", "elapsedMS")}
    if eject.get("status") != "succeeded":
        force = c.force_eject()
        c.measurements["forceEject"] = {k: force.get(k) for k in ("status", "error", "elapsedMS")}
        c.check(force.get("status") == "succeeded", "force eject failed: " + json.dumps(force))
    c.require_clean_inventory("after release")


# MARK: Mutual CHAP


def scenario_secrets(credentials):
    """Every secret a mutual scenario used: its pair and any other the body gave the target."""
    return [value for value in (credentials.get("password"), credentials.get("targetPassword"),
                                *credentials.get("otherSecrets", ())) if value]


def scan_for_secrets(result, credentials, logs, root, audit=None, context=None):
    """Searches the scenario's evidence for its secrets (its log directory, the fixture root's
    small files and this run's log), records only which files matched, then drops the audit's
    and the context's references to the secrets. A match fails the scenario."""
    paths = [logs]
    try:
        paths += [path for path in Path(root).iterdir() if path.is_file()
                  and not path.is_symlink() and path.stat().st_size <= 16 * 1048576]
    except OSError:
        pass
    log = run_log_path()
    if log:
        paths.append(log)
    scan = secret_mentions(scenario_secrets(credentials), paths)
    result["secretScan"] = dict(filesSearched=scan["files"], found=scan["found"],
                                runLogSearched=log is not None)
    if scan["found"]:
        result.setdefault("errors", []).append(
            "a scenario secret appears in: " + ", ".join(scan["found"])[:600])
        result["passed"] = False
    if audit is not None:
        audit.forget_credentials()
    if context is not None:
        context.credentials = None
    return scan


def require_mutual_first_login(c):
    """Before the body: the login that mounted the disk carried a verified mutual exchange and
    the observer saw nothing it could not check. Otherwise nothing after it would count."""
    report = c.audit.mutual_report()
    with c.audit.lock:
        failed = [v["code"] for v in c.audit.violations
                  if v["code"] in ("OBSERVATION_FAILED", "LOGIN_WITHOUT_MUTUAL_CHAP")]
    c.measurements["mutualFirstLogin"] = {key: report[key] for key in (
        "attempts", "logins", "mutualLogins", "loginsWithoutMutual")}
    if report["mutualLogins"] < 1 or report["loginsWithoutMutual"] or failed:
        raise ScenarioFailure(
            "the login that mounted the disk did not carry a verified mutual CHAP exchange: "
            + json.dumps(dict(c.measurements["mutualFirstLogin"], violations=failed)))


def check_mutual_logins(c, report):
    """After the scenario: every Normal login that completed carried the mutual exchange (the
    initiator challenged the target, and both proofs verified), and, unless the body expects
    it, the initiator never ended a login after the target proved itself."""
    c.measurements["mutualCHAP"] = dict(
        {key: report[key] for key in ("attempts", "logins", "mutualLogins", "loginsWithoutMutual",
                                      "refusedAfterTargetProof")},
        reLogins=max(0, report["mutualLogins"] - 1),
        uncheckedAttempts=sum(not row["checked"] for row in report["rows"]))
    c.check(report["logins"] >= 1 and report["mutualLogins"] == report["logins"],
            f"{report['loginsWithoutMutual']} of {report['logins']} Normal logins completed "
            "without a verified mutual CHAP exchange")
    c.check(all(row["checked"] for row in report["rows"]),
            "a Normal login attempt was not checked for mutual CHAP")
    if not c.target_refusals_expected:
        c.check(not report["refusedAfterTargetProof"],
                "the initiator ended logins after the target proved itself: connections "
                + str(report["refusedAfterTargetProof"]))


def require_mutual_relogins(c, minimum, label):
    report = c.audit.mutual_report()
    relogins = report["mutualLogins"] - 1
    c.check(relogins >= minimum and report["loginsWithoutMutual"] == 0,
            f"{label}: {relogins} mutual CHAP re-logins (at least {minimum} expected), "
            f"{report['loginsWithoutMutual']} logins without the mutual exchange")
    return relogins


def scenario_r3_mutual(c):
    """R3 with mutual CHAP: each of the three resets is followed by a login in which the target
    proves itself too, and the interrupted writes are redone on it."""
    scenario_r3(c)
    require_mutual_relogins(c, 3, "three resets")


def scenario_r2_mutual(c):
    """R2 with mutual CHAP: the login after the 40 s blackhole is a mutual one."""
    scenario_r2(c)
    require_mutual_relogins(c, 1, "40 s blackhole")


def mutual_bodies():
    """The mutual CHAP variants for main(): name -> (body, Harness.scenario options), with the
    digest policy of the scenario each derives from."""
    return {
        "R3-mutual": (scenario_r3_mutual, dict(digest="CRC32C", mutual=True)),
        "R2-mutual": (scenario_r2_mutual, dict(digest="None", mutual=True)),
        "R4-mutual": (scenario_r4_mutual, dict(digest="None", mutual=True)),
    }


R4_MUTUAL_OUTAGE = 40  # Seconds of blackhole, as R2: long enough that a reconnect is needed.


def scenario_r4_mutual(c):
    """The target's mutual CHAP secret changes during a 40 s outage, so the target can no longer
    prove itself with the secret this disk logged in with (R4-auth's counterpart, for the
    target's side). Login.swift turns the wrong proof into ProtocolError.authenticationFailed,
    which RecoveringSession never retries (disposition(ofLogin:)): the first login after the
    heal must be the last, the disk must stop at once (not after 0201/0202's 30 s or the 120 s
    window) without any login rejection, and restoring the target's secret must not bring it
    back. The reason itself is not visible here: the state attribute carries none, and
    RecoveringSession logs nothing; the wire and the timing tell it apart."""
    c.target_refusals_expected = True
    original = c.credentials["targetPassword"]
    changed = chap_secret((original, c.credentials["password"]))
    c.credentials.setdefault("otherSecrets", []).append(changed)
    c.start_workload(c.name)
    c.sleep(8)
    fault = c.faults.blackhole()
    secret_fault = c.audit.fault_start("target-secret-changed", time.monotonic_ns())
    rekey = c.faults.change_target_secret(changed)
    c.audit.change_target_secret(changed)
    c.sleep(max(0.0, R4_MUTUAL_OUTAGE - (time.monotonic_ns() - fault["appliedNS"]) / SECOND))
    before_heal = c.session.state()
    heal = c.faults.heal()
    hit = c.session.wait_state({"interrupted"}, heal["startNS"], 90)
    interrupted_ns = hit[0] if hit else None
    c.sleep(2)  # The relay records the initiator's end of the refused connection.
    c.check(before_heal == "reconnecting",
            f"the disk was {before_heal} at the heal, not reconnecting: the outage proved nothing")
    c.check(hit is not None, "the disk did not stop after the target's secret changed "
            f"(state {c.session.state()})")
    report = c.audit.mutual_report()
    after = [row for row in report["rows"] if row["openedNS"] >= rekey["startNS"]]
    refused = [row for row in after if row["connection"] in report["refusedAfterTargetProof"]]
    completed = [row for row in after if row["complete"]]
    rejections = rejections_since(c, fault["startNS"])
    c.check(len(refused) == 1, f"{len(refused)} logins ended after the target's proof with its "
            "new secret (exactly one expected: the first after the heal, then no other)")
    c.check(not completed, "a Normal login completed after the target's secret changed")
    c.check(not rejections, f"the target rejected logins ({rejections[:6]}): the initiator, "
            "not the target, must refuse")
    refused_ns = refused[0]["openedNS"] if refused else None
    stop_seconds = c.seconds(refused_ns, interrupted_ns)
    # The failed proof stops the disk at once: well inside the 30 s of 0201/0202 retries.
    c.check(stop_seconds is not None and 0 <= stop_seconds <= 10,
            f"the disk stopped {stop_seconds} s after the login whose target proof failed")
    if interrupted_ns is not None:
        c.audit.forbid_mutation_after(interrupted_ns, "target authentication failed")
    c.latched = True
    # The target can prove itself again; a disk that had not stopped would now log in.
    restored = c.faults.change_target_secret(original)
    c.audit.change_target_secret(original)
    c.audit.fault_end(secret_fault, restored["endNS"])
    c.sleep(20)
    later = c.audit.connections_opened_since(refused_ns + 1) if refused_ns else []
    c.check(refused_ns is not None and not later,
            f"the stopped disk opened connections {later[:8]} after the failed target proof")
    logins = [row for row in c.audit.normal_logins if row["ns"] >= rekey["startNS"]]
    c.check(not logins, "the stopped disk logged in again")
    errors = c.session.events_of("IO_ERROR", fault["startNS"])
    writers = [e for e in errors if e.get("operation") in ("write", "fullfsync", "fsync")]
    c.measurements["targetAuthentication"] = dict(
        stateAtHeal=before_heal, outageSeconds=c.seconds(fault["appliedNS"], heal["endNS"]),
        secretChangedAfterBlackholeSeconds=c.seconds(fault["appliedNS"], rekey["endNS"]),
        attemptsAfterChange=len(after), refusedConnections=[row["connection"] for row in refused],
        refusedAfterHealSeconds=c.seconds(heal["endNS"], refused_ns),
        stoppedAfterRefusedLoginSeconds=stop_seconds,
        stoppedAfterHealSeconds=c.seconds(heal["endNS"], interrupted_ns),
        loginRejections=rejections[:6], connectionsAfterRefusal=later[:8],
        firstErrors=[{k: e.get(k) for k in ("operation", "errno", "elapsedMS")}
                     for e in errors[:6]])
    c.check(all(e.get("errno") == 5 for e in writers), "a failed write was not EIO")
    c.stop_workload(c.name, timeout=120, expect_clean=False)
    eject = c.eject(timeout=300)
    c.measurements["normalEject"] = {k: eject.get(k) for k in ("status", "error", "elapsedMS")}
    if eject.get("status") != "succeeded":
        force = c.force_eject()
        c.measurements["forceEject"] = {k: force.get(k) for k in ("status", "error", "elapsedMS")}
        c.check(force.get("status") == "succeeded", "force eject failed: " + json.dumps(force))
    c.require_clean_inventory("after release")


def scenario_r5(c):
    c.start_workload(c.name, pause=5)
    c.sleep(10)
    crash = c.faults.crash(c.root, "Crash.img")
    c.measurements["reboot"] = dict(
        bootSeconds=c.seconds(crash["crashNS"], crash["bootedNS"]),
        restoredSeconds=c.seconds(crash["crashNS"], crash["restoredNS"]))
    remaining = WINDOW + 30 - (time.monotonic_ns() - crash["crashNS"]) / SECOND
    hit = c.session.wait_state({"connected", "interrupted"}, crash["restoredNS"], max(remaining, 30))
    state = hit[1] if hit else c.session.state()
    c.measurements["afterReboot"] = dict(
        state=state, seconds=c.seconds(crash["crashNS"], hit[0]) if hit else None)
    fault = dict(kind="reboot", startNS=crash["crashNS"], appliedNS=crash["crashNS"])
    c.outage_metrics(fault, dict(startNS=crash["restoredNS"], endNS=crash["restoredNS"]), "reboot")
    if state == "connected":
        c.sleep(15)
        c.stop_workload(c.name)
        eject = c.eject()
        c.check(eject.get("status") == "succeeded", "normal eject failed: " + json.dumps(eject))
    else:
        c.note(f"after the reboot the disk is {state}; checking the fail-stop path")
        c.check(state == "interrupted", f"unexpected state after reboot: {state}")
        c.latched = True
        c.final_strict = ["fullfsync"]
        c.stop_workload(c.name, expect_clean=False)
        eject = c.eject()
        if eject.get("status") != "succeeded":
            force = c.force_eject()
            c.check(force.get("status") == "succeeded", "force eject failed: " + json.dumps(force))
    # The crash point: everything F_FULLFSYNC acknowledged before sysrq-b was sent. Nothing
    # syncs the guest before the crash, so a version acknowledged within the kernel's dirty
    # expiry (30 s) before it is durable only through the initiator's SYNCHRONIZE CACHE.
    summary = c.verify(c.root / "Crash.img", cutoff_ns=crash["crashNS"], grace_ns=3 * SECOND,
                       strict=("fullfsync",), files=[], label="crash", recent_ns=30 * SECOND)
    recent = sum(counts.get("exactRecent", 0) for counts in summary["counts"]
                 if counts.get("exactRecent") is not None)
    c.measurements["crashRecentAcknowledged"] = recent
    c.check(recent > 0, "no version acknowledged within 30 s of the crash was verified; "
            "the crash check would prove nothing")


def scenario_r6(c):
    c.start_workload(c.name)
    c.sleep(8)
    fault = c.faults.blackhole()
    outage_start = c.snapshot("OutageStart.img")
    errors = []
    deadline = time.monotonic() + WINDOW + 90
    while time.monotonic() < deadline:
        errors = c.session.events_of("IO_ERROR", fault["startNS"])
        writers = [e for e in errors if e.get("operation") in ("write", "fullfsync", "fsync")]
        if writers and c.session.state() == "interrupted":
            break
        time.sleep(1)
    writers = [e for e in errors if e.get("operation") in ("write", "fullfsync", "fsync")]
    c.check(bool(writers), "no blocked write or synchronization failed after the window")
    first_error_ns = min(e["uptimeNS"] for e in writers) if writers else None
    first_reconnecting = next((s for s, v in c.session.states
                               if s >= fault["startNS"] and v == "reconnecting"), None)
    c.measurements["expiry"] = dict(
        firstWriterErrorAfterBlackholeSeconds=c.seconds(fault["appliedNS"], first_error_ns),
        firstWriterErrorAfterReconnectingSeconds=c.seconds(first_reconnecting, first_error_ns),
        errors=[{k: e.get(k) for k in ("operation", "errno", "elapsedMS", "thread")}
                for e in errors[:12]],
        stateAfter=c.session.state())
    c.check(all(e.get("errno") == 5 for e in writers), "a failed write was not EIO")
    c.check(c.session.state() == "interrupted", f"the latched disk reports {c.session.state()}")
    if first_error_ns:
        c.audit.forbid_mutation_after(first_error_ns, "window expired")
    c.latched = True
    c.final_strict = ["fullfsync", "fsync"]
    later = c.session.command("file-write", timeout=60, label=f"{c.name}-after", bytes=4096,
                              sync="fullfsync")
    c.measurements["writeAfterLatch"] = {k: later.get(k) for k in ("ok", "writeErrno", "syncErrno",
                                                                    "writeMS", "syncMS")}
    c.check(not later.get("ok"), "a write after the latch succeeded")
    c.stop_workload(c.name, timeout=120, expect_clean=False)
    eject = c.eject(timeout=300)
    c.measurements["normalEject"] = eject
    if eject.get("status") == "succeeded":
        c.note("the normal eject of the latched disk succeeded")
    else:
        force = c.force_eject()
        c.measurements["forceEject"] = force
        c.check(force.get("status") == "succeeded", "force eject failed: " + json.dumps(force))
    c.require_clean_inventory("after release (blackhole still active)")
    heal = c.faults.heal()
    c.sleep(20)
    logins_after = [row for row in c.audit.normal_logins if row["ns"] >= heal["startNS"]]
    c.check(not logins_after, "the latched disk logged in again after the heal")
    c.measurements["afterHeal"] = dict(normalLogins=len(logins_after))
    final = c.snapshot("FinalAfterHeal.img")
    changed = compare_images(outage_start, final, c.audit, fault["appliedNS"])
    c.measurements["backingStoreChange"] = changed
    c.check(not changed["unexplainedSectors"],
            "the backing store changed outside writes sent before the outage: "
            + json.dumps(changed)[:600])


def compare_images(before, after, audit, outage_ns):
    """Blocks that differ between two 512-byte-sector images, and whether each lies within a
    WRITE the initiator sent before the outage without a GOOD flush (data the target may still
    apply when the old connection's queued bytes arrive after the heal)."""
    sector = 512
    changed = []
    with open(before, "rb") as left, open(after, "rb") as right:
        offset = 0
        while True:
            a = left.read(1048576)
            b = right.read(1048576)
            if not a and not b:
                break
            if a != b:
                for index in range(0, max(len(a), len(b)), sector):
                    if a[index:index + sector] != b[index:index + sector]:
                        changed.append((offset + index) // sector)
            offset += max(len(a), len(b))
    candidates = [w for w in audit.unsynced_writes() if w["sentNS"] < outage_ns + 5 * SECOND]
    # Each changed sector must lie inside some unsynced WRITE sent before the outage.
    unexplained = [lba for lba in changed
                   if not any(w["lba"] <= lba < w["lba"] + w["blocks"] for w in candidates)]
    return dict(changedSectors=len(changed), unexplainedSectors=unexplained[:32],
                unexplainedSectorCount=len(unexplained),
                unsyncedWritesBeforeOutage=len(candidates))


def scenario_r7(c, variant):
    """Normal eject while the disk reconnects, with unsynced data in the file system.

    `held` keeps the blackhole until the disk is released; `heal` restores the network as
    soon as the ejection returns. A timed-out ejection's Disk Arbitration request stays
    pending until its callback drains; the inner file system's last writes hold it while they
    wait for the server. `held` expects the forced path to be accepted at once and to finish
    within FORCE_SECONDS: it stops reconnecting, so those writes fail, and waits for that
    request to end. `heal` expects a repeated normal eject to succeed once the writes complete.
    """
    dirty = c.session.command("file-write", timeout=120, label=f"{c.name}-dirty",
                              bytes=8 * 1048576, sync="none")
    c.check(dirty.get("ok"), "the dirty write failed: " + json.dumps(dirty))
    if dirty.get("ok"):
        c.files.append(dict(name=dirty["name"], sha256=dirty["sha256"], required=False))
    fault = c.faults.blackhole()
    hit = c.session.wait_state({"reconnecting"}, fault["startNS"], 90)
    c.check(hit is not None, "the idle disk never reported reconnecting")
    began = time.monotonic_ns()
    result = c.session.command("eject", timeout=WINDOW + 300, timeoutSeconds=400)
    ended = time.monotonic_ns()
    c.record("eject", status=result.get("status"), elapsedMS=result.get("elapsedMS"),
             error=result.get("error"))
    if result.get("status") == "succeeded" and result.get("remainingDisks") == 0:
        c.ejected = True
    c.measurements["ejectWhileReconnecting"] = dict(
        status=result.get("status"), error=result.get("error"),
        seconds=c.seconds(began, ended), stateAtEject=hit[1] if hit else None,
        stateAfter=c.session.state(), canPrepareForceAfter=result.get("canPrepareForce"),
        reconnectingToEjectSeconds=c.seconds(hit[0], began) if hit else None)
    if variant == "held":
        c.check(result.get("status") == "failed" and "timedOut" in str(result.get("error")),
                "the eject while reconnecting did not time out: " + json.dumps(
                    {k: result.get(k) for k in ("status", "error", "elapsedMS")}))
    heal = c.faults.heal() if variant == "heal" else None
    retry = []
    if not c.ejected and variant == "heal":
        # As a user would: eject again until the earlier request no longer blocks it.
        retried = time.monotonic_ns()
        while time.monotonic_ns() - retried < (WINDOW + 120) * SECOND:
            again = c.eject(timeout=120)
            retry.append(dict(atSeconds=c.seconds(ended, time.monotonic_ns()),
                              status=again.get("status"), error=again.get("error"),
                              state=c.session.state()))
            if c.ejected or "recoveryRequired" not in str(again.get("error")):
                break
            time.sleep(2)
        c.measurements["ejectAgainAfterHeal"] = retry[-6:] + [dict(attempts=len(retry))]
        c.check(c.ejected, "the repeated normal eject after the heal did not succeed")
    if not c.ejected:
        forcing = time.monotonic_ns()
        if variant == "held":
            # Nothing may reach the target once the release begins, through the heal.
            c.audit.forbid_mutation_after(forcing, "forced release after a timed-out eject")
        force = c.force_eject(retry_seconds=0 if variant == "held" else WINDOW + 120)
        attempts = force.get("attempts", [])
        accepted = next((a for a in attempts if a["status"] == "succeeded"), None)
        c.measurements["forcedPath"] = dict(
            status=force.get("status"), error=force.get("error"),
            attempts=len(attempts), refusals=sum(a["status"] != "succeeded" for a in attempts),
            acceptedSecondsAfterEjectReturned=round(
                c.seconds(ended, forcing) + accepted["atSeconds"], 3) if accepted else None,
            statesWhileRefused=sorted({a["state"] for a in attempts
                                       if a["status"] != "succeeded"}),
            sample=attempts[:3] + attempts[-3:])
        c.check(force.get("status") == "succeeded", "force eject failed: " + json.dumps(
            {k: force.get(k) for k in ("status", "error", "elapsedMS")}))
        if variant == "held":
            c.check(len(attempts) == 1 and (force.get("elapsedMS") or 0) < FORCE_SECONDS * 1000,
                    f"the forced path after the timed-out eject was not accepted at once and "
                    f"finished within {FORCE_SECONDS} s: " + json.dumps(attempts[:3]))
    states = [(c.seconds(began, s), v) for s, v in c.session.states if s >= began]
    c.measurements["statesSinceEject"] = [states[0]] + [
        b for a, b in zip(states, states[1:]) if a[1] != b[1]] if states else []
    if heal is None:
        heal = c.faults.heal()
    c.latched = not (retry and retry[-1]["status"] == "succeeded")
    c.final_strict = ["fullfsync"]
    c.require_clean_inventory("after release")


def scenario_r8(c, variant):
    c.start_workload(c.name)
    c.sleep(8)
    fault = c.faults.blackhole()
    hit = c.session.wait_state({"reconnecting"}, fault["startNS"], 90)
    c.check(hit is not None, "the disk never reported reconnecting before the swap")
    swap_ns = time.monotonic_ns()
    swapped = json.loads(c.harness.vm.configure("swap-" + variant, c.nonce, capture_output=True,
                                                text=True).stdout.strip().splitlines()[-1])
    c.record("swap", variant=variant, status=swapped)
    c.audit.forbid_mutation_after(swap_ns, "logical unit replaced")
    heal = c.faults.heal()
    outcome = c.session.wait_state({"interrupted", "connected"}, heal["startNS"], 150)
    c.measurements["afterSwap"] = dict(
        state=outcome[1] if outcome else c.session.state(),
        seconds=c.seconds(heal["endNS"], outcome[0]) if outcome else None,
        storeAfterSwap=swapped.get("stores"))
    c.check(outcome is not None and outcome[1] == "interrupted",
            f"the replaced logical unit was not refused (state {c.session.state()})")
    # The refusal must come from revalidating the new logical unit: a completed Normal login
    # after the heal that identified it (INQUIRY, READ CAPACITY) and sent it no WRITE or SYNC.
    report = c.audit.recovery_report(latched=True)
    revalidated = [info for info in report["connections"]
                   if info["sessionType"] == "Normal" and info["readyNS"]
                   and info["readyNS"] >= heal["startNS"]]
    c.measurements["revalidation"] = [dict(id=i["id"], preIO=i["preIO"], reads=i["readsSent"],
                                           writes=i["writesSent"], syncs=i["syncsSent"])
                                      for i in revalidated][:8]
    c.check(any("12" in i["preIO"] and ("9e" in i["preIO"] or "25" in i["preIO"])
                for i in revalidated),
            "no login after the swap identified the replacement before the refusal")
    c.check(all(i["writesSent"] == 0 and i["syncsSent"] == 0 for i in revalidated),
            "a WRITE or SYNC reached the replacement logical unit")
    c.latched = True
    c.final_strict = ["fullfsync", "fsync"]
    c.stop_workload(c.name, timeout=120, expect_clean=False)
    eject = c.eject(timeout=300)
    c.measurements["normalEject"] = {k: eject.get(k) for k in ("status", "error", "elapsedMS")}
    if eject.get("status") != "succeeded":
        force = c.force_eject()
        c.measurements["forceEject"] = {k: force.get(k) for k in ("status", "error", "elapsedMS")}
        c.check(force.get("status") == "succeeded", "force eject failed: " + json.dumps(force))
    c.require_clean_inventory("after release")
    status = json.loads(c.harness.vm.configure("status", c.nonce, capture_output=True,
                                               text=True).stdout)
    key = "imageSHA256" if variant == "serial" else "swappedSHA256"
    c.measurements["replacementHash"] = dict(atSwap=swapped.get(key), atEnd=status.get(key))
    c.check(swapped.get(key) == status.get(key) and status.get(key),
            "the replacement logical unit's backing file changed")
    if variant == "size":
        # The swapped (larger) file is the export now; snapshot the original separately.
        pass


def scenario_sleep(c, seconds, manual=False, wait_minutes=SLEEP_WAIT_MINUTES, watch=None):
    """Sleeps this host. With `manual`, the person at the Mac sleeps and wakes it instead.

    The workload runs across the sleep, each maintenance DarkWake and the full wake; it is
    stopped, and the disk ejected, only once this Mac is fully awake with its screen unlocked
    (SleepWatch). A wake that never gets there by the bound is a harness error: an eject then
    would only show the Keychain refusing a locked screen (APP043), not the product's
    recovery. The cleanup then retries the eject once the screen is unlocked."""
    watch = watch or SleepWatch(c.record, c.sleep)
    c.start_workload(c.name)
    c.sleep(8)
    # The awake clock stands still during sleep, so each sleep lies at one instant of it,
    # between two polls of the wait. Every connection cut from here on falls in this fault.
    asked = watch.awake_ns()
    began = watch.wall()
    c.audit.fault_start("sleep", asked)
    if manual:
        sleep_by = began + wait_minutes * 60
        print(f"SLEEP NOW: put this Mac to sleep by hand (close the lid, or choose Sleep in the "
              f"Apple menu) and wake it after about {seconds} s. Waiting until "
              f"{short_clock(sleep_by)} ({wait_minutes:g} minutes, --sleep-wait-minutes) for "
              "the sleep. After the wake, unlock the screen: the workload stops and the disk "
              "is ejected only once this Mac is fully awake with its screen unlocked, at the "
              f"latest {WAKE_UNLOCK_MINUTES} minutes after the sleep.", flush=True)
    else:
        subprocess.run(["sudo", "-n", "pmset", "relative", "wake", str(seconds)], check=True,
                       timeout=30)
        subprocess.run(["pmset", "sleepnow"], check=True, timeout=30)
        sleep_by = watch.wall() + 600
    c.record("sleep-requested", manual=manual, wall=wall_clock(began),
             sleepBy=wall_clock(sleep_by))
    outcome = watch.wait(sleep_by, requested=seconds)
    log = watch.log(began)
    c.measurements["sleep"] = dict(
        requestedSeconds=seconds, **watch.summary(),
        powerLog=None if log is None else [f"{wall_clock(stamp)} {kind}: {text}"
                                           for stamp, kind, text in log[-48:]])
    if outcome == "no-sleep":
        c.check(False, f"the host did not sleep (slept {round(watch.slept, 1)} s by "
                f"{short_clock(sleep_by)})")
        return
    if outcome != "ready":
        what = ("its screen was still locked" if outcome == "locked"
                else "it was not fully awake (only maintenance DarkWakes)")
        row = c.audit.harness_failure(
            "SLEEP_WAKE_NOT_READY", limit=outcome, unlockBy=watch.summary()["unlockBy"],
            message=f"this Mac slept {round(watch.slept)} s, but {what} by "
                    f"{short_clock(watch.unlock_by)}: the workload was not stopped and the disk "
                    "was not ejected from a full wake with the screen unlocked, so this run is "
                    "not evidence of the full-wake path")
        raise HarnessError(row)
    full = watch.full_wake
    c.wait_connected(full["sinceNS"], 180, "after the full wake")
    after = c.measurements["afterWake"] = wake_reconnects(c.session.states, asked, watch.sleeps,
                                                          full["sinceNS"])
    c.record("after-full-wake", state=c.session.state(), **after["afterFullWake"],
             reconnects=[dict(wake=row["wake"], seconds=row["reconnectSeconds"])
                         for row in after["reconnects"]])
    steps = c.workload_steps(c.name)
    c.check(c.wait_progress(c.name, steps, timeout=120) is not None,
            "the workload made no progress after the full wake and the unlock")
    c.sleep(10)
    c.stop_workload(c.name)
    locked = watch.state().get("locked")
    c.record("eject-requested", screenLocked=locked)
    eject = c.eject()
    if eject.get("status") != "succeeded" and keychain_refused(eject):
        c.check(False, "normal eject failed in its last step, removing the mount resource "
                f"Keychain item (screen locked at the eject: {locked}; the Keychain refuses "
                "it while the screen is locked, APP043): " + json.dumps(eject))
    else:
        c.check(eject.get("status") == "succeeded", "normal eject failed: " + json.dumps(eject))


EXTENSION_READ_ERROR = re.compile(
    r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) +\S+ +ISCSIFSExtension\[[^\]]*\] "
    r".*\bFSVolumeConnector readFrom:.*\berror:5(?!\d)")


def extension_read_errors(path):
    """The extension's failed reads (FSVolumeConnector readFrom … error:5) in the system log
    (collect_logs: compact style, local time to the millisecond), as (wall time, line). Lines
    of other processes and other operations don't count."""
    reads = []
    with open(path, errors="replace") as source:
        for line in source:
            match = EXTENSION_READ_ERROR.match(line)
            if match is not None:
                stamp = datetime.datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S.%f")
                reads.append((stamp.timestamp(), line.rstrip()[:400]))
    return reads


def measure_idle_premise(c, path, outage):
    """R9 issues no I/O during the outage, so the disk is idle only if nothing else reads it
    then. A read that reaches it waits, and the extension logs FSVolumeConnector readFrom …
    error:5 when it fails. measurements.idlePremise counts such lines from the blackhole being
    applied to the end of its heal (fault appliedNS and endNS; the runner's cleanup heals a
    blackhole the body left), and those after the heal to the end of the collected log. The
    log is dated in wall time, so both bounds are dated from the clock pair (wall, ns) taken
    at the blackhole. Where the reads come from is not known: the count never changes the
    verdict, the failures or the harness errors; a count above zero is only noted."""
    fault = outage["fault"]
    if fault.get("endNS") is None:
        c.measurements["idlePremise"] = dict(notMeasured="the blackhole has no recorded end")
        return

    def wall(ns):
        return outage["wall"] + (ns - outage["ns"]) / SECOND

    def clock(seconds):
        return datetime.datetime.fromtimestamp(seconds).astimezone().isoformat(
            timespec="milliseconds")

    since, until = wall(fault["appliedNS"]), wall(fault["endNS"])
    measured = c.measurements["idlePremise"] = dict(window=dict(since=clock(since),
                                                                until=clock(until)))
    try:
        reads = extension_read_errors(path)
    except OSError as error:
        measured["notMeasured"] = f"the system log is unreadable: {error}"
        return
    during = [line for stamp, line in reads if since <= stamp <= until]
    measured.update(readErrors=len(during), examples=during[:8],
                    readErrorsAfterHeal=sum(stamp > until for stamp, _ in reads))
    if during:
        c.note(f"{len(during)} read(s) failed in the extension during the outage (see "
               "measurements.idlePremise); the disk was not idle from the extension's point "
               "of view")


def scenario_r9(c):
    c.sleep(5)
    fault = c.faults.blackhole()
    # One clock pair dates the outage in the system log afterwards (measure_idle_premise).
    outage = dict(fault=fault, wall=time.time(), ns=time.monotonic_ns())
    c.system_log_checks.append(lambda path: measure_idle_premise(c, path, outage))
    hit = c.session.wait_state({"reconnecting"}, fault["startNS"], 90)
    c.check(hit is not None, "the idle disk never reported reconnecting")
    c.sleep(max(0, 300 - (time.monotonic_ns() - fault["appliedNS"]) / SECOND))
    during = c.session.state()
    heal = c.faults.heal()
    c.measurements["stateBeforeHeal"] = during
    c.check(during == "reconnecting", f"after 5 minutes idle the disk reports {during}")
    # FSKit's periodic flushes find nothing to write: none waits, fails or stops the disk.
    errors = c.session.events_of("IO_ERROR", fault["startNS"])
    c.check(not errors, "the idle disk reported errors during the outage: "
            + json.dumps(errors[:4]))
    c.wait_connected(heal["endNS"] - 1, 150, "after a 5 minute idle outage")
    c.outage_metrics(fault, heal, "5 min idle blackhole")
    c.start_workload(c.name)
    c.sleep(20)
    c.stop_workload(c.name)
    eject = c.eject()
    c.check(eject.get("status") == "succeeded", "normal eject failed: " + json.dumps(eject))


def scenario_r10(c, minutes):
    generator = random.Random(int(c.nonce[:8], 16))
    deadline = time.monotonic() + minutes * 60
    c.start_workload(c.name, pause=20)
    faults = []
    with Sampler(15) as sampler:
        while time.monotonic() < deadline - 90:
            c.sleep(generator.uniform(20, 60))
            if time.monotonic() >= deadline - 90:
                break
            if generator.random() < 0.75:
                length = generator.uniform(5, 60)
                fault = c.faults.blackhole()
                c.sleep(length)
                heal = c.faults.heal()
                hit = c.wait_connected(heal["endNS"] - 1, 150, f"after a {length:.0f}s blackhole")
                faults.append(dict(kind="blackhole", seconds=round(length, 1),
                                   reconnectedSeconds=c.seconds(heal["endNS"], hit[0]) if hit else None))
                c.outage_metrics(fault, heal, f"soak blackhole {length:.0f}s")
            else:
                reset = c.faults.reset()
                hit = c.wait_connected(reset["endNS"], 150, "after a reset")
                faults.append(dict(kind="reset", sockets=reset["sockets"],
                                   reconnectedSeconds=c.seconds(reset["endNS"], hit[0]) if hit else None))
            errors = c.session.events_of("IO_ERROR", c.started_ns)
            if errors:
                c.check(False, "application-visible error during the soak: " + json.dumps(errors[:2]))
                break
    c.measurements["soakFaults"] = faults
    rows = sampler.rows
    c.measurements["extension"] = summarize_extension(rows)
    c.stop_workload(c.name)
    eject = c.eject()
    c.check(eject.get("status") == "succeeded", "normal eject failed: " + json.dumps(eject))


FORCE_SECONDS = 30  # A forced release must not take the recovery window (WINDOW).
OFFER_DELAY = 10  # AttachedDisk.forcedReleaseReconnectingDelay


def released_while_unreachable(c, fault):
    """After a forced or normal release while the server stays away: no residue, then after
    the heal no login (and, through the audit's forbid window, no WRITE or SYNC)."""
    c.require_clean_inventory("after release (blackhole still active)")
    heal = c.faults.heal()
    c.sleep(20)
    logins = [row for row in c.audit.normal_logins if row["ns"] >= heal["startNS"]]
    c.check(not logins, "the released disk logged in again after the heal")
    c.measurements["afterHeal"] = dict(normalLogins=len(logins))
    c.measurements["outage"] = dict(seconds=c.seconds(fault["appliedNS"], heal["endNS"]))


def scenario_r11(c):
    """Read-write disk, server unreachable, Force Eject with no Eject before it.

    Data the file system hasn't written yet is lost by design; the confirmation says so. The
    release must not wait for the recovery window, and nothing is sent afterwards."""
    dirty = c.session.command("file-write", timeout=120, label=f"{c.name}-dirty",
                              bytes=4 * 1048576, sync="none")
    c.check(dirty.get("ok"), "the dirty write failed: " + json.dumps(dirty))
    if dirty.get("ok"):
        c.files.append(dict(name=dirty["name"], sha256=dirty["sha256"], required=False))
    fault = c.faults.blackhole()
    hit = c.session.wait_state({"reconnecting"}, fault["startNS"], 90)
    c.check(hit is not None, "the disk never reported reconnecting")
    # As a user would: the disk list shows the disk reconnecting, then Force Eject.
    shown = c.wait_record("reconnecting/", fault["startNS"], 30)
    c.check(shown is not None, "the disk list never showed the disk reconnecting")
    c.wait_force_offered(shown, "R11")
    forcing = time.monotonic_ns()
    c.audit.forbid_mutation_after(forcing, "forced release while unreachable")
    force = c.force_eject()
    finished = time.monotonic_ns()
    c.measurements["forceEject"] = dict(
        {k: force.get(k) for k in ("status", "error", "elapsedMS", "prepareMS", "forceMS",
                                   "canPrepareBefore", "reportsLostConnection")},
        seconds=c.seconds(forcing, finished),
        reconnectingToForceSeconds=c.seconds(hit[0], forcing) if hit else None)
    c.check(force.get("status") == "succeeded", "force eject failed: " + json.dumps(
        {k: force.get(k) for k in ("status", "error", "elapsedMS")}))
    c.check(force.get("canPrepareBefore") is True and force.get("reportsLostConnection") is True,
            "Force Eject was not offered for the reconnecting disk, or its confirmation didn't "
            "report the lost connection")
    c.check(c.seconds(forcing, finished) < FORCE_SECONDS,
            f"the forced release took {c.seconds(forcing, finished)} s")
    c.latched = True
    c.final_strict = ["fullfsync"]
    released_while_unreachable(c, fault)


def scenario_r12(c, variant):
    """Read-only disk, server unreachable: a normal Eject of the idle disk, or a Force Eject
    with an application's read waiting in the extension, ends promptly.

    The kernel refuses attribute writes on a read-only mount, so the forced path stops
    reconnecting by reading the volume's read-only control instead (no write is possible)."""
    first = c.session.command("raw-read", timeout=60, offset=0, length=65536)
    c.check(first.get("ok") and first.get("count") == 65536, "the read before the outage failed")
    # Who could reach the read-only control: owners and modes along the bridge's path.
    c.measurements["controlPaths"] = c.session.command("stat-paths", timeout=60)
    c.measurements["controlByFileID"] = c.session.command("volfs-path", timeout=60)
    fault = c.faults.blackhole()
    hit = c.session.wait_state({"reconnecting"}, fault["startNS"], 90)
    c.check(hit is not None, "the disk never reported reconnecting")
    waiting = None
    if variant == "force":
        # As a user would: the disk list shows the disk reconnecting, then Force Eject.
        shown = c.wait_record("reconnecting/", fault["startNS"], 30)
        c.check(shown is not None, "the disk list never showed the disk reconnecting")
        c.wait_force_offered(shown, "R12-force")
        # An uncached read of the image, as an application's would, waits for the server.
        waiting = c.session.send("raw-read", offset=96 * 1048576, length=4096)
        c.sleep(3)
        c.check(c.session.poll(waiting) is None, "the read during the outage didn't wait")
    began = time.monotonic_ns()
    c.audit.forbid_mutation_after(began, f"read-only {variant} while unreachable")
    if variant == "eject":
        result = c.eject(timeout=WINDOW + 60)
        c.measurements["eject"] = {k: result.get(k) for k in ("status", "error", "elapsedMS")}
        c.check(result.get("status") == "succeeded", "normal eject failed: " + json.dumps(
            c.measurements["eject"]))
    else:
        result = c.force_eject()
        c.measurements["forceEject"] = {k: result.get(k) for k in (
            "status", "error", "elapsedMS", "prepareMS", "forceMS", "canPrepareBefore",
            "reportsLostConnection")}
        c.check(result.get("status") == "succeeded", "force eject failed: " + json.dumps(
            c.measurements["forceEject"]))
        c.check(result.get("canPrepareBefore") is True
                and result.get("reportsLostConnection") is True,
                "Force Eject was not offered for the reconnecting disk, or its confirmation "
                "didn't report the lost connection")
    ended = time.monotonic_ns()
    c.measurements["releaseSeconds"] = c.seconds(began, ended)
    c.check(c.seconds(began, ended) < FORCE_SECONDS,
            f"releasing the read-only disk took {c.seconds(began, ended)} s")
    if waiting is not None:
        read = c.session.wait(waiting, 60)
        c.measurements["waitingRead"] = {k: read.get(k) for k in (
            "ok", "count", "errno", "elapsedMS", "endNS")}
        c.check(not read.get("ok"), "the read that waited for the server succeeded")
        c.check(read.get("endNS", 0) <= ended + 5 * SECOND,
                "the waiting read did not end with the release")
    c.latched = True
    c.final_strict = []
    released_while_unreachable(c, fault)


TRANSPORT_DEADLINE = 15  # TCPTransport's operation timeout: min(15 s, the login budget)
COMMAND_DEADLINE = 30  # ISCSISession's commandTimeout (withDeadline)
# The initiator's end of a stalled connection, in seconds after the cut. The receive's deadline
# is armed when the cut bytes arrive, just after the forwarder stamps the cut. For `dataout`
# the low bound counts from the cut and the high bound from the forwarder kernel's last intake
# (judge_stall): the send that times out starts after the last one that completed.
STALL_ABANDON_BOUNDS = (TRANSPORT_DEADLINE - 0.5, TRANSPORT_DEADLINE + 5)
STALL_CUT_TIMEOUT = 60  # Seconds the workload has to produce the PDU an armed stall cuts.
DATAOUT_WRITE_BYTES = 16 * 1048576  # R13-dataout's synchronized file write.
# R13-dataout: the initiator's close must come this many seconds before the command deadline
# (counted from the WRITE's start), to tell the send deadline from it on its own.
DATAOUT_COMMAND_MARGIN = 5
STALL_LOG_PREDICATE = ('process == "ISCSIFSExtension" AND (subsystem BEGINSWITH "dev.soba.iscsi" '
                       'OR subsystem == "com.apple.network")')


def judge_stall(stall, states, logins):
    """What the forwarder saw of one stall (RecoveryWireAudit.arm_stall), and every finding
    that contradicts the initiator's transport deadline ending it. `states` are the probe's
    (uptimeNS, state) samples, `logins` the times of the audit's Normal logins."""
    def seconds(start, end):
        return None if start is None or end is None else round((end - start) / SECOND, 3)

    start = stall["startNS"]
    end = stall["initiatorEnd"]
    target_end = stall["targetEnd"]
    following = stall["nextConnection"]
    redo = stall["redo"]
    reconnecting = next((s for s, v in states if start and s >= start and v == "reconnecting"),
                        None)
    stopped = next((s for s, v in states if start and s >= start and v == "interrupted"), None)
    login = next((ns for ns in logins if start and ns >= start), None)
    dataout = stall["kind"] == "dataout"
    hold = stall.get("hold") or {}
    if dataout:
        # The initiator's close, as the kernel's listing showed it (RecoveryWireAudit._hold):
        # its FIN can't reach the forwarder before the bytes the stall leaves unread.
        close = hold.get("closedNS")
    else:
        close = end["ns"] if end and not end["afterRelease"] else None
    abandon = seconds(start, close)
    metrics = dict(
        kind=stall["kind"], connection=stall["connection"], pdu=stall["pdu"],
        command=stall["command"], armedToCutSeconds=seconds(stall["armedNS"], start),
        commandSentBeforeCutSeconds=seconds((stall["command"] or {}).get("sentNS"), start),
        abandonSeconds=abandon, initiatorEnd=end and end["how"],
        targetEndSeconds=seconds(start, target_end and target_end["ns"]),
        targetEnd=target_end and target_end["how"],
        nextConnectionSeconds=seconds(start, following and following["openedNS"]),
        firstLoginSeconds=seconds(start, login),
        toReconnectingSeconds=seconds(start, reconnecting),
        redo=redo and dict(connection=redo["connection"], status=redo["status"],
                           sentSeconds=seconds(start, redo["sentNS"])),
        discarded=dict(stall["discarded"]), released=stall["released"])
    problems = []
    if dataout:
        metrics["dataout"], dataout_problems = judge_dataout(stall, start, close)
    if start is None:
        return metrics, [f"no {stall['kind']} PDU was cut, so nothing stalled"]
    if stall["released"] is not None:
        problems.append("the initiator did not end the stalled connection by itself; the "
                        "harness released it: " + json.dumps(stall["released"]))
    low, high = STALL_ABANDON_BOUNDS
    if abandon is None:
        problems.append("the forwarder saw no end of the initiator's side of the stalled "
                        "connection")
    elif not dataout and not low <= abandon <= high:
        problems.append(f"the initiator ended the stalled connection {abandon} s after the cut, "
                        f"outside [{low}, {high}] s: its transport deadline is "
                        f"{TRANSPORT_DEADLINE} s, its command deadline {COMMAND_DEADLINE} s")
    if dataout:
        problems.extend(dataout_problems)  # Its bounds count from the last intake too.
    ended = close if dataout else end and end["ns"]
    if following is None or (ended is not None and following["openedNS"] < ended):
        problems.append("no new connection followed the end of the stalled one")
    if login is None:
        problems.append("no Normal login after the stall")
    if reconnecting is None or seconds(start, reconnecting) >= COMMAND_DEADLINE:
        problems.append("the disk did not report reconnecting within the command deadline "
                        f"({metrics['toReconnectingSeconds']} s after the cut)")
    if stopped is not None:
        problems.append(f"the disk stopped {seconds(start, stopped)} s after the cut")
    if redo is None or redo["status"] != "good":
        problems.append("the command whose PDU was cut was not sent again on a later "
                        "connection, or did not complete: " + json.dumps(redo))
    return metrics, problems


def judge_dataout(stall, start, close):
    """A `dataout` stall's own evidence (RecoveryWireAudit._hold) and its findings, given the
    cut (`start`) and the initiator's close as the kernel's listing showed it (`close`).

    The initiator's sends blocked if the bytes drained after its close lack the burst's last
    Data-Out: it never handed the whole burst to its kernel. Each Data-Out is its own send
    with its own 15 s deadline, so the one that times out started after the last one that
    completed, which in the measurements came no earlier than the cut and no later than the
    forwarder kernel's last intake of the initiator's bytes (`lastAcceptedSeconds`; a
    zero-window probe added one step about 5 s in). The close must therefore be at least
    TRANSPORT_DEADLINE - 0.5 s after the cut and at most TRANSPORT_DEADLINE + 5 s after that
    last intake, and in any case DATAOUT_COMMAND_MARGIN before the command deadline from the
    WRITE's start. A burst drained whole shows nothing of a send that never finished, and a
    close at the command deadline while the initiator still held part of a one-PDU burst
    outside its kernel (heldByInitiatorBytes, from the listings) is reported as such; either
    fails the scenario. A drain after a release proves nothing (`blocked` is None)."""
    def seconds(begin, finish):
        return None if begin is None or finish is None else round((finish - begin) / SECOND, 3)

    hold = stall.get("hold") or {}
    r2t = stall.get("r2t") or {}
    handed = hold.get("handed") or {}
    samples = hold.get("samples") or []
    queued = hold.get("queued") or []
    accepted = max(start or 0, hold.get("lastGrowthNS") or 0) or None
    command = (stall.get("command") or {}).get("sentNS")
    whole = bool(handed.get("final")) and handed.get("dataBytes", 0) >= r2t.get(
        "desiredLength", float("inf"))
    # A drain after the harness released the stall reads nothing the initiator handed over.
    blocked = (None if hold.get("drainEnd") != "eof" or stall.get("released") is not None
               else not whole)
    # For a burst in one Data-Out: its bytes neither at the forwarder nor in the initiator's
    # kernel at the last listing that showed the socket, so still held by the initiator.
    pdu = stall.get("pdu") or {}
    alive = [row for row in samples if row.get("seen") and row.get("sendQueue") is not None]
    held = None
    if alive and queued and pdu and pdu.get("dataLength", 0) >= r2t.get("desiredLength", 0) > 0:
        before = [row["bytes"] for row in queued if row["ns"] <= alive[-1]["ns"]]
        held = (pdu["frameBytes"] - pdu["forwardedBytes"] - (before or [queued[0]["bytes"]])[-1]
                - alive[-1]["sendQueue"])
    metrics = dict(
        r2t=r2t or None, observed=hold.get("observed"), closedHow=hold.get("closedHow"),
        closeSeconds=seconds(start, close), lastAcceptedSeconds=seconds(start, accepted),
        closeAfterLastAcceptedSeconds=seconds(accepted, close),
        closeResolutionSeconds=seconds(hold.get("aliveNS"), close),
        commandToCloseSeconds=seconds(command, close),
        queuedFirst=queued[0]["bytes"] if queued else None,
        queuedMaximum=hold.get("maximumQueued"), readBeyondCut=hold.get("readBeyondCut"),
        initiatorFirst=samples[0] if samples else None,
        initiatorLast=samples[-1] if samples else None,
        probeErrors=len(hold.get("probeErrors") or []), drainedBytes=hold.get("drainedBytes"),
        drainEnd=hold.get("drainEnd"), handed=handed or None, blocked=blocked,
        heldByInitiatorBytes=held)
    if start is None:
        return metrics, []
    problems = []
    if not hold.get("observed"):
        problems.append("the forwarder never saw the initiator's end of the stalled connection "
                        "ESTABLISHED in the kernel's listing (lsof), so it could not time the "
                        "initiator's close: " + json.dumps(hold.get("probeErrors", [])[:4]))
    if blocked is None and stall.get("released") is not None:
        problems.append("what the initiator had handed its kernel is unknown from the drain: "
                        "the harness released the stall before the initiator closed")
    elif blocked is None:
        problems.append("what the initiator had handed its kernel is unknown: the drain after "
                        f"its close ended with {hold.get('drainEnd')}")
    elif not blocked:
        problems.append(
            f"the bytes drained after the initiator's close hold its whole Data-Out burst "
            f"({handed.get('dataBytes')} of {r2t.get('desiredLength')} B): it had handed all "
            f"of it to its kernel by its close, so nothing shows a send that never finished; "
            f"it closed the connection {metrics['closeSeconds']} s after the cut and "
            f"{metrics['commandToCloseSeconds']} s after the WRITE was sent (command deadline "
            f"{COMMAND_DEADLINE} s)")
    to_close = metrics["commandToCloseSeconds"]
    if held and (to_close is None or to_close >= COMMAND_DEADLINE - DATAOUT_COMMAND_MARGIN):
        problems.append(
            f"the initiator still held {held} B of the burst outside its kernel "
            f"{seconds(start, alive[-1]['ns'])} s after the cut (the listing's last change; "
            f"its socket was listed until {seconds(start, hold.get('aliveNS'))} s), yet its "
            f"{TRANSPORT_DEADLINE} s send deadline did not end the connection: it closed "
            f"{to_close} s after the WRITE was sent")
    if close is not None:
        low, high = STALL_ABANDON_BOUNDS
        after = metrics["closeAfterLastAcceptedSeconds"]
        if metrics["closeSeconds"] < low or after > high:
            problems.append(
                f"the initiator closed its end of the stalled connection "
                f"{metrics['closeSeconds']} s after the cut and {after} s after the forwarder's "
                f"kernel last took in its bytes, outside [{low} s after the cut, {high} s after "
                f"that]: its send deadline is {TRANSPORT_DEADLINE} s, its command deadline "
                f"{COMMAND_DEADLINE} s ({metrics['commandToCloseSeconds']} s after the WRITE "
                "was sent)")
        # Late intake would stretch the bound above toward the command deadline; keep the
        # close clearly before it on its own.
        to_close = metrics["commandToCloseSeconds"]
        if to_close is not None and to_close >= COMMAND_DEADLINE - DATAOUT_COMMAND_MARGIN:
            problems.append(
                f"the initiator closed its end of the stalled connection {to_close} s after "
                f"the WRITE was sent, not clearly before its {COMMAND_DEADLINE} s command "
                f"deadline (at most {COMMAND_DEADLINE - DATAOUT_COMMAND_MARGIN} s)")
    return metrics, problems


def target_timers(c):
    """LIO's own timers and session keys for this target (read-only). They can't end the
    stall for the initiator: the forwarder never passes the target's end on. The DataOut
    and NOP-In timers are attributes of the initiator's node ACL, not of the portal group."""
    names = ("attrib/default_erl", "param/DefaultTime2Wait", "param/ErrorRecoveryLevel",
             "param/MaxRecvDataSegmentLength", "acls/*/attrib/dataout_timeout",
             "acls/*/attrib/nopin_timeout", "acls/*/attrib/nopin_response_timeout")
    quoted = " ".join("'%s'" % name for name in names)  # $d/$f below expands the ACL glob.
    script = ("for d in /sys/kernel/config/target/iscsi/iqn.*/tpgt_*; do for f in " + quoted
              + '; do echo "$f $(cat $d/$f 2>/dev/null)"; done; done')
    try:
        result = c.faults.sudo(script, timeout=30)
        return {key: value.strip() for key, _, value in
                (line.partition(" ") for line in result.stdout.splitlines()) if key}
    except Exception as error:
        return dict(error=f"{type(error).__name__}: {error}")


def collect_stall_log(start_wall, end_wall, destination, runner=subprocess.run, cut_wall=None):
    """The extension's own and Network.framework's log lines, info and debug included, for
    one stall window (read-only). A failure is recorded, never raised. With `cut_wall`,
    `cancels` lists when Network.framework logged a connection's cancel, in seconds after
    the cut (log time stamps have millisecond resolution)."""
    form = "%Y-%m-%d %H:%M:%S"
    start = time.strftime(form, time.localtime(start_wall))
    end = time.strftime(form, time.localtime(end_wall + 1))
    record = dict(file=str(destination), start=start, end=end)
    try:
        with open(destination, "w") as output:
            result = runner(["/usr/bin/log", "show", "--style", "compact", "--info", "--debug",
                             "--start", start, "--end", end, "--predicate", STALL_LOG_PREDICATE],
                            stdout=output, stderr=subprocess.STDOUT, timeout=300, check=False)
        record["exit"] = result.returncode
    except subprocess.TimeoutExpired:
        record["unavailable"] = "TimeoutExpired"
    except Exception as error:
        record["unavailable"] = f"{type(error).__name__}: {error}"
    keys = ("cancel", "timed out", "timeout", "closed", "reset", "fail", "error")
    total, examples, cancels = 0, [], []
    try:
        with open(destination, errors="replace") as source:
            for line in source:
                total += 1
                if len(examples) < 80 and any(key in line.lower() for key in keys):
                    examples.append(line.rstrip()[:300])
                if (cut_wall is not None and len(cancels) < 16
                        and "[com.apple.network:connection]" in line
                        and line.rstrip().endswith("] cancel")):
                    try:
                        stamp = datetime.datetime.strptime(line[:23], "%Y-%m-%d %H:%M:%S.%f")
                    except ValueError:
                        continue
                    cancels.append(round(stamp.timestamp() - cut_wall, 3))
    except OSError:
        pass
    record.update(lines=total, examples=examples)
    if cut_wall is not None:
        record["cancels"] = cancels
    return record


def scenario_r13(c, variant):
    """Transport deadline: the initiator is left inside a PDU and nothing more arrives, or
    (`dataout`) inside a Data-Out burst that nothing reads any more.

    `datain` cuts a READ's Data-In after its header (and header digest) and half of its data;
    `response` cuts a WRITE's SCSI Response in the middle of its header. From the cut on, the
    audit forwarder forwards nothing more on that connection in either direction and never
    passes the target's end on (RecoveryWireAudit.arm_stall), so the target can't end the
    initiator's side; LIO may close its own side meanwhile (for example its DataOut timeout
    for an R2T whose data it never gets), which the initiator never sees.

    Expected, from the code at ae55ae2:
    - ISCSISession's receiver calls TCPTransport.receive with waitingForActivity = false while
      its decoder is not at a frame boundary (readContext), so this receive carries the
      transport's operation deadline (TCPTransport.operation, on its DeadlineTimer). The
      timeout is min(15 s, the login budget) (RedirectingLogin in SessionConnector): 15 s for
      the one portal here, for the first login (45 s budget) and for a reconnection early in
      the recovery window (RecoveringSession.attemptTimeout, 45 s).
    - At 15 s the receive fails with ProtocolError.timedOut and cancels the NWConnection (the
      forwarder sees the initiator's end). The receiver task fails the session
      (ISCSISession.fail), which fails the waiting commands with that error and reports it to
      RecoveringSession: disposition(ofTermination:) of .timedOut is .reconnect.
    - RecoveringSession.recover waits DefaultTime2Wait (2 s from LIO), logs in again with the
      same ISID and TSIH 0, revalidates the logical unit, and execute() sends the interrupted
      commands again on the new session. No error reaches the application; the disk does not
      stop.
    - The 30 s command deadline (ISCSISession.withDeadline) would end it at about 30 s
      instead; the idle heartbeat (10 s, 5 s timeout) doesn't run while a command is in flight.

    `dataout` cuts the initiator's first Data-Out for an R2T that solicits a whole burst
    (256 KiB, the most the product negotiates) of a WRITE, after its header (and header
    digest) and at most 4 KiB of its data, and from then on reads nothing from the initiator.
    It runs with ClampedForwarder, without which the loopback kernel takes in more than a
    burst. After arming, the probe writes DATAOUT_WRITE_BYTES to a new file with F_FULLFSYNC,
    whose WRITEs (up to 1 MiB each) solicit whole bursts.

    Expected for `dataout`, from the same code: with InitialR2T Yes, ImmediateData No and
    MaxOutstandingR2T 1 the initiator sends Data-Out only for an R2T, at most MaxBurstLength
    (at most 262,144 B, LoginNegotiation) per R2T, and one command at a time
    (executeCommand's inFlight), so a larger write only adds bursts, never a larger unsent
    remainder. ISCSISession.sendData sends each Data-Out (at most the target's declared
    MaxRecvDataSegmentLength; with this LIO target a whole 256 KiB burst went as one Data-Out
    in 20261116-185051, so one send) through sendFrame and TCPTransport.send, which is
    TCPTransport.operation with waitingForActivity false: each send has its own 15 s
    deadline from its call and completes when Network.framework reports .contentProcessed.
    (With an NWConnection test sender on this Mac, sends completed at once while the socket
    buffers had room and stopped completing once they were full; the bytes drained after its
    close held at most one frame more than its completed sends. One send of 164,048 or
    205,048 B completed at once although only about 147,000 B of a send had gone into the
    kernels in earlier tries, and one of 262,200 B did not.) A send the buffers can't take
    waits; at 15 s it
    fails with ProtocolError.timedOut and cancels the NWConnection. Nothing else on the
    Data-Out path is timed: checkDeadlines between frames checks only the 30 s command
    deadline from the WRITE's start, the receiver waits at a frame boundary (no deadline) and
    the heartbeat doesn't run. executeCommand fails the session with the send's error
    (failOperation), and RecoveringSession reconnects and sends the WRITE again as above. So
    the initiator closes its end 15 s after its last completed send, which in the
    measurements came between the cut and the forwarder kernel's last intake of its bytes,
    well before 30 s after the WRITE was sent. Had the sends not blocked, the command
    deadline would end the stall instead (a failure here).
    The initiator's close can't be seen on the wire (its FIN waits behind the unread bytes):
    the forwarder lists the initiator's socket (lsof) and drains the connection only once
    the listing no longer shows it (RecoveryWireAudit._hold).

    Observed on this Mac (2026-11-16, extension CDHash 5104eee6, 20261116-185051, -185451 and
    -190033; R13-dataout fails each time): LIO solicited the burst as one 262,144 B
    Data-Out, so the whole burst was one send (LIO's TPG parameter MaxRecvDataSegmentLength
    read 8192 meanwhile). The send deadline never ended the stall: the disk reported
    reconnecting 30.3 to 30.5 s after the cut, the command deadline 30 s after the WRITE
    was sent; it connected again about 2 s later, the WRITE was redone GOOD and no
    application error came. Cut at half the data (32 KiB SO_RCVBUF, 1 KiB segments), the
    extension held 17,064 B outside its kernel; cut at 4 KiB, its kernel took all the rest
    (196,872 B in its send queue).
    With a 24 KiB SO_RCVBUF and 512 B segments it held 57,920 B outside its kernel from the
    cut on and still did not end the connection at 15 s; its socket then stayed open and
    ESTABLISHED after the command deadline's cancel, until the harness released the stall
    at 61 s. Network.framework logged "Outstanding bytes to send, deferring socket
    disconnect" at that cancel and "sendmsg(fd 5, 57920 bytes): socket has been closed" at
    the release: it held those bytes itself. Whether the extension's send had completed
    (.contentProcessed with bytes still held, as for the test sender above) or was still
    pending without its 15 s deadline firing was not observed in the extension; the test
    sender's behaviour favours the first.

    Checks from the forwarder, independent of the initiator (judge_stall): the initiator ends
    its side of the stalled connection STALL_ABANDON_BOUNDS after the cut (for `dataout`, at
    least the low bound after the cut and at most the high bound after the last intake, and
    the bytes drained after the close lack the burst's last Data-Out: judge_dataout); a new
    connection follows and logs in (the audit: same ISID, TSIH 0, revalidation before I/O);
    the cut command (same opcode, LBA and length) is sent again on a later connection and
    completes GOOD; interrupted WRITEs are redone and flushed (the audit's redo check). From
    the probe: reconnecting before the command deadline, connected again, workload progress,
    no application errors or read mismatches, for `dataout` the large write synchronized,
    a normal eject. The final snapshot verification (with the large file for `dataout`) and
    the residue checks are the harness's.
    """
    c.measurements["targetTimers"] = target_timers(c)
    if variant == "dataout":
        clamp = c.measurements.get("clamp")
        c.check(bool(clamp) and clamp["listener"] and clamp["accepted"]
                and not clamp["failures"],
                "the forwarder's receive buffers toward the initiator were not clamped: "
                + json.dumps(clamp))
    c.start_workload(c.name)
    c.sleep(8)
    fault = c.audit.fault_start("transport-stall", time.monotonic_ns(), variant=variant)
    stall = None
    write, written = None, {}

    def collect_write():
        # The large write ends after the reconnection, or with the scenario's cleanup.
        if write is not None and not written:
            try:
                written.update(c.session.wait(write, 300))
            except (TimeoutError, RuntimeError, HarnessError) as error:
                written.update(ok=False, error=f"{type(error).__name__}: {error}")

    try:
        # Armed inside the try: a stall left armed would cut a PDU during the cleanup.
        stall = c.audit.arm_stall(variant)
        c.record("stall-armed", variant=variant)
        if variant == "dataout":
            write = c.session.send("file-write", label=c.name + "-large",
                                   bytes=DATAOUT_WRITE_BYTES, sync="fullfsync")
        deadline = time.monotonic() + STALL_CUT_TIMEOUT
        while stall["startNS"] is None and time.monotonic() < deadline:
            c.sleep(0.1)
        if stall["startNS"] is None:
            c.audit.disarm_stall()
            raise ScenarioFailure(f"no {variant} PDU to cut within {STALL_CUT_TIMEOUT} s")
        c.record("stall", connection=stall["connection"], pdu=stall["pdu"],
                 command=stall["command"], r2t=stall["r2t"])
        # The initiator must end its side by itself; wait well past the command deadline.
        limit = time.monotonic() + COMMAND_DEADLINE + 30
        while stall["initiatorEnd"] is None and time.monotonic() < limit:
            c.sleep(0.2)
        hold = stall["hold"] or {}
        closed = {key: hold.get(key) for key in ("closedNS", "closedHow")}
        c.record("stall-end", initiatorEnd=stall["initiatorEnd"], targetEnd=stall["targetEnd"],
                 **({"initiatorClosed": closed} if variant == "dataout" else {}))
        lost = c.session.wait_state({"reconnecting", "interrupted"}, stall["startNS"],
                                    COMMAND_DEADLINE + 30)
        c.check(lost is not None and lost[1] == "reconnecting",
                f"the disk did not report reconnecting after the stall (state "
                f"{c.session.state()})")
        before = c.workload_steps(c.name)
        if lost is not None and lost[1] == "reconnecting":
            c.wait_connected(lost[0], 120, "after the stalled connection")
        progressed = c.wait_progress(c.name, before, timeout=90)
        c.check(progressed is not None, "the workload made no progress after the stall")
        collect_write()
    finally:
        c.audit.disarm_stall()
        if stall is not None and stall["startNS"] is not None and stall["initiatorEnd"] is None:
            c.note("releasing a stalled connection the initiator did not end")
            c.audit.release_stall("the initiator did not end the stalled connection")
        collect_write()
        c.audit.fault_end(fault, time.monotonic_ns())
    if write is not None:
        c.measurements["largeWrite"] = {key: written.get(key) for key in (
            "ok", "size", "writeErrno", "syncErrno", "closeErrno", "writeMS", "syncMS", "error")}
        c.check(written.get("ok"), "the large write did not synchronize across the stall: "
                + json.dumps(c.measurements["largeWrite"]))
        if written.get("ok"):
            c.files.append(dict(name=written["name"], sha256=written["sha256"], required=True))
    if stall["startWall"] is not None:
        c.measurements["stallLog"] = collect_stall_log(
            stall["startWall"] - 5, time.time(), c.logs / "stall-window.log",
            cut_wall=stall["startWall"])
        # The product's own record of what ended the connection, for the report; the check
        # is the forwarder's (judge_stall).
        c.note("Network.framework cancels after the cut (s): "
               + json.dumps(c.measurements["stallLog"].get("cancels")))
    report = c.audit.recovery_report()
    c.measurements["revalidation"] = [
        dict(id=i["id"], preIO=i["preIO"], reads=i["readsSent"], writes=i["writesSent"])
        for i in report["connections"]
        if i["sessionType"] == "Normal" and i["readyNS"] and stall["startNS"]
        and i["readyNS"] >= stall["startNS"]][:8]
    errors = c.session.events_of("IO_ERROR", stall["armedNS"])
    c.check(not errors, "application-visible errors after the stall: " + json.dumps(errors[:4]))
    c.sleep(10)
    c.stop_workload(c.name)
    eject = c.eject()
    c.check(eject.get("status") == "succeeded", "normal eject failed: " + json.dumps(eject))
    c.measurements["eject"] = {k: eject.get(k) for k in ("status", "error", "elapsedMS")}
    metrics, problems = judge_stall(stall, list(c.session.states),
                                    [row["ns"] for row in c.audit.normal_logins])
    c.measurements["stall"] = metrics
    for problem in problems:
        c.check(False, problem)


# R10 makes at most one fault per 25 s (a pause of at least 20 s, an outage of at least 5 s).
# The initiator's 45 s login deadline and its 2 to 15 s backoff allow at most three accepted
# connections per fault (the soak of 20261112-162005 averaged 1.4). The connection budget
# per scenario (RecoveryWireAudit.MAXIMUM_CONNECTIONS) must cover the longest soak.
R10_CONNECTIONS_PER_MINUTE = 3 * 60 / 25
MAXIMUM_SOAK_MINUTES = 240


def soak_minutes_error(minutes):
    if 1 <= minutes <= MAXIMUM_SOAK_MINUTES:
        return None
    budget = RecoveryWireAudit.MAXIMUM_CONNECTIONS
    return (f"--soak-minutes must be between 1 and {MAXIMUM_SOAK_MINUTES}: the harness is sized "
            f"and checked for soaks of up to {MAXIMUM_SOAK_MINUTES // 60} hours (its budget of "
            f"{budget} connections per scenario covers about "
            f"{int(budget / R10_CONNECTIONS_PER_MINUTE)} minutes at R10's worst-case reconnect "
            "rate; the evidence collection is untested beyond 4 hours)")


def summarize_extension(rows):
    samples = [(row["ns"], process) for row in rows for process in row.get("processes", [])]
    if not samples:
        return dict(samples=0)
    by_pid = {}
    for stamp, process in samples:
        by_pid.setdefault(process["pid"], []).append((stamp, process))
    summary = {}
    for pid, values in by_pid.items():
        rss = [p["rssKiB"] for _, p in values]
        cpu = [p["cpu"] for _, p in values]
        summary[str(pid)] = dict(samples=len(values), rssFirstKiB=rss[0], rssLastKiB=rss[-1],
                                 rssMaxKiB=max(rss), cpuMax=max(cpu),
                                 cpuMean=round(sum(cpu) / len(cpu), 2),
                                 rssSeries=rss[::max(1, len(rss) // 24)])
    return summary


# MARK: Main


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenarios", default=",".join(DEFAULT_ORDER),
                        help="Comma-separated subset of R1..R13 (R4 runs R4, R4-staged and "
                             "R4-auth; R7 runs R7-held and R7-heal; R8 runs R8-serial and "
                             "R8-size; R12 runs R12-eject and R12-force; R13, which is not in "
                             "the default order, runs R13-datain and R13-response; each R13 "
                             "variant, R13-dataout among them, is also selectable by its name; "
                             "the mutual CHAP variants R3-mutual, R2-mutual and R4-mutual run "
                             "only by name) or SLEEP")
    parser.add_argument("--soak-minutes", type=float, default=30,
                        help=f"R10 duration (default 30, at most {MAXIMUM_SOAK_MINUTES})")
    parser.add_argument("--vm", help="Reuse a VM created by an earlier --keep-vm run")
    parser.add_argument("--allow-sleep", action="store_true",
                        help="SLEEP only: this Mac is a dedicated test host that may sleep")
    parser.add_argument("--manual-sleep", action="store_true",
                        help="SLEEP: wait for a person to sleep and wake this Mac by hand")
    parser.add_argument("--sleep-seconds", type=int, default=300,
                        help="SLEEP only: seconds asleep (longer than the recovery window)")
    parser.add_argument("--sleep-wait-minutes", type=float, default=SLEEP_WAIT_MINUTES,
                        help="SLEEP --manual-sleep only: minutes from the prompt for the person "
                             f"to put this Mac to sleep (default {SLEEP_WAIT_MINUTES}); the "
                             "prompt prints the deadline. After the sleep the harness waits up "
                             f"to {WAKE_UNLOCK_MINUTES} more minutes for a full wake with the "
                             "screen unlocked")
    parser.add_argument("--keep-vm", action="store_true",
                        help="Leave the VM running for another --vm run")
    parser.add_argument("--digest", choices=("None", "CRC32C"),
                        help="Override every scenario's digest policy")
    args = parser.parse_args()
    names = [name.strip().upper() for name in args.scenarios.split(",") if name.strip()]
    if "SLEEP" in names:
        if not args.allow_sleep:
            parser.error("SLEEP puts this Mac to sleep; run it only on a dedicated test host, "
                         "with --allow-sleep (see the module docstring)")
        if (not args.manual_sleep
                and subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0):
            parser.error("SLEEP needs passwordless sudo for `pmset relative wake`")
        if not 1 <= args.sleep_wait_minutes <= 24 * 60:
            parser.error("--sleep-wait-minutes must be between 1 and 1440")
    unknown = [name for name in names if name not in SCENARIOS and r13_variants(name) is None
               and mutual_variant(name) is None]
    if unknown:
        parser.error("Unknown scenarios: " + ", ".join(unknown))
    if soak_minutes_error(args.soak_minutes):
        parser.error(soak_minutes_error(args.soak_minutes))
    check_crc32c()
    assert shutil.which("limactl"), "Install Lima 2.2.1+ first"
    logs = ROOT / "build/Validation/LIORecovery" / time.strftime("%Y%m%d-%H%M%S")
    logs.mkdir(parents=True)
    # ISCSI_TEST_APP selects the app under test and its probe build (scripts/test-fskit.py).
    binary_dir = fixture.probe_binary_dir()
    vm = lio.LinuxTargetVM(logs, "lio")
    if args.vm:
        assert args.vm.startswith("iscsi-fskit-lio-") and len(args.vm) == len(vm.name)
        vm.name = args.vm
        vm.staging = "/tmp/" + vm.name
        listed = json.loads(subprocess.check_output(["limactl", "list", vm.name, "--json"],
                                                    text=True, timeout=30))
        assert listed["status"] == "Running"
        forwards = listed["config"]["portForwards"]
        vm.port = next(f["hostPort"] for f in forwards if f.get("guestPort") == 3260)
    summary = dict(started=time.strftime("%Y-%m-%dT%H:%M:%S"), vm=vm.name, scenarios=[])
    succeeded = False
    harness = None
    with fixture.signed_probe(binary_dir, keychain=True) as probe:
        preflight = run([probe, "--preflight"], capture_output=True, text=True)
        modules = [json.loads(line.removeprefix("FSKIT_MODULE ")) for line in preflight.stdout.splitlines()
                   if line.startswith("FSKIT_MODULE ")]
        assert len(modules) == 1
        fixture.verify_module(modules[0]["modulePath"])
        try:
            if args.vm:
                vm.shell("mkdir", "-m", "700", "-p", vm.staging)
                vm.stage_configuration()
            else:
                vm.start()
            harness = Harness(vm, probe, binary_dir, logs, args.digest)
            bodies = dict(
                R1=(scenario_r1, dict(digest="CRC32C", chap=True)),
                R2=(scenario_r2, dict(digest="None", chap=True)),
                R3=(scenario_r3, dict(digest="CRC32C", chap=True)),
                R5=(scenario_r5, dict(digest="None", chap=True)),
                R6=(scenario_r6, dict(digest="None", chap=True)),
                R9=(scenario_r9, dict(digest="None", chap=True)),
                R11=(scenario_r11, dict(digest="None", chap=True)),
                SLEEP=(lambda c: scenario_sleep(c, args.sleep_seconds, args.manual_sleep,
                                                args.sleep_wait_minutes),
                       dict(digest="CRC32C", chap=True)),
                R10=(lambda c: scenario_r10(c, args.soak_minutes), dict(digest="CRC32C", chap=True)),
                **mutual_bodies(),
            )
            with caffeinated():
                for name in names:
                    if harness.stop:
                        print("Skipping", name, "after a stuck scenario", flush=True)
                        continue
                    if name == "R4":
                        harness.scenario("R4", scenario_r4, "None")
                        for variant, body in (("R4-staged", scenario_r4_staged),
                                              ("R4-auth", scenario_r4_auth)):
                            if not harness.stop:
                                harness.scenario(variant, body, "None")
                        continue
                    if name == "R7":
                        harness.scenario("R7-held", lambda c: scenario_r7(c, "held"), "None")
                        if not harness.stop:
                            harness.scenario("R7-heal", lambda c: scenario_r7(c, "heal"), "None")
                        continue
                    if name == "R12":
                        for variant in ("eject", "force"):
                            if not harness.stop:
                                harness.scenario("R12-" + variant,
                                                 lambda c, v=variant: scenario_r12(c, v),
                                                 "None", read_only=True)
                        continue
                    if name == "R8":
                        harness.scenario("R8-serial", lambda c: scenario_r8(c, "serial"), "None")
                        if not harness.stop:
                            harness.scenario("R8-size", lambda c: scenario_r8(c, "size"), "None")
                        continue
                    if r13_variants(name) is not None:
                        # R13 alone runs datain and response; R13-dataout is chosen by name.
                        for variant, digest in r13_variants(name):
                            if not harness.stop:
                                harness.scenario("R13-" + variant,
                                                 lambda c, v=variant: scenario_r13(c, v), digest,
                                                 clamp=variant == "dataout")
                        continue
                    name = mutual_variant(name) or name
                    body, options = bodies[name]
                    harness.scenario(name, body, **options)
            succeeded = all(r["passed"] for r in harness.results) and bool(harness.results)
        finally:
            if harness is not None:
                summary["scenarios"] = [dict(scenario=r["scenario"], passed=r["passed"],
                                             verdict=r.get("verdict"),
                                             harnessErrors=r.get("harnessErrors", [])[:4],
                                             failures=r.get("failures", [])[:6],
                                             failuresAfterHarnessError=r.get(
                                                 "failuresAfterHarnessError", [])[:6],
                                             errors=r.get("errors", [])[:4])
                                        for r in harness.results]
            (logs / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(json.dumps(summary, indent=2), flush=True)
            if args.keep_vm and vm.safe_to_stop:
                print("Kept VM for --vm:", vm.name, flush=True)
            else:
                # A reused VM is stopped and deleted only after a fully successful run.
                vm.finish(succeeded)
    if not succeeded:
        sys.exit(1)


@contextmanager
def caffeinated():
    """Keep idle sleep from pausing the awake-time recovery window during a run."""
    process = subprocess.Popen(["/usr/bin/caffeinate", "-i", "-w", str(os.getpid())])
    try:
        yield
    finally:
        process.terminate()
        process.wait(timeout=10)


if __name__ == "__main__":
    main()
