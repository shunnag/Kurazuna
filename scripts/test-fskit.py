#!/usr/bin/env python3
"""Disposable loopback APFS target for the FSKit mount probe.

--fixture-only validates image creation and raw iSCSI reads without invoking FSKit.
The default requires an already-enabled signed extension; it never enables one.

ISCSI_TEST_APP selects the app under test: development (the default) is the signed Debug
build in build/Signed, installed as ~/Applications/Kurazuna Development.app; release is the
signed Release build in build/SignedRelease, installed as ~/Applications/Kurazuna.app. The
probe takes its identity from the Swift configuration, so release needs the probe from
`make build-release-probe` (`swift build -c release`) and accepts only ISCSIFSKitProbe.
Set ISCSI_TEST_DISTRIBUTION_APP to a Developer ID export to test its installed copy.
Set ISCSI_TEST_SYSTEM_INSTALL=1 to check /Applications for the release edition.
The probe continues to use the separate development validation identity and profile.
"""

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import selectors
import shutil
import shlex
import socket
import subprocess
import threading
import time
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_IMAGES = {"apfs": "APFS.img", "exfat": "ExFAT.img", "hfsplus": "HFSPlus.cdr"}
probe_signing_spec = importlib.util.spec_from_file_location(
    "validation_probe_signing", ROOT / "scripts/validation-probe-signing.py")
probe_signing = importlib.util.module_from_spec(probe_signing_spec)
probe_signing_spec.loader.exec_module(probe_signing)
application_identity_spec = importlib.util.spec_from_file_location(
    "fskit_application_identity", ROOT / "scripts/application_identity.py")
application_identity = importlib.util.module_from_spec(application_identity_spec)
application_identity_spec.loader.exec_module(application_identity)
# SwiftPM compiles the product identity into the probe: Debug is the development identity and
# `-c release` the release one. The probe's @testable imports need -enable-testing there.
PROBE_BUILD_ARGUMENTS = {"development": (), "release": ("-c", "release", "-Xswiftc", "-enable-testing")}


def application_under_test():
    """The app identity under test, from ISCSI_TEST_APP (development by default)."""
    return application_identity.identity_under_test(os.environ)


def expected_application(identity):
    exported = os.environ.get("ISCSI_TEST_DISTRIBUTION_APP")
    if exported is None:
        return ROOT / identity.signed_product
    if identity.edition != "release":
        raise ValueError("ISCSI_TEST_DISTRIBUTION_APP requires ISCSI_TEST_APP=release")
    path = Path(exported).resolve(strict=True)
    if path.suffix != ".app":
        raise ValueError("ISCSI_TEST_DISTRIBUTION_APP must name the exported app bundle")
    return path


def probe_binary_dir():
    """The SwiftPM products directory whose probe matches the app under test."""
    identity = application_under_test()
    return Path(subprocess.check_output(
        ["swift", "build", *PROBE_BUILD_ARGUMENTS[identity.edition], "--show-bin-path", "--disable-sandbox"],
        cwd=ROOT, text=True).strip())


def require_probe_build(binary_dir, binary_name, identity):
    """Refuse a probe whose compiled identity cannot match the app under test."""
    configuration = Path(binary_dir).name.lower()
    if identity.edition == "release":
        assert configuration == "release", (
            f"ISCSI_TEST_APP=release needs the probe built with -c release (make build-release-probe), not {binary_dir}")
        # Other probes (ISCSIAppModelProbe) are compiled for Debug only.
        assert binary_name == "ISCSIFSKitProbe", f"{binary_name} has no release-identity build"
    else:
        assert configuration != "release", f"A release-configuration probe tests the release app: {binary_dir}"


def write_fixture_manifest(root, file_system):
    assert file_system in FIXTURE_IMAGES
    with os.fdopen(os.open(root / "Fixture.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump({"fileSystem": file_system}, output)
        output.write("\n")


@contextmanager
def signed_probe(binary_dir, keychain=False, binary_name="ISCSIFSKitProbe"):
    """Query FSClient with the same signing identity as the extension.

    On the test Mac, an ad-hoc command sees Apple's modules but not our module,
    even when System Settings shows it enabled. Never change OS activation here.
    """
    assert binary_name in ("ISCSIFSKitProbe", "ISCSIAppModelProbe")
    identity = application_under_test()
    require_probe_build(binary_dir, binary_name, identity)
    if identity.edition != "development":
        print(f"TEST_APP {identity.edition}: {identity.extension_identifier}, "
              f"type {identity.file_system_type}, probe {binary_dir}", flush=True)
    app = ROOT / identity.signed_product
    product = expected_application(identity)
    subprocess.run(["python3", "scripts/verify-signed-app.py", "--app", str(app), "--edition", identity.edition],
                   cwd=ROOT, check=True, timeout=30)
    if os.environ.get("ISCSI_TEST_DISTRIBUTION_APP") is not None:
        subprocess.run(["python3", "scripts/verify-signed-app.py", "--app", str(product), "--edition", "release"],
                       cwd=ROOT, check=True, timeout=30)
        developer_id = "=anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        for bundle in (product, product / "Contents/Extensions/ISCSIFSExtension.appex"):
            subprocess.run(["codesign", "--verify", "--strict", "-R", developer_id, str(bundle)],
                           check=True, timeout=30)
    extension = app / "Contents/Extensions/ISCSIFSExtension.appex"
    with tempfile.TemporaryDirectory(prefix="FSKitProbe-", dir=ROOT / "build") as directory:
        directory = Path(directory)
        certificate_prefix = str(directory / "extension-signer")
        subprocess.run(["codesign", "-d", f"--extract-certificates={certificate_prefix}", str(extension)],
                       check=True, capture_output=True, timeout=30)
        certificate = Path(certificate_prefix + "0").read_bytes()
        # codesign identifies an available certificate by its SHA-1 fingerprint.
        identity = hashlib.sha1(certificate).hexdigest()
        bundle = None
        if keychain:
            # A separate App ID keeps validation metadata out of the product's
            # privacy identity. The profile authorizes the same existing shared
            # group and signer. Never fall back to the product's App ID.
            info = plistlib.loads((product / "Contents/Info.plist").read_bytes())
            signed = plistlib.loads(subprocess.check_output([
                "codesign", "-d", "--entitlements", "-", "--xml", str(app)], stderr=subprocess.DEVNULL))
            profile = probe_signing.select_profile(
                signed["com.apple.developer.team-identifier"],
                info["ISCSISharedKeychainAccessGroup"], certificate)
            bundle = directory / (probe_signing.DISPLAY_NAME + ".app")
            probe, entitlements = probe_signing.prepare_bundle(bundle, product, binary_name, profile)
            (directory / "probe.entitlements").write_bytes(plistlib.dumps(entitlements))
        else:
            probe = directory / binary_name
        shutil.copy2(binary_dir / binary_name, probe)
        signing = ["codesign", "--force", "--sign", identity]
        if keychain:
            signing += ["--options", "runtime", "--entitlements", str(directory / "probe.entitlements"), str(bundle)]
        else:
            signing += ["--identifier", probe_signing.IDENTIFIER + ".FSKitProbe", str(probe)]
        subprocess.run(signing,
                       check=True, timeout=30)
        subprocess.run(["codesign", "--verify", "--strict", str(probe)],
                       check=True, timeout=30)
        own_prefix = str(directory / "probe-signer")
        subprocess.run(["codesign", "-d", f"--extract-certificates={own_prefix}", str(probe)],
                       check=True, capture_output=True, timeout=30)
        assert Path(own_prefix + "0").read_bytes() == certificate, "Probe signer differs from the extension"
        print("PASS: probe signed with the extension's development certificate")
        yield str(probe)


def verify_module(module_path):
    module_path = Path(module_path)
    assert module_path.suffix == ".appex" and module_path.parent.name == "Extensions"
    assert module_path.parent.parent.name == "Contents"
    app = module_path.parents[2]
    assert app.suffix == ".app"
    identity = application_under_test()
    subprocess.run(["python3", "scripts/verify-signed-app.py", "--app", str(app), "--edition", identity.edition],
                   cwd=ROOT, check=True, timeout=30)
    product = expected_application(identity)
    if os.environ.get("ISCSI_TEST_DISTRIBUTION_APP") is not None:
        applications = Path("/Applications") if os.environ.get("ISCSI_TEST_SYSTEM_INSTALL") == "1" else Path.home() / "Applications"
        installed = applications / (identity.application_name + ".app")
        if app.resolve() != installed.resolve():
            raise ValueError("FSKit selected a different copy from the installed distribution app")
    expected = product / "Contents/Extensions/ISCSIFSExtension.appex"

    def code_hash(bundle):
        result = subprocess.run(["codesign", "-d", "--verbose=4", str(bundle)],
                                capture_output=True, text=True, check=True, timeout=30)
        hashes = [line.removeprefix("CDHash=") for line in result.stderr.splitlines() if line.startswith("CDHash=")]
        assert len(hashes) == 1, "Missing extension code hash"
        return hashes[0]

    assert code_hash(module_path) == code_hash(expected), "Enabled extension differs from the current signed build"
    if os.environ.get("ISCSI_TEST_DISTRIBUTION_APP") is not None:
        assert code_hash(app) == code_hash(product), "Installed app differs from the Developer ID export"
    print("PASS: module bundle signature, profile, and code hash match the signed build")


@contextmanager
def target_server(module, memory, read_write=False, chap=False, write_fault=None, logout_fault=None, trace_path=None,
                  initial_read_only=False, block_size=512, memory_control=False, mutual_chap=False,
                  authentication_fault=None, disconnection=None, deferred_sense=False, release=None):
    """Serve `memory` as a loopback target for the duration of the block.

    `release(failed)`, when given, runs before the target stops, whether the block failed or
    not, so that a bridge left mounted is ejected while its target still answers (see
    `release_fixture`). Its own failure is printed, never raised over the block's.
    """
    assert block_size in (512, 4096) and len(memory) % block_size == 0
    assert not mutual_chap or chap
    assert authentication_fault in (None, "mutual-digest", "mutual-name", "mutual-missing", "mutual-reflected")
    assert not authentication_fault or (mutual_chap and not read_write and not write_fault and not logout_fault)
    disconnected = threading.Event()
    silent = threading.Event()
    write_armed = threading.Event()
    write_fault_seen = threading.Event()
    logout_fault_seen = threading.Event()

    class DurableTarget(module.Target):
        durable = None
        durable_writes = 0
        suppressed = 0
        logout_started = None
        logout_elapsed = None

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.block_trace = []

        def trace(self, command, **fields):
            if trace_path is not None:
                assert len(self.block_trace) < 4096, "Block trace exceeded its diagnostic limit"
                self.block_trace.append(dict(command=command, timeNS=time.monotonic_ns(), **fields))

        def block_range(self, cdb):
            offset, length = super().block_range(cdb)
            if cdb[0] in (0x2A, 0x8A):
                self.trace("write", offset=offset, length=length)
            return offset, length

        def send(self, opcode, *args, **kwargs):
            if opcode == 0x26:
                self.logout_started = time.monotonic()
                if logout_fault:
                    logout_fault_seen.set()
                    if logout_fault == "eof":
                        self.connection.shutdown(socket.SHUT_RDWR)
                    return
            if silent.is_set():
                self.suppressed += 1
                return
            if opcode == 0x21 and self.probe_commands and self.probe_commands[-1][1] == 0x35:
                # Model a volatile target write cache: only SYNCHRONIZE CACHE
                # commits its contents. Capture before acknowledging the command.
                captured = bytes(self.memory)
                with lock:
                    self.durable = captured
                    self.durable_writes = self.writes
                    self.trace("synchronize", writes=self.writes)
            expected_opcode = 0x35 if write_fault == "flush-eof" else 0x2A
            if (write_fault and write_armed.is_set() and not write_fault_seen.is_set()
                    and opcode == 0x21 and self.probe_commands[-1][1] == expected_opcode):
                write_fault_seen.set()
                if write_fault == "write-silent":
                    silent.set()
                else:
                    disconnected.set()
                    self.connection.shutdown(socket.SHUT_RDWR)
                return
            return super().send(opcode, *args, **kwargs)

    active = set()
    workers = []
    observations = []
    targets = []
    errors = []
    lock = threading.Lock()
    stopping = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.2)
        address = f"127.0.0.1:{listener.getsockname()[1]}"

        def serve(connection):
            target = None
            try:
                with connection, connection.makefile("rb") as reader, connection.makefile("wb") as writer:
                    connection.settimeout(40)
                    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    environment = {"ISCSI_TEST_FILESYSTEM": "1", "ISCSI_TEST_BLOCK_SIZE": str(block_size)}
                    if memory_control:
                        # The seed is compared by SHA-256 in full before any
                        # test write. Avoid the deliberately slow bitwise CRC
                        # oracle in this diagnostic seed/export session only.
                        environment["ISCSI_TEST_NEGOTIATION"] = "reject-defaults"
                        environment["ISCSI_TEST_WIRE_FRAGMENT_BYTES"] = "65536"
                    if chap:
                        environment["ISCSI_TEST_CHAP"] = "1"
                    if mutual_chap:
                        environment["ISCSI_TEST_MUTUAL_CHAP"] = "1"
                    if authentication_fault:
                        environment["ISCSI_TEST_FAULT"] = authentication_fault
                    target = DurableTarget(reader, writer, environment)
                    target.memory = memory
                    target.segment_length = 8192
                    target.connection = connection
                    with lock:
                        targets.append(target)
                    try:
                        target.run()
                        if logout_fault == "silent" and logout_fault_seen.is_set():
                            connection.settimeout(12)
                            assert reader.read(1) == b"", "More requests followed Logout"
                    except EOFError:
                        assert target.pending_write is None, "Target closed during an incomplete write"
            except Exception as error:
                # A silent target never answers the recovery's logins; their idle sockets time out.
                expected_disconnect = (disconnected.is_set() or silent.is_set()) and isinstance(error, OSError)
                if not stopping.is_set() and not expected_disconnect:
                    errors.append(error)
            finally:
                if target is not None:
                    if target.logout_started is not None:
                        target.logout_elapsed = time.monotonic() - target.logout_started
                    observations.append(target)
                with lock:
                    active.discard(connection)

        def accept():
            while not stopping.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with lock:
                    active.add(connection)
                worker = threading.Thread(target=serve, args=(connection,), daemon=True)
                workers.append(worker)
                worker.start()

        acceptor = threading.Thread(target=accept, daemon=True)
        acceptor.start()

        def counters(durable_path=None, disconnect=None, arm_write=False):
            if arm_write:
                write_armed.set()
            if disconnect == "eof":
                disconnected.set()
                with lock:
                    connections = list(active)
                assert len(connections) == 1, "Expected one private connection to disconnect"
                for connection in connections:
                    connection.shutdown(socket.SHUT_RDWR)
            elif disconnect == "silent":
                silent.set()
            with lock:
                current = {"writes": sum(target.writes for target in targets),
                           "flushes": sum(target.flushes for target in targets),
                           "durableWrites": sum(target.durable_writes for target in targets),
                           "reads": sum(sum(cdb in (0x28, 0x88) for _, cdb in target.probe_commands) for target in targets),
                           "suppressed": sum(target.suppressed for target in targets),
                           "sessions": len(targets), "writeFaultSeen": write_fault_seen.is_set(),
                           "logouts": sum(target.logouts for target in targets)}
                selected = None
                if durable_path is not None:
                    assert len(targets) == 1 and targets[0].durable is not None
                    selected = targets[0].durable
                for target in targets:
                    target.trace("checkpoint", writes=target.writes, flushes=target.flushes,
                                 durableWrites=target.durable_writes,
                                 stableSnapshot=durable_path is not None)
            # Log the immutable snapshot selection before the potentially slow
            # host file write. Later target I/O must not shift its timestamp.
            if durable_path is not None:
                durable_path.write_bytes(selected)
                durable_path.chmod(0o600)
            return current

        failed = False
        try:
            yield address, counters
            deadline = time.monotonic() + 5
            while True:
                with lock:
                    remaining = len(active)
                if not remaining or time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
            assert not remaining, "FSKit did not close its fixture TCP session after ejection"
            if errors:
                raise errors[0]
            modes = (False, True, False) if initial_read_only else ((True, False) if read_write else (False,))
            recovered = (disconnection == "eof"
                         or (write_fault in ("write-eof", "flush-eof") and not deferred_sense))
            silent_recovery = disconnection == "silent" or write_fault == "write-silent"
            if recovered or silent_recovery:
                # The first session was cut; recovery logged in again with the same ISID
                # (closed connection) or kept trying against a silent target.
                ordered = list(targets)
                if recovered:
                    assert len(ordered) == 2, "A closed connection was not recovered by exactly one new session"
                    assert [t.logouts for t in ordered] == [0, 1], "Only the recovered session logs out at ejection"
                else:
                    assert len(ordered) >= 1 and all(t.logouts == 0 for t in ordered)
                    assert all(not t.probe_commands for t in ordered[1:]), "A silent target's later connection carried SCSI"
                if write_fault:
                    writes = [t.writes for t in ordered]
                    assert write_fault_seen.is_set(), "Write fault was not injected"
                    redone = [1, 2] if write_fault == "write-eof" else [1, 1]
                    assert writes == (redone if recovered else [1] + [0] * (len(ordered) - 1)), \
                        f"Unexpected write replay across sessions: {writes}"
                assert any(cdb in (0x28, 0x88) for _, cdb in ordered[0].probe_commands), "No block reads reached the fixture"
                print(f"PASS: {len(ordered)} target connections; recovery {'redid the interrupted I/O on one new session' if recovered else 'sent nothing to the silent target'}, logouts={[t.logouts for t in ordered]}, TCP closed")
                return
            if memory_control:
                assert read_write and not initial_read_only and not write_fault and not logout_fault
                modes = (True,)  # The exported target is the frozen state, not live memory.
            assert not initial_read_only or (read_write and not write_fault and not logout_fault)
            assert len(observations) == len(modes), "Unexpected fixture session count"
            for target in observations:
                assert target.normal, "Expected a normal fixture session"
                assert target.chap_phase == (3 if chap else 0), "CHAP exchange differs"
                assert target.mutual_chap == mutual_chap, "Target mutual authentication differs"
                if authentication_fault:
                    assert target.probe_commands == [], "SCSI command followed a rejected server proof"
                    assert target.writes == 0 and target.flushes == 0 and target.logouts == 0
                else:
                    assert any(cdb in (0x28, 0x88) for _, cdb in target.probe_commands), "No block reads reached the fixture"
                    interrupted = disconnected.is_set() or silent.is_set()
                    assert target.logouts == (0 if interrupted else 1), "Missing or repeated Logout after ejection"
            if logout_fault:
                assert logout_fault_seen.is_set(), "Logout response fault was not injected"
                assert len(observations) == 1 and 0 <= observations[0].logout_elapsed < 7
                print(f"PASS: Logout response {logout_fault}, one request, TCP closed after {observations[0].logout_elapsed:.3f}s")
            if write_fault:
                assert write_fault_seen.is_set(), "Write fault was not injected"
                assert observations[0].writes == 1, "Uncertain write was replayed"
                assert observations[0].flushes == (1 if write_fault == "flush-eof" else 0)
            elif read_write:
                for target, writable in zip(observations, modes):
                    if writable:
                        assert target.writes > 0 and target.flushes > 0, "Missing writes or SCSI flushes"
                    else:
                        assert target.writes == 0, "Read-only session received a write"
            else:
                assert observations[0].writes == 0, "A read-only fixture received a write"
            if authentication_fault:
                print(f"PASS: native mutual CHAP rejected {authentication_fault}; one login, no SCSI, no Logout, TCP closed")
            else:
                print(f"PASS: {len(observations)} normal target sessions, block I/O, CHAP={chap}, mutualCHAP={mutual_chap}, writes/flushes checked, logouts={sum(target.logouts for target in observations)}, TCP closed")
        except BaseException:
            failed = True
            raise
        finally:
            if release is not None:
                try:
                    release(failed)
                except Exception as error:
                    print(f"Fixture release before stopping the target failed: {error!r}", flush=True)
            stopping.set()
            acceptor.join(timeout=2)
            assert not acceptor.is_alive(), "Fixture listener cleanup failed"
            with lock:
                for connection in active:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            for worker in workers:
                worker.join(timeout=2)
                assert not worker.is_alive(), "Fixture connection cleanup failed"
            if trace_path is not None:
                trace_path.write_text(json.dumps([target.block_trace for target in targets], indent=2) + "\n")
                trace_path.chmod(0o600)


def run_mount_probe(arguments, counters, root, disconnection=None, write_fault=None, soak_seconds=None,
                    target_heartbeats=False, after_ejection=None, timeout_seconds=180, memory_control=False,
                    deferred_sense=False, before_filesystem_write=None, after_checkpoint=None,
                    synchronization_boundaries=False, historical_snapshot=None):
    """Audit live fixture checkpoints before I/O completion and ejection."""
    baseline = None
    # A lost connection is recovered (RecoveringSession): a closed connection is redone on a new
    # session with the same ISID; a target that stays silent fails the write after the window.
    recovered_write = write_fault in ("write-eof", "flush-eof") and not deferred_sense
    phase_names = (("before-idle", "after-idle", "before-fsync", "after-fsync", "before-fullfsync", "after-fullfsync") if soak_seconds else
                  (("before-uncertain-write", "after-write-return", "after-redone-write", "after-recovered-io")
                   if recovered_write else
                  (("before-uncertain-write", "after-write-return", "after-uncertain-write", "after-failed-write-retry") if write_fault else
                  (("before-live-raw-read", "disconnect", "after-recovery")
                  if disconnection else ("before-fsync", "after-fsync", "before-fullfsync", "after-fullfsync")))))
    if synchronization_boundaries:
        assert not any((disconnection, write_fault, soak_seconds, memory_control,
                        after_ejection, before_filesystem_write))
        assert after_checkpoint is not None
        phase_names = ("sync-boundaries",)
    if after_ejection is not None:
        assert not disconnection and not write_fault and not soak_seconds
        phase_names += ("source-ejected",)
    if before_filesystem_write is not None:
        assert not disconnection and not write_fault and not soak_seconds and not memory_control
        phase_names = ("before-filesystem-write",) + phase_names
    phases = iter(phase_names)
    cut = None
    failure = None
    with subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT) as process:
        try:
            timeout = timeout_seconds + (soak_seconds + 32 if soak_seconds else 0)
            deadline = time.monotonic() + timeout
            pending = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise subprocess.TimeoutExpired(arguments, timeout)
                    chunk = os.read(process.stdout.fileno(), 8192)
                    if not chunk:
                        selector.unregister(process.stdout)
                        break
                    pending.extend(chunk)
                    assert len(pending) <= 65_536, "Probe output line exceeds limit"
                    while b"\n" in pending:
                        line, _, rest = pending.partition(b"\n")
                        pending = bytearray(rest)
                        text = line.decode("utf-8", errors="replace")
                        print(text, flush=True)
                        if not text.startswith("FSKIT_CHECKPOINT "):
                            continue
                        checkpoint = json.loads(text.removeprefix("FSKIT_CHECKPOINT "))
                        phase = checkpoint["phase"]
                        current = counters()
                        print(f"CHECK: {phase}: {current}", flush=True)
                        error = None
                        if phase != next(phases, None):
                            error = "Unexpected synchronization checkpoint sequence"
                        elif phase == "before-filesystem-write":
                            before_filesystem_write()
                        elif phase == "before-idle":
                            baseline = current
                            if current["writes"] != 0:
                                error = "Read-only idle fixture received a write"
                        elif phase == "after-idle":
                            incoming, outgoing = (("targetNopIn", "targetNopOut") if target_heartbeats
                                                  else ("nopReplies", "nopOut"))
                            if (current[incoming] - baseline[incoming] < 2
                                    or current[outgoing] - baseline[outgoing] < 2
                                    or current["writes"] != 0 or current["sessions"] != baseline["sessions"]):
                                error = "Idle FSKit connection did not complete two heartbeat exchanges without reconnecting"
                            else:
                                origin = "target" if target_heartbeats else "initiator"
                                print("PASS: idle FSKit session completed multiple " + origin
                                      + " NOP exchanges without reconnecting")
                        elif write_fault:
                            if phase == "before-uncertain-write":
                                if current["writes"] or current["flushes"]:
                                    error = "Fixture has writes before the fault was armed"
                                else:
                                    baseline = counters(arm_write=True)
                            elif recovered_write and phase == "after-redone-write":
                                # The command whose connection closed is issued again on the new
                                # session; then, because the session epoch changed, the whole
                                # write callback (WRITE + SYNC) runs once more on it
                                # (RemoteDisk.repeatingWithinOneEpoch). The F_FULLFSYNC that
                                # follows finds every write flushed in this epoch and sends no
                                # SYNC (RemoteDisk's SynchronizationCoverage).
                                # write-eof: WRITE(lost) | WRITE, SYNC, WRITE, SYNC.
                                # flush-eof: WRITE, SYNC(lost) | SYNC, WRITE, SYNC.
                                expected_writes = 2 if write_fault == "flush-eof" else 3
                                expected_flushes = 3 if write_fault == "flush-eof" else 2
                                if (not current["writeFaultSeen"] or current["writes"] != expected_writes
                                        or current["flushes"] != expected_flushes or current["sessions"] != 2):
                                    error = "The interrupted write was not redone exactly once on one new session"
                                else:
                                    cut = current
                            elif recovered_write and phase == "after-recovered-io":
                                if current["reads"] <= cut["reads"] or current["sessions"] != 2:
                                    error = "I/O after the recovered write did not reach the new session"
                                else:
                                    print("PASS: a write whose status was lost to a closed connection was redone once on a new session")
                            elif phase != "after-write-return":
                                expected_flushes = 1 if write_fault == "flush-eof" else 0
                                expected_writes = 0 if deferred_sense and write_fault == "write-eof" else 1
                                # A silent target answers no new login: nothing is sent again.
                                expected_sessions = current["sessions"] >= 1 if write_fault == "write-silent" else current["sessions"] == 1
                                if (not current["writeFaultSeen"] or current["writes"] != expected_writes
                                        or current["flushes"] != expected_flushes or not expected_sessions):
                                    error = "Uncertain write or cache flush was replayed or not injected"
                                elif phase == "after-failed-write-retry":
                                    if current["reads"] != cut["reads"]:
                                        error = "Failed session sent more block reads"
                                    else:
                                        if deferred_sense:
                                            print("PASS: deferred error stopped native I/O with no replay or reconnection")
                                        else:
                                            print("PASS: a write the silent target never answered failed with EIO after the"
                                                  " recovery window; no write replay, login attempts carried no SCSI")
                                elif phase == "after-uncertain-write":
                                    cut = current
                        elif disconnection:
                            if phase == "before-live-raw-read":
                                baseline = current
                            elif phase == "disconnect":
                                if current["reads"] <= baseline["reads"]:
                                    error = "The uncached live raw read did not reach the target"
                                else:
                                    cut = counters(disconnect=disconnection)
                            elif phase == "after-recovery" and disconnection == "eof":
                                if current["sessions"] != 2 or current["reads"] <= cut["reads"] or current["writes"] != 0:
                                    error = "A closed connection was not recovered by one new session serving the read"
                                else:
                                    print("PASS: closed connection recovered by one new session; the waiting read was served")
                            elif phase == "after-recovery":
                                if current["reads"] != cut["reads"] or current["writes"] != 0:
                                    error = "I/O reached the silent target after the disconnection"
                                elif current["suppressed"] < 1:
                                    error = "Silent target did not suppress a heartbeat reply"
                                else:
                                    print("PASS: silent target received no further SCSI command; the waiting read failed with EIO")
                        elif phase == "before-fsync":
                            baseline = current
                        elif phase == "source-ejected":
                            after_ejection()
                        elif phase == "after-fullfsync" and baseline is not None:
                            if historical_snapshot is not None:
                                cutoff = checkpoint.get("fullsyncReturnedNS")
                                assert (type(cutoff) is int and 0 < cutoff <= checkpoint["uptimeNS"]), \
                                    "Exact native fullfsync return timestamp is required"
                                selected = historical_snapshot(root / "Stable.img", cutoff)
                                assert (selected["cutoffNS"] == cutoff
                                        and type(selected["selectedResponseNS"]) is int
                                        and 0 < selected["selectedResponseNS"] <= cutoff
                                        and 0 < selected["selectedWrites"] <= current["writes"]), \
                                    "Historical snapshot is not a synchronized prefix before API return"
                                assert hashlib.sha256((root / "Stable.img").read_bytes()).hexdigest() == selected["sha256"]
                                print("PASS: selected target GOOD flush prefix before native fullfsync return: "
                                      + json.dumps(selected), flush=True)
                            elif current["durableWrites"] < current["writes"]:
                                error = "The post-F_FULLFSYNC checkpoint includes writes beyond the target's synchronized prefix"
                            elif current["writes"] == 0 and not memory_control:
                                error = "Filesystem synchronization completed without target writes"
                            else:
                                counters(root / "Stable.img")
                                if memory_control:
                                    assert baseline["writes"] == 0 and current["flushes"] > 0
                                    assert current["reads"] == baseline["reads"], "Memory callbacks issued network reads"
                                    print(f"CONTROL: historical in-memory state transported after selection; not remote durability: {baseline} -> {current}")
                                else:
                                    print(f"PASS: synchronization reached target before close/ejection: {baseline} -> {current}")
                        if memory_control and phase in ("before-fsync", "after-fsync", "before-fullfsync"):
                            if current["writes"] != 0 or current["flushes"] != 0:
                                error = "Memory control sent network writes or flushes before snapshot selection"
                            elif baseline is not None and current["reads"] != baseline["reads"]:
                                error = "Memory control sent network reads after preloading"
                        if after_checkpoint is not None:
                            # after-fullfsync has already selected the immutable snapshot.
                            after_checkpoint(phase, current)
                        if error:
                            failure = error
                        response = json.dumps({"ok": error is None, "error": error}).encode() + b"\n"
                        process.stdin.write(response)
                        process.stdin.flush()
                if pending:
                    print(pending.decode("utf-8", errors="replace"), end="", flush=True)
            process.wait(timeout=max(1, deadline - time.monotonic()))
            if failure:
                raise AssertionError(failure)
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, arguments)
            assert next(phases, None) is None, "Probe exited before completing all checkpoints"
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def remove_empty_mounts(root):
    """Remove the fixture's bridge directory without recursion.

    The block-resource route keeps its marker images in Mounts/.Resources and removes
    only the image file after a normal eject. rmdir still refuses a remaining marker or
    a late child mount before the caller deletes ordinary fixture files recursively.
    """
    mounts = root / "Mounts"
    resources = mounts / ".Resources"
    if resources.exists():
        resources.rmdir()
    if mounts.exists():
        mounts.rmdir()


def journal_entries(root):
    """Connection records in the fixture's journal: 0 without a journal, -1 if unreadable."""
    try:
        return len(json.loads((Path(root) / "State/Connections.json").read_text())["entries"])
    except FileNotFoundError:
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        return -1


def resources_remain(root, records=False):
    """Whether an image attached from the fixture or a mount below it remains.

    With `records`, a connection record in the fixture's journal counts too, and so does an
    unreadable journal. An eject whose last step fails, removing the mount resource Keychain
    item while the screen is locked (MountResourceCleanupError, APP043), leaves nothing
    mounted but keeps the disk's record and that Keychain item for a retry; only a recovery
    (--recover-fixture) removes them. Callers that expect a record by design, such as the
    crash cases at unmountingBridge, leave `records` off.
    """
    data = subprocess.check_output(["/usr/bin/hdiutil", "info", "-plist"], timeout=30)
    images = plistlib.loads(data)["images"]
    attached = any(entry.get("image-path", "").startswith(str(root) + "/") for entry in images)
    mounts = subprocess.check_output(["/sbin/mount"], text=True, timeout=20)
    return attached or str(root) in mounts or (records and journal_entries(root) != 0)


def markers_remain(root):
    """Files left beneath the fixture's bridge directory, such as a block-resource marker."""
    mounts = root / "Mounts"
    return sorted(str(p) for p in mounts.rglob("*") if not p.is_dir()) if mounts.exists() else []


def bridge_mounted(root):
    """Whether anything is mounted below the fixture's bridge directory, from the mount table only."""
    table = subprocess.run(["/sbin/mount"], capture_output=True, text=True, check=True, timeout=20).stdout
    prefix = f" on {root / 'Mounts'}/"
    return any(prefix in line for line in table.splitlines())


def release_fixture(probe, root, nonce, failed, env=None, limit=150):
    """Release what a case left, while its target still serves the bridge.

    Stopping the target first leaves the extension reconnecting to nothing, which turned a
    few seconds of a busy bridge (another app reading Disk.img, ENV082) into stalls of 20 to
    120 s. The probe waits for other holders before each unmount and the product retries a
    busy bridge for a bounded time; the normal recovery is repeated within `limit`, then the
    confirmed forced path releases what still can't be ejected normally.
    """
    if not failed and not bridge_mounted(root):
        return None
    deadline = time.monotonic() + limit
    normal = []
    while True:
        result = subprocess.run([probe, "--recover-fixture", str(root), nonce], env=env, timeout=150)
        normal.append(result.returncode)
        if result.returncode == 0 or time.monotonic() >= deadline:
            break
        time.sleep(2)
    forced = None
    if normal[-1] != 0:
        forced = subprocess.run([probe, "--force-recover-fixture", str(root), nonce],
                                env=env, timeout=300).returncode
    outcome = dict(normal=normal, forced=forced, bridgeMounted=bridge_mounted(root))
    print("FIXTURE_RELEASE " + json.dumps(outcome), flush=True)
    return outcome


def recover_fixture(probe, root, nonce, env=None):
    """Release a failed case's fixture: the normal path, then the forced path a stopped disk needs.

    Returns both exit codes; the forced one is None when the normal path succeeded.
    """
    normal = subprocess.run([probe, "--recover-fixture", str(root), nonce], env=env, timeout=90)
    if normal.returncode == 0:
        return dict(normal=0, forced=None)
    forced = subprocess.run([probe, "--force-recover-fixture", str(root), nonce], env=env, timeout=300)
    return dict(normal=normal.returncode, forced=forced.returncode)


def run_crash_recovery(probe, address, root, nonce, stage):
    arguments = [probe, "--leave-stage-loopback-" + stage, address, str(root), nonce]
    with subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT) as owner:
        try:
            deadline = time.monotonic() + 120
            pending = bytearray()
            connected = False
            with selectors.DefaultSelector() as selector:
                selector.register(owner.stdout, selectors.EVENT_READ)
                while not connected:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise subprocess.TimeoutExpired(arguments, 120)
                    chunk = os.read(owner.stdout.fileno(), 8192)
                    assert chunk, "Owner exited before its connected checkpoint"
                    pending.extend(chunk)
                    assert len(pending) <= 65_536, "Owner output exceeds limit"
                    while b"\n" in pending:
                        line, _, rest = pending.partition(b"\n")
                        pending = bytearray(rest)
                        print(line.decode("utf-8", errors="replace"), flush=True)
                        connected |= line == ("FSKIT_STAGE " + stage).encode()
            subprocess.run([probe, "--assert-fixture-locked", str(root), nonce],
                           check=True, timeout=30)
            assert resources_remain(root) == (stage != "unmountingBridge"), "Fixture resource state differs before crash"
            owner.kill()
            assert owner.wait(timeout=10) == -9, "Owner did not terminate with SIGKILL"
            print("PASS: private connection owner terminated with SIGKILL; FSKit and target were not killed")
            assert resources_remain(root) == (stage != "unmountingBridge"), "Fixture resource state differs after crash"
            subprocess.run([probe, "--restore-stage-fixture-" + stage, str(root), nonce],
                           check=True, timeout=90)
        finally:
            if owner.poll() is None:
                owner.kill()
                owner.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--fixture-only", action="store_true")
    modes.add_argument("--preflight-only", action="store_true")
    modes.add_argument("--recover-fixture", nargs=2, metavar=("ROOT", "NONCE"))
    modes.add_argument("--crash-recovery", action="store_true")
    modes.add_argument("--disconnect", action="store_true")
    modes.add_argument("--write-fault", action="store_true")
    modes.add_argument("--logout-fault", action="store_true")
    modes.add_argument("--filesystem-matrix", action="store_true",
                       help="APFS, ExFAT and journaled HFS+, read-only/read-write, without/with CHAP")
    modes.add_argument("--mutual-chap-matrix", action="store_true",
                       help="APFS, ExFAT and journaled HFS+, read-only/read-write, with mutual CHAP")
    modes.add_argument("--mutual-chap-rejections", action="store_true",
                       help="Reject invalid server proofs before SCSI using the signed production extension")
    modes.add_argument("--bridge-holder", action="store_true",
                       help="Eject while another process holds the bridge's Disk.img (ENV082)")
    parser.add_argument("--read-write", action="store_true")
    authentication = parser.add_mutually_exclusive_group()
    authentication.add_argument("--chap", action="store_true")
    authentication.add_argument("--mutual-chap", action="store_true")
    parser.add_argument("--filesystem", choices=FIXTURE_IMAGES,
                        help="Disposable image filesystem (default: apfs)")
    args = parser.parse_args()
    if (args.fixture_only or args.preflight_only or args.recover_fixture or args.crash_recovery or args.disconnect or args.write_fault or args.logout_fault or args.filesystem_matrix or args.mutual_chap_matrix or args.mutual_chap_rejections or args.bridge_holder) and (args.read_write or args.chap or args.mutual_chap):
        parser.error("--read-write, --chap and --mutual-chap apply only to a mount test")
    if (args.filesystem_matrix or args.mutual_chap_matrix or args.mutual_chap_rejections or args.bridge_holder) and args.filesystem:
        parser.error("The filesystem matrix selects its own filesystems")
    binary_dir = probe_binary_dir()
    if args.fixture_only:
        run_fixture(str(binary_dir / "ISCSIFSKitProbe"), fixture_only=True,
                    file_system=args.filesystem or "apfs")
    else:
        # Every mount uses the block-resource route the app uses, which requires the shared
        # Keychain group of the validation bundle; a plain binary can only probe a URL source.
        with signed_probe(binary_dir, keychain=True) as probe:
            if args.recover_fixture:
                subprocess.run([probe, "--recover-fixture", *args.recover_fixture], check=True, timeout=90)
            else:
                if args.bridge_holder:
                    cases = [dict(bridge_holder=hold) for hold in ("short", "long", "relaunch")]
                elif args.mutual_chap_rejections:
                    cases = [dict(chap=True, mutual_chap=True, authentication_fault=fault)
                             for fault in ("mutual-digest", "mutual-name", "mutual-missing", "mutual-reflected")]
                elif args.mutual_chap_matrix:
                    cases = [dict(file_system=fs, read_write=rw, chap=True, mutual_chap=True)
                             for fs in ("apfs", "exfat", "hfsplus") for rw in (False, True)]
                elif args.filesystem_matrix:
                    cases = [dict(file_system=fs, read_write=rw, chap=chap)
                             for fs in ("apfs", "exfat", "hfsplus") for chap in (False, True) for rw in (False, True)]
                else:
                    stages = ("mountingBridge", "attachingImage", "connected", "detachingImage", "unmountingBridge") if args.crash_recovery else (None,)
                    cases = [dict(preflight_only=args.preflight_only, file_system=args.filesystem or "apfs",
                                  read_write=args.read_write, chap=args.chap or args.mutual_chap,
                                  mutual_chap=args.mutual_chap, crash_recovery=stage,
                                  disconnection=disconnection, write_fault=write_fault, logout_fault=logout_fault)
                             for stage in stages
                             for disconnection in (("eof", "silent") if args.disconnect else (None,))
                             for write_fault in (("write-eof", "flush-eof", "write-silent") if args.write_fault else (None,))
                             for logout_fault in (("eof", "silent") if args.logout_fault else (None,))]
                for case in cases:
                    run_fixture(probe, **case)


def run_bridge_holder(probe, root, nonce, address, hold):
    """ENV082: another process holds the bridge's Disk.img during an ordinary eject.

    The probe's holder reads Disk.img like Parallels Desktop's 7z and keeps it open: briefly
    (`short`, the eject succeeds once it leaves) or past the product's bounded wait (`long`,
    the eject reports EBUSY with the disk still verified and connected, and succeeds once
    released). `relaunch` leaves that disk recorded in `unmountingBridge` for a new process,
    which restores it from the journal and ejects it.
    """
    subprocess.run([probe, "--bridge-holder-loopback-" + hold, address, str(root), nonce],
                   check=True, timeout=180)
    if hold == "relaunch":
        entries = json.loads((root / "State/Connections.json").read_text())["entries"]
        assert [entry["phase"] for entry in entries] == ["unmountingBridge"], entries
        assert bridge_mounted(root), "The held bridge was not left mounted for the relaunch"
        subprocess.run([probe, "--restore-held-bridge-fixture", str(root), nonce], check=True, timeout=120)
    assert json.loads((root / "State/Connections.json").read_text())["entries"] == []
    print(f"PASS: held bridge case {hold}: ejected normally, connection journal empty", flush=True)


def run_fixture(probe, fixture_only=False, preflight_only=False, read_write=False, chap=False, crash_recovery=False, disconnection=None, write_fault=None, logout_fault=None, file_system="apfs", mutual_chap=False, authentication_fault=None, bridge_holder=None):
    assert not mutual_chap or chap
    assert not bridge_holder or not any((fixture_only, read_write, chap, crash_recovery, disconnection,
                                         write_fault, logout_fault, authentication_fault))
    if not fixture_only:
        preflight = subprocess.run([probe, "--preflight"], capture_output=True, text=True, timeout=30)
        print(preflight.stdout, end="")
        if preflight.returncode:
            print(preflight.stderr, end="")
            preflight.check_returncode()
        identities = [json.loads(line.removeprefix("FSKIT_MODULE ")) for line in preflight.stdout.splitlines() if line.startswith("FSKIT_MODULE ")]
        assert len(identities) == 1
        verify_module(identities[0]["modulePath"])
        if preflight_only:
            return
    nonce = str(uuid.uuid4())
    fixtures = ROOT / "build/FSKitFixtures"
    fixtures.mkdir(mode=0o700, parents=True, exist_ok=True)
    assert not fixtures.is_symlink() and fixtures.resolve() == fixtures, "Fixture parent must be a direct directory"
    root = Path(tempfile.mkdtemp(prefix=f"iSCSI-FSKit-{nonce}-", dir=fixtures)).resolve()
    succeeded = False
    try:
        write_fixture_manifest(root, file_system)
        print(f"CASE: filesystem={file_system}, readWrite={read_write}, CHAP={chap}, mutualCHAP={mutual_chap}, authenticationFault={authentication_fault}, bridgeHolder={bridge_holder}", flush=True)
        subprocess.run([probe, "--prepare-fixture", str(root), nonce], check=True, timeout=120)
        memory = bytearray((root / FIXTURE_IMAGES[file_system]).read_bytes())
        original = hashlib.sha256(memory).digest()
        spec = importlib.util.spec_from_file_location("iscsi_fixture_target", ROOT / "scripts/test-integration.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.TARGET = f"iqn.2026-10.test:fskit-{nonce}".encode()
        mode = "--validate-disposable-loopback" if fixture_only else "--mount-disposable-loopback"
        if read_write:
            mode += "-rw"
        if mutual_chap:
            mode += "-mutual-chap"
        elif chap:
            mode += "-chap"
        if disconnection:
            mode = "--disconnect-loopback-" + disconnection
        if write_fault:
            mode = "--raw-write-fault-loopback-" + write_fault
        # A bridge a failed case left mounted is ejected before its target stops serving it.
        release = None if fixture_only else (lambda failed: release_fixture(probe, root, nonce, failed))
        with target_server(module, memory, read_write=read_write, chap=chap, write_fault=write_fault,
                           logout_fault=logout_fault,
                           trace_path=root / "BlockTrace.json" if file_system == "hfsplus" else None,
                           mutual_chap=mutual_chap,
                           authentication_fault=authentication_fault,
                           disconnection=disconnection, release=release) as (address, counters):
            arguments = [probe, mode, address, str(root), nonce]
            if bridge_holder:
                run_bridge_holder(probe, root, nonce, address, bridge_holder)
            elif authentication_fault:
                result = subprocess.run(arguments, capture_output=True, text=True, timeout=90)
                print(result.stdout, end="", flush=True)
                assert result.returncode == 1, "Invalid target proof did not fail the mount probe"
                assert 'FSKit validation failed: failed(program: "mount", status: ' in result.stderr, result.stderr
                print("EXPECTED_MOUNT_REJECTION " + json.dumps(dict(
                    fault=authentication_fault, exit=result.returncode, error=result.stderr.strip())), flush=True)
                assert "PASS: private fixture credential removed from the shared keychain" in result.stdout
                assert not (root / "Credential.json").exists(), "Rejected mount retained its credential intent"
                assert json.loads((root / "State/Connections.json").read_text())["entries"] == []
                print(f"CHECK: expected production mount rejection for {authentication_fault}, exit=1", flush=True)
            elif crash_recovery:
                run_crash_recovery(probe, address, root, nonce, crash_recovery)
            elif read_write or disconnection or write_fault:
                run_mount_probe(arguments, counters, root, disconnection=disconnection, write_fault=write_fault)
            else:
                subprocess.run(arguments, check=True, timeout=180)
        if read_write:
            subprocess.run([probe, "--validate-durable-fixture", str(root), nonce],
                           check=True, timeout=120)
        if write_fault:
            expected = bytearray((root / FIXTURE_IMAGES[file_system]).read_bytes())
            payload = bytearray(b"\xd3" * 4096)
            payload[:len(nonce)] = nonce.encode()
            expected[64 * 1_048_576:64 * 1_048_576 + 4096] = payload
            assert memory == expected, "Uncertain write changed bytes outside the single intended raw region"
            print("PASS: exactly the one 4096-byte uncertain raw write reached the target")
        else:
            assert (hashlib.sha256(memory).digest() != original) == read_write, "Target contents differ from expected write mode"
        assert not resources_remain(root), "Fixture resources remain mounted"
        succeeded = True
        print(f"PASS: fixture RAM contents {'updated' if read_write or write_fault else 'unchanged'} and no mounted resources remain")
    finally:
        if succeeded:
            # Refuse a late child mount before recursively deleting ordinary fixture files.
            remove_empty_mounts(root)
            shutil.rmtree(root)
            print("PASS: fixture directory removed")
        else:
            print(f"Fixture retained for diagnosis: {root}")
            print("Recovery command: " + shlex.join([
                "python3", "scripts/test-fskit.py",
                "--recover-fixture", str(root), nonce,
            ]))


if __name__ == "__main__":
    main()
