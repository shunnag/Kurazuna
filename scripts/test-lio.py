#!/usr/bin/env python3
"""Real FSKit interoperability with a new, disposable Debian/Linux target VM.

Requires Lima 2.2.1+, network access and an enabled signed extension of the app under
test: the development app, or the release app with ISCSI_TEST_APP=release (scripts/test-fskit.py).
Creates no host shares. Never starts, changes or deletes an existing VM.
"""

from contextlib import contextmanager
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fskit_fixture", ROOT / "scripts/test-fskit.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
large_spec = importlib.util.spec_from_file_location("large_lio_fixture", ROOT / "tests/LIO/large_fixture.py")
large_fixture = importlib.util.module_from_spec(large_spec)
large_spec.loader.exec_module(large_fixture)
geometry_spec = importlib.util.spec_from_file_location("lio_geometry_fixture", ROOT / "tests/LIO/geometry_fixture.py")
geometry_fixture = importlib.util.module_from_spec(geometry_spec)
geometry_spec.loader.exec_module(geometry_fixture)
history_spec = importlib.util.spec_from_file_location("lio_history", ROOT / "scripts/lio-history.py")
history_module = importlib.util.module_from_spec(history_spec)
history_spec.loader.exec_module(history_module)
login_spec = importlib.util.spec_from_file_location("lio_login_audit", ROOT / "scripts/lio-login-audit.py")
login_audit = importlib.util.module_from_spec(login_spec)
login_spec.loader.exec_module(login_audit)
crc_spec = importlib.util.spec_from_file_location("lio_crc_fixture", ROOT / "scripts/test-integration.py")
crc_fixture = importlib.util.module_from_spec(crc_spec)
crc_spec.loader.exec_module(crc_fixture)
diagnostic_spec = importlib.util.spec_from_file_location(
    "lio_observer_diagnostics", ROOT / "scripts/lio-observer-diagnostics.py")
diagnostics = importlib.util.module_from_spec(diagnostic_spec)
diagnostic_spec.loader.exec_module(diagnostics)
lifecycle_spec = importlib.util.spec_from_file_location(
    "lio_forwarder_lifecycle", ROOT / "scripts/lio-forwarder-lifecycle.py")
lifecycle = importlib.util.module_from_spec(lifecycle_spec)
lifecycle_spec.loader.exec_module(lifecycle)
tgt_digest_spec = importlib.util.spec_from_file_location(
    "tgt_digest_policy", ROOT / "tests/TGT/digest_policy.py")
tgt_digest_policy = importlib.util.module_from_spec(tgt_digest_spec)
tgt_digest_spec.loader.exec_module(tgt_digest_policy)



def run(arguments, **kwargs):
    print("RUN:", " ".join(map(str, arguments)), flush=True)
    try:
        return subprocess.run(list(map(str, arguments)), check=True, timeout=kwargs.pop("timeout", 120), **kwargs)
    except subprocess.CalledProcessError as error:
        if error.stdout:
            print(error.stdout, flush=True)
        if error.stderr:
            print(error.stderr, flush=True)
        raise


class LinuxTargetVM:
    def __init__(self, logs, implementation="lio"):
        assert implementation in ("lio", "tgt")
        self.implementation = implementation
        self.label = "Linux " + implementation.upper()
        self.name = "iscsi-fskit-" + implementation + "-" + uuid.uuid4().hex[:12]
        self.logs = logs
        self.safe_to_stop = True
        self.staging = "/tmp/" + self.name
        with socket.socket() as port:
            port.bind(("127.0.0.1", 0))
            self.port = port.getsockname()[1]

    def shell(self, *arguments, **kwargs):
        return run(["limactl", "shell", "--workdir=/tmp", self.name, *arguments], **kwargs)

    def copy(self, source, destination):
        run(["limactl", "copy", "--backend=scp", source, destination])

    def configure(self, action, nonce, *options, **kwargs):
        return self.shell("sudo", "python3", self.staging + "/configure.py",
                          action, self.name, nonce, *options, **kwargs)

    def wait_for_target(self):
        deadline = time.monotonic() + 15
        while True:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)

    def startup_diagnostics(self):
        """Retain bounded observations; never retry startup or run a package manager."""
        deadline = time.monotonic() + 30
        observations = []
        commands = [
            ("instance", ["limactl", "list", self.name, "--json"]),
            ("cloud-final", ["limactl", "shell", "--workdir=/tmp", self.name,
                             "sudo", "journalctl", "-b", "-u", "cloud-final.service",
                             "--no-pager", "-n", "30"]),
            ("cloud-output", ["limactl", "shell", "--workdir=/tmp", self.name,
                              "sudo", "tail", "-c", "65536", "/var/log/cloud-init-output.log"]),
            ("processes", ["limactl", "shell", "--workdir=/tmp", self.name,
                           "ps", "-eo", "pid,ppid,comm"]),
        ]
        for label, command in commands:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                observations.append(dict(kind=label, unavailable="diagnostic budget exhausted"))
                continue
            result = dict(kind=label, command=command, observedNS=time.time_ns())
            # Files avoid accumulating command output in memory. Only the last 64 KiB
            # of each stream is retained in the private record, including on timeout.
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                try:
                    child = subprocess.run(command, stdout=out, stderr=err,
                                           timeout=min(5, remaining), check=False)
                    result["exit"] = child.returncode
                except (OSError, subprocess.TimeoutExpired) as error:
                    result["unavailable"] = type(error).__name__
                for name, stream in [("stdout", out), ("stderr", err)]:
                    size = stream.seek(0, os.SEEK_END)
                    stream.seek(max(0, size - 65536))
                    result[name] = stream.read(65536).decode("utf-8", errors="replace")
                    result[name + "Bytes"] = size
                    result[name + "Truncated"] = size > 65536
            observations.append(result)
        record = dict(complete=True, VM=self.name, readOnly=True,
                      startupRetried=False, retainedStreamLimit=65536,
                      maximumObservationSeconds=30, observations=observations)
        path = self.logs / "startup-diagnostics.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(record, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())

    def start(self):
        # Include the complete 8 GiB disk, 2 GiB RAM, download and temporary copies.
        run([sys.executable, ROOT / "scripts/check-storage.py", "--required-gib", "15"])
        existing = subprocess.check_output(["limactl", "list", "--json"], text=True, timeout=30)
        assert all(json.loads(line)["name"] != self.name for line in existing.splitlines() if line.strip())
        config = self.logs / (self.name + ".yaml")
        config.write_text(f"""minimumLimaVersion: 2.2.1
vmType: vz
arch: aarch64
images:
  - location: https://cloud.debian.org/images/cloud/trixie/20261001-2618/debian-13-genericcloud-arm64-20261001-2618.qcow2
    arch: aarch64
    digest: sha512:d8470b8c6c38fead046c794b5800a5a7b96672d5bcf543cc230ceb0c4b8ace05ed341a0c8928045422243fde26b2f1f2f58e99244c65709ffda2e3d4b674dd5a
cpus: 2
memory: 2GiB
disk: 8GiB
mounts: []
ssh:
  localPort: 0
  loadDotSSHPubKeys: false
  forwardAgent: false
containerd:
  system: false
  user: false
propagateProxyEnv: false
portForwards:
  - guestIP: 127.0.0.1
    guestPort: 3260
    hostIP: 127.0.0.1
    hostPort: {self.port}
  - guestIP: 0.0.0.0
    proto: any
    ignore: true
""")
        run(["limactl", "validate", config])
        with (self.logs / "vm-start.log").open("w") as log:
            try:
                run(["limactl", "start", "--tty=false", "--mount-none", "--containerd=none",
                     "--timeout=8m", "--name=" + self.name, config],
                    stdout=log, stderr=subprocess.STDOUT, timeout=510)
            except Exception:
                try:
                    self.startup_diagnostics()
                except Exception as diagnostic_error:
                    print("Startup diagnostics unavailable:", type(diagnostic_error).__name__, flush=True)
                raise
        effective = json.loads(subprocess.check_output(["limactl", "list", self.name, "--json"], text=True, timeout=30))
        assert not effective["config"].get("mounts", [])
        assert not effective["config"]["ssh"]["forwardAgent"]
        assert not effective["config"]["ssh"]["loadDotSSHPubKeys"]
        assert not effective["config"]["containerd"]["system"] and not effective["config"]["containerd"]["user"]
        mounts = self.shell("findmnt", "-rn", "-o", "FSTYPE,TARGET", capture_output=True, text=True)
        assert all(line.split()[0] not in ("virtiofs", "9p") for line in mounts.stdout.splitlines())
        self.shell("python3", "-c", "import shutil; "
                   "assert shutil.disk_usage('/').free >= 2 * 1024**3, "
                   "'Guest reserve plus package allocation does not fit'")
        with (self.logs / "vm-provision.log").open("w") as log:
            if self.implementation == "tgt":
                # Prevent package installation from starting a wildcard listener.
                # The test starts its own daemon with a private IPC socket below.
                self.shell("sudo", "systemctl", "mask", "tgt.service", stdout=log, stderr=subprocess.STDOUT)
            self.shell("sudo", "sh", "-c", "apt-get -o DPkg::Lock::Timeout=30 update && "
                       "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y "
                       "--no-install-recommends " + ("targetcli-fb" if self.implementation == "lio" else "tgt"),
                       stdout=log, stderr=subprocess.STDOUT, timeout=480)
        packages = "targetcli-fb python3-rtslib-fb" if self.implementation == "lio" else "tgt"
        version = self.shell("sh", "-c", "uname -r; dpkg-query -W " + packages + "; cat /etc/debian_version",
                             capture_output=True, text=True)
        print(version.stdout, end="", flush=True)
        (self.logs / "versions.txt").write_text(version.stdout)
        if self.implementation == "tgt":
            notice = self.shell("cat", "/usr/share/doc/tgt/copyright", capture_output=True, text=True)
            (self.logs / "tgt-copyright.txt").write_text(notice.stdout)
        self.shell("mkdir", "-m", "700", self.staging)
        self.stage_configuration()

    def stage_configuration(self):
        """Stage the configurator and its exact implementation-specific imports."""
        if self.implementation not in ("lio", "tgt"):
            raise ValueError("Unknown fixture implementation")
        self.copy(ROOT / "tests" / self.implementation.upper() / "configure.py",
                  self.name + ":" + self.staging + "/configure.py")
        if self.implementation == "tgt":
            self.copy(ROOT / "tests/TGT/digest_policy.py",
                      self.name + ":" + self.staging + "/digest_policy.py")
            self.copy(ROOT / "tests/LIO/geometry_fixture.py",
                      self.name + ":" + self.staging + "/geometry_fixture.py")
        else:
            self.copy(ROOT / "tests/LIO/large_fixture.py", self.name + ":" + self.staging + "/large_fixture.py")
            self.copy(ROOT / "tests/LIO/large_filesystem.py", self.name + ":" + self.staging + "/large_filesystem.py")
            self.copy(ROOT / "tests/LIO/geometry_fixture.py", self.name + ":" + self.staging + "/geometry_fixture.py")

    def finish(self, succeeded):
        if not self.safe_to_stop:
            print("Retained running test VM for mounted fixture recovery:", self.name, flush=True)
            return
        # No force: preserve evidence and report a failure if normal shutdown fails.
        run(["limactl", "stop", "--tty=false", self.name], timeout=90)
        if succeeded:
            run(["limactl", "delete", "--tty=false", self.name])
            print("PASS: only the newly created " + self.label + " VM was stopped and deleted", flush=True)
        else:
            print("Retained stopped test VM for diagnosis:", self.name, flush=True)


class WireAudit:
    """Observe command/GOOD ordering without changing forwarded iSCSI bytes.

    Authentication text and payloads are not persisted. This is
    an I/O observer, not another implementation of the target's SCSI behavior.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.paused = False
        self.pending_commands = 0
        self.writes = self.flushes = self.durable_writes = self.reads = 0
        self.acknowledged_writes = 0
        self.sessions = 0
        self.errors = []
        self.normal_digests = []
        self.nop_out = self.nop_replies = 0
        self.target_nop_in = self.target_nop_out = 0
        self.read_bytes = self.write_bytes = 0
        self.logouts = self.logout_replies = 0
        self.response_headers = []
        self.device_errors = []
        self.block_commands = []
        self.capacity16_requests = 0
        self.login_credentials = None
        self.login_states = []
        self.digest_checks = dict(header=0, data=0)
        self.observation_disabled = threading.Event()
        self.observation_failures = []
        self.transport_failures = []
        self.failure_lock = threading.Lock()
        # Failures of the forwarder itself (a bound tripped), not of the initiator or target.
        self.harness_errors = []
        self.harness_error_event = threading.Event()
        self.harness_listeners = []
        self.maximum_connections = 64
        self.diagnostic_codes = {
            WireAudit.forward.__code__: 'wire.forward',
            WireAudit.observe.__code__: 'wire.observe',
            HistoricalWireAudit.observe.__code__: 'history.dispatch',
            history_module.WireHistory.observe.__code__: 'history.observe',
            history_module.WireHistory._frame.__code__: 'history.write',
            login_audit.LoginAudit.observe.__code__: 'login.observe',
            login_audit.frame_layout.__code__: 'frame.layout',
            login_audit.validate_frame.__code__: 'frame.validate',
        }

    def validate_logins(self, require_sessions=False):
        with self.lock:
            valid = (len(self.login_states) == self.sessions
                     and (self.sessions > 0 or not require_sessions)
                     and all(state.summary()["complete"] for state in self.login_states)
                     and not self.observation_disabled.is_set() and not self.transport_failures)
        if not valid:
            self.observation_failed(login_audit.AuditError("LOGIN_COVERAGE"))
            raise login_audit.AuditError("LOGIN_COVERAGE")

    def observation_failed(self, error, *, stage='direct'):
        # Arbitrary parser exceptions may embed peer authentication bytes.
        code = "OBSERVER_FAILED"
        if (type(error) is login_audit.AuditError and len(error.args) == 1
                and type(error.args[0]) is str and error.args[0] in login_audit.AuditError.CODES):
            code = error.args[0]
        with self.failure_lock:
            if not self.observation_disabled.is_set():
                row = dict(code=code, monotonicNS=time.monotonic_ns())
                try:
                    row.update(diagnostics.detail(error, stage, self.diagnostic_codes, login_audit.AuditError))
                except BaseException:
                    pass  # Diagnostic failure must not change byte forwarding or failure admission.
                self.observation_failures.append(row)
                with self.lock:
                    self.errors.append(code)
                    self.observation_disabled.set()
                    self.condition.notify_all()

    def harness_failure(self, code, **detail):
        """Record, print and announce a forwarder failure at once, with its time.

        Call it without holding self.lock: listeners take their own locks."""
        row = dict(code=code, monotonicNS=time.monotonic_ns(),
                   wallTime=time.strftime("%Y-%m-%dT%H:%M:%S%z"), **detail)
        with self.failure_lock:
            self.harness_errors.append(row)
            listeners = list(self.harness_listeners)
        self.harness_error_event.set()
        print("HARNESS ERROR:", json.dumps(row, default=str), flush=True)
        for listener in listeners:
            try:
                listener(row)
            except Exception:
                pass  # Announcing must not change forwarding or the recorded failure.
        return row

    def add_harness_listener(self, listener):
        """Call `listener(row)` for each harness failure, including ones already recorded."""
        with self.failure_lock:
            self.harness_listeners.append(listener)
            recorded = list(self.harness_errors)
        for row in recorded:
            listener(row)

    def validate_logouts(self):
        self.validate_logins()
        with self.lock:
            valid = (self.sessions == self.logouts == self.logout_replies
                     and all(row["logoutRequests"] == row["logoutReplies"] == 1
                             for row in (state.summary() for state in self.login_states)))
        if not valid:
            self.observation_failed(login_audit.AuditError("LOGOUT_COVERAGE"))
            raise login_audit.AuditError("LOGOUT_COVERAGE")

    def observe(self, header, connection, to_target, body):
        opcode = header[0] & 0x3F
        if opcode in (3, 0x23):
            if "loginAudit" not in connection:
                with self.lock:
                    require_limit = len(self.login_states) < 64
                    if not require_limit:
                        raise login_audit.AuditError("LOGIN_CONNECTION_LIMIT")
                    connection["loginAudit"] = login_audit.LoginAudit(
                        self.login_credentials, connection.get("historyConnection", len(self.login_states) + 1))
                    self.login_states.append(connection["loginAudit"])
            state = connection["loginAudit"]
            finalized = state.observe(header, to_target, body)
            summary = state.summary()
            connection["normal"] = summary["sessionType"] == "Normal"
            connection["header"] = summary["headerDigest"] == "CRC32C"
            connection["data"] = summary["dataDigest"] == "CRC32C"
            connection["ready"] = state.ready
            if finalized and connection["normal"]:
                with self.lock:
                    self.normal_digests.append((connection["header"], connection["data"]))
            return
        if not connection["ready"]:
            raise login_audit.AuditError("FRAME_BEFORE_LOGIN")
        tag = bytes(header[16:20])
        transfer_tag = bytes(header[20:24])
        with self.lock:
            if to_target and opcode == 1:
                # Finish already admitted writes and their natural cache flush, but do
                # not admit another block request while copying the guest backstore.
                admitted = self.condition.wait_for(
                    lambda: not self.paused or self.observation_disabled.is_set()
                    or header[32] in (0x35, 0x91), timeout=20)
                assert admitted, "Snapshot admission pause exceeded its bound"
                if self.observation_disabled.is_set():
                    return
            target_reply = to_target and opcode == 0 and tag == b"\xff" * 4 and transfer_tag in connection["target_nops"]
            if to_target and connection["logout"] is not None:
                assert target_reply, "Another request followed Logout"
            if to_target and opcode == 6:
                assert header[0] == 0x46 and header[1] == 0x80 and not body
                if "loginAudit" in connection:
                    connection["loginAudit"].record_logout(True)
                connection["logout"] = tag
                self.logouts += 1
            elif not to_target and opcode == 0x26:
                if (connection["logout"] != tag or header[2] != 0 or body
                        or connection.get("logoutReplied", False)):
                    raise login_audit.AuditError("LOGOUT_RESPONSE")
                if "loginAudit" in connection:
                    connection["loginAudit"].record_logout(False)
                connection["logoutReplied"] = True
                self.logout_replies += 1
            elif to_target and opcode == 0 and tag != b"\xff" * 4:
                assert len(body) <= 64 and tag not in connection["nops"]
                connection["nops"][tag] = bytes(body)
                assert len(connection["nops"]) <= 4
                self.nop_out += 1
            elif not to_target and opcode == 0x20 and tag != b"\xff" * 4:
                assert connection["nops"].pop(tag) == body
                self.nop_replies += 1
            elif not to_target and opcode == 0x20 and transfer_tag != b"\xff" * 4:
                assert not body and transfer_tag not in connection["target_nops"]
                connection["target_nops"][transfer_tag] = bytes(header[8:16])
                assert len(connection["target_nops"]) <= 4
                self.target_nop_in += 1
            elif target_reply:
                assert not body and connection["target_nops"].pop(transfer_tag) == bytes(header[8:16])
                self.target_nop_out += 1
            elif to_target and opcode == 1:
                command = header[32]
                if command in (0x28, 0x2A, 0x88, 0x8A) and len(self.block_commands) < 512:
                    wide = command in (0x88, 0x8A)
                    self.block_commands.append(dict(
                        opcode=command, lba=int.from_bytes(header[34:42] if wide else header[34:38], "big"),
                        blocks=int.from_bytes(header[42:46] if wide else header[39:41], "big"),
                        transferBytes=int.from_bytes(header[20:24], "big")))
                if command == 0x9E and header[33] & 31 == 0x10:
                    self.capacity16_requests += 1
                assert tag not in connection["commands"]
                connection["commands"][tag] = (command, self.writes)
                self.pending_commands += 1
                assert len(connection["commands"]) <= 128
                if command in (0x2A, 0x8A):
                    self.writes += 1
                    self.write_bytes += int.from_bytes(header[20:24], "big")
                elif command in (0x28, 0x88):
                    self.reads += 1
                    self.read_bytes += int.from_bytes(header[20:24], "big")
                elif command in (0x35, 0x91):
                    assert self.acknowledged_writes == self.writes, "Flush sent before prior write completion"
            elif not to_target and opcode in (0x21, 0x25):
                if len(self.response_headers) < 64:
                    self.response_headers.append(bytes(header).hex())
                if opcode == 0x21 and header[3] and len(self.device_errors) < 64:
                    # Keep only SCSI error metadata, never a block or authentication payload.
                    error = dict(status=header[3], expDataSN=int.from_bytes(header[36:40], "big"))
                    sense_length = int.from_bytes(body[:2], "big") if len(body) >= 2 else 0
                    sense = body[2:2 + sense_length]
                    if len(sense) == sense_length and sense:
                        if sense[0] & 0x7F in (0x70, 0x71) and len(sense) >= 14:
                            error.update(senseKey=sense[2] & 15, asc=sense[12], ascq=sense[13])
                        elif sense[0] & 0x7F in (0x72, 0x73) and len(sense) >= 4:
                            error.update(senseKey=sense[1] & 15, asc=sense[2], ascq=sense[3])
                    self.device_errors.append(error)
                if opcode == 0x25 and not header[1] & 1:
                    return
                result = connection["commands"].pop(tag, None)
                if result is not None:
                    self.pending_commands -= 1
                if result is not None and header[2] == 0 and header[3] == 0:
                    command, previous_writes = result
                    if command in (0x2A, 0x8A):
                        self.acknowledged_writes += 1
                    elif command in (0x35, 0x91):
                        self.flushes += 1
                        self.durable_writes = previous_writes
                self.condition.notify_all()

    @contextmanager
    def quiesce(self, timeout=8):
        with self.condition:
            assert not self.paused, "Snapshots cannot overlap"
            self.paused = True
            self.condition.notify_all()
        try:
            with self.condition:
                complete = self.condition.wait_for(
                    lambda: self.pending_commands == 0 and self.durable_writes == self.writes,
                    timeout=timeout)
                assert complete, "Admitted commands did not finish before the snapshot"
            yield
        finally:
            with self.condition:
                self.paused = False
                self.condition.notify_all()

    def counters(self):
        with self.lock:
            return dict(writes=self.writes, flushes=self.flushes, durableWrites=self.durable_writes,
                        reads=self.reads, sessions=self.sessions, nopOut=self.nop_out,
                        nopReplies=self.nop_replies, readBytes=self.read_bytes, writeBytes=self.write_bytes,
                        logouts=self.logouts, logoutReplies=self.logout_replies,
                        targetNopIn=self.target_nop_in, targetNopOut=self.target_nop_out,
                        loginResults=[state.summary() for state in self.login_states],
                        digestChecks=dict(self.digest_checks),
                        observationDisabled=self.observation_disabled.is_set())

    def forward(self, source, destination, connection, to_target):
        pending = bytearray()
        try:
            while True:
                # One writer owns each direction. Wake it even if its peer stalls
                # after an observer in the opposite direction becomes invalid.
                if self.observation_disabled.is_set() and pending:
                    destination.sendall(pending)
                    pending.clear()
                if not select.select([source], [], [], .1)[0]:
                    continue
                data = source.recv(65536)
                if not data:
                    break
                pending.extend(data)
                if self.observation_disabled.is_set():
                    destination.sendall(pending)
                    pending.clear()
                    continue
                while len(pending) >= 48:
                    stage = 'frame-layout'
                    try:
                        policy = (connection["ready"], connection["header"], connection["data"])
                        size = login_audit.frame_layout(pending, *policy)[3]
                        if len(pending) < size:
                            break
                        stage = 'frame-validation'
                        body, checked_header, checked_data = login_audit.validate_frame(
                            pending[:size], *policy, crc_fixture.crc32c)
                        stage = 'digest-accounting'
                        if "loginAudit" in connection:
                            connection["loginAudit"].checked_digests(checked_header, checked_data)
                        with self.lock:
                            self.digest_checks["header"] += int(checked_header)
                            self.digest_checks["data"] += int(checked_data)
                        stage = 'command-observation'
                        self.observe(pending[:48], connection, to_target, body)
                    except Exception as error:
                        self.observation_failed(error, stage=stage)
                        destination.sendall(pending)
                        pending.clear()
                        break
                    destination.sendall(pending[:size])
                    del pending[:size]
                    if self.observation_disabled.is_set():
                        destination.sendall(pending)
                        pending.clear()
                        break
            if pending:
                self.observation_failed(login_audit.AuditError("PARTIAL_FRAME_AT_CLOSE"), stage='stream-close')
                destination.sendall(pending)
                pending.clear()
        except OSError:
            with self.failure_lock:
                self.transport_failures.append(dict(code="TRANSPORT_FAILED"))
            self.observation_failed(login_audit.AuditError("TRANSPORT_FAILED"), stage='transport')
        finally:
            if "loginAudit" in connection:
                if not connection["loginAudit"].ready:
                    self.observation_failed(login_audit.AuditError("LOGIN_INCOMPLETE_CLOSE"))
                connection["loginAudit"].close()
            elif not connection["ready"]:
                self.observation_failed(login_audit.AuditError("LOGIN_INCOMPLETE_CLOSE"))
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _relay(self, owner, pair, source, destination, connection, to_target):
        """One direction of a connection; the second to return closes both sockets, so the
        forwarder's bounds count connections in use rather than every one ever accepted."""
        try:
            self.forward(source, destination, connection, to_target)
        finally:
            with pair["lock"]:
                pair["running"] -= 1
                last = pair["running"] == 0
            if last:
                owner.release(*pair["streams"])

    @contextmanager
    def proxy(self, target_port, *, resources=None, owner=None):
        # Ownership survives failed entry and a consumed generator. Do not serialize it.
        owner = owner if owner is not None else lifecycle.Forwarder(
            socket_factory=socket.socket, thread_factory=threading.Thread)
        if resources is not None:
            assert not resources
            resources.update(listener=None, workers=owner.workers, streams=owner.streams,
                             stopping=owner.stopping, acceptor=None, owner=owner)
        failed = False
        try:
            listener = owner.new_socket(listener=True)
            if resources is not None:
                resources['listener'] = listener
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(0.2)

            def accept():
                client = remote = None
                try:
                    while not owner.stopping.is_set():
                        client = remote = None
                        try:
                            client, _ = listener.accept()
                        except socket.timeout:
                            continue
                        except OSError:
                            if owner.stopping.is_set():
                                break
                            raise
                        if not owner.adopt(client):
                            break
                        with self.lock:
                            exhausted = self.sessions >= self.maximum_connections
                            if not exhausted:
                                self.sessions += 1
                        if exhausted:
                            # A budget per run, unlike the forwarder's concurrent bounds.
                            self.harness_failure("CONNECTION_LIMIT",
                                                 limit=self.maximum_connections,
                                                 acceptedConnections=self.sessions)
                            self.observation_failed(login_audit.AuditError("CONNECTION_LIMIT"))
                            owner.interrupt()
                            break
                        remote = owner.new_socket()
                        try:
                            remote.settimeout(5)
                            remote.connect(("127.0.0.1", target_port))
                            remote.settimeout(None)
                        except OSError:
                            if not owner.stopping.is_set():
                                with self.lock:
                                    self.errors.append("TARGET_CONNECTION_FAILED")
                            client.close()
                            remote.close()
                            continue
                        connection = dict(ready=False, header=False, data=False, normal=False,
                                          commands={}, nops={}, target_nops={}, logout=None)
                        # Both relays of a connection must return before its sockets close.
                        pair = dict(lock=threading.Lock(), running=2, streams=(client, remote))
                        for args in ((client, remote, connection, True), (remote, client, connection, False)):
                            if owner.start(self._relay, (owner, pair) + args) is None:
                                break
                except BaseException:
                    if owner.tripped is None:
                        self.observation_failed(login_audit.AuditError("TRANSPORT_FAILED"))
                        owner.interrupt()
                    else:
                        # The connection being set up when a bound tripped can't be relayed:
                        # end it now (a relay already started sees EOF; cleanup closes the
                        # sockets). Connections relayed before the trip drain until cleanup.
                        for stream in (client, remote):
                            try:
                                if stream is not None:
                                    stream.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                finally:
                    if owner.tripped is not None:
                        self.harness_failure(
                            "FORWARDER_LIMIT", limit=owner.tripped["code"],
                            trippedNS=owner.tripped["monotonicNS"],
                            concurrentStreams=owner.tripped["streams"],
                            concurrentThreads=owner.tripped["threads"],
                            maximumStreams=owner.tripped["maximumStreams"],
                            maximumThreads=owner.tripped["maximumThreads"],
                            acceptedConnections=self.sessions)

            acceptor = owner.start(accept, producer=True)
            if resources is not None:
                resources['acceptor'] = acceptor
            assert acceptor is not None
            yield "127.0.0.1:" + str(listener.getsockname()[1])
        except BaseException:
            failed = True
            with owner.lock:
                owner.failures.add('CONTEXT_FAILED')
            raise
        finally:
            with self.condition:
                self.paused = False
                self.condition.notify_all()
            closed = owner.cleanup()
            if not failed:
                assert closed, "Forwarder resources remain owned for retry"
                self.validate_logins()
                self.validate_logouts()
                assert not owner.failures, "Forwarder lifecycle evidence invalid"
                assert not self.errors, self.errors


class HistoricalWireAudit(WireAudit):
    """Record fixture writes without hashing while a response is being forwarded."""

    def __init__(self, seed, block_size=512):
        super().__init__()
        self.history = history_module.WireHistory(seed, block_size=block_size)
        self.connection_count = 0

    def observe(self, header, connection, to_target, body):
        if header[0] & 0x3f not in (3, 0x23) and not connection["ready"]:
            raise login_audit.AuditError("FRAME_BEFORE_LOGIN")
        with self.lock:
            if "historyConnection" not in connection:
                self.connection_count += 1
                connection["historyConnection"] = self.connection_count
        state = connection.get("loginAudit")
        self.history.observe(header, connection["historyConnection"], to_target, body,
                             login_summary=state.summary() if state else None)
        return super().observe(header, connection, to_target, body)

    def historical_snapshot(self, destination, cutoff, *, boundary_name="file-fullfsync"):
        assert time.get_clock_info("monotonic").implementation == "mach_absolute_time()"
        assert not destination.exists()
        image, selected = self.history.snapshot(cutoff)
        destination.write_bytes(image)
        result = dict(cutoffNS=cutoff, selectedResponseNS=selected["responseObservedNS"],
                      selectedWrites=selected["writes"], sha256=selected["sha256"])
        destination.with_name("HistoricalSelection.json").write_text(json.dumps(dict(
            clock="mach_absolute_time", snapshots=[dict(boundary=dict(name=boundary_name, completedNS=cutoff),
            selected=selected, image=destination.name, sha256=selected["sha256"])],
            legacyCheckpointWrites=self.counters()["writes"], provenance=result), indent=2) + "\n")
        return result


def expected_normal_digests(implementation, digest):
    if implementation == "tgt":
        policy = tgt_digest_policy.parse_policy(digest, legacy_single=True)
        return tuple(policy[key] == "CRC32C" for key in ("header", "data"))
    if implementation != "lio" or type(digest) is not str or digest not in ("None", "CRC32C"):
        raise ValueError("Invalid fixture implementation or digest policy")
    return (digest == "CRC32C", digest == "CRC32C")


def run_case(vm, probe, binary_dir, digest, chap, read_write, block_size, soak_seconds=None, file_system="apfs"):
    expected_digests = expected_normal_digests(vm.implementation, digest)
    nonce = str(uuid.uuid4())
    parent = ROOT / "build/FSKitFixtures"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    assert parent.resolve() == parent and not parent.is_symlink()
    root = Path(tempfile.mkdtemp(prefix=f"iSCSI-FSKit-{nonce}-", dir=parent)).resolve()
    succeeded = configured = False
    audit = None
    try:
        fixture.write_fixture_manifest(root, file_system)
        print(f"CASE: filesystem={file_system}, digest={digest}, block={block_size}, readWrite={read_write}, CHAP={chap}", flush=True)
        run([probe, "--prepare-fixture", root, nonce])
        image = root / fixture.FIXTURE_IMAGES[file_system]
        original = hashlib.sha256(image.read_bytes()).hexdigest()
        vm.copy(image, vm.name + ":" + vm.staging + "/" + nonce + ".img")
        configured = True
        vm.configure("setup", nonce, digest, "yes" if chap else "no", str(block_size), original)
        vm.wait_for_target()
        audit = HistoricalWireAudit(image.read_bytes(), block_size) if read_write and not soak_seconds else WireAudit()

        def counters(destination=None):
            if destination is not None:
                with audit.quiesce():
                    before = audit.counters()
                    vm.configure("snapshot", nonce, timeout=10)
                    assert audit.counters()["writes"] == before["writes"], "Writes overlapped the image copy"
                    print("CHECK: quiesced guest snapshot prefix:", before, flush=True)
                # Only the guest-side source copy requires quiescence. The SCP input is
                # now immutable, so resume I/O before transferring it to the host.
                vm.copy(vm.name + ":" + vm.staging + "/" + nonce + "-snapshot.img", destination)
                vm.shell("rm", "--", vm.staging + "/" + nonce + "-snapshot.img")
                return before
            return audit.counters()

        with audit.proxy(vm.port) as address:
            kind = vm.implementation
            environment = dict(os.environ, ISCSI_INITIATOR_NAME="iqn.2026-10.dev.soba:" + kind + "-probe-" + nonce)
            discovery = run([binary_dir / "iscsi", "discover", address], env=environment,
                            capture_output=True, text=True)
            assert "iqn.2026-10.dev.soba:" + kind + "-" + nonce in discovery.stdout
            print(discovery.stdout, end="", flush=True)
            if not chap:
                run([probe, "--validate-" + kind + "-loopback", address, root, nonce])
            mode = "--mount-" + kind + "-loopback" + ("-rw" if read_write else "") + ("-chap" if chap else "")
            if soak_seconds:
                assert chap and read_write
                mode = "--soak-" + kind + "-loopback-chap"
            arguments = [probe, mode, address, str(root), nonce]
            try:
                if read_write:
                    if soak_seconds:
                        # This public test-only value is consumed by the probe, never by the extension.
                        previous = os.environ.get("ISCSI_SOAK_SECONDS")
                        os.environ["ISCSI_SOAK_SECONDS"] = str(soak_seconds)
                        try:
                            fixture.run_mount_probe(arguments, counters, root, soak_seconds=soak_seconds,
                                                    target_heartbeats=vm.implementation == "tgt")
                        finally:
                            if previous is None:
                                os.environ.pop("ISCSI_SOAK_SECONDS", None)
                            else:
                                os.environ["ISCSI_SOAK_SECONDS"] = previous
                    else:
                        fixture.run_mount_probe(arguments, counters, root,
                                                historical_snapshot=audit.historical_snapshot)
                else:
                    run(arguments, timeout=180)
            except Exception:
                run([probe, "--recover-fixture", root, nonce], timeout=90)
                raise
        if read_write:
            validation = "--validate-soak-durable-fixture" if soak_seconds else "--validate-durable-fixture"
            run([probe, validation, root, nonce])
            assert audit.writes > 0 and audit.flushes > 0
        else:
            assert audit.writes == 0
        assert audit.normal_digests and set(audit.normal_digests) == {expected_digests}
        assert audit.logouts == audit.logout_replies == audit.sessions, "Some sessions did not finish Logout"
        counters(root / "Final.img")
        if isinstance(audit, HistoricalWireAudit):
            history = audit.history.export(root)
            assert hashlib.sha256((root / "Final.img").read_bytes()).hexdigest() == history["finalSHA256"]
        assert (hashlib.sha256((root / "Final.img").read_bytes()).hexdigest() != original) == read_write
        assert not fixture.resources_remain(root)
        if soak_seconds:
            assert audit.sessions == 4, "Soak session was unexpectedly reconnected"
            if vm.implementation == "tgt":
                assert audit.target_nop_in > 0 and audit.target_nop_in == audit.target_nop_out
            report = json.loads((root / "SoakReport.json").read_text())
            report["wire"] = counters()
            (vm.logs / (nonce + "-soak.json")).write_text(json.dumps(report, indent=2) + "\n")
        report = dict(target=vm.implementation, filesystem=file_system, digest=digest, chap=chap,
                      readWrite=read_write, blockSize=block_size, wire=counters(),
                      deviceErrors=audit.device_errors)
        (vm.logs / (nonce + "-case.json")).write_text(json.dumps(report, indent=2) + "\n")
        print(f"PASS: {vm.label}, {digest}, CHAP={chap}, RW={read_write}, block={block_size}, filesystem={file_system}: {counters()}", flush=True)
        succeeded = True
    finally:
        if not succeeded and audit is not None:
            (vm.logs / (nonce + "-failure.json")).write_text(json.dumps(
                dict(wire=audit.counters(), responseHeaders=audit.response_headers,
                     deviceErrors=audit.device_errors,
                     errors=[str(error) for error in audit.errors]), indent=2) + "\n")
        if fixture.resources_remain(root):
            vm.safe_to_stop = False
            print("Mounted fixture retained; recover before stopping VM:", root, nonce, flush=True)
        else:
            if configured:
                vm.configure("remove", nonce)
            if succeeded:
                fixture.remove_empty_mounts(root)
                shutil.rmtree(root)
                print("PASS: local fixture removed", flush=True)
            else:
                print("Fixture retained for diagnosis:", root, flush=True)


def run_large_case(vm, probe, binary_dir, digest, chap, read_write, block_size=512):
    assert vm.implementation == "lio"
    assert block_size in (512, 4096) and (block_size == 512 or not read_write)
    nonce = str(uuid.uuid4())
    parent = ROOT / "build/FSKitFixtures"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    assert parent.resolve() == parent and not parent.is_symlink()
    root = Path(tempfile.mkdtemp(prefix=f"iSCSI-FSKit-{nonce}-", dir=parent)).resolve()
    succeeded = configured = False
    audit = WireAudit()
    try:
        regions = [dict(offset=offset, before=base64.b64encode(before).decode(),
                        after=base64.b64encode(after).decode())
                   for offset, before, after in large_fixture.regions(nonce)]
        manifest = dict(nonce=nonce, byteCount=large_fixture.BYTE_COUNT, blockSize=block_size, regions=regions)
        path = root / "LargeFixture.json"
        path.write_text(json.dumps(manifest) + "\n")
        path.chmod(0o600)
        print(f"CASE: sparse 3 TiB, block={block_size}, digest={digest}, CHAP={chap}, RW={read_write}", flush=True)
        configured = True
        vm.configure("setup-sparse", nonce, digest, "yes" if chap else "no", str(block_size), "sparse-3TiB-v1")
        vm.wait_for_target()

        def verify(mode):
            response = vm.configure("verify-sparse", nonce, mode, capture_output=True, text=True)
            value = json.loads(response.stdout)
            assert value["byteCount"] == large_fixture.BYTE_COUNT and value["mode"] == mode
            assert value["allAllocatedBytesMatch"] and not value["extraSyncIssued"]
            return value

        initial = verify("original")
        synchronized = None

        def counters(destination=None):
            nonlocal synchronized
            if destination is not None:
                # Capture only the small extent audit, never copy a multi-terabyte file.
                with audit.quiesce():
                    before = audit.counters()
                    synchronized = verify("written")
                    assert audit.counters()["writes"] == before["writes"]
                (root / "SparseSynchronized.json").write_text(json.dumps(synchronized, indent=2) + "\n")
                return before
            return audit.counters()

        with audit.proxy(vm.port) as address:
            environment = dict(os.environ, ISCSI_INITIATOR_NAME="iqn.2026-10.dev.soba:lio-probe-" + nonce)
            discovery = run([binary_dir / "iscsi", "discover", address], env=environment,
                            capture_output=True, text=True)
            assert "iqn.2026-10.dev.soba:lio-" + nonce in discovery.stdout
            mode = "--large-lio-loopback" + ("-rw" if read_write else "") + ("-chap" if chap else "")
            arguments = [probe, mode, address, str(root), nonce]
            try:
                if read_write:
                    fixture.run_mount_probe(arguments, counters, root)
                else:
                    run(arguments, timeout=180)
            except Exception:
                run([probe, "--recover-fixture", root, nonce], timeout=90)
                raise
        final = verify("written" if read_write else "original")
        assert audit.capacity16_requests > 0
        commands = audit.block_commands
        assert 0 < len(commands) < 512
        assert any(command["opcode"] == 0x28 for command in commands)
        if block_size == 512:
            assert any(command["opcode"] == 0x88 and command["lba"] >= 1 << 32 for command in commands)
        else:
            assert all(command["opcode"] == 0x28 for command in commands)
        for command in commands:
            assert command["blocks"] > 0 and command["transferBytes"] == command["blocks"] * block_size
            assert command["lba"] + command["blocks"] <= large_fixture.BYTE_COUNT // block_size
            narrow = command["lba"] + command["blocks"] - 1 <= 0xFFFFFFFF and command["blocks"] <= 65535
            assert (command["opcode"] in (0x28, 0x2A)) == narrow
        if read_write:
            assert synchronized is not None
            assert any(command["opcode"] == 0x2A for command in commands)
            assert any(command["opcode"] == 0x8A and command["lba"] >= 1 << 32 for command in commands)
            assert audit.writes > 0 and audit.durable_writes == audit.writes and audit.flushes > 0
        else:
            assert audit.writes == 0
        assert set(audit.normal_digests) == {(digest == "CRC32C", digest == "CRC32C")}
        assert audit.logouts == audit.logout_replies == audit.sessions
        assert not audit.device_errors and not fixture.resources_remain(root)
        report = dict(byteCount=large_fixture.BYTE_COUNT, blockSize=block_size, digest=digest, chap=chap,
                      readWrite=read_write, initial=initial, synchronized=synchronized, final=final,
                      wire=audit.counters(), capacity16Requests=audit.capacity16_requests,
                      blockCommands=commands, deviceErrors=audit.device_errors)
        (vm.logs / (nonce + "-large.json")).write_text(json.dumps(report, indent=2) + "\n")
        print("PASS: sparse 3 TiB native device, high LBA contents, CDB selection, sync and Logout", flush=True)
        succeeded = True
    finally:
        if not succeeded:
            (vm.logs / (nonce + "-large-failure.json")).write_text(json.dumps(
                dict(wire=audit.counters(), blockCommands=audit.block_commands,
                     deviceErrors=audit.device_errors, errors=[str(error) for error in audit.errors]), indent=2) + "\n")
        if fixture.resources_remain(root):
            vm.safe_to_stop = False
            print("Mounted large fixture retained; recover before stopping VM:", root, nonce, flush=True)
        else:
            if configured:
                vm.configure("remove", nonce)
            if succeeded:
                fixture.remove_empty_mounts(root)
                shutil.rmtree(root)
            else:
                print("Large fixture retained for diagnosis:", root, flush=True)


def run_large_filesystem(vm, probe, binary_dir, file_system):
    assert vm.implementation == "lio" and file_system in fixture.FIXTURE_IMAGES
    nonce = str(uuid.uuid4())
    parent = ROOT / "build/FSKitFixtures"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    assert parent.resolve() == parent and not parent.is_symlink()
    root = Path(tempfile.mkdtemp(prefix=f"iSCSI-FSKit-{nonce}-", dir=parent)).resolve()
    succeeded = configured = False
    audit = WireAudit()
    snapshot = None
    switched = None
    try:
        fixture.write_fixture_manifest(root, file_system)
        (root / "LargeFilesystem.json").write_text(json.dumps(dict(
            nonce=nonce, byteCount=large_fixture.BYTE_COUNT, blockSize=512)) + "\n")
        print(f"CASE: 3 TiB {file_system}, CRC32C, CHAP, live RW/RO and independent snapshot", flush=True)
        configured = True
        vm.configure("setup-filesystem", nonce, "CRC32C", "yes", "512", file_system)
        vm.wait_for_target()

        def counters(destination=None):
            nonlocal snapshot
            if destination is not None:
                with audit.quiesce():
                    before = audit.counters()
                    result = vm.configure("snapshot-large", nonce, capture_output=True, text=True, timeout=90)
                    snapshot = json.loads(result.stdout)
                    assert snapshot["byteCount"] == large_fixture.BYTE_COUNT
                    assert not snapshot["extraSyncIssued"]
                    assert audit.counters()["writes"] == before["writes"]
                (root / "LargeSnapshot.json").write_text(json.dumps(snapshot, indent=2) + "\n")
                return before
            return audit.counters()

        def switch():
            nonlocal switched
            switched = audit.counters()
            assert switched["sessions"] == switched["logouts"] == switched["logoutReplies"]
            vm.configure("switch-large", nonce, timeout=90)
            vm.wait_for_target()

        with audit.proxy(vm.port) as address:
            environment = dict(os.environ, ISCSI_INITIATOR_NAME="iqn.2026-10.dev.soba:lio-probe-" + nonce)
            discovery = run([binary_dir / "iscsi", "discover", address], env=environment,
                            capture_output=True, text=True)
            assert "iqn.2026-10.dev.soba:lio-" + nonce in discovery.stdout
            try:
                fixture.run_mount_probe([probe, "--large-filesystem-lio-loopback", address, str(root), nonce],
                                        counters, root, after_ejection=switch, timeout_seconds=600)
            except Exception:
                run([probe, "--recover-fixture", root, nonce], timeout=90)
                raise
        assert snapshot is not None and switched is not None
        result = vm.configure("verify-large-snapshot", nonce, capture_output=True, text=True, timeout=90)
        frozen = json.loads(result.stdout)
        assert frozen["sparseContentSHA256"] == snapshot["sparseContentSHA256"]
        assert audit.sessions == audit.logouts == audit.logout_replies == 4
        assert audit.writes == audit.durable_writes and audit.flushes > 0
        if file_system != "hfsplus":
            assert audit.writes == switched["writes"], "Read-only snapshot received a write"
        assert set(audit.normal_digests) == {(True, True)}
        assert not audit.device_errors and not fixture.resources_remain(root)
        spaces = [json.loads(path.read_text()) for path in sorted(root.glob("LargeSpace-*.json"))]
        assert len(spaces) == 3
        report = dict(filesystem=file_system, byteCount=large_fixture.BYTE_COUNT, blockSize=512,
                      snapshot=snapshot, frozenAfterVerification=frozen, frozenSnapshotUnchanged=True,
                      sourceEjectedCounters=switched, wire=audit.counters(), spaces=spaces,
                      capacity16Requests=audit.capacity16_requests, deviceErrors=audit.device_errors)
        (vm.logs / (nonce + "-large-filesystem.json")).write_text(json.dumps(report, indent=2) + "\n")
        print(f"PASS: 3 TiB {file_system}, original reconnect, pre-close snapshot recovery, immutable snapshot, Logout", flush=True)
        succeeded = True
    finally:
        if not succeeded:
            (vm.logs / (nonce + "-large-filesystem-failure.json")).write_text(json.dumps(dict(
                wire=audit.counters(), snapshot=snapshot, sourceEjectedCounters=switched,
                deviceErrors=audit.device_errors, errors=[str(value) for value in audit.errors]), indent=2) + "\n")
        if fixture.resources_remain(root):
            vm.safe_to_stop = False
            print("Mounted large filesystem retained; recover before stopping VM:", root, nonce, flush=True)
        else:
            if configured:
                vm.configure("remove" if succeeded else "deactivate", nonce)
            if succeeded:
                fixture.remove_empty_mounts(root)
                shutil.rmtree(root)
            else:
                print("Large filesystem retained for diagnosis:", root, flush=True)


NATIVE_4KN_FILESYSTEMS = ("apfs", "exfat", "hfsplus")
# Each filesystem is connected read-only, then a read-write connection is requested and must be
# refused: the product attaches read-write only at 512-byte geometry (DiskImages.attachImage).
NATIVE_4KN_ACCESS = ("read-only", "refused-read-write")
# The configuration of the earlier 4096 B case with a 512-byte GPT, so that only the GPT differs.
NATIVE_4KN_DIGEST = "None"


def native_4kn_plan(file_system=None):
    """The cases of --native-4kn, in order: all three filesystems, or only `file_system`."""
    if file_system is not None and file_system not in NATIVE_4KN_FILESYSTEMS:
        raise ValueError("Unknown native 4Kn filesystem")
    formats = NATIVE_4KN_FILESYSTEMS if file_system is None else (file_system,)
    return tuple((name, access) for name in formats for access in NATIVE_4KN_ACCESS)


def native_4kn_probe_mode(implementation, access):
    if implementation not in ("lio", "tgt") or access not in NATIVE_4KN_ACCESS:
        raise ValueError("Unknown native 4Kn case")
    if access == "read-only":
        return "--mount-" + implementation + "-loopback"
    return "--expect-geometry-write-refusal-" + implementation + "-loopback"


def check_native_4kn_commands(commands, read_only):
    """Every observed READ or WRITE addresses whole 4096-byte blocks inside the 512 MiB LUN."""
    block_size = geometry_fixture.BLOCK_SIZE
    capacity = geometry_fixture.BYTE_COUNT // block_size
    for command in commands:
        assert command["blocks"] > 0 and command["transferBytes"] == command["blocks"] * block_size, \
            "Block command is not in 4096-byte logical blocks"
        assert command["lba"] + command["blocks"] <= capacity, "Block command exceeds the 4Kn LUN"
    assert not any(command["opcode"] in (0x2A, 0x8A) for command in commands), "4Kn case wrote"
    if read_only:
        assert any(command["opcode"] in (0x28, 0x88) for command in commands), "Read-only 4Kn mount read nothing"


def run_geometry_probe(arguments, timeout=180):
    """Run a read-only mount with the probe's native device geometry checkpoint.

    With ISCSI_TEST_GEOMETRY_RUNTIME=1 the probe compares the attached device's
    DeviceBlockSize, TotalSize and WritableMedia (diskutil) with the fixture's GPT and the
    LUN's sector size, prints FSKIT_DEVICE_GEOMETRY, and waits for one acknowledgment.
    """
    arguments = list(map(str, arguments))
    print("RUN:", " ".join(arguments), flush=True)
    environment = dict(os.environ, ISCSI_TEST_GEOMETRY_RUNTIME="1")
    geometry, phases = [], []
    pending = bytearray()
    with subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env=environment) as process:
        try:
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    break
                pending.extend(chunk)
                assert len(pending) <= 65_536, "Probe output line exceeds limit"
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    text = line.decode("utf-8", errors="replace")
                    print(text, flush=True)
                    if text.startswith("FSKIT_DEVICE_GEOMETRY "):
                        geometry.append(text)
                    elif text.startswith("FSKIT_CHECKPOINT "):
                        phases.append(json.loads(text.removeprefix("FSKIT_CHECKPOINT "))["phase"])
                        expected = phases == ["connected-geometry"]
                        reply = dict(ok=True) if expected else dict(ok=False, error="Unexpected geometry checkpoint")
                        process.stdin.write((json.dumps(reply) + "\n").encode())
                        process.stdin.flush()
            code = process.wait(timeout=max(1, deadline - time.monotonic()))
        except BaseException:
            process.kill()
            raise
    if pending:
        print(pending.decode("utf-8", errors="replace"), flush=True)
    assert code == 0, f"Read-only native 4Kn probe exited with {code}"
    assert phases == ["connected-geometry"], phases
    expected = f"FSKIT_DEVICE_GEOMETRY bytes={geometry_fixture.BYTE_COUNT} blockSize=4096 readOnly=true"
    assert geometry == [expected], geometry
    return expected


def run_native_4kn_case(vm, probe, binary_dir, file_system, access, digest=NATIVE_4KN_DIGEST):
    """Serve an OS-created GPT with 4096-byte sectors from a 4096 B LUN, as
    scripts/test-fskit-geometry.py does from RAM: a read-only connection mounts and verifies the
    contents through FSKit, and a read-write request is refused before a device is created.
    Neither may write: the target's bytes stay identical to the prepared fixture."""
    if (file_system not in NATIVE_4KN_FILESYSTEMS or access not in NATIVE_4KN_ACCESS
            or vm.implementation not in ("lio", "tgt")):
        raise ValueError("Unknown native 4Kn case")
    if ("ISCSI_TEST_ATTACH_METHOD" in os.environ
            or os.environ.get("ISCSI_TEST_IMAGE_PRESENTATION", "raw") != "raw"):
        raise ValueError("Native 4Kn cases use the product's raw attachment policy")
    expected_digests = expected_normal_digests(vm.implementation, digest)
    kind = vm.implementation
    read_only = access == "read-only"
    nonce = str(uuid.uuid4())
    parent = ROOT / "build/FSKitFixtures"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    assert parent.resolve() == parent and not parent.is_symlink()
    root = Path(tempfile.mkdtemp(prefix=f"iSCSI-FSKit-{nonce}-", dir=parent)).resolve()
    succeeded = configured = False
    audit = WireAudit()
    report = dict(target=kind, filesystem=file_system, access=access, digest=digest, chap=False,
                  lunBlockSize=geometry_fixture.BLOCK_SIZE, gptBlockSize=geometry_fixture.BLOCK_SIZE,
                  byteCount=geometry_fixture.BYTE_COUNT,
                  expected=("mounted read-only; marker, raw prefix and space verified through FSKit"
                            if read_only else
                            "read-write connection refused (readOnlyGeometryRequired); no device or record"))
    try:
        fixture.write_fixture_manifest(root, file_system)
        print(f"CASE: native 4Kn GPT, filesystem={file_system}, access={access}, digest={digest}, "
              f"block=4096, CHAP=False", flush=True)
        # Only the OS formatting step uses the probe's explicit 4096 B attachment helper. The
        # connection below inherits no override and uses the product's attachment policy.
        run([probe, "--prepare-geometry-fixture", root, nonce],
            env=dict(os.environ, ISCSI_TEST_ATTACH_METHOD="legacy-4k"), timeout=180)
        image = root / fixture.FIXTURE_IMAGES[file_system]
        source = image.read_bytes()
        assert len(source) == geometry_fixture.BYTE_COUNT
        assert source[4096:4104] == b"EFI PART" and source[512:520] != b"EFI PART"
        original = hashlib.sha256(source).hexdigest()
        del source
        report.update(sourceSHA256=original, gpt=geometry_fixture.validate(image))
        vm.copy(image, vm.name + ":" + vm.staging + "/" + nonce + ".img")
        configured = True
        setup = vm.configure("setup-geometry", nonce, digest, "no", "4096", original,
                             capture_output=True, text=True)
        print(setup.stdout, end="", flush=True)
        report["targetSetup"] = json.loads(setup.stdout.strip().splitlines()[-1])
        assert report["targetSetup"]["blockSize"] == 4096
        vm.wait_for_target()
        with audit.proxy(vm.port) as address:
            environment = dict(os.environ, ISCSI_INITIATOR_NAME="iqn.2026-10.dev.soba:" + kind + "-probe-" + nonce)
            discovery = run([binary_dir / "iscsi", "discover", address], env=environment,
                            capture_output=True, text=True)
            assert "iqn.2026-10.dev.soba:" + kind + "-" + nonce in discovery.stdout
            print(discovery.stdout, end="", flush=True)
            arguments = [probe, native_4kn_probe_mode(kind, access), address, str(root), nonce]
            try:
                if read_only:
                    report["deviceGeometry"] = run_geometry_probe(arguments)
                else:
                    result = run(arguments, capture_output=True, text=True, timeout=180)
                    print(result.stdout, end="", flush=True)
                    refusals = [line for line in result.stdout.splitlines() if line.startswith(
                        "PASS: larger-sector write connection refused before device creation")]
                    assert len(refusals) == 1, "Read-write native 4Kn connection was not refused"
                    report["refusal"] = refusals[0]
            except Exception:
                run([probe, "--recover-fixture", root, nonce], timeout=90)
                raise
        assert audit.writes == 0, "A native 4Kn connection wrote to the target"
        assert audit.normal_digests and set(audit.normal_digests) == {expected_digests}
        assert audit.logouts == audit.logout_replies == audit.sessions, "Some sessions did not finish Logout"
        check_native_4kn_commands(audit.block_commands, read_only)
        # The target's backing file after Logout, hashed in the guest; nothing is copied back.
        snapshot = vm.configure("snapshot", nonce, capture_output=True, text=True, timeout=60)
        vm.shell("rm", "--", vm.staging + "/" + nonce + "-snapshot.img")
        report["targetSHA256"] = snapshot.stdout.strip().splitlines()[-1]
        assert report["targetSHA256"] == original, "Native 4Kn case changed target bytes"
        assert not fixture.resources_remain(root) and not fixture.markers_remain(root)
        report.update(wire=audit.counters(), blockCommands=audit.block_commands,
                      deviceErrors=audit.device_errors, observed="pass")
        (vm.logs / (nonce + "-native-4kn.json")).write_text(json.dumps(report, indent=2) + "\n")
        print(f"PASS: {vm.label}, native 4Kn {file_system}, {access}: target unchanged, "
              f"{audit.counters()['reads']} reads, no writes", flush=True)
        succeeded = True
    finally:
        if not succeeded:
            report.update(wire=audit.counters(), blockCommands=audit.block_commands,
                          responseHeaders=audit.response_headers, deviceErrors=audit.device_errors,
                          errors=[str(error) for error in audit.errors], observed="fail")
            (vm.logs / (nonce + "-native-4kn-failure.json")).write_text(json.dumps(report, indent=2) + "\n")
        if fixture.resources_remain(root):
            vm.safe_to_stop = False
            print("Mounted fixture retained; recover before stopping VM:", root, nonce, flush=True)
        else:
            if configured:
                vm.configure("remove", nonce)
            if succeeded:
                fixture.remove_empty_mounts(root)
                shutil.rmtree(root)
                print("PASS: local fixture removed", flush=True)
            else:
                print("Fixture retained for diagnosis:", root, flush=True)


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("lio", "tgt"), default="lio",
                        help="Independent target implementation (default: lio)")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--soak", nargs="?", const=600, type=int, metavar="SECONDS",
                       help="Run the concurrent APFS CHAP/CRC32C/4096 B soak (default: 600 seconds)")
    modes.add_argument("--filesystem-matrix", action="store_true",
                       help="Run the six normal cases for APFS, ExFAT and journaled HFS+")
    modes.add_argument("--large-lun", action="store_true",
                       help="Run native RO/RW and 32-bit-LBA boundary checks on a sparse 3 TiB LIO LUN")
    modes.add_argument("--large-filesystem", choices=("apfs", "exfat", "hfsplus", "all"),
                       help="Format only a new 3 TiB LIO LUN and reopen an independent pre-close snapshot")
    modes.add_argument("--native-4kn", action="store_true",
                       help="Serve OS-created GPTs with 4096-byte sectors from a 4096 B LUN: read-only "
                            "APFS, ExFAT and HFS+, each with a refused read-write request")
    parser.add_argument("--filesystem", choices=fixture.FIXTURE_IMAGES,
                        help="Disposable image filesystem (default: apfs; with --native-4kn: all three)")
    args = parser.parse_args(argv)
    if args.large_lun and (args.target != "lio" or args.filesystem):
        parser.error("--large-lun requires LIO and selects an unformatted fixture")
    if args.large_filesystem and (args.target != "lio" or args.filesystem):
        parser.error("--large-filesystem requires LIO and selects its own filesystem")
    if args.soak is not None and not 60 <= args.soak <= 3600:
        parser.error("--soak must be between 60 and 3600 seconds")
    if args.filesystem_matrix and args.filesystem:
        parser.error("--filesystem-matrix selects its own filesystems")
    if args.soak and args.filesystem not in (None, "apfs"):
        parser.error("The extended-attribute soak currently requires APFS")
    if args.native_4kn and ("ISCSI_TEST_ATTACH_METHOD" in os.environ
                            or os.environ.get("ISCSI_TEST_IMAGE_PRESENTATION", "raw") != "raw"):
        parser.error("--native-4kn uses the product's raw attachment policy; unset "
                     "ISCSI_TEST_ATTACH_METHOD and ISCSI_TEST_IMAGE_PRESENTATION")
    return args


def main():
    args = parse_arguments()
    assert shutil.which("limactl"), "Install Lima 2.2.1+ first"
    logs = ROOT / "build/Validation" / args.target.upper() / time.strftime("%Y%m%d-%H%M%S")
    logs.mkdir(parents=True)
    # ISCSI_TEST_APP selects the app under test and its probe build (scripts/test-fskit.py).
    binary_dir = fixture.probe_binary_dir()
    vm = LinuxTargetVM(logs, args.target)
    succeeded = False
    with fixture.signed_probe(binary_dir, keychain=True) as probe:
        preflight = run([probe, "--preflight"], capture_output=True, text=True)
        modules = [json.loads(line.removeprefix("FSKIT_MODULE ")) for line in preflight.stdout.splitlines()
                   if line.startswith("FSKIT_MODULE ")]
        assert len(modules) == 1
        fixture.verify_module(modules[0]["modulePath"])
        try:
            vm.start()
            if args.native_4kn:
                for file_system, access in native_4kn_plan(args.filesystem):
                    run_native_4kn_case(vm, probe, binary_dir, file_system, access)
                succeeded = True
                return
            if args.large_filesystem:
                formats = ("apfs", "exfat", "hfsplus") if args.large_filesystem == "all" else (args.large_filesystem,)
                for file_system in formats:
                    run_large_filesystem(vm, probe, binary_dir, file_system)
                succeeded = True
                return
            if args.large_lun:
                run_large_case(vm, probe, binary_dir, "CRC32C", True, True)
                run_large_case(vm, probe, binary_dir, "None", False, False)
                run_large_case(vm, probe, binary_dir, "CRC32C", True, False, block_size=4096)
                succeeded = True
                return
            cases = (("CRC32C", True, True, 4096),) if args.soak else (
                ("CRC32C", False, False, 512), ("CRC32C", False, True, 512),
                ("CRC32C", True, False, 512), ("CRC32C", True, True, 512),
                ("None", False, False, 4096), ("None", False, True, 4096),
            )
            formats = ("apfs", "exfat", "hfsplus") if args.filesystem_matrix else (args.filesystem or "apfs",)
            for file_system in formats:
                for digest, chap, read_write, block in cases:
                    run_case(vm, probe, binary_dir, digest, chap, read_write, block,
                             soak_seconds=args.soak, file_system=file_system)
            succeeded = True
        finally:
            vm.finish(succeeded)


if __name__ == "__main__":
    main()
