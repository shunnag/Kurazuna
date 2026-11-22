#!/usr/bin/env python3
"""Independent RFC 7143 target; RAM only, standard library only.

Default uses pipes; --loopback also tests Network.framework and the CLI over TCP.
"""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
TARGET = b"iqn.2026-10.test:memory"
SERIAL_MASK = (1 << 32) - 1


def crc32c(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return struct.pack("<I", crc ^ 0xFFFFFFFF)


def exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            raise EOFError("Initiator disconnected")
        data.extend(chunk)
    return bytes(data)


def parameters(data):
    assert not data or data[-1] == 0
    pairs = [part.split(b"=", 1) for part in data.split(b"\0")[:-1]]
    assert len(dict(pairs)) == len(pairs), "Duplicate request keys"
    return dict(pairs)


def encode_parameters(values):
    return b"".join(key + b"=" + value + b"\0" for key, value in values.items())


class Target:
    def __init__(self, reader, writer, environment=None):
        environment = os.environ if environment is None else environment
        self.reader, self.writer = reader, writer
        self.digest = False
        self.initial_cmd = int(environment.get("ISCSI_TEST_INITIAL_CMDSN", "1"))
        self.stat = int(environment.get("ISCSI_TEST_INITIAL_STATSN", "0"))
        assert 0 <= self.initial_cmd <= SERIAL_MASK and 0 <= self.stat <= SERIAL_MASK
        self.exp_cmd = self.initial_cmd
        self.check_wrap = environment.get("ISCSI_TEST_SEQUENCE_WRAP") == "1"
        self.last_command = self.last_status = None
        self.command_wrapped = self.status_wrapped = False
        self.image_io = environment.get("ISCSI_TEST_IMAGE_IO") == "1"
        self.file_system_fixture = environment.get("ISCSI_TEST_FILESYSTEM") == "1"
        memory_size = 20 * 1024 * 1024 if self.image_io else 65536
        self.memory = bytearray(bytes((i * 3) & 255 for i in range(256)) * (memory_size // 256))
        self.segment_length = 8192 if self.image_io else 512
        self.wire_fragment_bytes = int(environment.get("ISCSI_TEST_WIRE_FRAGMENT_BYTES", "17"))
        assert 1 <= self.wire_fragment_bytes <= 65_536
        self.block_size = int(environment.get("ISCSI_TEST_BLOCK_SIZE", "512"))
        self.maximum_transfer_blocks = int(environment.get("ISCSI_TEST_MAX_TRANSFER_BLOCKS", "0"))
        assert 0 <= self.maximum_transfer_blocks <= 0xFFFFFFFF
        self.block_requests = []
        self.write_protected = environment.get("ISCSI_TEST_WRITE_PROTECTED") == "1"
        self.write_protection_rejections = 0
        self.mode_sense_requests = []
        self.base_lba = int(environment.get("ISCSI_TEST_BASE_LBA", "0"))
        assert self.block_size in (512, 4096)
        assert 0 <= self.base_lba <= (1 << 64) - 129
        self.pending_write = None
        self.flushes = self.writes = 0
        self.logouts = 0
        self.chap_phase = 0
        self.unit_attention_delivered = False
        self.fault = environment.get("ISCSI_TEST_FAULT", "")
        self.lun = bytes.fromhex(environment.get("ISCSI_TEST_LUN", "0000000000000000"))
        assert len(self.lun) == 8
        self.inspect_luns = environment.get("ISCSI_TEST_LUN_INSPECTION") == "1"
        self.probe_commands = []
        self.exercise_nop = environment.get("ISCSI_TEST_NOP") == "1"
        self.chap = environment.get("ISCSI_TEST_CHAP") == "1"
        self.mutual_chap = environment.get("ISCSI_TEST_MUTUAL_CHAP") == "1"
        assert not self.mutual_chap or self.chap
        self.discovery_authentication = environment.get("ISCSI_TEST_DISCOVERY_AUTH", "")
        self.auth_username = b"test-user"
        self.auth_password = b"correct horse battery staple"
        challenge_bytes = int(environment.get("ISCSI_TEST_CHALLENGE_BYTES", "16"))
        assert 1 <= challenge_bytes <= 1024
        self.challenge_encoding = environment.get("ISCSI_TEST_CHALLENGE_ENCODING", "hex")
        assert self.challenge_encoding in ("hex", "base64")
        self.fragment_challenge = environment.get("ISCSI_TEST_FRAGMENT_CHALLENGE") == "1"
        self.auth_challenge = (os.urandom(challenge_bytes)
                               if environment.get("ISCSI_TEST_RANDOM_CHALLENGE") == "1"
                               else bytes(i % 256 for i in range(challenge_bytes)))
        self.target_username = b"test-server"
        self.target_password = b"independent server password"
        self.normal = False
        self.target_name_received = False
        self.portal_group_declared = False
        self.initiator_pings = 0
        self.pings = {}
        self.next_ping = 0x70000000
        self.negotiation = environment.get("ISCSI_TEST_NEGOTIATION", "")
        self.operational_round = 0
        self.expected_answers = {}
        self.security_answers = {}
        self.security_answered = False
        self.login_request_text = bytearray()
        self.login_request_identity = None
        self.maximum_burst = 262144

    def receive(self):
        header = exact(self.reader, 48)
        assert header[4] == 0
        if self.digest:
            assert exact(self.reader, 4) == crc32c(header), "Bad header digest"
        length = int.from_bytes(header[5:8], "big")
        assert length <= 262144
        padded = exact(self.reader, (length + 3) & ~3)
        if length and self.digest:
            assert exact(self.reader, 4) == crc32c(padded), "Bad data digest"
        return header, padded[:length]

    def send(self, opcode, flags, tag, payload=b"", *, consume=True, fields=(), corrupt=False):
        window_case = self.fault in ("stale-command-window", "invalid-command-window", "future-invalid-command-window")
        if window_case and opcode in (0x21, 0x25, 0x31):
            # A current acknowledgment precedes a queued PDU with older/invalid window fields.
            # It consumes neither StatSN nor CmdSN and requests no echo.
            self.send(0x20, 0x80, 0xFFFFFFFF, consume=False)
        if self.fault == "data-ack-at-erl-zero" and opcode == 0x25:
            flags |= 0x40
        header = bytearray(48)
        header[0:2] = bytes((opcode, flags))
        header[5:8] = len(payload).to_bytes(3, "big")
        struct.pack_into(">IIII", header, 16, tag, 0xFFFFFFFF, self.stat, self.exp_cmd)
        struct.pack_into(">I", header, 32, (self.exp_cmd + 31) & SERIAL_MASK)
        for offset, value in fields:
            header[offset:offset + len(value)] = value
        if self.fault == "data-ack-at-erl-zero" and opcode == 0x25:
            header[20:24] = struct.pack(">I", 73)
        if window_case and opcode in (0x21, 0x25, 0x31):
            expected = self.initial_cmd if self.fault == "stale-command-window" else self.exp_cmd
            if self.fault == "future-invalid-command-window":
                expected = (expected + 100) & SERIAL_MASK
            maximum = ((expected - 1) if self.fault == "stale-command-window" else expected - 2) & SERIAL_MASK
            struct.pack_into(">II", header, 28, expected, maximum)
        if self.fault == "future-command-ack" and opcode == 0x25:
            struct.pack_into(">II", header, 28, (self.exp_cmd + 1) & SERIAL_MASK,
                             (self.exp_cmd + 32) & SERIAL_MASK)
        if (self.fault == "unused-residual" and opcode in (0x21, 0x25)
                and (opcode == 0x21 or flags & 1) and not flags & 6):
            header[44:48] = b"\xde\xad\xbe\xef"
        wire = bytes(header) + (crc32c(header) if self.digest else b"")
        padded = payload + b"\0" * ((-len(payload)) % 4)
        wire += padded
        if self.digest and payload:
            checksum = bytearray(crc32c(padded))
            if corrupt:
                checksum[0] ^= 1
            wire += checksum
        for offset in range(0, len(wire), self.wire_fragment_bytes):
            self.writer.write(wire[offset:offset + self.wire_fragment_bytes])
            self.writer.flush()
        if consume:
            self.status_wrapped |= self.last_status == SERIAL_MASK and self.stat == 0
            self.last_status = self.stat
            self.stat = (self.stat + 1) & SERIAL_MASK

    def login_response(self, flags, tag, values, identity, part_bytes=8192):
        if self.target_name_received and not self.portal_group_declared:
            # RFC 7143 13.9: declare the advertised group in the first allowed
            # response. Keep it ahead of extension keys that may require more PDUs.
            values = {b"TargetPortalGroupTag": b"1", **values}
            self.portal_group_declared = True
        data = encode_parameters(values)
        parts = [data[start:start + part_bytes] for start in range(0, len(data), part_bytes)] or [b""]
        for index, part in enumerate(parts):
            more = index + 1 < len(parts)
            self.send(0x23, (flags & 0x0C) | 0x40 if more else flags, tag, part, fields=identity)
            if more:
                header, payload = self.receive()
                assert header[0] == 0x43 and not payload and not header[1] & 0x40
                assert header[1] & 0x0C == flags & 0x0C
                assert header[8:14] == identity[0][1] and int.from_bytes(header[16:20], "big") == tag
                assert int.from_bytes(header[24:28], "big") == self.initial_cmd
                assert int.from_bytes(header[28:32], "big") == self.stat

    @staticmethod
    def security_extensions():
        return {(f"FutureSecurity{index:04d}".ljust(49, "x")).encode(): b"1" for index in range(256)}

    def run(self):
        while True:
            header, data = self.receive()
            opcode, tag = header[0] & 0x3F, int.from_bytes(header[16:20], "big")
            if opcode == 3:
                assert int.from_bytes(header[24:28], "big") == self.initial_cmd
                assert len(data) <= 8192 and header[1] & 0xC0 != 0xC0
                stage = (header[1] >> 2) & 3
                identity = [(8, header[8:14]), (14, b"\0\1")]
                if self.login_request_identity is not None or header[1] & 0x40:
                    assert tag == 1 and int.from_bytes(header[28:32], "big") == self.stat
                    current = (header[8:24], header[1] & 0x0C, header[24:28])
                    if self.login_request_identity is None:
                        self.login_request_identity = current
                    assert self.login_request_identity == current
                    self.login_request_text.extend(data)
                    assert len(self.login_request_text) <= 1048576
                    if header[1] & 0x40:
                        flags, payload, response_tag, fields = stage << 2, b"", tag, identity
                        if self.negotiation == "long-ack-poll" and data:
                            flags |= 0x40
                        if self.normal:
                            if self.fault == "login-continuation-data":
                                payload = b"TargetAlias=InvalidDuringContinuation\0"
                            elif self.fault == "login-continuation-transit":
                                flags = 0x87
                            elif self.fault == "login-continuation-stage":
                                flags = 0
                            elif self.fault == "login-continuation-sequence":
                                fields = identity + [(24, struct.pack(">I", (self.stat + 1) & SERIAL_MASK))]
                            elif self.fault == "login-continuation-tag":
                                response_tag += 1
                            elif self.fault == "login-continuation-reject":
                                fields = identity + [(36, b"\x02\x00")]
                            elif self.fault == "login-continuation-loop":
                                flags |= 0x40
                        self.send(0x23, flags, response_tag, payload, fields=fields)
                        continue
                    data = bytes(self.login_request_text)
                    self.login_request_text.clear()
                    self.login_request_identity = None
                keys = parameters(data)
                self.target_name_received |= b"TargetName" in keys
                if b"SessionType" in keys:
                    self.normal = keys[b"SessionType"] == b"Normal"
                    if not self.normal:
                        if self.fault == "discovery-auth-rejected":
                            self.send(0x23, 0, tag, fields=identity + [(36, b"\x02\x01")])
                            return
                        if self.discovery_authentication:
                            assert self.discovery_authentication in ("none", "chap", "mutual")
                            self.chap = self.discovery_authentication != "none"
                            self.mutual_chap = self.discovery_authentication == "mutual"
                            self.auth_username = b"search-user"
                            self.auth_password = b"independent discovery password"
                            self.target_username = b"search-server"
                            self.target_password = b"independent discovery server password"
                assert header[0] & 0x40
                if stage == 0:
                    if self.mutual_chap and self.chap_phase == 3 and self.negotiation == "mutual-deferred":
                        assert not keys and header[1] & 0x80
                        self.login_response(0x81, tag, {}, identity)
                        self.chap_phase += 1
                        continue
                    if self.security_answers and not self.security_answered:
                        assert all(keys.get(key) == value for key, value in self.security_answers.items())
                        keys = {key: value for key, value in keys.items() if key not in self.security_answers}
                        self.security_answered = True
                        if not self.chap:
                            assert not keys and header[1] & 0x80
                            self.login_response(0x81, tag, {}, identity)
                            continue
                    if self.chap:
                        challenge = self.auth_challenge
                        if self.chap_phase == 0:
                            assert keys[b"AuthMethod"] == b"CHAP" and not header[1] & 0x80
                            reply = {b"AuthMethod": b"CHAP"}
                            if self.normal and self.fault == "mutual-early":
                                reply.update({b"CHAP_N": b"test-server", b"CHAP_R": b"0x" + b"00" * 16})
                        elif self.chap_phase == 1:
                            assert keys[b"CHAP_A"] == b"5" and not header[1] & 0x80
                            reply = {b"CHAP_A": b"0x5" if self.negotiation == "hex" else b"5",
                                     b"CHAP_I": b"0x7" if self.negotiation == "hex" else b"7",
                                     b"CHAP_C": (b"0b" + base64.b64encode(challenge)
                                                 if self.challenge_encoding == "base64"
                                                 else b"0x" + challenge.hex().encode())}
                        else:
                            expected = b"0x" + hashlib.md5(b"\x07" + self.auth_password + challenge).hexdigest().encode()
                            assert keys[b"CHAP_N"] == self.auth_username and keys[b"CHAP_R"] == expected
                            assert header[1] & 0x80
                            reply = {}
                            if self.mutual_chap:
                                identifier = int(keys[b"CHAP_I"])
                                mutual_challenge = bytes.fromhex(keys[b"CHAP_C"][2:].decode())
                                assert 0 <= identifier <= 255 and len(mutual_challenge) == 32
                                assert mutual_challenge != challenge
                                result = hashlib.md5(bytes([identifier]) + self.target_password + mutual_challenge).digest()
                                if self.normal:
                                    if self.fault == "mutual-digest":
                                        result = bytes([result[0] ^ 1]) + result[1:]
                                    elif self.fault == "mutual-reflected":
                                        result = hashlib.md5(bytes([identifier]) + self.auth_password + mutual_challenge).digest()
                                    elif self.fault == "mutual-length":
                                        result = result[:-1]
                                encoded = b"0b" + base64.b64encode(result) if self.negotiation == "mutual-base64" else b"0x" + result.hex().encode()
                                reply = {b"CHAP_N": self.target_username, b"CHAP_R": encoded}
                                if self.normal:
                                    if self.fault == "mutual-missing":
                                        reply = {}
                                    elif self.fault == "mutual-name":
                                        reply[b"CHAP_N"] = b"wrong-server"
                                    elif self.fault == "mutual-encoding":
                                        reply[b"CHAP_R"] = b"0xzz"
                                    elif self.fault == "mutual-half":
                                        del reply[b"CHAP_R"]
                        if self.chap_phase == 0 and self.negotiation == "security-metadata":
                            reply[b"TargetAlias"] = b"Archive"
                            if self.target_name_received:
                                reply[b"TargetPortalGroupTag"] = b"0bAAE="
                        if self.chap_phase == 0 and self.negotiation == "long-security":
                            extensions = self.security_extensions()
                            reply.update(extensions)
                            self.security_answers = {key: b"NotUnderstood" for key in extensions}
                        final = self.chap_phase == 2
                        part_bytes = 7 if final and self.negotiation == "mutual-continued" else 8192
                        if self.chap_phase == 1 and self.fragment_challenge:
                            part_bytes = 16 if len(challenge) <= 16 else 512
                        self.login_response(0x81 if final and self.negotiation != "mutual-deferred" else 0,
                                            tag, reply, identity,
                                            part_bytes=part_bytes)
                        self.chap_phase += 1
                    else:
                        assert keys[b"AuthMethod"] == b"None"
                        reply = {b"AuthMethod": b"None"}
                        if self.negotiation == "security-metadata":
                            reply[b"TargetAlias"] = b"Archive"
                            if self.target_name_received:
                                reply[b"TargetPortalGroupTag"] = b"0x01"
                        if self.negotiation == "long-security":
                            extensions = self.security_extensions()
                            reply.update(extensions)
                            self.security_answers = {key: b"NotUnderstood" for key in extensions}
                        self.login_response(0 if self.security_answers else 0x81, tag, reply, identity)
                else:
                    assert stage == 1
                    if self.operational_round:
                        assert keys == self.expected_answers, f"Incorrect negotiation answers: {keys!r}"
                        selected = {b"MaxRecvDataSegmentLength": b"512"} if self.fault == "repeated-login-key" else {}
                    else:
                        selected = dict(keys)
                        selected.update({b"HeaderDigest": b"CRC32C", b"DataDigest": b"CRC32C",
                                         b"MaxRecvDataSegmentLength": str(self.segment_length).encode()})
                        if self.normal and self.negotiation == "irrelevant-burst":
                            selected.update({b"FirstBurstLength": b"Irrelevant", b"MaxBurstLength": b"1024"})
                            self.maximum_burst = 1024
                        if self.negotiation == "reject-defaults":
                            for key in (b"HeaderDigest", b"DataDigest", b"MaxConnections", b"MaxBurstLength",
                                        b"DataPDUInOrder", b"DataSequenceInOrder"):
                                if key in selected:
                                    selected[key] = b"Reject"
                        if self.negotiation == "hex":
                            selected = {key: hex(int(value)).encode() if value.isdigit() else value
                                        for key, value in selected.items()}
                        if self.normal:
                            replacement = {"not-understood-standard": (b"HeaderDigest", b"NotUnderstood"),
                                           "invalid-wait-selection": (b"DefaultTime2Wait", b"1"),
                                           "invalid-retain-selection": (b"DefaultTime2Retain", b"20"),
                                           "final-unanswered-key": (b"X-com.example.feature", b"Enabled")}
                            if self.fault in replacement:
                                key, value = replacement[self.fault]
                                selected[key] = value
                        if self.negotiation == "target-proposals":
                            selected.update({b"ExampleExtension": b"Enabled", b"IFMarker": b"Yes", b"OFMarker": b"No",
                                             b"IFMarkInt": b"2048~4096", b"OFMarkInt": b"2048~4096",
                                             b"TaskReporting": b"FastAbort,ResponseFence,RFC3720", b"iSCSIProtocolLevel": b"2",
                                             b"X#NodeArchitecture": b"Disposable target/1.0"})
                            self.expected_answers = {b"ExampleExtension": b"NotUnderstood", b"IFMarker": b"Reject",
                                                     b"OFMarker": b"Reject", b"IFMarkInt": b"Reject", b"OFMarkInt": b"Reject",
                                                     b"TaskReporting": b"RFC3720" if self.normal else b"Irrelevant",
                                                     b"iSCSIProtocolLevel": b"0" if self.normal else b"Irrelevant"}
                            if not self.normal:
                                selected.update({b"InitialR2T": b"No", b"DefaultTime2Wait": b"20", b"DefaultTime2Retain": b"20"})
                                self.expected_answers.update({b"InitialR2T": b"Irrelevant", b"DefaultTime2Wait": b"20", b"DefaultTime2Retain": b"0"})
                        if self.negotiation in ("long-operational", "long-operational-none", "long-ack-poll") and (
                                not self.fault.startswith("login-continuation-") or self.normal):
                            extensions = {f"FutureKey{index:04d}".encode(): b"1" for index in range(600)}
                            selected.update(extensions)
                            self.expected_answers = {key: b"NotUnderstood" for key in extensions}
                        if self.negotiation == "long-operational-none":
                            selected.update({b"HeaderDigest": b"None", b"DataDigest": b"None"})
                    partial = self.operational_round == 0 and (bool(self.expected_answers)
                                or (self.normal and self.fault == "repeated-login-key"))
                    self.login_response(0x04 if partial else 0x87, tag, selected, identity)
                    self.operational_round += 1
                    if partial:
                        continue
                    self.digest = self.negotiation not in ("reject-defaults", "long-operational-none")
                    if self.exercise_nop:
                        self.target_ping()
            elif opcode == 0:
                assert header[0] == 0x40
                transfer_tag = int.from_bytes(header[20:24], "big")
                if tag == 0xFFFFFFFF:
                    assert transfer_tag in self.pings and data == b""
                    assert header[8:16] == self.pings.pop(transfer_tag)
                else:
                    assert transfer_tag == 0xFFFFFFFF
                    self.initiator_pings += 1
                    if self.fault != "lost-idle-echo":
                        self.send(0x20, 0x80, tag, b"bad echo" if self.fault == "bad-idle-echo" else data)
            elif opcode == 4:
                assert int.from_bytes(header[24:28], "big") == self.exp_cmd
                assert parameters(data) == {b"SendTargets": b"All"}
                self.send(0x24, 0x80, tag, b"TargetName=" + TARGET + b"\0TargetAddress=127.0.0.1:3260,1\0")
            elif opcode == 1:
                command = int.from_bytes(header[24:28], "big")
                assert command == self.exp_cmd
                self.command_wrapped |= self.last_command == SERIAL_MASK and command == 0
                self.last_command = command
                self.exp_cmd = (self.exp_cmd + 1) & SERIAL_MASK
                length, cdb = int.from_bytes(header[20:24], "big"), header[32:48]
                lun = header[8:16]
                if cdb[0] == 0xA0:
                    assert lun == b"\0" * 8
                elif self.inspect_luns:
                    assert lun in [bytes([0, number]) + b"\0" * 6 for number in range(7)]
                else:
                    assert lun == self.lun
                self.probe_commands.append((lun, cdb[0]))
                if cdb[0] in (0x28, 0x2A, 0x88, 0x8A):
                    blocks = int.from_bytes(cdb[7:9] if cdb[0] in (0x28, 0x2A) else cdb[10:14], "big")
                    oversized = bool(self.maximum_transfer_blocks and blocks > self.maximum_transfer_blocks)
                    self.block_requests.append(dict(opcode=cdb[0], blocks=blocks, bytes=length,
                                                    rejected=oversized))
                    if oversized:
                        sense = bytes([0x72, 5, 0x24, 0, 0, 0, 0, 0])
                        self.send(0x21, 0x80, tag, struct.pack(">H", len(sense)) + sense,
                                  fields=[(3, b"\x02")])
                        continue
                if self.exercise_nop:
                    self.target_ping()
                if self.write_protected and cdb[0] in (0x2A, 0x8A):
                    self.write_protection_rejections += 1
                    sense = bytes([0x72, 7, 0x27, 0, 0, 0, 0, 0])
                    self.send(0x21, 0x80, tag, struct.pack(">H", len(sense)) + sense,
                              fields=[(3, b"\x02")])
                    continue
                if cdb[0] in (0x5A, 0x1A):
                    ten = cdb[0] == 0x5A
                    assert cdb[1] == 8 and cdb[2] in (0, 0x3F) and cdb[3] == 0
                    expected = bytearray(16)
                    expected[0:3] = cdb[0:3]
                    if ten:
                        expected[8] = 8
                    else:
                        expected[4] = 4
                    assert cdb == expected and length == (8 if ten else 4)
                    self.mode_sense_requests.append(cdb.hex())
                    payload = bytearray(length)
                    if ten:
                        payload[1] = 6
                        payload[3] = 0x80 if self.write_protected else 0
                    else:
                        payload[0] = 3
                        payload[2] = 0x80 if self.write_protected else 0
                    self.send(0x25, 0x81, tag, payload)
                elif cdb[0] == 0x12 and cdb[1] == 1 and cdb[2] == 0x83:
                    # Opening a disk records the logical unit's names (device identification)
                    # to compare after every reconnection. This RAM disk has none.
                    assert length == int.from_bytes(cdb[3:5], "big") and cdb[5:] == b"\0" * 11
                    payload = bytearray(b"\0\x83\0\0")
                    self.send(0x25, 0x83 if len(payload) < length else 0x81, tag, payload,
                              fields=[(44, struct.pack(">I", length - len(payload)))])
                elif cdb[0] == 0x12 and cdb[1] == 1:
                    assert length == int.from_bytes(cdb[3:5], "big") == 64
                    assert cdb[2] == 0xB0 and cdb[5:] == b"\0" * 11
                    payload = bytearray(64)
                    payload[1:4] = b"\xb0\0\x3c"
                    struct.pack_into(">I", payload, 8, self.maximum_transfer_blocks)
                    self.send(0x25, 0x81, tag, payload)
                elif cdb[0] == 0x12:
                    assert length == int.from_bytes(cdb[3:5], "big") == 96
                    assert cdb[1:3] == b"\0\0" and cdb[5:] == b"\0" * 11
                    bad_residuals = {"error-residual-both": (0x86, 1),
                                     "error-underflow-zero": (0x82, 0),
                                     "error-underflow-large": (0x82, length + 1),
                                     "error-overflow-zero": (0x84, 0)}
                    if self.fault in bad_residuals:
                        flags, residual = bad_residuals[self.fault]
                        sense = bytes([0x72, 6, 0x29, 0, 0, 0, 0, 0])
                        self.send(0x21, flags, tag, struct.pack(">H", len(sense)) + sense,
                                  fields=[(3, b"\x02"), (44, struct.pack(">I", residual))])
                        # The sense requests a retry, but a malformed PDU must stop it.
                        self.require_close()
                        return
                    if self.fault in ("inquiry-unit-attention", "inquiry-unit-attention-residual",
                                      "inquiry-unit-attention-unused-residual") and not self.unit_attention_delivered:
                        self.unit_attention_delivered = True
                        sense = bytes([0x72, 6, 0x29, 0, 0, 0, 0, 0])
                        underflow = self.fault == "inquiry-unit-attention-residual"
                        residual = length if underflow else 0xDEADBEEF
                        self.send(0x21, 0x82 if underflow else 0x80, tag,
                                  struct.pack(">H", len(sense)) + sense,
                                  fields=[(3, b"\x02"), (44, struct.pack(">I", residual))])
                        continue
                    payload = bytearray(36)
                    payload[0:5] = bytes([0, 0, 6, 2, 31])
                    payload[8:16], payload[16:32], payload[32:36] = b"SobaDev ", b"RAM Disk        ", b"1.0 "
                    if self.fault == "tape-device" or (self.inspect_luns and lun[1] == 1):
                        payload[0] = 1
                    elif self.fault == "unavailable-device":
                        payload[0] = 0x7F
                    elif self.fault == "inquiry-optional-tail":
                        payload[4] = 255
                        payload += b"\0" * 60
                    elif self.fault == "inquiry-header-only":
                        payload = bytearray([0, 0, 6, 2, 0])
                    elif self.fault == "short-inquiry" or (self.inspect_luns and lun[1] == 5):
                        payload = payload[:5]
                    self.send(0x25, 0x83 if len(payload) < length else 0x81, tag, payload,
                              fields=[(44, struct.pack(">I", length - len(payload)))])
                elif cdb[0] == 0x9E:
                    assert self.fault not in ("tape-device", "unavailable-device", "short-inquiry")
                    if self.inspect_luns:
                        assert lun[1] not in (1, 5), "An unusable LUN received READ CAPACITY"
                        if lun[1] in (2, 3, 4):
                            sense = bytes([0x72, 2, 0x3A if lun[1] == 3 else 4, 0, 0, 0, 0, 0])
                            self.send(0x21, 0x80, tag, b"" if lun[1] == 4 else struct.pack(">H", len(sense)) + sense,
                                      fields=[(3, b"\x18" if lun[1] == 4 else b"\x02")])
                            continue
                    if self.fault == "repeat-unit-attention" or (self.fault == "unit-attention" and not self.unit_attention_delivered):
                        self.unit_attention_delivered = True
                        sense = bytes([0x70, 0, 6, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x29, 0])
                        self.send(0x21, 0x80, tag, struct.pack(">H", len(sense)) + sense, fields=[(3, b"\x02")])
                        continue
                    if self.fault in ("capacity10", "capacity10-residual"):
                        sense = bytes([0x72, 5, 0x20, 0, 0, 0, 0, 0])
                        underflow = self.fault == "capacity10-residual"
                        self.send(0x21, 0x82 if underflow else 0x80, tag,
                                  struct.pack(">H", len(sense)) + sense,
                                  fields=[(3, b"\x02"), (44, struct.pack(">I", length if underflow else 0))])
                        continue
                    payload = struct.pack(">QI", self.base_lba + len(self.memory) // self.block_size - 1, self.block_size) + b"\0" * 20
                    assert length == 32
                    self.send(0x25, 0x81, tag, payload)
                elif cdb[0] == 0x25:
                    assert length == 8
                    self.send(0x25, 0x81, tag, struct.pack(">II", min(0xFFFFFFFF, self.base_lba + len(self.memory) // self.block_size - 1), self.block_size))
                elif cdb[0] == 0xA0:
                    assert length == int.from_bytes(cdb[6:10], "big") == 65536
                    luns = (b"".join(bytes([0, number]) + b"\0" * 6 for number in range(7))
                            if self.inspect_luns else self.lun)
                    payload = struct.pack(">I", len(luns)) + b"\0" * 4 + luns
                    self.send(0x25, 0x83, tag, payload, fields=[(44, struct.pack(">I", length - len(payload)))])
                    if self.fault == "future-command-ack":
                        self.require_close()
                        return
                elif cdb[0] in (0x28, 0x88):
                    if self.fault == "nop-without-command-response":
                        self.ping_until_disconnect()
                        return
                    offset, transfer_length = self.block_range(cdb)
                    assert transfer_length == length
                    payload = bytes(self.memory[offset:offset + length])
                    assert len(payload) == length
                    short = self.fault == "short-block-read"
                    if short:
                        payload = payload[:-self.block_size]
                        assert payload
                    for sequence, offset in enumerate(range(0, len(payload), self.segment_length)):
                        part = payload[offset:offset + self.segment_length]
                        last = offset + len(part) == len(payload)
                        final_sequence = last or (offset + len(part)) % self.maximum_burst == 0
                        self.send(0x25, (0x80 if final_sequence else 0) | (1 if last else 0) | (2 if short and last else 0), tag, part, consume=last,
                                  fields=[(36, struct.pack(">II", sequence, offset)),
                                          (44, struct.pack(">I", length - len(payload) if last else 0))],
                                  corrupt=self.fault == "corrupt-read" and last)
                    if short:
                        self.require_close()
                        return
                elif cdb[0] in (0x2A, 0x8A):
                    offset, transfer_length = self.block_range(cdb)
                    assert transfer_length == length and data == b""
                    if self.fault == "reject-write-command":
                        self.reject_and_require_close(tag)
                        return
                    if self.fault == "premature-write-success":
                        self.send(0x21, 0x80, tag)
                        continue
                    self.pending_write = [tag, offset, length, 0, 0, 0, 0]
                    self.request_burst()
                elif cdb[0] in (0x35, 0x91):
                    assert length == 0 and cdb[1:] == b"\0" * 15
                    if self.fault == "reject-sync-cache":
                        # An invalid-opcode rejection of SYNCHRONIZE CACHE(10) is followed,
                        # once, by (16). Reject that too; only then must the connection end.
                        if cdb[0] == 0x35:
                            self.reject(tag)
                            continue
                        self.reject_and_require_close(tag)
                        return
                    assert cdb[0] == 0x35, "Whole-LUN flush must use SYNCHRONIZE CACHE(10)"
                    self.flushes += 1
                    self.send(0x21, 0x80, tag)
                else:
                    raise AssertionError(f"Unexpected CDB: {cdb.hex()}")
            elif opcode == 5:
                assert header[8:16] == self.lun
                pending = self.pending_write
                assert pending and pending[0] == tag
                assert int.from_bytes(header[20:24], "big") == 73
                assert int.from_bytes(header[36:40], "big") == pending[4]
                assert int.from_bytes(header[40:44], "big") == pending[3]
                assert len(data) <= self.segment_length and pending[3] + len(data) <= pending[6]
                start = pending[1] + pending[3]
                self.memory[start:start + len(data)] = data
                pending[3] += len(data)
                pending[4] += 1
                if header[1] & 0x80:
                    assert pending[3] == pending[6]
                    if self.fault == "partial-write-disconnect":
                        # Close after one accepted R2T burst, before the next request
                        # or a completion status. The command remains incomplete.
                        assert pending[3] == 1024 < pending[2]
                        assert self.writes == self.flushes == 0
                        return
                    if self.fault == "short-block-write":
                        assert pending[3] < pending[2]
                        self.send(0x21, 0x82, tag, fields=[(44, struct.pack(">I", pending[2] - pending[3]))])
                        self.require_close()
                        return
                    if pending[3] == pending[2]:
                        self.pending_write = None
                        self.writes += 1
                        if self.fault == "lost-write-status":
                            return
                        if self.fault == "silent-write-status":
                            try:
                                self.receive()
                            except EOFError:
                                return
                            raise AssertionError("Initiator sent more data after an uncertain write")
                        self.send(0x21, 0x80, tag)
                    else:
                        self.request_burst()
            elif opcode == 6:
                assert header[0] == 0x46 and header[1] == 0x80 and not data
                assert int.from_bytes(header[24:28], "big") == self.exp_cmd
                assert self.pending_write is None
                self.logouts += 1
                if self.check_wrap and self.normal:
                    assert self.command_wrapped, "No actual command crossed ffffffff to zero"
                    assert self.status_wrapped, "No actual status crossed ffffffff to zero"
                if self.normal and self.inspect_luns:
                    expected = [(b"\0" * 8, 0xA0)]
                    for number in range(7):
                        lun = bytes([0, number]) + b"\0" * 6
                        expected.append((lun, 0x12))
                        if number not in (1, 5):
                            expected.append((lun, 0x9E))
                        if number in (0, 6):
                            expected.append((lun, 0x5A))
                    assert self.probe_commands == expected, self.probe_commands
                if self.exercise_nop:
                    assert not self.pings, "Target ping was not answered"
                    assert not self.normal or self.initiator_pings > 0, "No idle initiator probe"
                if self.writes:
                    if self.file_system_fixture:
                        # FSKit issues a flush for every completed raw write. The mount
                        # harness checks the synchronized write prefix independently.
                        assert self.flushes > 0
                    else:
                        # The image write callback flushes its own writes; the explicit
                        # synchronization after it then has nothing to make durable and
                        # sends no SYNCHRONIZE CACHE (RemoteDisk's SynchronizationCoverage).
                        assert self.flushes == 1
                if self.normal and self.image_io:
                    start, count = 511, 16_777_217
                    expected = bytes((i * 7 + 11) & 255 for i in range(256))
                    expected = expected * (count // 256) + expected[:count % 256]
                    assert self.memory[start:start + count] == expected, "Large image write contents"
                    assert self.memory[:start] == bytes((i * 3) & 255 for i in range(start))
                    assert self.memory[start + count:] == bytes(
                        (i * 3) & 255 for i in range(start + count, len(self.memory)))
                    assert self.writes > 16, "Large image write did not pass through bounded commands"
                self.send(0x26, 0x80, tag)
                return
            else:
                raise AssertionError(f"Unexpected opcode: {opcode}")

    def block_range(self, cdb):
        ten_byte = cdb[0] in (0x28, 0x2A)
        if ten_byte:
            start = int.from_bytes(cdb[2:6], "big")
            blocks = int.from_bytes(cdb[7:9], "big")
            assert cdb[1] == cdb[6] == 0 and cdb[9:] == b"\0" * 7
        else:
            start, blocks = struct.unpack_from(">QI", cdb, 2)
            assert cdb[1] == 0 and cdb[14:] == b"\0\0"
        assert blocks > 0
        assert ten_byte == (start + blocks - 1 <= 0xFFFFFFFF and blocks <= 0xFFFF)
        if self.fault in ("capacity10", "capacity10-residual"):
            assert ten_byte, "Legacy target does not support READ/WRITE(16)"
        offset = (start - self.base_lba) * self.block_size
        length = blocks * self.block_size
        assert 0 <= offset <= len(self.memory) and offset + length <= len(self.memory)
        return offset, length

    def reject(self, tag):
        # CHECK CONDITION, ILLEGAL REQUEST, INVALID COMMAND OPERATION CODE (20h/00h).
        sense = bytes([0x72, 5, 0x20, 0, 0, 0, 0, 0])
        self.send(0x21, 0x80, tag, struct.pack(">H", len(sense)) + sense, fields=[(3, b"\x02")])

    def reject_and_require_close(self, tag):
        self.reject(tag)
        self.require_close()

    def require_close(self):
        try:
            self.receive()
        except (EOFError, ConnectionResetError):
            return
        raise AssertionError("Initiator sent another PDU after an operation that must stop")

    def request_burst(self):
        pending = self.pending_write
        length = min(65536 if self.image_io else 1024, pending[2] - pending[3])
        pending[4], pending[6] = 0, pending[3] + length
        if self.exercise_nop:
            self.target_ping()
        self.send(0x31, 0x80, pending[0], consume=False, fields=[(8, self.lun),
            (20, struct.pack(">I", 73)), (36, struct.pack(">III", pending[5], pending[3], length))])
        pending[5] += 1

    def target_ping(self):
        tag = self.next_ping
        self.next_ping += 1
        self.pings[tag] = self.lun
        self.send(0x20, 0x80, 0xFFFFFFFF, consume=False,
                  fields=[(8, self.lun), (20, struct.pack(">I", tag))])

    def ping_until_disconnect(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.target_ping()
            try:
                header, data = self.receive()
            except EOFError:
                return
            assert header[0] == 0x40 and header[16:20] == b"\xff" * 4 and data == b""
            assert header[8:16] == self.pings.pop(int.from_bytes(header[20:24], "big"))
            time.sleep(0.01)
        raise AssertionError("NOP traffic incorrectly extended the command deadline")


@contextmanager
def loopback_server(handler, connection_count=1, allow_disconnect=False, host="127.0.0.1",
                    accept_timeout=20):
    """A fresh RAM-only server per case; always close streams and join its worker."""
    errors = []
    completed = []
    active = []
    lock = threading.Lock()
    stopping = threading.Event()
    assert host in ("127.0.0.1", "::1"), "Only a private loopback target is permitted"
    assert 0 < accept_timeout <= 180
    with socket.socket(socket.AF_INET6 if host == "::1" else socket.AF_INET) as listener:
        listener.bind((host, 0))
        listener.listen()
        listener.settimeout(0.2)
        address = f"{'[::1]' if host == '::1' else host}:{listener.getsockname()[1]}"

        def serve():
            try:
                deadline = time.monotonic() + accept_timeout
                while len(completed) < connection_count and not stopping.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        assert time.monotonic() < deadline, "Initiator did not connect"
                        continue
                    with lock:
                        active.append(connection)
                    try:
                        with connection, connection.makefile("rb") as reader, connection.makefile("wb") as writer:
                            connection.settimeout(20)
                            handler(reader, writer)
                    except (EOFError, BrokenPipeError, ConnectionResetError):
                        if not allow_disconnect:
                            raise
                    finally:
                        with lock:
                            active.remove(connection)
                    completed.append(True)
            except Exception as error:
                if not stopping.is_set():
                    errors.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield address
            worker.join(timeout=21)
            assert not worker.is_alive(), "Loopback target did not finish"
            if errors:
                raise errors[0]
            assert len(completed) == connection_count, "Missing loopback connection"
        finally:
            stopping.set()
            with lock:
                for connection in active:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            worker.join(timeout=1)
            assert not worker.is_alive(), "Loopback target cleanup did not finish"


def run_cli(binary_dir, environment):
    def serve(reader, writer):
        Target(reader, writer, environment).run()

    with loopback_server(serve, connection_count=2) as address:
        subprocess.run([str(binary_dir / "iscsi"), "discover", address], check=True, timeout=30)
        subprocess.run([str(binary_dir / "iscsi"), "info", address, TARGET.decode()], check=True, timeout=30)
    print("PASS: CLI discovery and capacity over TCP")


def run_probe(binary_dir, loopback, environment, expected_error=None):
    command = [str(binary_dir / "ISCSIIntegrationProbe")]

    def invoke(arguments):
        result = subprocess.run(command + arguments, cwd=ROOT, env=environment,
                                capture_output=expected_error is not None,
                                text=True, timeout=180 if environment.get("ISCSI_TEST_IMAGE_IO") == "1" else 30)
        if expected_error is None:
            result.check_returncode()
        else:
            assert result.returncode == 1, f"Expected a controlled rejection: {result}"
            assert "PASS:" not in result.stdout
            assert expected_error in result.stderr, result.stderr

    if loopback:
        def serve(reader, writer):
            Target(reader, writer, environment).run()

        count = 1 if environment.get("ISCSI_TEST_FAULT") == "discovery-auth-rejected" else 2
        with loopback_server(serve, connection_count=count,
                             allow_disconnect=expected_error is not None) as address:
            invoke(["--disposable-loopback", address])
    else:
        invoke(["--stdio-target", str(Path(__file__).resolve())])


def run_login_continuations(binary_dir, loopback, environment):
    for negotiation in ("long-operational", "long-operational-none", "long-security", "long-ack-poll"):
        for chap in ("0", "1"):
            run_probe(binary_dir, loopback, {**environment, "ISCSI_TEST_NEGOTIATION": negotiation,
                                            "ISCSI_TEST_CHAP": chap})
            print(f"PASS: login continuation {negotiation}, CHAP={chap}")
    for fault, expected in (
            ("data", "login continuation acknowledgment"),
            ("transit", "login stage flags"),
            ("stage", "login stage flags"),
            ("sequence", "login StatSN"),
            ("tag", "login response identity"),
            ("reject", "rejected the connection (2:0)"),
            ("loop", "login exchanges")):
        run_probe(binary_dir, loopback, {**environment, "ISCSI_TEST_NEGOTIATION": "long-operational",
                                        "ISCSI_TEST_CHAP": "1",
                                        "ISCSI_TEST_FAULT": f"login-continuation-{fault}"},
                  expected_error=expected)
        print(f"PASS: rejected login continuation {fault}")


def run_mutual_chap(binary_dir, loopback, environment):
    environment = {**environment, "ISCSI_TEST_CHAP": "1", "ISCSI_TEST_MUTUAL_CHAP": "1"}
    for mode in ("", "long-security", "long-operational", "long-ack-poll", "hex", "reject-defaults",
                 "long-operational-none", "mutual-base64", "mutual-continued", "mutual-deferred"):
        run_probe(binary_dir, loopback, {**environment, "ISCSI_TEST_NEGOTIATION": mode})
        print(f"PASS: mutual CHAP {mode or 'standard'}")
    for fault in ("missing", "name", "digest", "reflected", "length", "encoding", "half", "early"):
        expected = "unexpected authentication key" if fault == "early" else "Server authentication failed."
        run_probe(binary_dir, loopback, {**environment, "ISCSI_TEST_FAULT": f"mutual-{fault}"},
                  expected_error=expected)
        print(f"PASS: rejected mutual CHAP {fault}")


def run_discovery_authentication(binary_dir, loopback, environment):
    combinations = (("chap", "none"), ("mutual", "none"), ("none", "chap"), ("none", "mutual"),
                    ("chap", "chap"), ("mutual", "mutual"), ("chap", "mutual"), ("mutual", "chap"))
    for connection, discovery in combinations:
        controls = {**environment, "ISCSI_TEST_CHAP": "0" if connection == "none" else "1",
                    "ISCSI_TEST_MUTUAL_CHAP": "1" if connection == "mutual" else "0",
                    "ISCSI_TEST_DISCOVERY_AUTH": discovery}
        run_probe(binary_dir, loopback, controls)
        print(f"PASS: independent authentication connection={connection}, discovery={discovery}")
    for discovery in ("chap", "mutual"):
        run_probe(binary_dir, loopback, {**environment, "ISCSI_TEST_CHAP": "1",
                  "ISCSI_TEST_DISCOVERY_AUTH": discovery, "ISCSI_TEST_FAULT": "discovery-auth-rejected"},
                  expected_error="rejected the connection (2:1)")
        print(f"PASS: rejected discovery {discovery} without authentication fallback or Normal session")


def run_chap_boundaries(binary_dir, loopback, environment):
    """Exercise decoded challenge limits without treating simulated peers as vendor hardware."""
    for length in (1, 1024):
        for encoding in ("hex", "base64"):
            for mutual in (False, True):
                controls = {**environment, "ISCSI_TEST_CHAP": "1",
                            "ISCSI_TEST_MUTUAL_CHAP": str(int(mutual)),
                            "ISCSI_TEST_DISCOVERY_AUTH": "mutual" if mutual else "chap",
                            "ISCSI_TEST_CHALLENGE_BYTES": str(length),
                            "ISCSI_TEST_CHALLENGE_ENCODING": encoding,
                            "ISCSI_TEST_FRAGMENT_CHALLENGE": "1"}
                run_probe(binary_dir, loopback, controls)
                print(f"PASS: CHAP challenge {length} bytes/{encoding}, mutual={mutual}, discovery+normal")
    for encoding in ("hex", "base64"):
        for fault in ("missing", "reflected", "length"):
            controls = {**environment, "ISCSI_TEST_CHAP": "1", "ISCSI_TEST_MUTUAL_CHAP": "1",
                        "ISCSI_TEST_DISCOVERY_AUTH": "mutual", "ISCSI_TEST_CHALLENGE_BYTES": "1",
                        "ISCSI_TEST_CHALLENGE_ENCODING": encoding,
                        "ISCSI_TEST_FAULT": f"mutual-{fault}"}
            run_probe(binary_dir, loopback, controls, expected_error="Server authentication failed.")
            print(f"PASS: short CHAP challenge/{encoding} still rejects target proof {fault}")


def run_transport_cases(binary_dir, environment):
    for behavior in ("receive-timeout", "idle-receive", "cancel-receive", "close-receive"):
        def serve(reader, writer):
            assert exact(reader, 1) == b"\xa1"
            if behavior == "idle-receive":
                # Longer than the probe's 100 ms operation timeout.
                time.sleep(0.35)
                writer.write(b"\xb2")
                writer.flush()
            assert reader.read(1) == b"", "Transport did not close after the check"

        with loopback_server(serve) as address:
            subprocess.run([str(binary_dir / "ISCSIIntegrationProbe"), "--transport-loopback", address],
                           cwd=ROOT, env={**environment, "ISCSI_TEST_TRANSPORT": behavior},
                           check=True, timeout=10)
        print(f"PASS: TCP transport {behavior}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdio-target", action="store_true")
    parser.add_argument("--loopback", action="store_true")
    parser.add_argument("--login-continuations", action="store_true")
    parser.add_argument("--mutual-chap", action="store_true")
    parser.add_argument("--discovery-authentication", action="store_true")
    parser.add_argument("--chap-boundaries", action="store_true")
    args = parser.parse_args()
    if args.stdio_target:
        Target(sys.stdin.buffer, sys.stdout.buffer).run()
        return
    binary_dir = Path(subprocess.check_output(
        ["swift", "build", "--show-bin-path", "--disable-sandbox"], cwd=ROOT, text=True).strip())
    # Test controls must not leak in from a developer's shell into unrelated cases.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ISCSI_TEST_")}
    if args.chap_boundaries:
        run_chap_boundaries(binary_dir, args.loopback, environment)
        return
    if args.discovery_authentication:
        run_discovery_authentication(binary_dir, args.loopback, environment)
        return
    if args.mutual_chap:
        run_mutual_chap(binary_dir, args.loopback, environment)
        return
    if args.login_continuations:
        run_login_continuations(binary_dir, args.loopback, environment)
        return
    if args.loopback:
        run_cli(binary_dir, environment)
        run_transport_cases(binary_dir, environment)
    run_probe(binary_dir, args.loopback, environment)
    run_probe(binary_dir, args.loopback, {**environment, "ISCSI_TEST_CHAP": "1"})
    print("PASS: independent CHAP discovery and normal login")
    for block_size, chap in ((512, "0"), (4096, "1")):
        run_probe(binary_dir, args.loopback, {**environment, "ISCSI_TEST_IMAGE_IO": "1",
                  "ISCSI_TEST_BLOCK_SIZE": str(block_size), "ISCSI_TEST_CHAP": chap})
        print(f"PASS: FSKit volume large write over iSCSI, block size={block_size}, CHAP={chap}")
    for chap in ("0", "1"):
        env = {**environment, "ISCSI_TEST_CHAP": chap, "ISCSI_TEST_SEQUENCE_WRAP": "1",
               "ISCSI_TEST_INITIAL_CMDSN": str(SERIAL_MASK - 1),
               "ISCSI_TEST_INITIAL_STATSN": str(SERIAL_MASK - (4 if chap == "1" else 2))}
        if chap == "1":
            env.update({"ISCSI_TEST_NOP": "1", "ISCSI_TEST_FAULT": "stale-command-window"})
        run_probe(binary_dir, args.loopback, env)
        print(f"PASS: command and status sequence wrap, CHAP={chap}, stale windows={chap}")
    for chap in ("0", "1"):
        run_probe(binary_dir, args.loopback, {**environment, "ISCSI_TEST_NOP": "1", "ISCSI_TEST_CHAP": chap})
        print(f"PASS: idle and interleaved NOP with CRC32C, CHAP={chap}")
    for lun in ("4001000000000000", "0001400200034004", "c101000000000000"):
        run_probe(binary_dir, args.loopback, {**environment, "ISCSI_TEST_LUN": lun})
        print(f"PASS: exact LUN address {lun}")
    for behavior in ("unit-attention", "capacity10", "capacity10-residual"):
        run_probe(binary_dir, args.loopback, {**environment, "ISCSI_TEST_FAULT": behavior})
        print(f"PASS: {behavior}")
    for base, block_size in ((0, 4096), (0xFFFFFFFF, 512), (0x100000000, 512), (0x100000000, 4096)):
        env = {**environment, "ISCSI_TEST_BASE_LBA": str(base), "ISCSI_TEST_BLOCK_SIZE": str(block_size)}
        if block_size == 4096 and base:
            env.update({"ISCSI_TEST_CHAP": "1", "ISCSI_TEST_NOP": "1"})
        run_probe(binary_dir, args.loopback, env)
        print(f"PASS: command size selection at LBA {base}, block size {block_size}")
    for behavior in ("inquiry-unit-attention", "inquiry-unit-attention-residual",
                     "inquiry-unit-attention-unused-residual", "inquiry-optional-tail",
                     "inquiry-header-only", "unused-residual", "stale-command-window",
                     "invalid-command-window", "future-invalid-command-window", "data-ack-at-erl-zero"):
        run_probe(binary_dir, args.loopback, {**environment, "ISCSI_TEST_FAULT": behavior})
        print(f"PASS: {behavior}")
    for chap in ("0", "1"):
        run_probe(binary_dir, args.loopback, {**environment, "ISCSI_TEST_LUN_INSPECTION": "1", "ISCSI_TEST_CHAP": chap})
        print(f"PASS: mixed usable, unsupported, not-ready, no-media, reserved and invalid LUNs, CHAP={chap}")
    for negotiation in ("irrelevant-burst", "reject-defaults", "hex", "security-metadata", "target-proposals"):
        for chap in ("0", "1"):
            run_probe(binary_dir, args.loopback, {**environment, "ISCSI_TEST_NEGOTIATION": negotiation, "ISCSI_TEST_CHAP": chap})
            print(f"PASS: negotiation {negotiation}, CHAP={chap}")
    run_login_continuations(binary_dir, args.loopback, environment)
    run_mutual_chap(binary_dir, args.loopback, environment)
    run_discovery_authentication(binary_dir, args.loopback, environment)
    for block_size in (512, 4096):
        for chap in ("0", "1"):
            for operation, fault in (("write", "reject-write-command"), ("synchronize", "reject-sync-cache")):
                run_probe(binary_dir, args.loopback, {**environment, "ISCSI_TEST_BLOCK_SIZE": str(block_size),
                          "ISCSI_TEST_CHAP": chap, "ISCSI_TEST_FAULT": fault,
                          "ISCSI_TEST_MUTATION_RETIREMENT": operation})
                print(f"PASS: failed mutation retirement, operation={operation}, block size={block_size}, CHAP={chap}")
    for fault in ("corrupt-read", "premature-write-success", "lost-write-status",
                  "silent-write-status", "partial-write-disconnect",
                  "repeat-unit-attention", "bad-idle-echo", "lost-idle-echo", "nop-without-command-response",
                  "tape-device", "unavailable-device", "short-inquiry",
                  "reject-write-command", "reject-sync-cache",
                  "short-block-read", "short-block-write",
                  "error-residual-both", "error-underflow-zero", "error-underflow-large", "error-overflow-zero",
                  "future-command-ack",
                  "not-understood-standard", "invalid-wait-selection", "invalid-retain-selection",
                  "final-unanswered-key", "repeated-login-key"):
        env = {**environment, "ISCSI_TEST_FAULT": fault}
        if fault in ("bad-idle-echo", "lost-idle-echo"):
            env["ISCSI_TEST_NOP"] = "1"
        expected = {"corrupt-read": "integrity", "premature-write-success": "premature write status",
                    "lost-write-status": "closed the connection", "partial-write-disconnect": "closed the connection",
                    "repeat-unit-attention": "disk returned an error",
                    "bad-idle-echo": "connection is not ready", "lost-idle-echo": "connection is not ready",
                    "silent-write-status": "did not respond in time",
                    "tape-device": "type of storage device is not supported",
                    "unavailable-device": "logical unit is unavailable", "short-inquiry": "disk information is invalid",
                    "reject-write-command": "disk returned an error", "reject-sync-cache": "disk returned an error",
                    "short-block-read": "short block transfer", "short-block-write": "short block transfer",
                    "error-residual-both": "SCSI residual count", "error-underflow-zero": "SCSI residual count",
                    "error-underflow-large": "SCSI residual count", "error-overflow-zero": "SCSI residual count",
                    "future-command-ack": "command window",
                    "nop-without-command-response": "did not respond in time",
                    "not-understood-standard": "Invalid iSCSI response", "invalid-wait-selection": "Invalid iSCSI response",
                    "invalid-retain-selection": "Invalid iSCSI response", "final-unanswered-key": "Invalid iSCSI response",
                    "repeated-login-key": "Invalid iSCSI response"}[fault]
        run_probe(binary_dir, args.loopback, env, expected_error=expected)
        print(f"PASS: rejected {fault}")


if __name__ == "__main__":
    main()
