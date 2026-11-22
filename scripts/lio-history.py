#!/usr/bin/env python3
"""Bounded, passive history of a disposable LIO image, reconstructed from iSCSI.

Call observe before forwarding each frame unchanged. Only SCSI metadata and the
synthetic fixture's write bytes are retained; login/authentication text is ignored.
GOOD SYNCHRONIZE CACHE responses select historical prefixes, not current counters.
The caller must use the native probe's clock and compare the final reconstruction
with the independent target's complete backstore. This is no power-loss model.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import threading
import time

_spec = importlib.util.spec_from_file_location('history_scsi_completion', Path(__file__).with_name('lio-scsi-completion.py'))
scsi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scsi)


class WireHistory:
    def __init__(self, seed, block_size=512, clock=time.monotonic_ns,
                 maximum_payload=64 * 1048576, maximum_commands=4096):
        assert seed and block_size > 0 and len(seed) % block_size == 0
        self.seed = bytes(seed)
        self.block_size = block_size
        self.clock = clock
        self.maximum_payload = maximum_payload
        self.maximum_commands = maximum_commands
        self.lock = threading.Lock()
        self.pending = {}
        self.commands, self.frames, self.commits = [], [], []
        self.payloads = bytearray()
        self.writes = 0

    def _frame(self, command, offset, payload, timestamp):
        assert payload and offset == command['receivedBytes'], 'Overlapping or missing write data'
        assert len(payload) <= command['transferBytes'] - offset, 'Write data exceeds CDB'
        assert len(self.payloads) + len(payload) <= self.maximum_payload, 'Write capture limit'
        self.frames.append(dict(commandIndex=command['index'], offset=offset,
                                absoluteOffset=command['absoluteOffset'] + offset,
                                payloadOffset=len(self.payloads), length=len(payload),
                                observedNS=timestamp))
        self.payloads.extend(payload)
        command['receivedBytes'] += len(payload)

    def observe(self, header, connection_id, to_target, body, *, login_summary=None):
        timestamp = self.clock()
        assert len(header) == 48
        op = header[0] & 63
        if op not in (1, 5, 0x21, 0x25):
            return  # Never persist authentication, Text or other control payloads.
        tag = int.from_bytes(header[16:20], 'big')
        key = (connection_id, tag)
        with self.lock:
            if to_target and op == 1:
                assert len(self.commands) < self.maximum_commands, 'Command capture limit'
                assert key not in self.pending, 'Reused active task tag'
                cdb = bytes(header[32:48])
                command = dict(index=len(self.commands), connection=connection_id, taskTag=tag,
                               cdb=cdb.hex(), opcode=cdb[0], commandObservedNS=timestamp,
                               rawLUN=bytes(header[8:16]).hex(), directionFlags=header[1] & 0x60,
                               transferBytes=int.from_bytes(header[20:24], 'big'), receivedBytes=0,
                               dataInPDUs=0, readBytes=0, lastDataFinal=False,
                               loginProof=scsi.login_binding(login_summary, connection_id))
                if cdb[0] in (0x2a, 0x8a):
                    wide = cdb[0] == 0x8a
                    lba = int.from_bytes(cdb[2:10] if wide else cdb[2:6], 'big')
                    blocks = int.from_bytes(cdb[10:14] if wide else cdb[7:9], 'big')
                    assert not cdb[1] & 8, 'FUA needs a separate durability model'
                    assert blocks > 0 and command['transferBytes'] == blocks * self.block_size
                    command['absoluteOffset'] = lba * self.block_size
                    assert command['absoluteOffset'] + command['transferBytes'] <= len(self.seed)
                    if body:
                        self._frame(command, 0, bytes(body), timestamp)
                elif cdb[0] in (0x35, 0x91):
                    assert not any(cdb[1:]), 'Only whole, non-IMMED flushes with zero control fields'
                    assert not body and command['transferBytes'] == 0
                self.pending[key] = command
                self.commands.append(command)
            elif to_target and op == 5:
                command = self.pending[key]
                assert command['opcode'] in (0x2a, 0x8a)
                self._frame(command, int.from_bytes(header[40:44], 'big'), bytes(body), timestamp)
            elif not to_target and op in (0x21, 0x25):
                command = self.pending.get(key)
                if command is None:
                    return
                if op == 0x25:
                    command['dataInPDUs'] += 1
                    command['readBytes'] += len(body)
                    command['lastDataFinal'] = bool(header[1] & 0x80)
                    if not header[1] & 1:
                        return
                self.pending.pop(key)
                good = header[3] == 0 and (op != 0x21 or header[2] == 0)
                command.update(responseObservedNS=timestamp, good=good, scsiStatus=header[3],
                               responseOpcode=op, responseFlags=header[1],
                               responseCode=header[2] if op == 0x21 else 0,
                               responseDataSN=int.from_bytes(header[36:40], 'big'),
                               residualCount=int.from_bytes(header[44:48], 'big') if header[1] & 6 else 0)
                # Independent raw completion metadata, without adopting failed read data.
                # The LUN observer applies the complete transfer/sense admission policy.
                command['sense'] = (scsi.sense_metadata(body)
                                    if op == 0x21 and header[3] == 2 and body else None)
                if command['opcode'] in (0x2a, 0x8a):
                    assert good and not header[1] & 6, 'Unsuccessful or residual write'
                    assert command['receivedBytes'] == command['transferBytes'], 'Incomplete write'
                    self.writes += 1
                elif command['opcode'] in (0x35, 0x91):
                    assert good, 'Unsuccessful flush'
                    assert not any(c['opcode'] in (0x2a, 0x8a) for c in self.pending.values()), 'Flush overtook write'
                    self.commits.append(dict(commandIndex=command['index'], responseObservedNS=timestamp,
                                             deltaCount=len(self.frames), writes=self.writes))

    def _replay(self, count):
        image = bytearray(self.seed)
        for frame in self.frames[:count]:
            start = frame['absoluteOffset'];p = frame['payloadOffset'];n = frame['length']
            image[start:start + n] = self.payloads[p:p + n]
        return image

    def snapshot(self, cutoff):
        with self.lock:
            eligible = [c for c in self.commits if c['responseObservedNS'] <= cutoff]
            selected = dict(eligible[-1]) if eligible else dict(
                commandIndex=None, responseObservedNS=None, deltaCount=0, writes=0,
                sha256=hashlib.sha256(self.seed).hexdigest())
            image = self._replay(selected['deltaCount'])
            selected['sha256'] = hashlib.sha256(image).hexdigest()
            return bytes(image), selected

    def export(self, root):
        with self.lock:
            assert not self.pending, 'Commands remain in flight'
            # Hash only after capture, never on the response-forwarding path.
            image = bytearray(self.seed)
            position = 0
            for commit in self.commits:
                for frame in self.frames[position:commit['deltaCount']]:
                    start = frame['absoluteOffset'];p = frame['payloadOffset'];n = frame['length']
                    image[start:start + n] = self.payloads[p:p + n]
                position = commit['deltaCount']
                commit['sha256'] = hashlib.sha256(image).hexdigest()
            for frame in self.frames:
                p = frame['payloadOffset'];n = frame['length']
                frame['sha256'] = hashlib.sha256(self.payloads[p:p + n]).hexdigest()
            final_image = self._replay(len(self.frames))
            report = dict(blockSize=self.block_size, byteCount=len(self.seed),
                          seedSHA256=hashlib.sha256(self.seed).hexdigest(),
                          finalSHA256=hashlib.sha256(final_image).hexdigest(),
                          hashingDeferredUntilSnapshotOrExport=True, hashesDuringObservation=False,
                          responseTimestampBeforeForward=True, payloadBytes=len(self.payloads),
                          commands=self.commands, frames=self.frames, commits=self.commits)
            (root / 'WireHistory.json').write_text(json.dumps(report, indent=2) + '\n')
            (root / 'WritePayloads.bin').write_bytes(self.payloads)
            return report
