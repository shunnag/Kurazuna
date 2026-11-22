"""Bounded, independent login and digest checks for the disposable LIO tests.

This observer never serializes authentication fields. It is deliberately stricter
than a general initiator: unsupported observation conditions invalidate evidence.
The caller must keep forwarding the original bytes when observation fails.
"""

import base64
import hashlib
import hmac
import threading


class AuditError(Exception):
    """A fixed diagnostic code, without peer bytes or chained parse errors."""

    CODES = frozenset("""AUTH_ENCODING_LIMIT AUTH_ENCODING AUTH_BINARY_LIMIT AUTH_IDENTIFIER
        AUTH_REPEATED_METHOD AUTH_SELECTION AUTH_REQUIRED AUTH_ALGORITHM AUTH_REPEATED_ALGORITHM
        AUTH_ALGORITHM_SELECTION AUTH_CHALLENGE AUTH_REPEATED_CHALLENGE AUTH_CHALLENGE_ORDER
        AUTH_REFLECTION AUTH_PROOF_ORDER AUTH_PROOF AUTH_PROOF_CHALLENGE AUTH_INCOMPLETE AUTH_UNRESOLVED
        LOGIN_FRAME LOGIN_AFTER_FINAL LOGIN_DIRECTION LOGIN_FLAGS LOGIN_TRANSITION LOGIN_PDU_LIMIT
        LOGIN_TEXT_LIMIT LOGIN_TEXT_TERMINATOR LOGIN_TEXT_PAIR LOGIN_TEXT_KEY LOGIN_SESSION_TYPE
        LOGIN_REQUEST_OVERLAP LOGIN_CONTINUATION_ACK LOGIN_UNMATCHED_RESPONSE LOGIN_IDENTITY LOGIN_FAILED
        LOGIN_REQUEST_ACK LOGIN_UNAUTHORIZED_TRANSITION LOGIN_INCOMPLETE LOGIN_COVERAGE
        LOGIN_INCOMPLETE_CLOSE LOGIN_CONNECTION_LIMIT LOGIN_PARSE CONNECTION_LIMIT
        DIGEST_REPEATED_OFFER DIGEST_OFFER DIGEST_SELECTION DIGEST_UNRESOLVED
        FRAME_HEADER FRAME_LIMIT FRAME_LENGTH FRAME_BEFORE_LOGIN HEADER_CRC DATA_CRC
        PARTIAL_FRAME_AT_CLOSE TRANSPORT_FAILED OBSERVER_FAILED
        LOGOUT_REQUEST LOGOUT_RESPONSE LOGOUT_COVERAGE
        ERL_STAGE ERL_VALUE ERL_REPEATED ERL_SELECTION ERL_UNRESOLVED ERL_DISCOVERY
        LOGIN_EXISTING_SESSION""".split())

    def __init__(self, code):
        super().__init__(code if isinstance(code, str) and code in self.CODES else "OBSERVER_FAILED")


def require(value, code):
    if not value:
        raise AuditError(code)


def binary(value, maximum):
    try:
        require(len(value) <= 2 + maximum * 2 + 8, "AUTH_ENCODING_LIMIT")
        if value.startswith(b"0x"):
            encoded = value[2:]
            require(len(encoded) % 2 == 0 and all(x in b"0123456789abcdefABCDEF" for x in encoded), "AUTH_ENCODING")
            result = bytes.fromhex(encoded.decode("ascii"))
        else:
            require(value.startswith(b"0b"), "AUTH_ENCODING")
            result = base64.b64decode(value[2:], validate=True)
        require(0 < len(result) <= maximum, "AUTH_BINARY_LIMIT")
        return result
    except AuditError:
        raise
    except Exception:
        raise AuditError("AUTH_ENCODING") from None


def identifier(value):
    try:
        require(0 < len(value) <= 24, "AUTH_IDENTIFIER")
        if value.startswith(b"0b"):
            result = int.from_bytes(binary(value, 8), "big")
        else:
            base, digits = (16, value[2:]) if value.startswith(b"0x") else (10, value)
            alphabet = b"0123456789abcdefABCDEF" if base == 16 else b"0123456789"
            require(digits and all(x in alphabet for x in digits), "AUTH_IDENTIFIER")
            result = int(digits, base)
        require(0 <= result <= 255, "AUTH_IDENTIFIER")
        return result
    except AuditError:
        raise
    except Exception:
        raise AuditError("AUTH_IDENTIFIER") from None


class LoginAudit:
    """One connection. credential_provider(session_type) enables mutual proof checks."""

    def __init__(self, credential_provider=None, connection_id=None):
        self.lock = threading.Lock()
        self.connection_id = connection_id
        self.provider = credential_provider
        self.stage = 0
        self.identity = None
        self.initial_tsih = None
        self.outstanding = None
        self.response_authorization = None
        self.fragments = {True: bytearray(), False: bytearray()}
        self.pdus = self.text_bytes = 0
        self.session_type = None
        self.method_offer = None
        self.method = None
        self.algorithm_offer = self.algorithm = False
        self.challenges = {}
        self.proofs = {True: False, False: False}
        self.challenge_lengths = {}
        self.digest_offers = {}
        self.digest_offer_stages = {}
        self.digest_answers = {}
        self.digest_raw_answers = {}
        self.digest_sources = {}
        self.erl_proposer = None
        self.erl_offer = self.erl_answer = None
        self.erl_level = self.erl_source = None
        self.ready = False
        self.failed = False
        self.digest_checks = dict(header=0, data=0)
        self.logout_requests = self.logout_replies = 0

    def record_logout(self, request):
        with self.lock:
            require(self.ready and not self.failed, "LOGOUT_REQUEST" if request else "LOGOUT_RESPONSE")
            if request:
                require(self.logout_requests == self.logout_replies == 0, "LOGOUT_REQUEST")
                self.logout_requests = 1
            else:
                require(self.logout_requests == 1 and self.logout_replies == 0, "LOGOUT_RESPONSE")
                self.logout_replies = 1

    def checked_digests(self, header, data):
        with self.lock:
            self.digest_checks["header"] += int(header)
            self.digest_checks["data"] += int(data)

    def clear_sensitive(self):
        self.challenges.clear()
        for value in self.fragments.values():
            value.clear()

    def close(self):
        with self.lock:
            self.clear_sensitive()
            if not self.ready:
                self.failed = True

    def summary(self):
        with self.lock:
            return dict(connectionID=self.connection_id, sessionType=self.session_type, complete=self.ready and not self.failed,
                        mutualProofsVerified=bool(self.provider and all(self.proofs.values())),
                        initiatorProofVerified=self.proofs[True], targetProofVerified=self.proofs[False],
                        peerChallengeBytes=self.challenge_lengths.get(False),
                        initiatorChallengeBytes=self.challenge_lengths.get(True),
                        headerDigest=self.digest_answers.get(b"HeaderDigest", b"None").decode("ascii"),
                        dataDigest=self.digest_answers.get(b"DataDigest", b"None").decode("ascii"),
                        digestNegotiation={key.decode('ascii'): dict(
                            offer=[value.decode('ascii') for value in self.digest_offers.get(key, [])],
                            offerStage=self.digest_offer_stages.get(key),
                            response=None if key not in self.digest_raw_answers else self.digest_raw_answers[key].decode('ascii'),
                            effective=None if key not in self.digest_answers else self.digest_answers[key].decode('ascii'),
                            source=self.digest_sources.get(key)) for key in [b'HeaderDigest', b'DataDigest']},
                        fullFeaturePhase=self.ready and self.stage == 3 and not self.failed,
                        initialTSIH=self.initial_tsih,
                        errorRecoveryLevel=self.erl_level, errorRecoveryLevelSource=self.erl_source,
                        errorRecoveryLevelOffer=self.erl_offer, errorRecoveryLevelResponse=self.erl_answer,
                        errorRecoveryLevelProposer=self.erl_proposer,
                        loginPDUs=self.pdus, failed=self.failed, digestChecks=dict(self.digest_checks),
                        logoutRequests=self.logout_requests, logoutReplies=self.logout_replies)

    def _text(self, body, to_target, continued):
        pending = self.fragments[to_target]
        self.text_bytes += len(body)
        require(self.text_bytes <= 262144 and len(pending) + len(body) <= 65536, "LOGIN_TEXT_LIMIT")
        pending.extend(body)
        if continued:
            return {}
        data = bytes(pending)
        pending.clear()
        require(not data or data.endswith(b"\0"), "LOGIN_TEXT_TERMINATOR")
        result = {}
        for part in data.split(b"\0")[:-1]:
            require(b"=" in part, "LOGIN_TEXT_PAIR")
            key, value = part.split(b"=", 1)
            require(key and key not in result and len(key) <= 255, "LOGIN_TEXT_KEY")
            result[key] = value
        return result

    def _fields(self, values, to_target):
        if b"SessionType" in values:
            require(to_target and self.session_type is None and values[b"SessionType"] in (b"Discovery", b"Normal"), "LOGIN_SESSION_TYPE")
            self.session_type = values[b"SessionType"].decode("ascii")
        if b"ErrorRecoveryLevel" in values:
            require(self.stage == 1, "ERL_STAGE")
            sender = "initiator" if to_target else "target"
            value = values[b"ErrorRecoveryLevel"]
            if value == b"Reject":
                require(self.erl_proposer is not None and self.erl_proposer != sender
                        and self.erl_answer is None, "ERL_SELECTION")
                self.erl_answer = "Reject"
                self.erl_level, self.erl_source = 0, "rejected-default"
            else:
                hexadecimal = value.startswith((b"0x", b"0X"))
                digits = value[2:] if hexadecimal else value
                alphabet = b"0123456789abcdefABCDEF" if hexadecimal else b"0123456789"
                require(0 < len(digits) <= 16 and all(c in alphabet for c in digits), "ERL_VALUE")
                number = int(digits, 16 if hexadecimal else 10)
                require(number <= 2, "ERL_VALUE")
                if self.erl_proposer is None:
                    self.erl_proposer, self.erl_offer = sender, number
                else:
                    require(self.erl_proposer != sender and self.erl_answer is None, "ERL_REPEATED")
                    require(number <= self.erl_offer, "ERL_SELECTION")
                    self.erl_answer = self.erl_level = number
                    self.erl_source = "negotiated"
        if b"AuthMethod" in values:
            if to_target:
                require(self.method_offer is None, "AUTH_REPEATED_METHOD")
                self.method_offer = values[b"AuthMethod"].split(b",")
            else:
                require(self.method is None and self.method_offer is not None and values[b"AuthMethod"] in self.method_offer, "AUTH_SELECTION")
                self.method = values[b"AuthMethod"]
        if self.provider:
            if self.method is not None:
                require(self.method == b"CHAP", "AUTH_REQUIRED")
            if b"CHAP_A" in values:
                algorithms = [identifier(value) for value in values[b"CHAP_A"].split(b",")]
                if to_target:
                    require(5 in algorithms and len(algorithms) <= 16 and len(set(algorithms)) == len(algorithms), "AUTH_ALGORITHM")
                    require(not self.algorithm_offer, "AUTH_REPEATED_ALGORITHM")
                    self.algorithm_offer = True
                else:
                    require(algorithms == [5], "AUTH_ALGORITHM")
                    require(self.algorithm_offer and not self.algorithm, "AUTH_ALGORITHM_SELECTION")
                    self.algorithm = True
            if b"CHAP_I" in values or b"CHAP_C" in values:
                require(self.algorithm and self.method == b"CHAP" and b"CHAP_I" in values and b"CHAP_C" in values, "AUTH_CHALLENGE")
                require(to_target not in self.challenges, "AUTH_REPEATED_CHALLENGE")
                challenge = binary(values[b"CHAP_C"], 1024)
                if not to_target:
                    require(not self.proofs[True], "AUTH_CHALLENGE_ORDER")
                else:
                    require(False in self.challenges, "AUTH_CHALLENGE_ORDER")
                    require(challenge != self.challenges[False][1], "AUTH_REFLECTION")
                self.challenges[to_target] = (identifier(values[b"CHAP_I"]), challenge)
                self.challenge_lengths[to_target] = len(challenge)
            if b"CHAP_N" in values or b"CHAP_R" in values:
                require(self.session_type is not None and self.method == b"CHAP" and self.algorithm, "AUTH_PROOF_ORDER")
                require(b"CHAP_N" in values and b"CHAP_R" in values and not self.proofs[to_target], "AUTH_PROOF")
                require((not to_target) in self.challenges, "AUTH_PROOF_CHALLENGE")
                credentials = self.provider(self.session_type)
                name = credentials["username" if to_target else "targetUsername"].encode("utf-8")
                secret = credentials["password" if to_target else "targetPassword"].encode("utf-8")
                challenge_id, challenge = self.challenges[not to_target]
                answer = binary(values[b"CHAP_R"], 16)
                require(len(answer) == 16 and values[b"CHAP_N"] == name, "AUTH_PROOF")
                expected = hashlib.md5(bytes([challenge_id]) + secret + challenge).digest()
                require(hmac.compare_digest(answer, expected), "AUTH_PROOF")
                self.proofs[to_target] = True
        for key in [b"HeaderDigest", b"DataDigest"]:
            if key not in values:
                continue
            value = values[key]
            if to_target:
                require(key not in self.digest_offers, "DIGEST_REPEATED_OFFER")
                options = value.split(b",")
                require(options and len(set(options)) == len(options) and all(v in [b"None", b"CRC32C"] for v in options), "DIGEST_OFFER")
                self.digest_offers[key] = options
                self.digest_offer_stages[key] = self.stage
            else:
                require(key in self.digest_offers and key not in self.digest_answers, "DIGEST_SELECTION")
                if value == b'Reject':
                    # RFC7143 6.1/13.1: a fresh connection retains default None.
                    # The observed product offers None explicitly; never infer a
                    # permitted downgrade for an absent or CRC-only proposal.
                    require(self.stage == 1 and self.initial_tsih == 0
                            and self.digest_offer_stages[key] == 1
                            and b'None' in self.digest_offers[key], 'DIGEST_REJECT_DEFAULT')
                    self.digest_answers[key] = b'None'
                    self.digest_sources[key] = 'rejected-default'
                else:
                    require(value in self.digest_offers[key], 'DIGEST_SELECTION')
                    self.digest_answers[key] = value
                    self.digest_sources[key] = 'negotiated'
                self.digest_raw_answers[key] = value

    def observe(self, header, to_target, body):
        with self.lock:
            try:
                require(len(header) == 48 and len(body) == int.from_bytes(header[5:8], "big"), "LOGIN_FRAME")
                require(not self.ready and not self.failed, "LOGIN_AFTER_FINAL")
                opcode = header[0] & 0x3f
                require(opcode == (3 if to_target else 0x23), "LOGIN_DIRECTION")
                flags = header[1]
                stage, next_stage = (flags >> 2) & 3, flags & 3
                transit, continued = bool(flags & 0x80), bool(flags & 0x40)
                if self.identity is None and to_target and stage == 1 and not self.provider:
                    self.stage = 1
                require(stage == self.stage and stage in [0, 1] and not (transit and continued), "LOGIN_FLAGS")
                if transit:
                    require((stage, next_stage) in [(0, 1), (0, 3), (1, 3)], "LOGIN_TRANSITION")
                self.pdus += 1
                require(self.pdus <= 128, "LOGIN_PDU_LIMIT")
                identity = bytes(header[8:14]) + bytes(header[16:20])
                if self.identity is None:
                    require(to_target, "LOGIN_UNMATCHED_RESPONSE")
                    self.identity = identity
                    self.initial_tsih = int.from_bytes(header[14:16], "big")
                require(identity == self.identity, "LOGIN_IDENTITY")
                if to_target:
                    # Current product creates fresh leading sessions. Inherited session
                    # ERL needs a separate model; omitted observation is never ERL0.
                    require(header[14:16] == b"\0\0", "LOGIN_EXISTING_SESSION")
                    require(self.outstanding is None, "LOGIN_REQUEST_OVERLAP")
                    if self.response_authorization is not None:
                        require(not body and not transit and not continued, "LOGIN_CONTINUATION_ACK")
                    values = self._text(body, True, continued)
                    self._fields(values, True)
                    self.outstanding = dict(stage=stage, transit=transit, next=next_stage, continued=continued)
                    return False
                require(self.outstanding is not None, "LOGIN_UNMATCHED_RESPONSE")
                require(header[36] == header[37] == 0, "LOGIN_FAILED")
                request = self.response_authorization or self.outstanding
                if self.outstanding["continued"]:
                    require(not body and not transit and not continued, "LOGIN_REQUEST_ACK")
                values = self._text(body, False, continued)
                self._fields(values, False)
                if continued:
                    if self.response_authorization is None:
                        self.response_authorization = self.outstanding
                else:
                    if transit:
                        require(request["transit"] and next_stage == request["next"], "LOGIN_UNAUTHORIZED_TRANSITION")
                        require(self.method_offer is None or self.method is not None, "AUTH_UNRESOLVED")
                        if self.provider:
                            require(self.method == b"CHAP" and all(self.proofs.values()), "AUTH_INCOMPLETE")
                        self.stage = next_stage
                    self.response_authorization = None
                self.outstanding = None
                if transit and next_stage == 3:
                    require(self.session_type is not None and not any(self.fragments.values()), "LOGIN_INCOMPLETE")
                    if self.erl_proposer is None:
                        self.erl_level, self.erl_source = 0, "default"
                    else:
                        require(self.erl_answer is not None, "ERL_UNRESOLVED")
                    require(self.session_type != "Discovery" or self.erl_level == 0, "ERL_DISCOVERY")
                    for key in [b"HeaderDigest", b"DataDigest"]:
                        if key not in self.digest_answers:
                            require(not self.provider, "DIGEST_UNRESOLVED")
                            # RFC defaults are allowed for the legacy, non-auth-verifying observer.
                            require(key not in self.digest_offers, "DIGEST_UNRESOLVED")
                            self.digest_answers[key] = b"None"
                            self.digest_sources[key] = 'default'
                    self.ready = True
                    self.clear_sensitive()
                    return True
                return False
            except AuditError:
                self.failed = True
                self.clear_sensitive()
                raise
            except Exception:
                self.failed = True
                self.clear_sensitive()
                raise AuditError("LOGIN_PARSE") from None


def frame_layout(header, ready, header_digest, data_digest):
    require(len(header) >= 48 and header[4] == 0, "FRAME_HEADER")
    length = int.from_bytes(header[5:8], "big")
    require(length <= 16 * 1048576, "FRAME_LIMIT")
    login = header[0] & 0x3f in (3, 0x23)
    require(not login or length <= 65536, "LOGIN_TEXT_LIMIT")
    use_header = ready and header_digest and not login
    use_data = ready and data_digest and length > 0 and not login
    start = 48 + (4 if use_header else 0)
    padded = (length + 3) & ~3
    return start, length, padded, start + padded + (4 if use_data else 0), use_header, use_data


def validate_frame(frame, ready, header_digest, data_digest, crc32c):
    start, length, padded, size, use_header, use_data = frame_layout(frame, ready, header_digest, data_digest)
    require(len(frame) == size, "FRAME_LENGTH")
    if use_header:
        require(frame[48:52] == crc32c(frame[:48]), "HEADER_CRC")
    if use_data:
        require(frame[start + padded:size] == crc32c(frame[start:start + padded]), "DATA_CRC")
    return bytes(frame[start:start + length]), use_header, use_data
