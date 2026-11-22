"""Numeric SCSI completion metadata shared by passive fixture observers.

No payload, authentication bytes or retry policy is exported here. The TGT
CHECK CONDITION/zero ExpDataSN quirk is a failed completion, never a GOOD read.
"""

MAXIMUM_SENSE_BYTES = 263
LOGIN_KEYS = ('connectionID', 'sessionType', 'complete', 'fullFeaturePhase', 'initialTSIH',
              'errorRecoveryLevel', 'errorRecoveryLevelSource',
              'errorRecoveryLevelOffer', 'errorRecoveryLevelResponse',
              'errorRecoveryLevelProposer')


def integer(value, maximum=0xffffffff):
    assert type(value) is int and 0 <= value <= maximum, 'Invalid numeric metadata'
    return value


def validate_login_binding(value):
    assert type(value) is dict and set(value) == set(LOGIN_KEYS), 'Incomplete login binding'
    assert integer(value['connectionID']) > 0
    assert value['complete'] is True and value['fullFeaturePhase'] is True
    assert integer(value['initialTSIH'], 65535) == 0, 'Unproven leading login'
    assert value['sessionType'] in ('Normal', 'Discovery')
    level = integer(value['errorRecoveryLevel'], 2)
    source, offer, answer, proposer = (value[k] for k in
        ('errorRecoveryLevelSource', 'errorRecoveryLevelOffer',
         'errorRecoveryLevelResponse', 'errorRecoveryLevelProposer'))
    if source == 'default':
        assert offer is answer is proposer is None and level == 0
    else:
        assert proposer in ('initiator', 'target')
        integer(offer, 2)
        if source == 'negotiated':
            assert integer(answer, 2) <= offer and level == answer
        else:
            assert source == 'rejected-default' and answer == 'Reject' and level == 0
    assert value['sessionType'] != 'Discovery' or level == 0


def login_binding(summary, connection_id):
    if summary is None:
        return None  # Synthetic post-login tests cannot establish an ERL0 exception.
    assert type(summary) is dict and summary['failed'] is False
    value = {k: summary[k] for k in LOGIN_KEYS}
    validate_login_binding(value)
    assert value['connectionID'] == integer(connection_id)
    return value


def validate_sense(value):
    assert type(value) is dict and set(value) == {
        'responseCode', 'deferred', 'senseBytes', 'additionalLength', 'senseKey', 'asc', 'ascq'}
    code = integer(value['responseCode'], 255)
    assert code in (0x70, 0x71, 0x72, 0x73)
    assert type(value['deferred']) is bool and value['deferred'] == (code in (0x71, 0x73))
    integer(value['senseKey'], 15);integer(value['asc'], 255);integer(value['ascq'], 255)
    size, additional = integer(value['senseBytes'], MAXIMUM_SENSE_BYTES), integer(value['additionalLength'], 255)
    assert 8 + additional <= size
    assert code not in (0x70, 0x71) or (size >= 14 and additional >= 6)


def sense_metadata(body):
    assert 2 <= len(body) <= MAXIMUM_SENSE_BYTES + 2, 'Sense segment bound'
    size = int.from_bytes(body[:2], 'big')
    assert size == len(body) - 2 and size >= 8, 'Incomplete sense segment'
    sense = body[2:]
    assert 8 + sense[7] <= size, 'Truncated additional sense'
    code = sense[0] & 0x7f
    assert code in (0x70, 0x71, 0x72, 0x73), 'Unknown sense format'
    if code in (0x70, 0x71):
        assert size >= 14 and sense[7] >= 6, 'Truncated fixed sense'
        key, asc, ascq = sense[2] & 15, sense[12], sense[13]
    else:
        key, asc, ascq = sense[1] & 15, sense[2], sense[3]
    value = dict(responseCode=code, deferred=code in (0x71, 0x73), senseBytes=size,
                 additionalLength=sense[7], senseKey=key, asc=asc, ascq=ascq)
    validate_sense(value)
    return value


def validate_completion(value, record):
    """Recompute the narrow exception from raw metadata and observed login."""
    op = integer(value['responseOpcode'], 63)
    flags, status = integer(value['responseFlags'], 255), integer(value['scsiStatus'], 255)
    assert status in (0, 2, 4, 8, 0x10, 0x14, 0x18, 0x22, 0x28, 0x30, 0x40)
    assert op in (0x21, 0x25) and flags & 0x80, 'Completion without final'
    assert not flags & ~(0x86 if op == 0x21 else 0x87), 'Unsupported completion flags'
    assert integer(value['responseCode'], 255) == 0
    sn, residual = integer(value['responseDataSN']), integer(value['residualCount'])
    count, received = integer(record['dataInPDUs']), integer(record['readBytes'])
    allocation, direction = integer(record['transferBytes']), integer(record['directionFlags'], 0x60)
    assert direction in (0, 0x20, 0x40) and type(record['lastDataFinal']) is bool
    assert received <= allocation and (not count or direction == 0x40)
    assert count or received == 0
    exception = False
    if op == 0x21:
        assert not count or record['lastDataFinal'], 'Response before final sequence'
        if sn != count:
            binding = record.get('loginProof')
            validate_login_binding(binding)
            assert status == 2 and sn == 0 and binding['sessionType'] == 'Normal'
            assert binding['errorRecoveryLevel'] == 0, 'Wrong ExpDataSN outside proven ERL0'
            exception = True
    else:
        assert flags & 1 and status == 0
        assert count > 0 and sn == count - 1
    if status == 2:
        validate_sense(value['sense'])
    else:
        assert value['sense'] is None
    residual_flags = flags & 6
    assert residual_flags in (0, 2), 'Unsupported residual flags'
    assert (0 < residual <= allocation) if residual_flags else residual == 0
    if status == 0 and direction == 0x40:
        assert received + residual == allocation, 'Incomplete successful read'
    return exception


def completion(header, body, record):
    assert len(header) == 48 and int.from_bytes(header[5:8], 'big') == len(body)
    op = header[0] & 63
    result = dict(responseOpcode=op, responseFlags=header[1], scsiStatus=header[3],
                  responseCode=header[2] if op == 0x21 else 0,
                  responseDataSN=int.from_bytes(header[36:40], 'big'),
                  residualCount=int.from_bytes(header[44:48], 'big') if header[1] & 6 else 0,
                  sense=None)
    if op == 0x21:
        if header[3] == 2:
            result['sense'] = sense_metadata(body)
        else:
            assert not body, 'Unexpected response segment'
    result['expDataSNException'] = validate_completion(result, record)
    return result
