"""Digest policy for owned TGT fixtures; no upstream implementation copied.

Target parameter readback proves configured values. Login/digest observation
must independently prove what each actual session negotiated.
"""

import re

_CHOICES = ("None", "CRC32C")
_PARAMETERS = (("header", "HeaderDigest"), ("data", "DataDigest"))
_READBACK_LINE = re.compile(r"(HeaderDigest|DataDigest)[ \t]*=[ \t]*(None|CRC32C)")


def checked_policy(value):
    if type(value) is not dict or len(value) != 2 or set(value) != {"header", "data"}:
        raise ValueError("Invalid TGT fixture digest policy")
    if any(type(value[key]) is not str or value[key] not in _CHOICES
           for key, _ in _PARAMETERS):
        raise ValueError("Invalid TGT fixture digest policy")
    return {key: value[key] for key, _ in _PARAMETERS}


def parse_policy(value, *, legacy_single=False):
    if type(value) is not str or len(value) > 32 or type(legacy_single) is not bool:
        raise ValueError("Invalid TGT fixture digest policy")
    parts = value.split("/")
    if legacy_single and len(parts) == 1:
        parts *= 2
    if len(parts) != 2:
        raise ValueError("Invalid TGT fixture digest policy")
    return checked_policy(dict(zip(("header", "data"), parts)))


def format_policy(value):
    policy = checked_policy(value)
    return policy["header"] + "/" + policy["data"]


def configure_target(adm, value):
    """Change only the two digest parameters of this fixture's target 1."""
    policy = checked_policy(value)
    for key, parameter in _PARAMETERS:
        adm("--mode", "target", "--op", "update", "--tid", "1",
            "--name", parameter, "--value", policy[key])
    return policy


def verify_target(parameters, expected):
    expected = checked_policy(expected)
    if type(parameters) is not str or len(parameters) > 262144:
        raise ValueError("Invalid TGT fixture digest readback")
    values = {}
    for raw in parameters.split("\n"):
        line = raw.removesuffix("\r").strip(" \t")
        if not line.startswith(("HeaderDigest", "DataDigest")):
            continue
        match = _READBACK_LINE.fullmatch(line)
        if match is None or match[1] in values:
            raise ValueError("Invalid TGT fixture digest readback")
        values[match[1]] = match[2]
    if set(values) != {parameter for _, parameter in _PARAMETERS}:
        raise ValueError("Invalid TGT fixture digest readback")
    actual = {key: values[parameter] for key, parameter in _PARAMETERS}
    if actual != expected:
        raise ValueError("TGT fixture digest readback differs from requested policy")
    return actual
