"""Bounded codecs for identity-safe Wave 5B database service probes.

This module contains no socket acquisition.  It builds reviewed requests,
recognizes complete response framing, and parses only compact structural
evidence.  Raw LDAP values and Oracle descriptors are intentionally discarded.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable


DATABASE_PROBE_FRAMEWORK_VERSION = "service-probe-adapter.v3"
WAVE5B_SERVICE_POLICY_VERSION = "ssc-wave5b-database-service-identification.v1"
DATABASE_PROBE_BUILDER_VERSION = "database-probe-builder.v1"
LDAP_ROOTDSE_REQUEST = bytes.fromhex(
    "30 2a 02 01 01 63 25 04 00 0a 01 00 0a 01 00 "
    "02 01 01 02 01 01 01 01 ff 87 0b "
    "6f 62 6a 65 63 74 43 6c 61 73 73 "
    "30 05 04 03 31 2e 31"
)
ORACLE_PROBE_SERVICE = "SSC_PROBE_DO_NOT_CREATE_V1"
MAX_CODEC_BYTES = 4096
MAX_BER_DEPTH = 8


@dataclass(frozen=True)
class ProbeRequestContext:
    connect_host: str
    port: int
    attempt_nonce: bytes
    declared_hostname: str | None = None


@dataclass(frozen=True)
class BuiltProbe:
    payload: bytes
    correlation_metadata: dict[str, object]


@dataclass(frozen=True)
class DatabaseProbeDecision:
    outcome: str
    reason: str
    response_class: str | None = None
    correlation_result: str = "not_available"
    declared_response_bytes: int | None = None
    structural_counts: dict[str, int] | None = None

    @property
    def matched(self) -> bool | None:
        return {"MATCH": True, "NO_MATCH": False}.get(self.outcome)


@dataclass(frozen=True)
class DatabaseProbeAdapter:
    protocol: str
    issue_key: str
    probe_type: str
    probe_version: str
    request_model: str
    parser: Callable[[bytes], DatabaseProbeDecision]
    completion: Callable[[bytes], bool]
    fixed_payload: bytes | None = None
    request_builder: Callable[[ProbeRequestContext], BuiltProbe] | None = None
    framework_version: str = DATABASE_PROBE_FRAMEWORK_VERSION
    policy_version: str = WAVE5B_SERVICE_POLICY_VERSION
    builder_version: str = DATABASE_PROBE_BUILDER_VERSION

    def build(self, context: ProbeRequestContext) -> BuiltProbe:
        if self.request_builder is not None:
            return self.request_builder(context)
        return BuiltProbe(self.fixed_payload or b"", {})


class _BERError(ValueError):
    def __init__(self, message: str, *, incomplete: bool = False):
        super().__init__(message)
        self.incomplete = incomplete


@dataclass(frozen=True)
class _TLV:
    tag: int
    start: int
    value_start: int
    end: int


def _tlv(data: bytes, offset: int, *, depth: int = 0) -> _TLV:
    if depth > MAX_BER_DEPTH:
        raise _BERError("BER nesting limit exceeded")
    if offset >= len(data):
        raise _BERError("BER tag is truncated", incomplete=True)
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise _BERError("high-tag-number BER is unsupported")
    if offset + 1 >= len(data):
        raise _BERError("BER length is truncated", incomplete=True)
    first = data[offset + 1]
    cursor = offset + 2
    if first == 0x80:
        raise _BERError("indefinite BER length is prohibited")
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 2:
            raise _BERError("BER length width is invalid")
        if cursor + count > len(data):
            raise _BERError("BER long length is truncated", incomplete=True)
        raw = data[cursor:cursor + count]
        if raw[0] == 0 or (count == 1 and raw[0] < 0x80):
            raise _BERError("BER length is not minimally encoded")
        length = int.from_bytes(raw, "big")
        cursor += count
    else:
        length = first
    if length > MAX_CODEC_BYTES:
        # Acquisition must exhaust its configured ceiling so the persisted
        # completion reason is response_limit, never a parser-shaped negative.
        raise _BERError("BER value exceeds the response ceiling", incomplete=True)
    end = cursor + length
    if end > len(data):
        raise _BERError("BER value is truncated", incomplete=True)
    return _TLV(tag, offset, cursor, end)


def _children(data: bytes, parent: _TLV, *, depth: int) -> list[_TLV]:
    result: list[_TLV] = []
    cursor = parent.value_start
    while cursor < parent.end:
        child = _tlv(data, cursor, depth=depth)
        if child.end > parent.end:
            raise _BERError("BER child exceeds parent length")
        result.append(child)
        cursor = child.end
    if cursor != parent.end:
        raise _BERError("BER child framing is inconsistent")
    return result


def _integer(data: bytes, value: _TLV, *, tag: int) -> int:
    raw = data[value.value_start:value.end]
    if value.tag != tag or not raw or len(raw) > 4:
        raise _BERError("LDAP integer field is invalid")
    if len(raw) > 1 and ((raw[0] == 0 and raw[1] < 0x80) or (raw[0] == 0xFF and raw[1] >= 0x80)):
        raise _BERError("LDAP integer is not minimally encoded")
    return int.from_bytes(raw, "big", signed=True)


def _validate_controls(data: bytes, controls: _TLV) -> None:
    if controls.tag != 0xA0:
        raise _BERError("LDAP trailing field is not controls")
    for control in _children(data, controls, depth=3):
        if control.tag != 0x30:
            raise _BERError("LDAP control is not a sequence")
        fields = _children(data, control, depth=4)
        if not 1 <= len(fields) <= 3 or fields[0].tag != 0x04 or fields[0].end == fields[0].value_start:
            raise _BERError("LDAP control OID is invalid")
        index = 1
        if index < len(fields) and fields[index].tag == 0x01:
            boolean = data[fields[index].value_start:fields[index].end]
            if len(boolean) != 1 or boolean[0] not in {0x00, 0xFF}:
                raise _BERError("LDAP control criticality is invalid")
            index += 1
        if index < len(fields):
            if fields[index].tag != 0x04:
                raise _BERError("LDAP control value is invalid")
            index += 1
        if index != len(fields):
            raise _BERError("LDAP control has extra fields")


def _ldap_message(data: bytes, offset: int) -> tuple[_TLV, int, _TLV]:
    message = _tlv(data, offset)
    if message.tag != 0x30:
        raise _BERError("LDAPMessage is not a sequence")
    fields = _children(data, message, depth=1)
    if len(fields) not in {2, 3}:
        raise _BERError("LDAPMessage has an invalid field count")
    message_id = _integer(data, fields[0], tag=0x02)
    if fields[2:] and fields[2].tag != 0xA0:
        raise _BERError("LDAPMessage trailing field is invalid")
    if len(fields) == 3:
        _validate_controls(data, fields[2])
    return message, message_id, fields[1]


def _validate_entry(data: bytes, operation: _TLV) -> None:
    fields = _children(data, operation, depth=2)
    if len(fields) != 2 or fields[0].tag != 0x04 or fields[1].tag != 0x30:
        raise _BERError("SearchResultEntry fields are invalid")
    for attribute in _children(data, fields[1], depth=3):
        if attribute.tag != 0x30:
            raise _BERError("LDAP partial attribute is invalid")
        parts = _children(data, attribute, depth=4)
        if len(parts) != 2 or parts[0].tag != 0x04 or parts[1].tag != 0x31:
            raise _BERError("LDAP partial attribute fields are invalid")
        for value in _children(data, parts[1], depth=5):
            if value.tag != 0x04:
                raise _BERError("LDAP attribute value is invalid")


def _validate_reference(data: bytes, operation: _TLV) -> None:
    uris = _children(data, operation, depth=2)
    if not uris or any(uri.tag != 0x04 or uri.end == uri.value_start for uri in uris):
        raise _BERError("SearchResultReference is invalid")


_LDAP_RESULT_CODES = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14,
    16, 17, 18, 19, 20, 21, 32, 33, 34, 36, 48, 49, 50, 51,
    52, 53, 54, 64, 65, 66, 67, 68, 69, 71, 80,
}


def _validate_ldap_result(data: bytes, operation: _TLV) -> int:
    fields = _children(data, operation, depth=2)
    if len(fields) not in {3, 4}:
        raise _BERError("LDAPResult has an invalid field count")
    result_code = _integer(data, fields[0], tag=0x0A)
    if result_code not in _LDAP_RESULT_CODES or fields[1].tag != 0x04 or fields[2].tag != 0x04:
        raise _BERError("LDAPResult fields are invalid")
    if len(fields) == 4:
        referral = fields[3]
        if referral.tag != 0xA3:
            raise _BERError("LDAPResult trailing field is invalid")
        uris = _children(data, referral, depth=3)
        if not uris or any(uri.tag != 0x04 or uri.end == uri.value_start for uri in uris):
            raise _BERError("LDAPResult referral is invalid")
    return result_code


def ldap_response_complete(data: bytes) -> bool:
    if not data:
        return False
    cursor = 0
    try:
        while cursor < len(data):
            message, _, operation = _ldap_message(data, cursor)
            cursor = message.end
            if operation.tag == 0x65:
                return True
            if operation.tag not in {0x64, 0x73}:
                return True
    except _BERError as exc:
        return not exc.incomplete
    return False


def parse_ldap_response(data: bytes) -> DatabaseProbeDecision:
    cursor = entries = references = messages = 0
    try:
        while cursor < len(data):
            message, message_id, operation = _ldap_message(data, cursor)
            messages += 1
            cursor = message.end
            if message_id != 1:
                raise _BERError("LDAP response message ID does not correlate")
            if operation.tag == 0x64:
                _validate_entry(data, operation)
                entries += 1
            elif operation.tag == 0x73:
                _validate_reference(data, operation)
                references += 1
            elif operation.tag == 0x65:
                result_code = _validate_ldap_result(data, operation)
                if cursor != len(data):
                    raise _BERError("LDAP data follows SearchResultDone")
                return DatabaseProbeDecision(
                    "MATCH",
                    "received a complete correlated LDAP search response ending in SearchResultDone",
                    "ldap_search_result_done",
                    "message_id_1_matched",
                    len(data),
                    {"messages": messages, "entries": entries, "references": references, "result_code": result_code},
                )
            else:
                raise _BERError("LDAP search response operation order is invalid")
    except _BERError as exc:
        return DatabaseProbeDecision("INDETERMINATE", str(exc), "malformed_ldap_response")
    return DatabaseProbeDecision("INDETERMINATE", "LDAP search response is missing SearchResultDone", "incomplete_ldap_sequence")


def build_oracle_connect(context: ProbeRequestContext) -> BuiltProbe:
    try:
        host = ipaddress.ip_address(context.connect_host).compressed
    except ValueError as exc:
        raise ValueError("Oracle probe requires a canonical pinned numeric IP") from exc
    if host != context.connect_host:
        raise ValueError("Oracle probe connect_host must be the canonical pinned numeric IP")
    if isinstance(context.port, bool) or not 1 <= context.port <= 65535:
        raise ValueError("Oracle probe port must be between 1 and 65535")
    descriptor = (
        f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={context.port}))"
        f"(CONNECT_DATA=(SERVICE_NAME={ORACLE_PROBE_SERVICE})))"
    ).encode("ascii")
    if len(descriptor) > 230:
        raise ValueError("Oracle CONNECT descriptor exceeds the reviewed inline bound")
    body = bytearray()
    body.extend((319).to_bytes(2, "big"))
    body.extend((300).to_bytes(2, "big"))
    body.extend((0x0001).to_bytes(2, "big"))
    body.extend((8192).to_bytes(2, "big"))
    body.extend((8192).to_bytes(2, "big"))
    body.extend((0x4F98).to_bytes(2, "big"))
    body.extend((0).to_bytes(2, "big"))
    body.extend((1).to_bytes(2, "big"))
    body.extend(len(descriptor).to_bytes(2, "big"))
    body.extend((74).to_bytes(2, "big"))
    body.extend((0).to_bytes(4, "big"))
    body.extend(b"\x84\x84")
    body.extend(bytes(24))
    body.extend((8192).to_bytes(4, "big"))
    body.extend((8192).to_bytes(4, "big"))
    body.extend((0).to_bytes(4, "big"))
    body.extend((0).to_bytes(4, "big"))
    if len(body) != 66:
        raise AssertionError("Oracle CONNECT fixed body must end at offset 74")
    packet_length = 8 + len(body) + len(descriptor)
    header = packet_length.to_bytes(2, "big") + b"\x00\x00\x01\x00\x00\x00"
    return BuiltProbe(
        header + bytes(body) + descriptor,
        {"endpoint_correlation": "canonical_numeric_ip_and_port"},
    )


def oracle_response_complete(data: bytes) -> bool:
    if len(data) < 2:
        return False
    declared = int.from_bytes(data[:2], "big")
    if declared < 8:
        return True
    if declared > MAX_CODEC_BYTES:
        return False
    return len(data) >= declared


def _printable_descriptor(value: bytes) -> bool:
    return bool(value) and value.startswith(b"(") and all(byte == 0 or 0x20 <= byte <= 0x7E for byte in value)


def parse_oracle_response(data: bytes) -> DatabaseProbeDecision:
    if len(data) < 8:
        return DatabaseProbeDecision("INDETERMINATE", "TNS header is truncated", "malformed_tns_response")
    declared = int.from_bytes(data[:2], "big")
    if declared < 8 or declared != len(data) or data[2:4] != b"\x00\x00" or data[6:8] != b"\x00\x00":
        return DatabaseProbeDecision("INDETERMINATE", "TNS packet framing is invalid", "malformed_tns_response", declared_response_bytes=declared)
    packet_type = data[4]
    body = data[8:]
    if packet_type == 2:
        # Current ACCEPT layout contains version/options, ten fixed bytes,
        # flags, nine fixed bytes and a large SDU.  Older short ACCEPT packets
        # are not accepted until separately reviewed.
        if len(body) < 28:
            return DatabaseProbeDecision("INDETERMINATE", "TNS ACCEPT body is truncated", "malformed_tns_accept", declared_response_bytes=declared)
        version = int.from_bytes(body[:2], "big")
        sdu = int.from_bytes(body[24:28], "big")
        if not 300 <= version <= 0xFFFF or not 512 <= sdu <= 0x7FFFFFFF:
            return DatabaseProbeDecision("INDETERMINATE", "TNS ACCEPT fields are invalid", "malformed_tns_accept", declared_response_bytes=declared)
        response_class = "tns_accept"
        counts = {"packets": 1, "accept_fields_validated": 2}
    elif packet_type == 4:
        if len(body) < 5:
            return DatabaseProbeDecision("INDETERMINATE", "TNS REFUSE body is truncated", "malformed_tns_refuse", declared_response_bytes=declared)
        message_length = int.from_bytes(body[2:4], "big")
        message = body[4:]
        if message_length != len(message) or not _printable_descriptor(message) or b"(ERR=" not in message:
            return DatabaseProbeDecision("INDETERMINATE", "TNS REFUSE fields are invalid", "malformed_tns_refuse", declared_response_bytes=declared)
        response_class = "tns_refuse"
        counts = {"packets": 1, "refuse_reason_bytes": 2}
    elif packet_type == 5:
        if len(body) < 3:
            return DatabaseProbeDecision("INDETERMINATE", "TNS REDIRECT body is truncated", "malformed_tns_redirect", declared_response_bytes=declared)
        redirect_length = int.from_bytes(body[:2], "big")
        redirect = body[2:]
        if redirect_length != len(redirect) or not _printable_descriptor(redirect):
            return DatabaseProbeDecision("INDETERMINATE", "TNS REDIRECT fields are invalid", "malformed_tns_redirect", declared_response_bytes=declared)
        response_class = "tns_redirect"
        counts = {"packets": 1, "redirects_followed": 0}
    else:
        return DatabaseProbeDecision("INDETERMINATE", "TNS packet type is not an identification response", "unsupported_tns_packet", declared_response_bytes=declared)
    return DatabaseProbeDecision(
        "MATCH",
        "received one complete structurally valid Oracle Net identification response",
        response_class,
        "declared_endpoint_response",
        declared,
        counts,
    )


DATABASE_PROBES = {
    "ldap": DatabaseProbeAdapter(
        "ldap", "service_ldap", "ldap-rootdse-search", "1.0",
        "CORRELATED_FIXED_PAYLOAD", parse_ldap_response, ldap_response_complete,
        fixed_payload=LDAP_ROOTDSE_REQUEST,
    ),
    "oracle": DatabaseProbeAdapter(
        "oracle", "service_oracle_db", "oracle-tns-connect", "1.0",
        "ENDPOINT_AWARE_PAYLOAD", parse_oracle_response, oracle_response_complete,
        request_builder=build_oracle_connect,
    ),
}
