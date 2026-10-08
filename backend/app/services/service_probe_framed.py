"""Bounded codecs for Wave 5C framed service identification.

Socket acquisition deliberately remains in ``service_probes``.  This module
only builds reviewed requests, determines exact response framing, and parses
compact structural evidence.  Raw responses and optional server content are
never returned by the parsers.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Callable

from app.services.service_probe_database import (
    BuiltProbe,
    DatabaseProbeDecision,
    ProbeRequestContext,
)


FRAMED_PROBE_FRAMEWORK_VERSION = "service-probe-adapter.v3"
WAVE5C_SERVICE_POLICY_VERSION = "ssc-wave5c-framed-service-identification.v1"
FRAMED_PROBE_BUILDER_VERSION = "wave5c-framed-probe-builder.v1"
MAX_FRAME_BYTES = 4096
MAX_MINECRAFT_VARINT_BYTES = 5
MAX_MINECRAFT_HOSTNAME_BYTES = 255
MAX_MINECRAFT_JSON_DEPTH = 32
MAX_MINECRAFT_JSON_NODES = 512
MAX_MINECRAFT_VERSION_NAME_BYTES = 256
MINECRAFT_DISCOVERY_PROTOCOL_VERSION = -1
PPTP_MESSAGE_BYTES = 156
PPTP_MAGIC_COOKIE = 0x1A2B3C4D
RDP_NEGOTIATION_REQUEST = bytes.fromhex(
    "03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 0b 00 00 00"
)


@dataclass(frozen=True)
class FramedProbeAdapter:
    protocol: str
    issue_key: str
    probe_type: str
    probe_version: str
    request_model: str
    parser: Callable[[bytes], DatabaseProbeDecision]
    completion: Callable[[bytes], bool]
    next_read_size: Callable[[bytes, int], int]
    fixed_payload: bytes | None = None
    request_builder: Callable[[ProbeRequestContext], BuiltProbe] | None = None
    framework_version: str = FRAMED_PROBE_FRAMEWORK_VERSION
    policy_version: str = WAVE5C_SERVICE_POLICY_VERSION
    builder_version: str = FRAMED_PROBE_BUILDER_VERSION

    def build(self, context: ProbeRequestContext) -> BuiltProbe:
        if self.request_builder is not None:
            return self.request_builder(context)
        return BuiltProbe(self.fixed_payload or b"", {})


class _CodecError(ValueError):
    def __init__(self, message: str, *, incomplete: bool = False):
        super().__init__(message)
        self.incomplete = incomplete


def encode_minecraft_varint(value: int) -> bytes:
    if isinstance(value, bool) or not -(1 << 31) <= value <= (1 << 31) - 1:
        raise ValueError("Minecraft VarInt must be a signed 32-bit integer")
    unsigned = value & 0xFFFFFFFF
    encoded = bytearray()
    while True:
        current = unsigned & 0x7F
        unsigned >>= 7
        if unsigned:
            current |= 0x80
        encoded.append(current)
        if not unsigned:
            return bytes(encoded)


def _decode_minecraft_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    unsigned = 0
    for index in range(MAX_MINECRAFT_VARINT_BYTES):
        cursor = offset + index
        if cursor >= len(data):
            raise _CodecError("Minecraft VarInt is truncated", incomplete=True)
        current = data[cursor]
        if index == 4 and (current & 0xF0):
            raise _CodecError("Minecraft VarInt overflows signed 32-bit encoding")
        unsigned |= (current & 0x7F) << (7 * index)
        if not current & 0x80:
            value = unsigned - (1 << 32) if unsigned & (1 << 31) else unsigned
            width = index + 1
            if encode_minecraft_varint(value) != data[offset:offset + width]:
                raise _CodecError("Minecraft VarInt is not minimally encoded")
            return value, width
    raise _CodecError("Minecraft VarInt exceeds five bytes")


def build_minecraft_status_request(context: ProbeRequestContext) -> BuiltProbe:
    hostname = context.declared_hostname
    if not isinstance(hostname, str) or not hostname:
        raise ValueError("Minecraft probe requires the declared target hostname")
    try:
        encoded_hostname = hostname.encode("idna").decode("ascii").encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Minecraft hostname must be IDNA/ASCII compatible") from exc
    if not 1 <= len(encoded_hostname) <= MAX_MINECRAFT_HOSTNAME_BYTES:
        raise ValueError("Minecraft hostname must contain between 1 and 255 encoded bytes")
    if isinstance(context.port, bool) or not 1 <= context.port <= 65535:
        raise ValueError("Minecraft probe port must be between 1 and 65535")

    handshake = b"".join((
        encode_minecraft_varint(0),
        encode_minecraft_varint(MINECRAFT_DISCOVERY_PROTOCOL_VERSION),
        encode_minecraft_varint(len(encoded_hostname)),
        encoded_hostname,
        context.port.to_bytes(2, "big"),
        encode_minecraft_varint(1),
    ))
    payload = encode_minecraft_varint(len(handshake)) + handshake + b"\x01\x00"
    return BuiltProbe(
        payload,
        {"declared_hostname_used": True, "declared_port_used": True},
    )


def minecraft_response_complete(data: bytes) -> bool:
    try:
        declared, width = _decode_minecraft_varint(data)
    except _CodecError as exc:
        return not exc.incomplete
    if declared < 0:
        return True
    if width + declared > MAX_FRAME_BYTES:
        return False
    return len(data) >= width + declared


def _minecraft_next_read_size(data: bytes, response_limit: int) -> int:
    remaining_limit = response_limit - len(data)
    if remaining_limit <= 0:
        return 0
    try:
        declared, width = _decode_minecraft_varint(data)
    except _CodecError as exc:
        return 1 if exc.incomplete else 1
    if declared < 0:
        return 1
    return min(512, remaining_limit, max(1, width + declared - len(data)))


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value {value!r} is prohibited")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _json_shape(value: object, *, depth: int = 1) -> tuple[int, int]:
    if depth > MAX_MINECRAFT_JSON_DEPTH:
        raise ValueError("Minecraft JSON nesting limit exceeded")
    nodes = 1
    maximum_depth = depth
    children: object
    if isinstance(value, dict):
        children = value.values()
    elif isinstance(value, list):
        children = value
    else:
        return nodes, maximum_depth
    for child in children:
        child_nodes, child_depth = _json_shape(child, depth=depth + 1)
        nodes += child_nodes
        maximum_depth = max(maximum_depth, child_depth)
        if nodes > MAX_MINECRAFT_JSON_NODES:
            raise ValueError("Minecraft JSON structural node limit exceeded")
    return nodes, maximum_depth


def parse_minecraft_response(data: bytes) -> DatabaseProbeDecision:
    declared: int | None = None
    try:
        declared, frame_width = _decode_minecraft_varint(data)
        if declared < 0 or frame_width + declared != len(data):
            raise _CodecError("Minecraft response frame length is inconsistent")
        frame = data[frame_width:]
        packet_id, packet_width = _decode_minecraft_varint(frame)
        if packet_id != 0:
            raise _CodecError("Minecraft status response packet ID is not zero")
        json_length, json_width = _decode_minecraft_varint(frame, packet_width)
        if json_length < 0:
            raise _CodecError("Minecraft JSON string length is negative")
        json_start = packet_width + json_width
        if json_start + json_length != len(frame):
            raise _CodecError("Minecraft JSON string length does not consume the frame")
        raw_json = frame[json_start:]
        text = raw_json.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        nodes, depth = _json_shape(document)
        if not isinstance(document, dict):
            raise _CodecError("Minecraft status JSON root is not an object")
        version = document.get("version")
        if not isinstance(version, dict):
            raise _CodecError("Minecraft status JSON has no version object")
        name = version.get("name")
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > MAX_MINECRAFT_VERSION_NAME_BYTES:
            raise _CodecError("Minecraft version.name is not a non-empty bounded string")
        protocol = version.get("protocol")
        if isinstance(protocol, bool) or not isinstance(protocol, int) or not -(1 << 31) <= protocol <= (1 << 31) - 1:
            raise _CodecError("Minecraft version.protocol is not a signed integer")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError, _CodecError) as exc:
        return DatabaseProbeDecision(
            "INDETERMINATE",
            str(exc),
            "malformed_minecraft_status_response",
            declared_response_bytes=declared,
        )
    return DatabaseProbeDecision(
        "MATCH",
        "received a complete Minecraft Server List Ping status response with a valid version object",
        "minecraft_status_response",
        "declared_endpoint_status_response",
        declared,
        {"frames": 1, "json_nodes": nodes, "json_depth": depth, "version_fields": len(version)},
    )


def _fixed_identity(value: bytes) -> bytes:
    if len(value) > 64:
        raise AssertionError("PPTP fixed identity exceeds 64 bytes")
    return value.ljust(64, b"\x00")


PPTP_START_CONTROL_CONNECTION_REQUEST = struct.pack(
    "!HHIHHHHIIHH64s64s",
    PPTP_MESSAGE_BYTES,
    1,
    PPTP_MAGIC_COOKIE,
    1,
    0,
    0x0100,
    0,
    0x00000003,
    0x00000003,
    0,
    1,
    _fixed_identity(b"ssc-probe.invalid"),
    _fixed_identity(b"SSC Wave5C probe"),
)


def pptp_response_complete(data: bytes) -> bool:
    if len(data) < 2:
        return False
    declared = int.from_bytes(data[:2], "big")
    if declared > MAX_FRAME_BYTES:
        return False
    return len(data) >= declared


def _two_byte_length_next_read_size(data: bytes, response_limit: int) -> int:
    remaining_limit = response_limit - len(data)
    if remaining_limit <= 0:
        return 0
    if len(data) < 2:
        return min(2 - len(data), remaining_limit)
    declared = int.from_bytes(data[:2], "big")
    return min(512, remaining_limit, max(1, declared - len(data)))


def parse_pptp_response(data: bytes) -> DatabaseProbeDecision:
    declared = int.from_bytes(data[:2], "big") if len(data) >= 2 else None
    if len(data) != PPTP_MESSAGE_BYTES or declared != PPTP_MESSAGE_BYTES:
        return DatabaseProbeDecision(
            "INDETERMINATE", "PPTP SCCRP must be exactly 156 bytes",
            "malformed_pptp_sccrp", declared_response_bytes=declared,
        )
    try:
        (
            length, message_type, cookie, control_type, reserved, protocol_version,
            result_code, error_code, framing_caps, bearer_caps, _maximum_channels,
            _firmware_revision, _hostname, _vendor,
        ) = struct.unpack("!HHIHHHBBIIHH64s64s", data)
    except struct.error as exc:
        return DatabaseProbeDecision(
            "INDETERMINATE", str(exc), "malformed_pptp_sccrp", declared_response_bytes=declared,
        )
    if length != PPTP_MESSAGE_BYTES or message_type != 1 or cookie != PPTP_MAGIC_COOKIE or control_type != 2:
        reason = "PPTP SCCRP header fields are invalid"
    elif reserved != 0:
        reason = "PPTP SCCRP reserved field is nonzero"
    elif result_code not in {1, 2, 3, 4, 5}:
        reason = "PPTP SCCRP result code is undefined"
    elif result_code == 2 and error_code not in {1, 2, 3, 4, 5, 6}:
        reason = "PPTP SCCRP general-error result has an undefined error code"
    elif result_code != 2 and error_code != 0:
        reason = "PPTP SCCRP result/error fields are inconsistent"
    elif result_code == 5 and protocol_version == 0:
        reason = "PPTP version-rejection reply advertises a zero protocol version"
    elif result_code != 5 and protocol_version != 0x0100:
        reason = "PPTP SCCRP protocol version is inconsistent"
    elif framing_caps & ~0x00000003 or bearer_caps & ~0x00000003:
        reason = "PPTP SCCRP contains undefined capability bits"
    else:
        return DatabaseProbeDecision(
            "MATCH",
            "received a complete structurally valid PPTP Start-Control-Connection-Reply",
            "pptp_start_control_connection_reply",
            "sccrq_sccrp_exchange",
            declared,
            {
                "frames": 1,
                "fields_validated": 14,
                "result_code": result_code,
                "error_code": error_code,
                "protocol_version": protocol_version,
            },
        )
    return DatabaseProbeDecision(
        "INDETERMINATE", reason, "malformed_pptp_sccrp", declared_response_bytes=declared,
    )


def rdp_response_complete(data: bytes) -> bool:
    if len(data) < 4:
        return False
    if data[0] != 3 or data[1] != 0:
        return True
    declared = int.from_bytes(data[2:4], "big")
    if declared > MAX_FRAME_BYTES:
        return False
    return len(data) >= declared


def _rdp_next_read_size(data: bytes, response_limit: int) -> int:
    remaining_limit = response_limit - len(data)
    if remaining_limit <= 0:
        return 0
    if len(data) < 4:
        return min(4 - len(data), remaining_limit)
    declared = int.from_bytes(data[2:4], "big")
    return min(512, remaining_limit, max(1, declared - len(data)))


def parse_rdp_response(data: bytes) -> DatabaseProbeDecision:
    declared = int.from_bytes(data[2:4], "big") if len(data) >= 4 else None
    if len(data) < 4 or data[0] != 3 or data[1] != 0 or declared != len(data):
        return DatabaseProbeDecision(
            "INDETERMINATE", "RDP TPKT framing is invalid",
            "malformed_rdp_negotiation", declared_response_bytes=declared,
        )
    if len(data) < 11:
        return DatabaseProbeDecision(
            "INDETERMINATE", "RDP X.224 Connection Confirm is truncated",
            "malformed_rdp_negotiation", declared_response_bytes=declared,
        )
    length_indicator = data[4]
    if 5 + length_indicator != len(data) or data[5] != 0xD0:
        reason = "RDP X.224 Connection Confirm length or type is invalid"
    elif data[6:8] != b"\x00\x00" or data[10] != 0:
        reason = "RDP X.224 Connection Confirm reference or class is invalid"
    elif length_indicator == 6 and len(data) == 11:
        return DatabaseProbeDecision(
            "INDETERMINATE",
            "bare X.224 Connection Confirm is not uniquely RDP",
            "bare_x224_connection_confirm",
            declared_response_bytes=declared,
            structural_counts={"tpkt_frames": 1, "x224_confirms": 1, "rdp_negotiation_structures": 0},
        )
    elif length_indicator != 14 or len(data) != 19:
        reason = "RDP Connection Confirm does not contain exactly one negotiation structure"
    else:
        negotiation_type = data[11]
        flags = data[12]
        negotiation_length = int.from_bytes(data[13:15], "little")
        value = int.from_bytes(data[15:19], "little")
        if negotiation_length != 8:
            reason = "RDP negotiation structure length is invalid"
        elif negotiation_type == 2:
            if flags & ~0x1F:
                reason = "RDP negotiation response contains undefined flags"
            elif value not in {0x00000001, 0x00000002, 0x00000008}:
                reason = "RDP selected protocol is inconsistent with the offered protocols"
            else:
                return DatabaseProbeDecision(
                    "MATCH",
                    "received a complete RDP X.224 Connection Confirm with a legal negotiation response",
                    "rdp_negotiation_response",
                    "connection_confirm_negotiation_reply",
                    declared,
                    {"tpkt_frames": 1, "x224_confirms": 1, "rdp_negotiation_structures": 1, "selected_protocol": value},
                )
        elif negotiation_type == 3:
            if flags != 0 or value not in set(range(1, 8)):
                reason = "RDP negotiation failure fields are invalid"
            else:
                return DatabaseProbeDecision(
                    "MATCH",
                    "received a complete RDP X.224 Connection Confirm with a legal negotiation failure",
                    "rdp_negotiation_failure",
                    "connection_confirm_negotiation_reply",
                    declared,
                    {"tpkt_frames": 1, "x224_confirms": 1, "rdp_negotiation_structures": 1, "failure_code": value},
                )
        else:
            reason = "RDP negotiation structure type is invalid"
    return DatabaseProbeDecision(
        "INDETERMINATE", reason, "malformed_rdp_negotiation", declared_response_bytes=declared,
    )


FRAMED_PROBES = {
    "minecraft": FramedProbeAdapter(
        "minecraft", "minecraft_server", "minecraft-status", "minecraft-status.v1",
        "ENDPOINT_AWARE_PAYLOAD", parse_minecraft_response, minecraft_response_complete,
        _minecraft_next_read_size, request_builder=build_minecraft_status_request,
    ),
    "pptp": FramedProbeAdapter(
        "pptp", "service_pptp", "pptp-sccrq", "pptp-sccrq.v1",
        "FIXED_PAYLOAD", parse_pptp_response, pptp_response_complete,
        _two_byte_length_next_read_size, fixed_payload=PPTP_START_CONTROL_CONNECTION_REQUEST,
    ),
    "rdp": FramedProbeAdapter(
        "rdp", "service_rdp", "rdp-negotiation", "rdp-negotiation.v1",
        "FIXED_PAYLOAD", parse_rdp_response, rdp_response_complete,
        _rdp_next_read_size, fixed_payload=RDP_NEGOTIATION_REQUEST,
    ),
}
