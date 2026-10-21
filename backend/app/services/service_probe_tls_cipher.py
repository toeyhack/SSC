"""Bounded provider-independent TLS weak-cipher negotiation primitives.

The catalog is a reviewed, immutable expansion of SecurityScorecard's public
2026-08-11 weak-cipher criteria over the IANA TLS Cipher Suites registry.  It
is intentionally independent of the host OpenSSL build.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import struct
from dataclasses import dataclass
from typing import Iterable


ISSUE_KEY = "tls_weak_cipher"
PROBE_VERSION = "tls-raw-clienthello.v1"
METHOD_VERSION = "ssc-wave2-tls-weak-cipher-observation.v2"
POLICY_VERSION = "ssc-wave2-tls-weak-cipher-policy.v2"
CATALOG_VERSION = "ssc-tls-weak-cipher-catalog.2026-08-11.v1"

TLS_VERSIONS = {"TLSv1.0": 0x0301, "TLSv1.1": 0x0302, "TLSv1.2": 0x0303}
MAX_CLIENT_HELLO_BYTES = 1024
MAX_RESPONSE_BYTES = 4096
MAX_TLS_RECORDS = 8
MAX_HANDSHAKE_MESSAGES = 8
MAX_PARTITIONS = 3
MAX_ATTEMPTS_PER_ENDPOINT = 4
ATTEMPT_TIMEOUT_SECONDS = 3.0
ENDPOINT_DEADLINE_SECONDS = 12.0
TOTAL_DEADLINE_SECONDS = 36.0

TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF
TLS_FALLBACK_SCSV = 0x5600

# Static IANA identities reviewed on 2026-10-21.  Membership is the union of
# the frozen strength, SSC family-name, and SSC exact-name sets below.
_IANA_SUITES = (
    (0x0001, "TLS_RSA_WITH_NULL_MD5"),
    (0x0002, "TLS_RSA_WITH_NULL_SHA"),
    (0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
    (0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
    (0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    (0x0009, "TLS_RSA_WITH_DES_CBC_SHA"),
    (0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
    (0x000C, "TLS_DH_DSS_WITH_DES_CBC_SHA"),
    (0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"),
    (0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    (0x000F, "TLS_DH_RSA_WITH_DES_CBC_SHA"),
    (0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
    (0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA"),
    (0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
    (0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    (0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
    (0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"),
    (0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"),
    (0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"),
    (0x001A, "TLS_DH_anon_WITH_DES_CBC_SHA"),
    (0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"),
    (0x001E, "TLS_KRB5_WITH_DES_CBC_SHA"),
    (0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"),
    (0x0020, "TLS_KRB5_WITH_RC4_128_SHA"),
    (0x0022, "TLS_KRB5_WITH_DES_CBC_MD5"),
    (0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"),
    (0x0024, "TLS_KRB5_WITH_RC4_128_MD5"),
    (0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5"),
    (0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"),
    (0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"),
    (0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"),
    (0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"),
    (0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"),
    (0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"),
    (0x002C, "TLS_PSK_WITH_NULL_SHA"),
    (0x002D, "TLS_DHE_PSK_WITH_NULL_SHA"),
    (0x002E, "TLS_RSA_PSK_WITH_NULL_SHA"),
    (0x003B, "TLS_RSA_WITH_NULL_SHA256"),
    (0x008A, "TLS_PSK_WITH_RC4_128_SHA"),
    (0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA"),
    (0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA"),
    (0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"),
    (0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA"),
    (0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"),
    (0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"),
    (0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"),
    (0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
    (0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
    (0x00B0, "TLS_PSK_WITH_NULL_SHA256"),
    (0x00B1, "TLS_PSK_WITH_NULL_SHA384"),
    (0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256"),
    (0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384"),
    (0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256"),
    (0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384"),
    (0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"),
    (0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"),
    (0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
    (0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
    (0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA"),
    (0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA"),
    (0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
    (0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
    (0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC015, "TLS_ECDH_anon_WITH_NULL_SHA"),
    (0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA"),
    (0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"),
    (0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"),
    (0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"),
    (0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    (0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"),
    (0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"),
    (0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA"),
    (0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256"),
    (0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384"),
    (0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"),
    (0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"),
    (0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"),
    (0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"),
    (0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"),
    (0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8"),
    (0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8"),
)

_EFFECTIVE_STRENGTH_BITS = {
    0x0001: 0, 0x0002: 0, 0x0003: 40, 0x0006: 40, 0x0008: 40,
    0x0009: 56, 0x000A: 112, 0x000B: 40, 0x000C: 56, 0x000D: 112,
    0x000E: 40, 0x000F: 56, 0x0010: 112, 0x0011: 40, 0x0012: 56,
    0x0013: 112, 0x0014: 40, 0x0015: 56, 0x0016: 112, 0x0017: 40,
    0x0019: 40, 0x001A: 56, 0x001B: 112, 0x001E: 56, 0x001F: 112,
    0x0022: 56, 0x0023: 112, 0x0026: 40, 0x0027: 40, 0x0028: 40,
    0x0029: 40, 0x002A: 40, 0x002B: 40, 0x002C: 0, 0x002D: 0,
    0x002E: 0, 0x003B: 0, 0x008B: 112, 0x008F: 112, 0x0093: 112,
    0x00B0: 0, 0x00B1: 0, 0x00B4: 0, 0x00B5: 0, 0x00B8: 0,
    0x00B9: 0, 0xC001: 0, 0xC003: 112, 0xC006: 0, 0xC008: 112,
    0xC00B: 0, 0xC00D: 112, 0xC010: 0, 0xC012: 112, 0xC015: 0,
    0xC017: 112, 0xC01A: 112, 0xC01B: 112, 0xC01C: 112,
    0xC034: 112, 0xC039: 0, 0xC03A: 0, 0xC03B: 0,
}

_NAME_FAMILY_IDS = frozenset({
    0x0001, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x000B, 0x000E,
    0x0011, 0x0014, 0x0017, 0x0018, 0x0019, 0x0020, 0x0022, 0x0023,
    0x0024, 0x0025, 0x0027, 0x0028, 0x0029, 0x002A, 0x002B, 0x008A,
    0x008E, 0x0092, 0xC002, 0xC007, 0xC00C, 0xC011, 0xC016, 0xC033,
})

_EXACT_NAME_IDS = frozenset({
    0x00A2, 0x00A3, 0xC056, 0xC057, 0xC080, 0x0096,
    0x009A, 0xC072, 0xC073, 0xC023, 0xC0A2, 0xC0A3,
})

_TLS12_ONLY_IDS = frozenset({
    0x003B, 0x00A2, 0x00A3, 0x00B0, 0x00B1, 0x00B4, 0x00B5,
    0x00B8, 0x00B9, 0xC023, 0xC03A, 0xC03B, 0xC056, 0xC057,
    0xC072, 0xC073, 0xC080, 0xC0A2, 0xC0A3,
})

STRONG_CONTROL_SUITES = (
    0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0x009E,  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
)


@dataclass(frozen=True)
class CipherSuiteEntry:
    suite_id: int
    canonical_name: str
    tls_versions: tuple[str, ...]
    reasons: tuple[str, ...]
    effective_strength_bits: int | None

    def canonical_record(self) -> dict[str, object]:
        return {
            "id": self.suite_id,
            "canonical_name": self.canonical_name,
            "tls_versions": list(self.tls_versions),
            "reasons": list(self.reasons),
            "effective_strength_bits": self.effective_strength_bits,
        }


def _build_catalog() -> tuple[CipherSuiteEntry, ...]:
    catalog = []
    for suite_id, name in _IANA_SUITES:
        reasons = []
        if suite_id in _EFFECTIVE_STRENGTH_BITS:
            reasons.append("effective_strength_below_128")
        if suite_id in _NAME_FAMILY_IDS:
            reasons.append("ssc_disclosed_name_family")
        if suite_id in _EXACT_NAME_IDS:
            reasons.append("ssc_exact_suite")
        versions = ("TLSv1.2",) if suite_id in _TLS12_ONLY_IDS else tuple(TLS_VERSIONS)
        catalog.append(CipherSuiteEntry(
            suite_id=suite_id,
            canonical_name=name,
            tls_versions=versions,
            reasons=tuple(reasons),
            effective_strength_bits=_EFFECTIVE_STRENGTH_BITS.get(suite_id),
        ))
    return tuple(catalog)


SSC_WEAK_CIPHER_CATALOG = _build_catalog()
SSC_WEAK_CIPHER_BY_ID = {entry.suite_id: entry for entry in SSC_WEAK_CIPHER_CATALOG}
_CATALOG_JSON = json.dumps(
    [entry.canonical_record() for entry in SSC_WEAK_CIPHER_CATALOG],
    sort_keys=True, separators=(",", ":"), ensure_ascii=True,
)
CATALOG_SHA256 = hashlib.sha256(_CATALOG_JSON.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class ClientHelloPartition:
    partition_id: str
    tls_version: str
    offered_suite_ids: tuple[int, ...]
    request_bytes: bytes
    suite_class: str


@dataclass(frozen=True)
class ParsedTLSResponse:
    terminal: bool
    matched: bool | None
    outcome: str
    reason_code: str
    selected_suite_id: int | None = None
    selected_suite_class: str | None = None
    server_hello_valid: bool = False
    alert_class: str | None = None
    definitive_rejection: bool = False
    record_count: int = 0
    handshake_message_count: int = 0


def prohibited_suite_ids(tls_version: str) -> tuple[int, ...]:
    if tls_version not in TLS_VERSIONS:
        raise ValueError(f"unsupported TLS partition: {tls_version}")
    return tuple(entry.suite_id for entry in SSC_WEAK_CIPHER_CATALOG if tls_version in entry.tls_versions)


def build_prohibited_partitions(server_name: str) -> tuple[ClientHelloPartition, ...]:
    partitions = []
    for tls_version in TLS_VERSIONS:
        offered = prohibited_suite_ids(tls_version)
        partitions.append(ClientHelloPartition(
            partition_id=tls_version.casefold().replace("tlsv", "tls").replace(".", ""),
            tls_version=tls_version,
            offered_suite_ids=offered,
            request_bytes=build_client_hello(tls_version, offered, server_name),
            suite_class="ssc_prohibited",
        ))
    return tuple(partitions)


def build_strong_control(server_name: str) -> ClientHelloPartition:
    return ClientHelloPartition(
        partition_id="tls12_strong_control",
        tls_version="TLSv1.2",
        offered_suite_ids=STRONG_CONTROL_SUITES,
        request_bytes=build_client_hello("TLSv1.2", STRONG_CONTROL_SUITES, server_name),
        suite_class="strong_control",
    )


def build_client_hello(
    tls_version: str,
    suite_ids: Iterable[int],
    server_name: str,
    *,
    random_bytes: bytes | None = None,
) -> bytes:
    if tls_version not in TLS_VERSIONS:
        raise ValueError(f"unsupported TLS version: {tls_version}")
    suites = tuple(suite_ids)
    if not suites or len(suites) != len(set(suites)):
        raise ValueError("cipher suite list must be non-empty and unique")
    if any(not 0 <= suite_id <= 0xFFFF for suite_id in suites):
        raise ValueError("cipher suite ID is outside uint16")
    client_random = random_bytes if random_bytes is not None else secrets.token_bytes(32)
    if len(client_random) != 32:
        raise ValueError("ClientHello random must be exactly 32 bytes")

    offered = suites + (TLS_EMPTY_RENEGOTIATION_INFO_SCSV,)
    cipher_bytes = b"".join(struct.pack("!H", suite_id) for suite_id in offered)
    extensions = _client_extensions(tls_version, server_name)
    body = (
        struct.pack("!H", TLS_VERSIONS[tls_version])
        + client_random
        + b"\x00"  # empty legacy_session_id
        + struct.pack("!H", len(cipher_bytes)) + cipher_bytes
        + b"\x01\x00"  # one compression method: null
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    if len(record) > MAX_CLIENT_HELLO_BYTES:
        raise ValueError("ClientHello exceeds reviewed 1024-byte bound")
    return record


def _client_extensions(tls_version: str, server_name: str) -> bytes:
    extensions = []
    if server_name and not _is_numeric_address(server_name):
        hostname = server_name.encode("idna")
        if not hostname or len(hostname) > 253:
            raise ValueError("SNI hostname is invalid")
        name = b"\x00" + struct.pack("!H", len(hostname)) + hostname
        extensions.append(_extension(0, struct.pack("!H", len(name)) + name))

    # ECDHE suites in every legacy partition require curve and point-format
    # capabilities.  FFDHE groups cover modern finite-field DHE servers.
    groups = (23, 24, 25, 29, 256, 257, 258)
    group_bytes = b"".join(struct.pack("!H", value) for value in groups)
    extensions.append(_extension(10, struct.pack("!H", len(group_bytes)) + group_bytes))
    extensions.append(_extension(11, b"\x01\x00"))

    if tls_version == "TLSv1.2":
        algorithms = (0x0201, 0x0202, 0x0203, 0x0401, 0x0402, 0x0403, 0x0501, 0x0503, 0x0601, 0x0603)
        algorithm_bytes = b"".join(struct.pack("!H", value) for value in algorithms)
        extensions.append(_extension(13, struct.pack("!H", len(algorithm_bytes)) + algorithm_bytes))
    return b"".join(extensions)


def _extension(extension_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", extension_type, len(data)) + data


def _is_numeric_address(value: str) -> bool:
    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def parse_tls_response(
    data: bytes,
    partition: ClientHelloPartition,
    *,
    eof: bool = False,
    response_limit_exceeded: bool = False,
) -> ParsedTLSResponse:
    if response_limit_exceeded or len(data) > MAX_RESPONSE_BYTES:
        return _indeterminate("response_limit_exceeded")
    cursor = 0
    records = 0
    handshake = bytearray()
    messages = 0
    while cursor < len(data):
        if len(data) - cursor < 5:
            return _indeterminate("truncated_record_header", records, messages) if eof else _need_more(records, messages)
        content_type, major, minor, length = struct.unpack("!BBBH", data[cursor:cursor + 5])
        if major != 3 or minor > 3 or length > (1 << 14) + 2048:
            return _indeterminate("invalid_record_header", records, messages)
        if len(data) - cursor - 5 < length:
            return _indeterminate("truncated_record", records, messages) if eof else _need_more(records, messages)
        fragment = data[cursor + 5:cursor + 5 + length]
        cursor += 5 + length
        records += 1
        if records > MAX_TLS_RECORDS:
            return _indeterminate("record_limit_exceeded", records, messages)
        if content_type == 21:
            if len(fragment) != 2:
                return _indeterminate("malformed_alert", records, messages)
            level, description = fragment
            if level != 2:
                return _indeterminate("non_fatal_alert", records, messages, alert_class=_alert_name(description))
            alert_name = _alert_name(description)
            definitive = description in {40, 70, 71}
            return ParsedTLSResponse(
                terminal=True, matched=False if definitive else None,
                outcome="REJECTION_CANDIDATE" if definitive else "INDETERMINATE",
                reason_code=f"fatal_{alert_name}", alert_class=alert_name,
                definitive_rejection=definitive, record_count=records,
                handshake_message_count=messages,
            )
        if content_type != 22:
            return _indeterminate("unexpected_record_type", records, messages)
        handshake.extend(fragment)
        while len(handshake) >= 4:
            message_length = int.from_bytes(handshake[1:4], "big")
            if message_length > MAX_RESPONSE_BYTES:
                return _indeterminate("handshake_message_too_large", records, messages)
            if len(handshake) < 4 + message_length:
                break
            message_type = handshake[0]
            body = bytes(handshake[4:4 + message_length])
            del handshake[:4 + message_length]
            messages += 1
            if messages > MAX_HANDSHAKE_MESSAGES:
                return _indeterminate("handshake_message_limit_exceeded", records, messages)
            if message_type == 0:  # legacy HelloRequest; bounded and otherwise ignored
                continue
            if message_type != 2:
                return _indeterminate("unexpected_handshake_message", records, messages)
            return _parse_server_hello(body, partition, records, messages)
    if eof:
        return _indeterminate("peer_closed_without_terminal_tls_message", records, messages)
    return _need_more(records, messages)


def _parse_server_hello(
    body: bytes,
    partition: ClientHelloPartition,
    records: int,
    messages: int,
) -> ParsedTLSResponse:
    if len(body) < 38:
        return _indeterminate("truncated_server_hello", records, messages)
    version = int.from_bytes(body[:2], "big")
    if version != TLS_VERSIONS[partition.tls_version]:
        return _indeterminate("unexpected_server_version", records, messages)
    cursor = 34
    session_length = body[cursor]
    cursor += 1
    if session_length > 32 or cursor + session_length + 3 > len(body):
        return _indeterminate("invalid_session_id", records, messages)
    cursor += session_length
    selected = int.from_bytes(body[cursor:cursor + 2], "big")
    cursor += 2
    compression = body[cursor]
    cursor += 1
    if compression != 0:
        return _indeterminate("invalid_compression", records, messages)
    if cursor < len(body):
        if len(body) - cursor < 2:
            return _indeterminate("truncated_extension_length", records, messages)
        extensions_length = int.from_bytes(body[cursor:cursor + 2], "big")
        cursor += 2
        if cursor + extensions_length != len(body):
            return _indeterminate("invalid_extension_block_length", records, messages)
        seen = set()
        end = cursor + extensions_length
        while cursor < end:
            if end - cursor < 4:
                return _indeterminate("truncated_extension", records, messages)
            extension_type, extension_length = struct.unpack("!HH", body[cursor:cursor + 4])
            cursor += 4
            if extension_type in seen or cursor + extension_length > end:
                return _indeterminate("duplicate_or_truncated_extension", records, messages)
            seen.add(extension_type)
            cursor += extension_length
    if selected not in partition.offered_suite_ids:
        return _indeterminate("server_selected_unoffered_suite", records, messages, selected_suite_id=selected)
    if selected in {TLS_EMPTY_RENEGOTIATION_INFO_SCSV, TLS_FALLBACK_SCSV} or _is_grease(selected):
        return _indeterminate("server_selected_non_negotiable_value", records, messages, selected_suite_id=selected)
    if partition.suite_class == "ssc_prohibited":
        if selected not in SSC_WEAK_CIPHER_BY_ID:
            return _indeterminate("selected_suite_not_in_frozen_catalog", records, messages, selected_suite_id=selected)
        selected_class = "ssc_prohibited"
    else:
        if selected in SSC_WEAK_CIPHER_BY_ID:
            return _indeterminate("control_selected_prohibited_suite", records, messages, selected_suite_id=selected)
        selected_class = "strong_control"
    return ParsedTLSResponse(
        terminal=True, matched=True, outcome="MATCH", reason_code="server_selected_offered_suite",
        selected_suite_id=selected, selected_suite_class=selected_class,
        server_hello_valid=True, record_count=records, handshake_message_count=messages,
    )


def _is_grease(value: int) -> bool:
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def _alert_name(description: int) -> str:
    return {
        40: "handshake_failure", 47: "illegal_parameter", 50: "decode_error",
        70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
        110: "unsupported_extension",
    }.get(description, f"alert_{description}")


def _need_more(records: int, messages: int) -> ParsedTLSResponse:
    return ParsedTLSResponse(False, None, "NEED_MORE", "incomplete_response", record_count=records, handshake_message_count=messages)


def _indeterminate(
    reason: str,
    records: int = 0,
    messages: int = 0,
    *,
    alert_class: str | None = None,
    selected_suite_id: int | None = None,
) -> ParsedTLSResponse:
    return ParsedTLSResponse(
        True, None, "INDETERMINATE", reason, selected_suite_id=selected_suite_id,
        alert_class=alert_class, record_count=records, handshake_message_count=messages,
    )


def evaluate_endpoint_observation(observation: dict[str, object]) -> bool | None:
    attempts = observation.get("attempts")
    if not isinstance(attempts, list):
        return None
    if any(isinstance(item, dict) and item.get("matched") is True for item in attempts):
        return True
    prohibited = [item for item in attempts if isinstance(item, dict) and item.get("suite_class") == "ssc_prohibited"]
    expected_ids = {f"tls{version[-3:].replace('.', '')}" for version in TLS_VERSIONS}
    if {item.get("partition_id") for item in prohibited} != expected_ids:
        return None
    if not observation.get("catalog_complete") or not all(item.get("definitive_rejection") is True for item in prohibited):
        return None
    control = observation.get("control")
    if not isinstance(control, dict) or control.get("matched") is not True:
        return None
    return False


assert len(SSC_WEAK_CIPHER_CATALOG) == 90
assert len(SSC_WEAK_CIPHER_BY_ID) == len(SSC_WEAK_CIPHER_CATALOG)
assert all(entry.reasons for entry in SSC_WEAK_CIPHER_CATALOG)
assert all(set(entry.tls_versions) <= set(TLS_VERSIONS) for entry in SSC_WEAK_CIPHER_CATALOG)
assert not ({TLS_EMPTY_RENEGOTIATION_INFO_SCSV, TLS_FALLBACK_SCSV} & set(SSC_WEAK_CIPHER_BY_ID))
assert all(not _is_grease(suite_id) for suite_id in SSC_WEAK_CIPHER_BY_ID)
assert len(build_prohibited_partitions("catalog.test")) == MAX_PARTITIONS
assert all(
    len(partition.request_bytes) <= MAX_CLIENT_HELLO_BYTES
    for partition in build_prohibited_partitions("catalog.test")
)
