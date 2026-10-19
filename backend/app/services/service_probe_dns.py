"""Pure, bounded DNS protocol identity for SSC Wave 5E.

This module performs no socket, resolver, inventory, or authorization work.
It builds the one reviewed query, strictly parses UDP DNS messages and TCP
length-framed messages, and returns compact structural evidence.  Raw DNS
messages, transaction IDs, queried names, and response RDATA are never
returned as evidence.
"""
from __future__ import annotations

import secrets
import struct
from datetime import datetime, timezone
from typing import Any

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rdataclass
import dns.rdatatype


DNS_SERVICE_ISSUE_KEY = "service_dns"
DNS_SERVICE_FRAMEWORK_VERSION = "dns-service-probe.v1"
DNS_SERVICE_POLICY_VERSION = "ssc-wave5e-dns-service-identification.v1"
DNS_QUERY_POLICY_VERSION = "ssc-wave5e-dns-query-policy.v1"
DNS_SERVICE_EVIDENCE_SCHEMA_VERSION = "ssc-wave5e-dns-service-evidence.v1"

DNS_SERVICE_QNAME_TEXT = "ssc-dns-service-probe-v1.invalid."
DNS_SERVICE_QNAME = dns.name.from_text(DNS_SERVICE_QNAME_TEXT)
DNS_SERVICE_REQUEST_SHAPE = "QUERY_A_IN_RD0_ONE_QUESTION_NO_EDNS"

MAX_DNS_SERVICE_ENDPOINTS = 2
MAX_DNS_UDP_RESPONSE_BYTES = 512
MAX_DNS_TCP_RESPONSE_BYTES = 4096
DNS_SERVICE_ATTEMPT_TIMEOUT_SECONDS = 3.0
DNS_SERVICE_TOTAL_DEADLINE_SECONDS = 6.0

_ACCEPTED_RCODE_V1 = frozenset({0, 1, 2, 3, 4, 5})
_DNS_HEADER_BYTES = 12
_DNS_RESERVED_Z = 0x0040


def build_dns_service_query(transaction_id: int | None = None) -> tuple[bytes, int]:
    """Build the exact reviewed A/IN, RD=0 query with no EDNS or options."""
    if transaction_id is None:
        transaction_id = secrets.randbits(16)
    if isinstance(transaction_id, bool) or not isinstance(transaction_id, int) or not 0 <= transaction_id <= 0xFFFF:
        raise ValueError("DNS transaction ID must be an unsigned 16-bit integer")
    query = dns.message.make_query(
        DNS_SERVICE_QNAME,
        dns.rdatatype.A,
        dns.rdataclass.IN,
        use_edns=False,
        want_dnssec=False,
        id=transaction_id,
        flags=0,
    )
    wire = query.to_wire(max_size=MAX_DNS_UDP_RESPONSE_BYTES)
    if (
        len(wire) != 50
        or query.opcode() != dns.opcode.QUERY
        or query.flags != 0
        or len(query.question) != 1
        or query.additional
        or query.edns >= 0
    ):
        raise AssertionError("reviewed DNS identity query shape changed")
    return wire, transaction_id


def indeterminate_dns_attempt(
    *,
    transport: str,
    port: int,
    reason_code: str,
    elapsed_ms: int,
    observed_at: str | None = None,
    response_bytes: int = 0,
    source_match: bool | None = None,
) -> dict[str, Any]:
    """Return minimized evidence for acquisition or framing failure."""
    attempt = _attempt_base(
        transport=transport,
        port=port,
        elapsed_ms=elapsed_ms,
        observed_at=observed_at,
        response_bytes=response_bytes,
        source_match=source_match,
    )
    attempt.update({
        "outcome": "INDETERMINATE",
        "matched": None,
        "reason_code": reason_code,
    })
    return attempt


def evaluate_udp_dns_response(
    wire: bytes,
    *,
    expected_transaction_id: int,
    port: int,
    source_match: bool,
    elapsed_ms: int,
    observed_at: str | None = None,
    oversized: bool = False,
) -> dict[str, Any]:
    if oversized or len(wire) > MAX_DNS_UDP_RESPONSE_BYTES:
        return indeterminate_dns_attempt(
            transport="udp",
            port=port,
            reason_code="udp_response_oversized",
            elapsed_ms=elapsed_ms,
            observed_at=observed_at,
            response_bytes=len(wire),
            source_match=source_match,
        )
    return evaluate_dns_response(
        wire,
        expected_transaction_id=expected_transaction_id,
        transport="udp",
        port=port,
        source_match=source_match,
        elapsed_ms=elapsed_ms,
        observed_at=observed_at,
    )


def evaluate_tcp_dns_frame(
    frame: bytes,
    *,
    expected_transaction_id: int,
    port: int,
    source_match: bool,
    elapsed_ms: int,
    observed_at: str | None = None,
) -> dict[str, Any]:
    if len(frame) < 2:
        return indeterminate_dns_attempt(
            transport="tcp", port=port, reason_code="tcp_length_prefix_partial",
            elapsed_ms=elapsed_ms, observed_at=observed_at, source_match=source_match,
        )
    declared = int.from_bytes(frame[:2], "big")
    if declared == 0:
        reason = "tcp_length_zero"
    elif declared < _DNS_HEADER_BYTES:
        reason = "tcp_length_below_dns_header"
    elif declared > MAX_DNS_TCP_RESPONSE_BYTES:
        reason = "tcp_length_oversized"
    elif len(frame) < declared + 2:
        reason = "tcp_dns_body_partial"
    elif len(frame) > declared + 2:
        reason = "tcp_frame_trailing_bytes"
    else:
        return evaluate_dns_response(
            frame[2:],
            expected_transaction_id=expected_transaction_id,
            transport="tcp",
            port=port,
            source_match=source_match,
            elapsed_ms=elapsed_ms,
            observed_at=observed_at,
        )
    return indeterminate_dns_attempt(
        transport="tcp",
        port=port,
        reason_code=reason,
        elapsed_ms=elapsed_ms,
        observed_at=observed_at,
        response_bytes=max(0, len(frame) - 2),
        source_match=source_match,
    )


def evaluate_dns_response(
    wire: bytes,
    *,
    expected_transaction_id: int,
    transport: str,
    port: int,
    source_match: bool,
    elapsed_ms: int,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Apply the strict, transport-independent DNS identity predicate."""
    attempt = _attempt_base(
        transport=transport,
        port=port,
        elapsed_ms=elapsed_ms,
        observed_at=observed_at,
        response_bytes=len(wire),
        source_match=source_match,
    )
    raw_flags: int | None = None
    if len(wire) >= _DNS_HEADER_BYTES:
        message_id, raw_flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", wire[:12])
        attempt.update({
            "transaction_match": message_id == expected_transaction_id,
            "qr": bool(raw_flags & dns.flags.QR),
            "opcode": (raw_flags >> 11) & 0xF,
            "rcode": raw_flags & 0xF,
            "aa": bool(raw_flags & dns.flags.AA),
            "tc": bool(raw_flags & dns.flags.TC),
            "rd": bool(raw_flags & dns.flags.RD),
            "ra": bool(raw_flags & dns.flags.RA),
            "qdcount": qdcount,
            "ancount": ancount,
            "nscount": nscount,
            "arcount": arcount,
        })
    try:
        message = dns.message.from_wire(
            wire,
            keyring=None,
            ignore_trailing=False,
            raise_on_truncation=False,
            continue_on_error=False,
        )
        attempt["wire_complete"] = True
    except Exception:
        return _indeterminate(attempt, "dns_parsing_failed")

    question_match = bool(
        len(message.question) == 1
        and message.question[0].name.canonicalize() == DNS_SERVICE_QNAME.canonicalize()
        and message.question[0].rdtype == dns.rdatatype.A
        and message.question[0].rdclass == dns.rdataclass.IN
    )
    attempt["question_match"] = question_match
    full_rcode = int(message.rcode())
    attempt["rcode"] = full_rcode

    checks = (
        (source_match, "response_source_mismatch"),
        (message.id == expected_transaction_id, "transaction_id_mismatch"),
        (bool(message.flags & dns.flags.QR), "not_a_dns_response"),
        (message.opcode() == dns.opcode.QUERY, "opcode_mismatch"),
        (attempt["qdcount"] == 1 and len(message.question) == 1, "question_count_mismatch"),
        (question_match, "question_mismatch"),
        (not bool(message.flags & dns.flags.RD), "recursion_desired_mismatch"),
        (raw_flags is not None and not bool(raw_flags & _DNS_RESERVED_Z), "reserved_z_flag_set"),
        (full_rcode in _ACCEPTED_RCODE_V1, "rcode_not_accepted_v1"),
    )
    for valid, reason_code in checks:
        if not valid:
            return _indeterminate(attempt, reason_code)

    attempt.update({
        "identity_class": "dns_query_response",
        "outcome": "MATCH",
        "matched": True,
        "reason_code": "dns_protocol_identity_confirmed",
    })
    return attempt


def aggregate_dns_service_attempts(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    matched = next((attempt for attempt in attempts if attempt.get("outcome") == "MATCH"), None)
    if matched is not None:
        outcome, matched_value, reason = (
            "MATCH", True, "at_least_one_declared_dns_endpoint_matched",
        )
    else:
        outcome, matched_value, reason = (
            "INDETERMINATE", None, "no_declared_dns_endpoint_proved_identity",
        )
    return {
        "outcome": outcome,
        "matched": matched_value,
        "reason_code": reason,
        "policy_version": DNS_SERVICE_POLICY_VERSION,
        "framework_version": DNS_SERVICE_FRAMEWORK_VERSION,
        "evidence_schema_version": DNS_SERVICE_EVIDENCE_SCHEMA_VERSION,
        "attempts": attempts,
    }


def _attempt_base(
    *,
    transport: str,
    port: int,
    elapsed_ms: int,
    observed_at: str | None,
    response_bytes: int,
    source_match: bool | None,
) -> dict[str, Any]:
    return {
        "issue_key": DNS_SERVICE_ISSUE_KEY,
        "transport": transport,
        "port": port,
        "query_policy_version": DNS_QUERY_POLICY_VERSION,
        "request_shape": DNS_SERVICE_REQUEST_SHAPE,
        "source_match": source_match,
        "transaction_match": None,
        "question_match": None,
        "qr": None,
        "opcode": None,
        "rcode": None,
        "aa": None,
        "tc": None,
        "rd": None,
        "ra": None,
        "qdcount": None,
        "ancount": None,
        "nscount": None,
        "arcount": None,
        "response_bytes": response_bytes,
        "wire_complete": False,
        "identity_class": None,
        "framework_version": DNS_SERVICE_FRAMEWORK_VERSION,
        "evidence_schema_version": DNS_SERVICE_EVIDENCE_SCHEMA_VERSION,
        "elapsed_ms": max(0, elapsed_ms),
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat(),
    }


def _indeterminate(attempt: dict[str, Any], reason_code: str) -> dict[str, Any]:
    attempt.update({
        "outcome": "INDETERMINATE",
        "matched": None,
        "reason_code": reason_code,
    })
    return attempt
