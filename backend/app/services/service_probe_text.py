"""Strict parsers for bounded, non-authenticating staged text probes.

This module contains protocol syntax only.  Socket acquisition, deadlines and
evidence persistence remain in :mod:`app.services.service_probes`.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable


WAVE5A_SERVICE_POLICY_VERSION = "ssc-wave5a-text-service-identification.v1"
SMTP_STANDARD_PORT_POLICY_VERSION = "smtp-standard-ports.v1"
SMTP_STANDARD_PORTS = frozenset({25, 465, 587})


@dataclass(frozen=True)
class TextStageResult:
    valid: bool
    reason: str
    response_class: str | None = None
    magic: str | None = None
    version: str | None = None
    normalized: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StagedTextProbeSpec:
    protocol: str
    issue_key: str
    probe_type: str
    probe_version: str
    outbound_payload: bytes
    stage1_completion: Callable[[bytes], bool]
    stage1_parser: Callable[[bytes], TextStageResult]
    stage2_completion: Callable[[bytes], bool]
    stage2_parser: Callable[[bytes], TextStageResult]


_NUMERIC_LINE = re.compile(rb"^(?P<code>[0-9]{3})(?P<separator>[ -])(?P<text>[\x20-\x7e]*)\r\n$")
_SMTP_DOMAIN = re.compile(rb"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\[[\x21-\x7e]+\])$")
_IMAP_GREETING = re.compile(rb"^\* (OK|PREAUTH)(?: ([\x20-\x7e]*))?\r\n$")
_IMAP_CAPABILITY = re.compile(rb"^\* CAPABILITY ([\x21-\x7e]+(?: [\x21-\x7e]+)*)\r\n$")
_IMAP_TAGGED_OK = re.compile(rb"^A001 OK(?: ([\x20-\x7e]*))?\r\n$")
_POP3_OK = re.compile(rb"^\+OK(?: ([\x20-\x7e]*))?\r\n$")
_POP3_ERROR = re.compile(rb"^-ERR(?: ([\x20-\x7e]*))?\r\n$")
_POP3_CAPABILITY = re.compile(rb"^[A-Za-z0-9][A-Za-z0-9-]*(?: [\x21-\x7e]+)*\r\n$")
_SMTP_EXTENSION = re.compile(rb"^[A-Za-z0-9][A-Za-z0-9-]*(?:[ =][\x21-\x7e]+(?: [\x21-\x7e]+)*)?$")


def _lines(data: bytes) -> list[bytes]:
    return data.splitlines(keepends=True)


def _numeric_reply_complete(data: bytes) -> bool:
    lines = _lines(data)
    if not lines or not lines[0].endswith(b"\r\n"):
        return False
    first = _NUMERIC_LINE.fullmatch(lines[0])
    if first is None:
        return True
    if first.group("separator") == b" ":
        return True
    terminator = first.group("code") + b" "
    return any(line.startswith(terminator) and line.endswith(b"\r\n") for line in lines[1:])


def _parse_numeric_reply(data: bytes, expected_code: bytes, protocol: str) -> TextStageResult:
    lines = _lines(data)
    if not lines or b"".join(lines) != data or not all(line.endswith(b"\r\n") for line in lines):
        return TextStageResult(False, f"{protocol} reply is incomplete")
    first = _NUMERIC_LINE.fullmatch(lines[0])
    if first is None:
        return TextStageResult(False, f"{protocol} reply has invalid three-digit framing")
    code = first.group("code")
    separator = first.group("separator")
    if separator == b"-":
        if len(lines) < 2:
            return TextStageResult(False, f"{protocol} multiline reply has no terminating line")
        for line in lines[1:]:
            if not line.endswith(b"\r\n") or any(value < 0x20 or value > 0x7e for value in line[:-2]):
                return TextStageResult(False, f"{protocol} multiline reply contains malformed text")
        if not lines[-1].startswith(code + b" "):
            return TextStageResult(False, f"{protocol} multiline reply terminator does not repeat its code")
        if any(line.startswith(code + b" ") for line in lines[1:-1]):
            return TextStageResult(False, f"{protocol} multiline reply contains data after its terminator")
    elif len(lines) != 1:
        return TextStageResult(False, f"{protocol} single-line reply has trailing lines")
    if code != expected_code:
        return TextStageResult(False, f"{protocol} reply code is not {expected_code.decode()}", f"{protocol}_reply_{code.decode()}", code.decode())
    return TextStageResult(
        True,
        f"received a complete {protocol} {expected_code.decode()} reply",
        f"{protocol}_reply_{expected_code.decode()}",
        expected_code.decode(),
    )


def ftp_stage1(data: bytes) -> TextStageResult:
    return _parse_numeric_reply(data, b"220", "ftp")


def ftp_stage2(data: bytes) -> TextStageResult:
    return _parse_numeric_reply(data, b"200", "ftp")


def _single_crlf_line_complete(data: bytes) -> bool:
    return b"\r\n" in data


def imap_stage1(data: bytes) -> TextStageResult:
    matched = _IMAP_GREETING.fullmatch(data)
    if matched is None:
        return TextStageResult(False, "IMAP greeting is not a complete legal OK or PREAUTH response")
    greeting_class = matched.group(1).decode("ascii").lower()
    return TextStageResult(True, "received a complete legal IMAP server greeting", f"imap_{greeting_class}_greeting", "* " + matched.group(1).decode("ascii"), "IMAP")


def imap_stage2_complete(data: bytes) -> bool:
    return any(line.startswith(b"A001 ") and line.endswith(b"\r\n") for line in _lines(data))


def _normalized_marker_details(values: list[bytes], name: str) -> dict[str, Any]:
    normalized = b"\n".join(value.upper() for value in values)
    return {
        f"{name}_count": len(values),
        f"{name}_sha256": hashlib.sha256(normalized).hexdigest(),
    }


def imap_stage2(data: bytes) -> TextStageResult:
    lines = _lines(data)
    if not lines or b"".join(lines) != data or not all(line.endswith(b"\r\n") for line in lines):
        return TextStageResult(False, "IMAP CAPABILITY response is incomplete")
    tagged_indexes = [index for index, line in enumerate(lines) if line.startswith(b"A001 ")]
    if tagged_indexes != [len(lines) - 1] or _IMAP_TAGGED_OK.fullmatch(lines[-1]) is None:
        return TextStageResult(False, "IMAP response lacks the exact A001 OK completion")
    capability_lines = [line for line in lines[:-1] if line.startswith(b"* CAPABILITY ")]
    if len(capability_lines) != 1 or len(lines) != 2:
        return TextStageResult(False, "IMAP response does not contain exactly one valid untagged CAPABILITY result")
    matched = _IMAP_CAPABILITY.fullmatch(capability_lines[0])
    if matched is None:
        return TextStageResult(False, "IMAP CAPABILITY data is malformed")
    capabilities = matched.group(1).split(b" ")
    return TextStageResult(
        True,
        "received a valid IMAP CAPABILITY response and matching A001 OK completion",
        "imap_capability_tagged_ok",
        "* CAPABILITY/A001 OK",
        "IMAP",
        _normalized_marker_details(capabilities, "capability"),
    )


def pop3_stage1(data: bytes) -> TextStageResult:
    if _POP3_OK.fullmatch(data) is None:
        return TextStageResult(False, "POP3 greeting is not a complete +OK response")
    return TextStageResult(True, "received a complete POP3 +OK greeting", "pop3_ok_greeting", "+OK", "POP3")


def pop3_stage2_complete(data: bytes) -> bool:
    lines = _lines(data)
    if not lines or not lines[0].endswith(b"\r\n"):
        return False
    if _POP3_ERROR.fullmatch(lines[0]) is not None:
        return True
    if _POP3_OK.fullmatch(lines[0]) is None:
        return True
    return any(line == b".\r\n" for line in lines[1:])


def pop3_stage2(data: bytes) -> TextStageResult:
    lines = _lines(data)
    if not lines or b"".join(lines) != data or not all(line.endswith(b"\r\n") for line in lines):
        return TextStageResult(False, "POP3 CAPA response is incomplete")
    if _POP3_ERROR.fullmatch(lines[0]) is not None:
        return TextStageResult(False, "POP3 CAPA returned -ERR", "pop3_capa_error", "-ERR")
    if _POP3_OK.fullmatch(lines[0]) is None or len(lines) < 2 or lines[-1] != b".\r\n":
        return TextStageResult(False, "POP3 CAPA response lacks +OK framing and exact dot termination")
    capability_lines = lines[1:-1]
    if any(_POP3_CAPABILITY.fullmatch(line) is None for line in capability_lines):
        return TextStageResult(False, "POP3 CAPA response contains a malformed capability line")
    capability_values = [line[:-2] for line in capability_lines]
    return TextStageResult(
        True,
        "received a complete dot-terminated POP3 CAPA response",
        "pop3_capa_complete",
        "+OK/.",
        "POP3",
        _normalized_marker_details(capability_values, "capability"),
    )


def _smtp_first_domain(line: bytes) -> bytes | None:
    matched = _NUMERIC_LINE.fullmatch(line)
    if matched is None:
        return None
    text = matched.group("text")
    domain = text.split(b" ", 1)[0] if text else b""
    return domain if domain and _SMTP_DOMAIN.fullmatch(domain) else None


def smtp_stage1(data: bytes) -> TextStageResult:
    numeric = _parse_numeric_reply(data, b"220", "smtp")
    if not numeric.valid:
        return numeric
    lines = _lines(data)
    if _smtp_first_domain(lines[0]) is None:
        return TextStageResult(False, "SMTP 220 greeting lacks a legal server domain or address literal")
    if any(
        (matched := _NUMERIC_LINE.fullmatch(line)) is None or matched.group("code") != b"220"
        for line in lines[1:]
    ):
        return TextStageResult(False, "SMTP multiline greeting does not repeat the 220 reply code")
    return TextStageResult(True, "received a complete legal SMTP 220 greeting", "smtp_220_greeting", "220", "SMTP")


def smtp_stage2(data: bytes) -> TextStageResult:
    numeric = _parse_numeric_reply(data, b"250", "smtp")
    if not numeric.valid:
        return numeric
    lines = _lines(data)
    if _smtp_first_domain(lines[0]) is None:
        return TextStageResult(False, "SMTP EHLO reply lacks a legal server domain or address literal")
    extension_values: list[bytes] = []
    for line in lines[1:]:
        matched = _NUMERIC_LINE.fullmatch(line)
        if matched is None or matched.group("code") != b"250" or _SMTP_EXTENSION.fullmatch(matched.group("text")) is None:
            return TextStageResult(False, "SMTP EHLO reply contains a malformed extension line")
        extension_values.append(matched.group("text"))
    return TextStageResult(
        True,
        "received a complete SMTP 250 EHLO reply",
        "smtp_ehlo_250",
        "220/250",
        "SMTP",
        _normalized_marker_details(extension_values, "extension"),
    )


STAGED_TEXT_PROBES: dict[str, StagedTextProbeSpec] = {
    "ftp": StagedTextProbeSpec(
        "ftp", "service_ftp", "ftp-greeting-noop", "1.0", b"NOOP\r\n",
        _numeric_reply_complete, ftp_stage1, _numeric_reply_complete, ftp_stage2,
    ),
    "imap": StagedTextProbeSpec(
        "imap", "service_imap", "imap-greeting-capability", "1.0", b"A001 CAPABILITY\r\n",
        _single_crlf_line_complete, imap_stage1, imap_stage2_complete, imap_stage2,
    ),
    "pop3": StagedTextProbeSpec(
        "pop3", "service_pop3", "pop3-greeting-capa", "1.0", b"CAPA\r\n",
        _single_crlf_line_complete, pop3_stage1, pop3_stage2_complete, pop3_stage2,
    ),
    "smtp": StagedTextProbeSpec(
        "smtp", "mail_server_unusual_port", "smtp-greeting-ehlo-port-policy", "1.0", b"EHLO scanner.invalid\r\n",
        _numeric_reply_complete, smtp_stage1, _numeric_reply_complete, smtp_stage2,
    ),
}
