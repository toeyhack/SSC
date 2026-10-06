"""Bounded, non-authenticating service-protocol probe adapters.

The adapters identify only protocol-valid responses.  Port numbers and TCP
reachability are never identification evidence, and arbitrary/malformed bytes
remain indeterminate rather than becoming clean negatives.
"""
from __future__ import annotations

import hashlib
import re
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from app.services.service_probe_text import (
    SMTP_STANDARD_PORT_POLICY_VERSION,
    SMTP_STANDARD_PORTS,
    STAGED_TEXT_PROBES,
    WAVE5A_SERVICE_POLICY_VERSION,
    StagedTextProbeSpec,
    TextStageResult,
)


SERVICE_PROBE_FRAMEWORK_VERSION = "service-probe-adapter.v2"
SERVICE_PROBE_POLICY_VERSION = "ssc-wave3a-service-identification.v1"
MAX_SERVICE_PROBES = 6
MAX_SERVICE_PROBE_RESPONSE_BYTES = 4096
MAX_SERVICE_PROBE_OUTBOUND_BYTES = 1024
MAX_SERVICE_PROBE_LINE_BYTES = 512
MAX_SERVICE_PROBE_LINES = 64
MAX_SERVICE_PROBE_STAGES = 2


@dataclass(frozen=True)
class ProbeDecision:
    outcome: str
    reason: str
    response_class: str | None = None
    magic: str | None = None
    version: str | None = None

    @property
    def matched(self) -> bool | None:
        return {"MATCH": True, "NO_MATCH": False}.get(self.outcome)


@dataclass(frozen=True)
class ServiceProbeAdapter:
    protocol: str
    issue_key: str
    probe_type: str
    probe_version: str
    initial_payload: bytes
    server_first: bool
    parser: Callable[[bytes], ProbeDecision]
    completion: Callable[[bytes], bool]
    followup: Callable[[bytes], bytes] | None = None


_RFB_GREETING = re.compile(rb"^RFB (003)\.(003|007|008)\n$")
_RSYNC_GREETING = re.compile(rb"^@RSYNCD: ([0-9]{1,3})\.([0-9]{1,3})(?: [^\r\n]{1,96})?\r?\n$")


def _match(reason: str, response_class: str, magic: str, version: str | None = None) -> ProbeDecision:
    return ProbeDecision("MATCH", reason, response_class, magic, version)


def _indeterminate(reason: str, response_class: str | None = None) -> ProbeDecision:
    return ProbeDecision("INDETERMINATE", reason, response_class)


def _parse_vnc(data: bytes) -> ProbeDecision:
    matched = _RFB_GREETING.fullmatch(data)
    if not matched:
        return _indeterminate("response is not an exact supported RFB version greeting")
    version = f"{matched.group(1).decode()}.{matched.group(2).decode()}"
    return _match("received a complete supported RFB version greeting", "rfb_version_greeting", "RFB", version)


def _parse_rsync(data: bytes) -> ProbeDecision:
    matched = _RSYNC_GREETING.fullmatch(data)
    if not matched:
        return _indeterminate("response is not a complete rsync daemon greeting")
    major, minor = (int(matched.group(1)), int(matched.group(2)))
    if major < 20:
        return _indeterminate("rsync-like greeting declares an unsupported historical version")
    return _match("received a complete rsync daemon protocol greeting", "rsync_daemon_greeting", "@RSYNCD:", f"{major}.{minor}")


def _parse_redis(data: bytes) -> ProbeDecision:
    if data == b"+PONG\r\n":
        return _match("RESP PING returned the exact PONG simple string", "redis_resp_pong", "+PONG", "RESP2")
    if data.startswith((b"-NOAUTH ", b"-NOPERM ")) and data.endswith(b"\r\n") and b"\x00" not in data:
        return _match("RESP PING returned a Redis authorization error without an authentication attempt", "redis_resp_error", data[1:].split(b" ", 1)[0].decode("ascii"), "RESP2")
    return _indeterminate("response is not a bounded Redis PING result")


def _parse_socks5(data: bytes) -> ProbeDecision:
    if len(data) != 2 or data[0] != 0x05:
        return _indeterminate("response is not an exact SOCKS5 method-selection frame")
    return _match("received a complete SOCKS5 method-selection response", "socks5_method_selection", "0x05", "5")


def _parse_telnet(data: bytes) -> ProbeDecision:
    if b"\xff\xfb\x03" in data:
        return _match("server accepted the requested Telnet suppress-go-ahead option", "telnet_option_negotiation", "IAC WILL SGA", "RFC854")
    if b"\xff\xfc\x03" in data:
        return _match("server explicitly rejected the requested Telnet option using valid negotiation", "telnet_option_negotiation", "IAC WONT SGA", "RFC854")
    return _indeterminate("response did not complete the requested Telnet option negotiation")


def _smb2_frame(data: bytes) -> tuple[bytes, int] | None:
    if len(data) < 4 or data[0] != 0x00:
        return None
    declared = int.from_bytes(data[1:4], "big")
    if declared < 64 or declared > MAX_SERVICE_PROBE_RESPONSE_BYTES or len(data) != declared + 4:
        return None
    payload = data[4:]
    if payload[:4] != b"\xfeSMB" or int.from_bytes(payload[4:6], "little") != 64:
        return None
    if int.from_bytes(payload[12:14], "little") != 0 or not (int.from_bytes(payload[16:20], "little") & 1):
        return None
    return payload, int.from_bytes(payload[8:12], "little")


def _parse_smb2(data: bytes) -> ProbeDecision:
    framed = _smb2_frame(data)
    if framed is None:
        return _indeterminate("response is not a complete SMB2 negotiate response frame")
    payload, status = framed
    body_structure = int.from_bytes(payload[64:66], "little") if len(payload) >= 66 else None
    if status == 0:
        if len(payload) < 128 or body_structure != 65:
            return _indeterminate("successful SMB2 header has an incomplete negotiate response body")
        dialect = int.from_bytes(payload[68:70], "little")
        if dialect not in {0x0202, 0x0210, 0x0300, 0x0302, 0x0311}:
            return _indeterminate("SMB2 negotiate response contains an unknown dialect")
        return _match("received a complete SMB2 negotiate response", "smb2_negotiate_response", "0xFE534D42", f"0x{dialect:04x}")
    if len(payload) >= 72 and body_structure == 9:
        return _match("received a protocol-valid SMB2 error response to negotiate", "smb2_error_response", "0xFE534D42", f"status=0x{status:08x}")
    return _indeterminate("SMB2-like response has a malformed error body")


def _line_complete(data: bytes) -> bool:
    return b"\n" in data


def _fixed_or_foreign(size: int) -> Callable[[bytes], bool]:
    return lambda data: len(data) >= size or _foreign_protocol(data) is not None


def _smb_complete(data: bytes) -> bool:
    if _foreign_protocol(data, include_smb=False) is not None:
        return True
    return len(data) >= 4 and data[0] == 0 and len(data) >= 4 + int.from_bytes(data[1:4], "big")


def _telnet_complete(data: bytes) -> bool:
    return b"\xff\xfb\x03" in data or b"\xff\xfc\x03" in data or b"\n" in data or _foreign_protocol(data) is not None


def _rfb_followup(data: bytes) -> bytes:
    return data if _RFB_GREETING.fullmatch(data) else b""


def _rsync_followup(data: bytes) -> bytes:
    return b"@RSYNCD: 31.0\n#exit\n" if _RSYNC_GREETING.fullmatch(data) else b""


def _smb2_negotiate_request() -> bytes:
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    header[4:6] = (64).to_bytes(2, "little")
    header[12:14] = (0).to_bytes(2, "little")
    header[14:16] = (1).to_bytes(2, "little")
    body = bytearray(36)
    body[0:2] = (36).to_bytes(2, "little")
    body[2:4] = (2).to_bytes(2, "little")
    body[4:6] = (1).to_bytes(2, "little")
    body[12:28] = bytes.fromhex("5353432d5741564533412d50524f4245")
    payload = bytes(header + body) + b"\x02\x02\x10\x02"
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


ADAPTERS: dict[str, ServiceProbeAdapter | StagedTextProbeSpec] = {
    "vnc": ServiceProbeAdapter("vnc", "service_vnc", "rfb-version-greeting", "1.0", b"", True, _parse_vnc, _fixed_or_foreign(12), _rfb_followup),
    "rsync": ServiceProbeAdapter("rsync", "service_rsync", "rsync-daemon-greeting", "1.0", b"", True, _parse_rsync, _line_complete, _rsync_followup),
    "redis": ServiceProbeAdapter("redis", "service_redis", "redis-resp-ping", "1.0", b"*1\r\n$4\r\nPING\r\n", False, _parse_redis, _line_complete),
    "socks5": ServiceProbeAdapter("socks5", "service_socks_proxy", "socks5-method-negotiation", "1.0", b"\x05\x01\x00", False, _parse_socks5, _fixed_or_foreign(2)),
    "telnet": ServiceProbeAdapter("telnet", "service_telnet", "telnet-option-negotiation", "1.0", b"\xff\xfd\x03", False, _parse_telnet, _telnet_complete),
    "smb2": ServiceProbeAdapter("smb2", "service_smb", "smb2-negotiate", "1.0", _smb2_negotiate_request(), False, _parse_smb2, _smb_complete),
    **STAGED_TEXT_PROBES,
}


def _foreign_protocol(data: bytes, *, include_smb: bool = True) -> str | None:
    """Return a protocol only for a complete, specification-shaped response."""
    if _parse_vnc(data).outcome == "MATCH":
        return "vnc"
    if _parse_rsync(data).outcome == "MATCH":
        return "rsync"
    if _parse_redis(data).outcome == "MATCH":
        return "redis"
    if _parse_socks5(data).outcome == "MATCH":
        return "socks5"
    if _parse_telnet(data).outcome == "MATCH":
        return "telnet"
    if include_smb and _parse_smb2(data).outcome == "MATCH":
        return "smb2"
    return None


def evaluate_service_probe_response(
    protocol: str,
    response: bytes,
    *,
    stop_reason: str = "response_complete",
    error_class: str | None = None,
    transport: str = "tcp",
) -> dict[str, Any]:
    adapter = ADAPTERS.get(protocol)
    policy_version = (
        WAVE5A_SERVICE_POLICY_VERSION
        if isinstance(adapter, StagedTextProbeSpec)
        else SERVICE_PROBE_POLICY_VERSION
    )
    if adapter is None:
        decision = _indeterminate("probe adapter is unsupported")
    elif transport.lower() != "tcp":
        decision = _indeterminate("probe transport is unsupported")
    elif error_class is not None or stop_reason in {
        "connect_error", "write_error", "read_error", "timed_out", "reset", "response_limit",
        "line_length_limit", "line_count_limit", "outbound_limit", "peer_closed",
    }:
        decision = _indeterminate("probe acquisition did not complete")
    elif isinstance(adapter, StagedTextProbeSpec):
        decision = _indeterminate("staged protocol identification requires both reviewed response phases")
    else:
        decision = adapter.parser(response)
        if decision.outcome == "INDETERMINATE":
            foreign = _foreign_protocol(response)
            if foreign is not None and foreign != protocol:
                decision = ProbeDecision(
                    "NO_MATCH",
                    f"received a complete protocol-valid {foreign} response instead of {protocol}",
                    f"foreign_{foreign}_response",
                    foreign.upper(),
                )
    return {
        "matched": decision.matched,
        "outcome": decision.outcome,
        "reason": decision.reason,
        "response_class": decision.response_class,
        "response_magic": decision.magic,
        "response_version": decision.version,
        "policy_version": policy_version,
    }


def evaluate_staged_service_probe_responses(
    protocol: str,
    stage_responses: list[bytes] | tuple[bytes, ...],
    *,
    port: int,
    stop_reason: str = "response_complete",
    error_class: str | None = None,
    transport: str = "tcp",
) -> dict[str, Any]:
    """Evaluate only complete phase-aware evidence for a staged text adapter."""
    adapter = ADAPTERS.get(protocol)
    if not isinstance(adapter, StagedTextProbeSpec):
        decision = _indeterminate("staged probe adapter is unsupported")
    elif transport.lower() != "tcp":
        decision = _indeterminate("probe transport is unsupported")
    elif error_class is not None or stop_reason != "response_complete":
        decision = _indeterminate("staged probe acquisition did not complete")
    elif not stage_responses:
        decision = _indeterminate("server greeting stage is missing")
    else:
        stage1 = adapter.stage1_parser(stage_responses[0])
        if not stage1.valid:
            decision = _indeterminate(stage1.reason, stage1.response_class)
        elif len(stage_responses) != MAX_SERVICE_PROBE_STAGES:
            decision = _indeterminate("required two-stage exchange is incomplete", stage1.response_class)
        else:
            stage2 = adapter.stage2_parser(stage_responses[1])
            if not stage2.valid:
                decision = _indeterminate(stage2.reason, stage2.response_class)
            elif protocol == "smtp" and port in SMTP_STANDARD_PORTS:
                decision = ProbeDecision(
                    "NO_MATCH",
                    "SMTP was positively identified but the declared port is standard under smtp-standard-ports.v1",
                    "smtp_verified_standard_port",
                    stage2.magic,
                    stage2.version,
                )
            else:
                decision = _match(stage2.reason, stage2.response_class or "staged_protocol_response", stage2.magic or protocol.upper(), stage2.version)
    result = {
        "matched": decision.matched,
        "outcome": decision.outcome,
        "reason": decision.reason,
        "response_class": decision.response_class,
        "response_magic": decision.magic,
        "response_version": decision.version,
        "policy_version": WAVE5A_SERVICE_POLICY_VERSION,
    }
    if protocol == "smtp":
        result.update({
            "port_policy_version": SMTP_STANDARD_PORT_POLICY_VERSION,
            "standard_ports": sorted(SMTP_STANDARD_PORTS),
        })
    return result


def _line_budget_stop(data: bytes) -> str | None:
    pieces = data.split(b"\n")
    if any(
        len(piece) + (1 if index < len(pieces) - 1 else 0) > MAX_SERVICE_PROBE_LINE_BYTES
        for index, piece in enumerate(pieces)
    ):
        return "line_length_limit"
    line_count = len(pieces) - (1 if pieces[-1] == b"" else 0)
    if line_count > MAX_SERVICE_PROBE_LINES:
        return "line_count_limit"
    return None


def _stage_evidence(
    number: int,
    response: bytes,
    parsed: TextStageResult | None,
    *,
    bytes_sent: int,
    completion_reason: str,
) -> dict[str, Any]:
    evidence = {
        "stage_number": number,
        "direction": "server_to_client" if number == 1 else "client_to_server_then_server_to_client",
        "bytes_sent": bytes_sent,
        "bytes_received": len(response),
        "response_sha256": hashlib.sha256(response).hexdigest() if response else None,
        "response_class": parsed.response_class if parsed is not None else None,
        "completion_reason": completion_reason,
    }
    if parsed is not None and parsed.normalized:
        evidence["normalized"] = parsed.normalized
    return evidence


def _run_staged_service_probe(
    connect_host: str,
    port: int,
    adapter: StagedTextProbeSpec,
    *,
    timeout: float,
    response_limit: int,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    deadline = started + timeout
    responses: list[bytes] = []
    stages: list[dict[str, Any]] = []
    combined = bytearray()
    total_sent = 0
    stop_reason = "not_started"
    error_class: str | None = None
    active_phase = "connect"

    def read_stage(connection: socket.socket, completion: Callable[[bytes], bool]) -> tuple[bytes, str, str | None]:
        response = bytearray()
        while True:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                return bytes(response), "timed_out", None
            remaining_bytes = response_limit - len(combined)
            if remaining_bytes <= 0:
                return bytes(response), "response_limit", None
            connection.settimeout(remaining_time)
            try:
                chunk = connection.recv(min(512, remaining_bytes))
            except socket.timeout as exc:
                return bytes(response), "timed_out", exc.__class__.__name__
            except ConnectionResetError as exc:
                return bytes(response), "reset", exc.__class__.__name__
            except OSError as exc:
                return bytes(response), "read_error", exc.__class__.__name__
            if not chunk:
                return bytes(response), "peer_closed", None
            response.extend(chunk)
            combined.extend(chunk)
            budget_stop = _line_budget_stop(bytes(combined))
            if budget_stop is not None:
                return bytes(response), budget_stop, None
            if completion(bytes(response)):
                return bytes(response), "response_complete", None

    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("service probe deadline exhausted before connect")
        with socket.create_connection((connect_host, port), timeout=remaining) as connection:
            active_phase = "stage1_read"
            stage1_response, stage1_stop, stage1_error = read_stage(connection, adapter.stage1_completion)
            responses.append(stage1_response)
            stage1_parsed = adapter.stage1_parser(stage1_response) if stage1_stop == "response_complete" else None
            stages.append(_stage_evidence(
                1, stage1_response, stage1_parsed, bytes_sent=0, completion_reason=stage1_stop,
            ))
            stop_reason, error_class = stage1_stop, stage1_error
            if stage1_stop == "response_complete" and stage1_parsed is not None and stage1_parsed.valid:
                stages.append(_stage_evidence(
                    2, b"", None, bytes_sent=0, completion_reason="not_started",
                ))
                if len(adapter.outbound_payload) > MAX_SERVICE_PROBE_OUTBOUND_BYTES:
                    stop_reason = "outbound_limit"
                    stages[-1]["completion_reason"] = stop_reason
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        stop_reason = "timed_out"
                        stages[-1]["completion_reason"] = stop_reason
                    else:
                        active_phase = "stage2_write"
                        connection.settimeout(remaining)
                        try:
                            connection.sendall(adapter.outbound_payload)
                            total_sent = len(adapter.outbound_payload)
                            stages[-1]["bytes_sent"] = total_sent
                        except socket.timeout as exc:
                            stop_reason, error_class = "timed_out", exc.__class__.__name__
                            stages[-1]["completion_reason"] = stop_reason
                        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                            stop_reason, error_class = "write_error", exc.__class__.__name__
                            stages[-1]["completion_reason"] = stop_reason
                        else:
                            if time.monotonic() >= deadline:
                                stop_reason = "timed_out"
                                stages[-1]["completion_reason"] = stop_reason
                            else:
                                active_phase = "stage2_read"
                                stage2_response, stage2_stop, stage2_error = read_stage(connection, adapter.stage2_completion)
                                responses.append(stage2_response)
                                stage2_parsed = adapter.stage2_parser(stage2_response) if stage2_stop == "response_complete" else None
                                stages[-1] = _stage_evidence(
                                    2, stage2_response, stage2_parsed,
                                    bytes_sent=total_sent, completion_reason=stage2_stop,
                                )
                                stop_reason, error_class = stage2_stop, stage2_error
    except socket.timeout as exc:
        stop_reason, error_class = "timed_out", exc.__class__.__name__
    except ConnectionResetError as exc:
        stop_reason, error_class = "reset", exc.__class__.__name__
    except OSError as exc:
        stop_reason = "connect_error" if active_phase == "connect" else "read_error"
        error_class = exc.__class__.__name__

    completed_at = datetime.now(timezone.utc)
    decision = evaluate_staged_service_probe_responses(
        adapter.protocol,
        responses,
        port=port,
        stop_reason=stop_reason,
        error_class=error_class,
    )
    return {
        "protocol": adapter.protocol,
        "issue_key": adapter.issue_key,
        "transport": "tcp",
        "port": port,
        "probe_type": adapter.probe_type,
        "probe_version": adapter.probe_version,
        "framework_version": SERVICE_PROBE_FRAMEWORK_VERSION,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "stage_count": len(stages),
        "stages": stages,
        "total_bytes_sent": total_sent,
        "total_bytes_received": len(combined),
        # Preserve the Wave 3A flat evidence keys for downstream compatibility.
        "bytes_sent": total_sent,
        "bytes_received": len(combined),
        "response_sha256": hashlib.sha256(combined).hexdigest() if combined else None,
        "stop_reason": stop_reason,
        "error_class": error_class,
        **decision,
    }


def run_service_probe(
    connect_host: str,
    port: int,
    protocol: str,
    *,
    timeout: float,
    response_limit: int,
) -> dict[str, Any]:
    adapter = ADAPTERS[protocol]
    if isinstance(adapter, StagedTextProbeSpec):
        return _run_staged_service_probe(
            connect_host, port, adapter, timeout=timeout, response_limit=response_limit,
        )
    started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    response = bytearray()
    sent = 0
    stop_reason = "not_started"
    error_class = None
    stage = "connect"
    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            if adapter.initial_payload:
                stage = "write"
                connection.sendall(adapter.initial_payload)
                sent += len(adapter.initial_payload)
            stage = "read"
            while len(response) < response_limit:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    stop_reason = "timed_out"
                    break
                connection.settimeout(remaining)
                try:
                    chunk = connection.recv(min(512, response_limit - len(response)))
                except socket.timeout:
                    stop_reason = "timed_out"
                    break
                except ConnectionResetError as exc:
                    stop_reason, error_class = "reset", exc.__class__.__name__
                    break
                except OSError as exc:
                    stop_reason, error_class = "read_error", exc.__class__.__name__
                    break
                if not chunk:
                    stop_reason = "peer_closed"
                    break
                response.extend(chunk)
                if adapter.completion(bytes(response)):
                    stop_reason = "response_complete"
                    break
            else:
                stop_reason = "response_limit"
            if stop_reason == "response_complete" and adapter.followup is not None:
                followup = adapter.followup(bytes(response))
                if followup:
                    stage = "write"
                    connection.sendall(followup)
                    sent += len(followup)
    except socket.timeout as exc:
        stop_reason, error_class = "timed_out", exc.__class__.__name__
    except ConnectionResetError as exc:
        stop_reason, error_class = "reset", exc.__class__.__name__
    except OSError as exc:
        stop_reason, error_class = ("write_error" if stage == "write" else "connect_error"), exc.__class__.__name__

    completed_at = datetime.now(timezone.utc)
    decision = evaluate_service_probe_response(
        protocol, bytes(response), stop_reason=stop_reason, error_class=error_class,
    )
    stage_evidence = {
        "stage_number": 1,
        "direction": "server_to_client" if adapter.server_first else "client_to_server_then_server_to_client",
        "bytes_sent": sent,
        "bytes_received": len(response),
        "response_sha256": hashlib.sha256(response).hexdigest() if response else None,
        "response_class": decision["response_class"],
        "completion_reason": stop_reason,
    }
    return {
        "protocol": protocol,
        "issue_key": adapter.issue_key,
        "transport": "tcp",
        "port": port,
        "probe_type": adapter.probe_type,
        "probe_version": adapter.probe_version,
        "framework_version": SERVICE_PROBE_FRAMEWORK_VERSION,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "stage_count": 1,
        "stages": [stage_evidence],
        "total_bytes_sent": sent,
        "total_bytes_received": len(response),
        "bytes_sent": sent,
        "bytes_received": len(response),
        "response_sha256": hashlib.sha256(response).hexdigest() if response else None,
        "stop_reason": stop_reason,
        "error_class": error_class,
        **decision,
    }


def aggregate_service_probe_evaluations(attempts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for attempt in attempts:
        grouped.setdefault(attempt["issue_key"], []).append(attempt)
    evaluations = {}
    for issue_key, issue_attempts in grouped.items():
        outcomes = [item["outcome"] for item in issue_attempts]
        if "MATCH" in outcomes:
            outcome, matched, reason = "MATCH", True, "at least one declared endpoint returned protocol-valid identification evidence"
        elif outcomes and all(value == "NO_MATCH" for value in outcomes):
            outcome, matched, reason = "NO_MATCH", False, "every declared endpoint returned a deterministic reviewed negative"
        else:
            outcome, matched, reason = "INDETERMINATE", None, "one or more declared endpoints lacked conclusive protocol evidence"
        evaluations[issue_key] = {
            "outcome": outcome,
            "matched": matched,
            "reason": reason,
            "policy_version": issue_attempts[0].get("policy_version", SERVICE_PROBE_POLICY_VERSION),
            "attempts": issue_attempts,
        }
    return evaluations
