"""Bounded pre-authentication SSH identification and SSH2 KEXINIT collection.

The immutable SSC issue details define the policy categories as CBC/Arcfour
ciphers, MD5 MACs, and protocol versions below 2.  Exact wire names are pinned
here so target-controlled names are never classified by substring.
"""
from __future__ import annotations

import hashlib
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any


SSH_COLLECTOR_VERSION = "ssc-ssh-negotiation-collector.v1"
SSH_CRYPTO_POLICY_VERSION = "ssc-wave4a-ssh-crypto-policy.v1"
SSH_AEAD_POLICY_VERSION = "ssc-wave4a-ssh-aead-policy.v2"
CLIENT_IDENTIFICATION = b"SSH-2.0-SSC_Wave4A_1.0\r\n"

MAX_SSH_ENDPOINTS = 6
MAX_IDENTIFICATION_LINE_BYTES = 255
MAX_IDENTIFICATION_BYTES = 2048
MAX_IDENTIFICATION_LINES = 8
MAX_PACKET_BYTES = 35000
MAX_TOTAL_BYTES = 131072
MAX_PACKET_COUNT = 4
MAX_NAME_LIST_BYTES = 4096
MAX_ALGORITHMS_PER_LIST = 128

# Provenance: immutable SSC detail ssh_weak_cipher says Arcfour or CBC.
# Spellings are from RFC 4253 section 6.3, RFC 4345, the IANA SSH encryption
# registry, and the historical OpenSSH Rijndael CBC alias.  `none` is omitted:
# it is not within the reviewed SSC category.
PROHIBITED_CIPHERS = frozenset({
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "des-cbc",
    "idea-cbc",
    "rijndael-cbc@lysator.liu.se",
    "serpent128-cbc",
    "serpent192-cbc",
    "serpent256-cbc",
    "twofish-cbc",
    "twofish128-cbc",
    "twofish192-cbc",
    "twofish256-cbc",
})

# Provenance: immutable SSC detail ssh_weak_mac says MD5.  RFC 4253 defines
# the first two names; OpenSSH documents the encrypt-then-MAC variants.
PROHIBITED_MACS = frozenset({
    "hmac-md5",
    "hmac-md5-96",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
})

MAC_IGNORED = "MAC_IGNORED"
PAIRED_AEAD_MAC = "PAIRED_AEAD_MAC"

# Versioned exact-name AEAD negotiation policy.  RFC 5647 section 5.1 requires
# AES-GCM to be selected in both roles, and section 9 registers the uppercase
# names in both SSH encryption and MAC name spaces.  The OpenSSH
# AES-GCM extension and the IETF/OpenSSH ChaCha20-Poly1305 specifications put
# integrated integrity in the cipher and ignore separate MAC negotiation.
# No target-controlled name is classified by substring.
AEAD_CIPHER_MAC_MODES = {
    "AEAD_AES_128_GCM": PAIRED_AEAD_MAC,
    "AEAD_AES_256_GCM": PAIRED_AEAD_MAC,
    "aes128-gcm@openssh.com": MAC_IGNORED,
    "aes256-gcm@openssh.com": MAC_IGNORED,
    "chacha20-poly1305": MAC_IGNORED,
    "chacha20-poly1305@openssh.com": MAC_IGNORED,
}
AEAD_CIPHERS = frozenset(AEAD_CIPHER_MAC_MODES)

# Exact IANA/OpenSSH encryption identifiers known to use standalone SSH MAC
# negotiation.  An unclassified private/future cipher is not assumed to be in
# this set: when no known non-AEAD cipher is present, applicability fails closed.
KNOWN_NON_AEAD_CIPHERS = PROHIBITED_CIPHERS | frozenset({
    "3des-ctr",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "blowfish-ctr",
    "cast128-ctr",
    "idea-ctr",
    "none",
    "serpent128-ctr",
    "serpent192-ctr",
    "serpent256-ctr",
    "twofish128-ctr",
    "twofish192-ctr",
    "twofish256-ctr",
})

_IDENTIFICATION = re.compile(rb"^SSH-([0-9]+\.[0-9]+)-([\x21-\x7e]+)(?: ([\x20-\x7e]*))?$")
_ALGORITHM_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)
_PERSISTED_ALGORITHM_FIELDS = _ALGORITHM_FIELDS[:6]


class SSHProtocolError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _base_attempt(hostname: str, connect_host: str, port: int, timeout: float) -> dict[str, Any]:
    return {
        "port": port,
        "hostname": hostname,
        "resolved_address": connect_host,
        "transport": "tcp",
        "collector_version": SSH_COLLECTOR_VERSION,
        "crypto_policy_version": SSH_CRYPTO_POLICY_VERSION,
        "aead_policy_version": SSH_AEAD_POLICY_VERSION,
        "limits": {
            "timeout_seconds": timeout,
            "identification_line_bytes": MAX_IDENTIFICATION_LINE_BYTES,
            "identification_total_bytes": MAX_IDENTIFICATION_BYTES,
            "identification_lines": MAX_IDENTIFICATION_LINES,
            "packet_bytes": MAX_PACKET_BYTES,
            "total_bytes": MAX_TOTAL_BYTES,
            "packet_count": MAX_PACKET_COUNT,
            "algorithm_list_bytes": MAX_NAME_LIST_BYTES,
            "algorithms_per_list": MAX_ALGORITHMS_PER_LIST,
        },
        "identification_status": "not_received",
        "identification_protocol_version": None,
        "identification_sha256": None,
        "kexinit_status": "not_received",
        **{field: None for field in _PERSISTED_ALGORITHM_FIELDS},
        "bytes_sent": 0,
        "bytes_received": 0,
        "packets_received": 0,
        "authentication_attempted": False,
        "application_commands_sent": 0,
        "stop_reason": "not_started",
        "error_class": None,
        "error_reason": None,
        "response_state": "unavailable",
    }


def parse_identification_line(line: bytes) -> dict[str, str]:
    """Validate one complete SSH identification line without retaining it."""
    if not line.endswith(b"\n"):
        raise SSHProtocolError("truncated_identification")
    if len(line) > MAX_IDENTIFICATION_LINE_BYTES:
        raise SSHProtocolError("oversized_identification")
    wire = line
    value = line[:-1]
    if value.endswith(b"\r"):
        value = value[:-1]
    matched = _IDENTIFICATION.fullmatch(value)
    if matched is None:
        raise SSHProtocolError("malformed_identification")
    protocol = matched.group(1).decode("ascii")
    return {
        "protocol_version": protocol,
        "sha256": hashlib.sha256(wire).hexdigest(),
    }


def _parse_name_list(payload: bytes, offset: int, *, field: str) -> tuple[list[str], int]:
    if offset + 4 > len(payload):
        raise SSHProtocolError("truncated_kexinit")
    size = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    if size > MAX_NAME_LIST_BYTES:
        raise SSHProtocolError("excessive_algorithm_list")
    if offset + size > len(payload):
        raise SSHProtocolError("truncated_kexinit")
    raw = payload[offset:offset + size]
    offset += size
    if not raw:
        return [], offset
    parts = raw.split(b",")
    if len(parts) > MAX_ALGORITHMS_PER_LIST:
        raise SSHProtocolError("excessive_algorithm_list")
    values: list[str] = []
    for part in parts:
        if not part or len(part) > 64 or any(byte < 33 or byte > 126 or byte == 44 for byte in part):
            raise SSHProtocolError("malformed_algorithm_list")
        values.append(part.decode("ascii"))
    if len(values) != len(set(values)):
        raise SSHProtocolError("malformed_algorithm_list")
    return values, offset


def parse_kexinit_payload(payload: bytes) -> dict[str, list[str]]:
    """Parse a complete unencrypted SSH_MSG_KEXINIT payload."""
    if len(payload) < 22 or payload[0] != 20:
        raise SSHProtocolError("not_kexinit")
    offset = 17  # message number plus 16-byte cookie
    parsed: dict[str, list[str]] = {}
    for field in _ALGORITHM_FIELDS:
        parsed[field], offset = _parse_name_list(payload, offset, field=field)
    if offset + 5 > len(payload):
        raise SSHProtocolError("truncated_kexinit")
    first_packet_follows = payload[offset]
    reserved = int.from_bytes(payload[offset + 1:offset + 5], "big")
    offset += 5
    if first_packet_follows not in (0, 1) or reserved != 0 or offset != len(payload):
        raise SSHProtocolError("malformed_kexinit")
    # KEX, host-key, cipher, and compression lists are always required.  For
    # the two MAC lists, modern AEAD extensions make standalone MAC selection
    # unnecessary; accept an empty list only when every cipher in that exact
    # direction is recognized by the pinned AEAD policy.
    for field in (
        "kex_algorithms", "server_host_key_algorithms",
        "encryption_algorithms_client_to_server", "encryption_algorithms_server_to_client",
        "compression_algorithms_client_to_server", "compression_algorithms_server_to_client",
    ):
        if not parsed[field]:
            raise SSHProtocolError("missing_required_algorithm_list")
    for cipher_field, mac_field in (
        ("encryption_algorithms_client_to_server", "mac_algorithms_client_to_server"),
        ("encryption_algorithms_server_to_client", "mac_algorithms_server_to_client"),
    ):
        if not parsed[mac_field] and not set(parsed[cipher_field]).issubset(AEAD_CIPHERS):
            raise SSHProtocolError("missing_required_algorithm_list")
    return {field: parsed[field] for field in _PERSISTED_ALGORITHM_FIELDS}


def _deadline_recv(connection: socket.socket, size: int, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    connection.settimeout(remaining)
    return connection.recv(size)


def _read_identification(
    connection: socket.socket,
    buffer: bytearray,
    deadline: float,
    attempt: dict[str, Any],
) -> tuple[dict[str, str], bytearray]:
    total = len(buffer)
    lines = 0
    while lines < MAX_IDENTIFICATION_LINES:
        newline = buffer.find(b"\n")
        while newline < 0:
            if len(buffer) > MAX_IDENTIFICATION_LINE_BYTES:
                raise SSHProtocolError("oversized_identification")
            if total >= MAX_IDENTIFICATION_BYTES:
                raise SSHProtocolError("identification_byte_limit")
            chunk = _deadline_recv(connection, min(512, MAX_IDENTIFICATION_BYTES - total), deadline)
            if not chunk:
                raise SSHProtocolError("truncated_identification" if buffer else "non_ssh_service")
            buffer.extend(chunk)
            total += len(chunk)
            attempt["bytes_received"] += len(chunk)
            newline = buffer.find(b"\n")
        line = bytes(buffer[:newline + 1])
        del buffer[:newline + 1]
        lines += 1
        if line.startswith(b"SSH-"):
            return parse_identification_line(line), buffer
        if len(line) > MAX_IDENTIFICATION_LINE_BYTES or b"\x00" in line:
            raise SSHProtocolError("malformed_identification")
    raise SSHProtocolError("identification_line_limit")


def _read_exact(
    connection: socket.socket,
    buffer: bytearray,
    size: int,
    deadline: float,
    attempt: dict[str, Any],
) -> bytes:
    while len(buffer) < size:
        remaining_budget = MAX_TOTAL_BYTES - attempt["bytes_received"]
        if remaining_budget <= 0:
            raise SSHProtocolError("total_byte_limit")
        chunk = _deadline_recv(connection, min(4096, size - len(buffer), remaining_budget), deadline)
        if not chunk:
            raise SSHProtocolError("truncated_packet")
        buffer.extend(chunk)
        attempt["bytes_received"] += len(chunk)
    value = bytes(buffer[:size])
    del buffer[:size]
    return value


def _read_kexinit(
    connection: socket.socket,
    buffer: bytearray,
    deadline: float,
    attempt: dict[str, Any],
) -> dict[str, list[str]]:
    for _ in range(MAX_PACKET_COUNT):
        header = _read_exact(connection, buffer, 4, deadline, attempt)
        packet_length = int.from_bytes(header, "big")
        if packet_length < 12 or packet_length > MAX_PACKET_BYTES:
            raise SSHProtocolError("malformed_packet_length" if packet_length < 12 else "oversized_packet")
        if (packet_length + 4) % 8:
            raise SSHProtocolError("malformed_packet_length")
        packet = _read_exact(connection, buffer, packet_length, deadline, attempt)
        attempt["packets_received"] += 1
        padding_length = packet[0]
        if padding_length < 4 or padding_length > packet_length - 2:
            raise SSHProtocolError("malformed_packet")
        payload = packet[1:packet_length - padding_length]
        if not payload:
            raise SSHProtocolError("malformed_packet")
        if payload[0] == 20:
            return parse_kexinit_payload(payload)
        if payload[0] == 1:
            raise SSHProtocolError("server_disconnect_before_kexinit")
    raise SSHProtocolError("packet_count_limit")


def collect_ssh_negotiation(
    connect_host: str,
    hostname: str,
    port: int,
    *,
    timeout: float,
) -> dict[str, Any]:
    """Use one TCP connection and stop immediately after server KEXINIT."""
    attempt = _base_attempt(hostname, connect_host, port, timeout)
    started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    attempt["started_at"] = started_at.isoformat()
    deadline = started + timeout
    buffer = bytearray()
    stage = "connect"
    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as connection:
            stage = "identification"
            identification, buffer = _read_identification(connection, buffer, deadline, attempt)
            protocol = identification["protocol_version"]
            attempt.update({
                "identification_status": "valid",
                "identification_protocol_version": protocol,
                "identification_sha256": identification["sha256"],
                "response_state": "ssh_valid",
            })
            if protocol.startswith("1.") and protocol != "1.99":
                attempt["kexinit_status"] = "not_applicable"
                attempt["stop_reason"] = "ssh1_identification_complete"
            elif protocol in {"2.0", "1.99"}:
                stage = "client_identification"
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                connection.settimeout(remaining)
                connection.sendall(CLIENT_IDENTIFICATION)
                attempt["bytes_sent"] = len(CLIENT_IDENTIFICATION)
                stage = "kexinit"
                algorithms = _read_kexinit(connection, buffer, deadline, attempt)
                attempt.update(algorithms)
                attempt["kexinit_status"] = "complete"
                attempt["stop_reason"] = "kexinit_complete"
            else:
                attempt["response_state"] = "ssh_ambiguous"
                attempt["kexinit_status"] = "not_applicable"
                attempt["stop_reason"] = "unsupported_protocol"
    except TimeoutError as exc:
        attempt["stop_reason"] = "timed_out"
        attempt["error_class"] = exc.__class__.__name__
        attempt["error_reason"] = f"{stage}_timeout"
        if attempt["identification_status"] == "valid":
            attempt["response_state"] = "ssh_ambiguous"
        elif attempt["bytes_received"]:
            attempt["response_state"] = "non_ssh"
    except ConnectionResetError as exc:
        attempt["stop_reason"] = "reset"
        attempt["error_class"] = exc.__class__.__name__
        attempt["error_reason"] = f"{stage}_reset"
        if attempt["identification_status"] == "valid":
            attempt["response_state"] = "ssh_ambiguous"
        elif attempt["bytes_received"]:
            attempt["response_state"] = "non_ssh"
    except SSHProtocolError as exc:
        attempt["stop_reason"] = exc.reason
        attempt["error_class"] = exc.__class__.__name__
        attempt["error_reason"] = exc.reason
        if attempt["identification_status"] == "valid" or exc.reason != "non_ssh_service":
            attempt["response_state"] = "ssh_ambiguous"
        else:
            attempt["response_state"] = "non_ssh"
    except (socket.timeout, OSError) as exc:
        attempt["stop_reason"] = "timed_out" if isinstance(exc, socket.timeout) else f"{stage}_error"
        attempt["error_class"] = exc.__class__.__name__
        attempt["error_reason"] = attempt["stop_reason"]
        if attempt["identification_status"] == "valid":
            attempt["response_state"] = "ssh_ambiguous"
    attempt["completed_at"] = datetime.now(timezone.utc).isoformat()
    attempt["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    attempt["evaluations"] = evaluate_ssh_attempt(attempt)
    return attempt


def _decision(outcome: str, reason: str, **evidence: Any) -> dict[str, Any]:
    return {
        "outcome": outcome,
        "matched": {"MATCH": True, "NO_MATCH": False}.get(outcome),
        "reason": reason,
        "policy_version": SSH_CRYPTO_POLICY_VERSION,
        **evidence,
    }


def _evaluate_mac_direction(
    direction: str,
    cipher_algorithms: Any,
    mac_algorithms: Any,
    *,
    complete: bool,
) -> dict[str, Any]:
    result = {
        "direction": direction,
        "aead_only": None,
        "cipher_mac_modes": {},
        "mac_ignored_aead": [],
        "paired_aead": [],
        "paired_aead_consistent": None,
        "standalone_mac_applicable": None,
        "prohibited_mac_matches": [],
        "advertised_prohibited_mac_names": [],
        "unknown_cipher_algorithms": [],
        "evaluation_reason": "complete directional cipher/MAC evidence was not obtained",
        "outcome": "INDETERMINATE",
    }
    if not complete:
        return result
    if (
        not isinstance(cipher_algorithms, list) or not cipher_algorithms
        or not all(isinstance(name, str) and name for name in cipher_algorithms)
    ):
        result["evaluation_reason"] = "cipher applicability is missing or incomplete"
        return result
    cipher_names = set(cipher_algorithms)
    known_non_aead = cipher_names & KNOWN_NON_AEAD_CIPHERS
    unknown_ciphers = cipher_names - AEAD_CIPHERS - KNOWN_NON_AEAD_CIPHERS
    mac_ignored_aead = {
        name for name in cipher_names if AEAD_CIPHER_MAC_MODES.get(name) == MAC_IGNORED
    }
    paired_aead = {
        name for name in cipher_names if AEAD_CIPHER_MAC_MODES.get(name) == PAIRED_AEAD_MAC
    }
    result.update({
        "cipher_mac_modes": {
            name: AEAD_CIPHER_MAC_MODES[name]
            for name in sorted(cipher_names & AEAD_CIPHERS)
        },
        "mac_ignored_aead": sorted(mac_ignored_aead),
        "paired_aead": sorted(paired_aead),
        "unknown_cipher_algorithms": sorted(unknown_ciphers),
    })
    if not isinstance(mac_algorithms, list) or not all(isinstance(name, str) and name for name in mac_algorithms):
        result["evaluation_reason"] = "MAC evidence is missing or malformed"
        return result

    advertised_prohibited = sorted(set(mac_algorithms) & PROHIBITED_MACS)
    result["advertised_prohibited_mac_names"] = advertised_prohibited

    if known_non_aead:
        result.update({
            "aead_only": False,
            "standalone_mac_applicable": True,
        })
        if not mac_algorithms:
            result["evaluation_reason"] = "a standalone MAC is selectable but its MAC list is empty"
            return result
        result.update({
            "prohibited_mac_matches": advertised_prohibited,
            "evaluation_reason": (
                "an exact prohibited standalone MAC is selectable with a known non-AEAD cipher"
                if advertised_prohibited else
                "a standalone MAC is selectable and the complete MAC list contains no prohibited name"
            ),
            "outcome": "MATCH" if advertised_prohibited else "NO_MATCH",
        })
        return result

    if not unknown_ciphers:
        result.update({
            "aead_only": True,
            "standalone_mac_applicable": False,
        })
        if paired_aead:
            paired_consistent = paired_aead.issubset(set(mac_algorithms))
            result["paired_aead_consistent"] = paired_consistent
            if not paired_consistent:
                result["evaluation_reason"] = (
                    "RFC 5647 AEAD encryption names lack matching paired MAC-list evidence"
                )
                return result
            result["evaluation_reason"] = (
                "all RFC 5647 AEAD names have matching paired MAC evidence and no standalone MAC is selectable"
                if not mac_ignored_aead else
                "mixed recognized AEAD modes have complete RFC 5647 pairing and no standalone MAC is selectable"
            )
        else:
            result["evaluation_reason"] = (
                "only MAC-ignored AEAD ciphers are selectable; standalone MAC names are not applicable"
            )
        result["outcome"] = "NO_MATCH"
        return result

    result["evaluation_reason"] = "cipher applicability is unknown under the pinned AEAD policy"
    return result


def evaluate_ssh_attempt(attempt: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Evaluate the exact three Wave 4A issues for one endpoint."""
    version = attempt.get("identification_protocol_version")
    complete = attempt.get("identification_status") == "valid" and attempt.get("kexinit_status") == "complete"
    if attempt.get("crypto_policy_version") != SSH_CRYPTO_POLICY_VERSION:
        unknown = _decision("INDETERMINATE", "unknown SSH crypto-policy version")
        return {key: dict(unknown) for key in ("ssh_weak_protocol", "ssh_weak_cipher", "ssh_weak_mac")}

    if isinstance(version, str) and version.startswith("1.") and version != "1.99":
        protocol = _decision("MATCH", "valid SSH identification deterministically advertises a protocol version below 2")
    elif version == "2.0" and complete:
        protocol = _decision("NO_MATCH", "valid SSH-2.0 identification and complete SSH2 KEXINIT provide no prohibited-protocol evidence")
    elif version == "1.99":
        protocol = _decision("INDETERMINATE", "SSH-1.99 compatibility is not treated as proof of SSH1 support")
    else:
        protocol = _decision("INDETERMINATE", "complete valid SSH2 protocol evidence was not obtained")

    c2s = attempt.get("encryption_algorithms_client_to_server")
    s2c = attempt.get("encryption_algorithms_server_to_client")
    if not complete or not isinstance(c2s, list) or not isinstance(s2c, list) or not c2s or not s2c:
        cipher = _decision("INDETERMINATE", "complete cipher lists in both SSH2 directions were not obtained")
    else:
        prohibited = sorted((set(c2s) | set(s2c)) & PROHIBITED_CIPHERS)
        cipher = _decision(
            "MATCH" if prohibited else "NO_MATCH",
            "server KEXINIT advertises an exact policy-prohibited cipher" if prohibited else
            "both complete cipher lists contain no exact policy-prohibited name",
            prohibited_algorithms=prohibited,
        )

    mac_c2s = attempt.get("mac_algorithms_client_to_server")
    mac_s2c = attempt.get("mac_algorithms_server_to_client")
    if attempt.get("aead_policy_version") != SSH_AEAD_POLICY_VERSION:
        mac = _decision(
            "INDETERMINATE",
            "unknown SSH AEAD applicability-policy version",
            aead_policy_version=attempt.get("aead_policy_version"),
            direction_evaluations=[],
        )
    else:
        directions = [
            _evaluate_mac_direction("client_to_server", c2s, mac_c2s, complete=complete),
            _evaluate_mac_direction("server_to_client", s2c, mac_s2c, complete=complete),
        ]
        if any(item["outcome"] == "MATCH" for item in directions):
            mac_outcome = "MATCH"
            mac_reason = "a prohibited standalone MAC is deterministically selectable in at least one direction"
        elif all(item["outcome"] == "NO_MATCH" for item in directions):
            mac_outcome = "NO_MATCH"
            mac_reason = "both SSH directions are conclusively clean for selectable standalone MACs"
        else:
            mac_outcome = "INDETERMINATE"
            mac_reason = "standalone MAC applicability or required MAC evidence is inconclusive"
        prohibited = sorted({
            name for item in directions for name in item["prohibited_mac_matches"]
        })
        mac = _decision(
            mac_outcome,
            mac_reason,
            prohibited_algorithms=prohibited,
            aead_policy_version=SSH_AEAD_POLICY_VERSION,
            direction_evaluations=directions,
        )
    return {
        "ssh_weak_protocol": protocol,
        "ssh_weak_cipher": cipher,
        "ssh_weak_mac": mac,
    }


def aggregate_ssh_evaluations(attempts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Aggregate only response-bearing SSH endpoints; unavailable/foreign peers are outside that boundary."""
    evaluations: dict[str, dict[str, Any]] = {}
    for issue_key in ("ssh_weak_protocol", "ssh_weak_cipher", "ssh_weak_mac"):
        endpoint_results = []
        for attempt in attempts:
            decision = attempt.get("evaluations", {}).get(issue_key) or evaluate_ssh_attempt(attempt)[issue_key]
            endpoint_result = {
                "port": attempt.get("port"),
                "response_state": attempt.get("response_state"),
                "outcome": decision["outcome"],
                "reason": decision["reason"],
                "stop_reason": attempt.get("stop_reason"),
                "prohibited_algorithms": decision.get("prohibited_algorithms", []),
            }
            if "direction_evaluations" in decision:
                endpoint_result["direction_evaluations"] = decision["direction_evaluations"]
            endpoint_results.append(endpoint_result)
        applicable = [item for item in endpoint_results if item["response_state"] in {"ssh_valid", "ssh_ambiguous"}]
        if any(item["outcome"] == "MATCH" for item in applicable):
            outcome, reason = "MATCH", "at least one declared SSH endpoint deterministically matches"
        elif applicable and all(item["outcome"] == "NO_MATCH" for item in applicable):
            outcome, reason = "NO_MATCH", "every response-bearing applicable SSH endpoint is conclusively negative"
        else:
            outcome, reason = "INDETERMINATE", "zero usable SSH endpoints or an applicable SSH endpoint is ambiguous"
        evaluations[issue_key] = _decision(outcome, reason, endpoint_results=endpoint_results)
    return evaluations
