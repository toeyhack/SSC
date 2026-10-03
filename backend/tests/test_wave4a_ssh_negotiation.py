import hashlib
import json
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import engine
from app.models.catalog_models import CatalogIssueTypeVersion, SourceTypeEnum
from app.models.rule_models import RuleEngineRule
from app.models.scan_models import ScanTargetTypeEnum
from app.services.cli_scan import scan_inventory_target
from app.services.cli_setup import add_inventory_target
from app.services.golden_baseline_importer import import_golden_baseline
from app.services.scan_executors import InventoryScanTarget, TCPExecutor, validate_scan_config
from app.services.scoring_engine import ScoringDefinition
from app.services.ssh_negotiation import (
    AEAD_CIPHER_MAC_MODES,
    AEAD_CIPHERS,
    CLIENT_IDENTIFICATION,
    MAX_ALGORITHMS_PER_LIST,
    MAX_PACKET_BYTES,
    MAC_IGNORED,
    KNOWN_NON_AEAD_CIPHERS,
    PAIRED_AEAD_MAC,
    PROHIBITED_CIPHERS,
    PROHIBITED_MACS,
    SSH_AEAD_POLICY_VERSION,
    SSH_COLLECTOR_VERSION,
    SSH_CRYPTO_POLICY_VERSION,
    SSHProtocolError,
    aggregate_ssh_evaluations,
    collect_ssh_negotiation,
    evaluate_ssh_attempt,
    parse_identification_line,
    parse_kexinit_payload,
)
from app.services.ssc_api_baseline import API_ORIGIN, FACTORS_ENDPOINT, ISSUES_ENDPOINT, normalize_api_payloads
from app.services.wave1_rules import WAVE1_RULES
from app.services.wave2_rules import WAVE2_RULES
from app.services.wave3a_rules import WAVE3A_RULES
from app.services.wave3b_rules import WAVE3B_RULES
from app.services.wave4a_rules import WAVE4A_RULES, active_wave4a_mappings


DEFAULT_ALGORITHMS = {
    "kex_algorithms": ["curve25519-sha256"],
    "server_host_key_algorithms": ["ssh-ed25519"],
    "encryption_algorithms_client_to_server": ["aes128-ctr"],
    "encryption_algorithms_server_to_client": ["aes128-ctr"],
    "mac_algorithms_client_to_server": ["hmac-sha2-256"],
    "mac_algorithms_server_to_client": ["hmac-sha2-256"],
}


def _name_list(values):
    raw = ",".join(values).encode("ascii")
    return len(raw).to_bytes(4, "big") + raw


def _kexinit_payload(**changes):
    algorithms = {**DEFAULT_ALGORITHMS, **changes}
    lists = [
        algorithms["kex_algorithms"], algorithms["server_host_key_algorithms"],
        algorithms["encryption_algorithms_client_to_server"],
        algorithms["encryption_algorithms_server_to_client"],
        algorithms["mac_algorithms_client_to_server"], algorithms["mac_algorithms_server_to_client"],
        ["none"], ["none"], [], [],
    ]
    return b"\x14" + bytes(range(16)) + b"".join(_name_list(values) for values in lists) + b"\x00" + b"\x00" * 4


def _packet(payload):
    padding = 4
    while (4 + 1 + len(payload) + padding) % 8:
        padding += 1
    packet_length = 1 + len(payload) + padding
    return packet_length.to_bytes(4, "big") + bytes([padding]) + payload + b"\x00" * padding


def _attempt(protocol="2.0", *, complete=True, policy=SSH_CRYPTO_POLICY_VERSION, **changes):
    value = {
        "port": 22,
        "identification_status": "valid",
        "identification_protocol_version": protocol,
        "kexinit_status": "complete" if complete else "truncated",
        "crypto_policy_version": policy,
        "aead_policy_version": SSH_AEAD_POLICY_VERSION,
        "response_state": "ssh_valid" if complete else "ssh_ambiguous",
        "stop_reason": "kexinit_complete" if complete else "truncated_packet",
        **DEFAULT_ALGORITHMS,
    }
    value.update(changes)
    value["evaluations"] = evaluate_ssh_attempt(value)
    return value


@contextmanager
def _ssh_server(identification=b"SSH-2.0-TestServer\r\n", packets=(), *, delay=0, reset=False, capture=None):
    capture = capture if capture is not None else []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if reset:
                self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
                return
            if delay:
                time.sleep(delay)
            if identification:
                self.request.sendall(identification)
            if packets:
                self.request.settimeout(1)
                try:
                    capture.append(self.request.recv(512))
                except OSError:
                    capture.append(b"")
                for packet in packets:
                    self.request.sendall(packet)
                self.request.settimeout(0.2)
                try:
                    extra = self.request.recv(512)
                    if extra:
                        capture.append(extra)
                except OSError:
                    pass

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_protocol_confirmed_ssh1_matches_and_199_is_indeterminate():
    ssh1 = _attempt("1.5", complete=False)
    ssh1["kexinit_status"] = "not_applicable"
    assert evaluate_ssh_attempt(ssh1)["ssh_weak_protocol"]["outcome"] == "MATCH"
    assert evaluate_ssh_attempt(_attempt("1.99"))["ssh_weak_protocol"]["outcome"] == "INDETERMINATE"


def test_valid_ssh2_requires_complete_kexinit_for_protocol_no_match():
    assert evaluate_ssh_attempt(_attempt())["ssh_weak_protocol"]["outcome"] == "NO_MATCH"
    assert evaluate_ssh_attempt(_attempt(complete=False))["ssh_weak_protocol"]["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("line", [b"HTTP/1.1 200 OK\r\n", b"SSH-2.0-\r\n", b"SSH-2.0-bad\x00name\r\n", b"SSH-2.0-truncated"])
def test_foreign_malformed_and_truncated_identification_are_rejected(line):
    with pytest.raises(SSHProtocolError):
        parse_identification_line(line)


def test_identification_hashes_exact_wire_value_without_persisting_banner():
    line = b"SSH-2.0-sensitive-product-string\r\n"
    parsed = parse_identification_line(line)
    assert parsed == {"protocol_version": "2.0", "sha256": hashlib.sha256(line).hexdigest()}
    assert "sensitive" not in repr(parsed)


@pytest.mark.parametrize(("direction", "cipher"), [
    ("encryption_algorithms_client_to_server", "aes128-cbc"),
    ("encryption_algorithms_server_to_client", "arcfour256"),
])
def test_prohibited_exact_cipher_in_either_direction_matches(direction, cipher):
    result = evaluate_ssh_attempt(_attempt(**{direction: [cipher]}))["ssh_weak_cipher"]
    assert result["outcome"] == "MATCH" and result["prohibited_algorithms"] == [cipher]


def test_complete_clean_cipher_lists_no_match_and_missing_direction_indeterminate():
    assert evaluate_ssh_attempt(_attempt())["ssh_weak_cipher"]["outcome"] == "NO_MATCH"
    assert evaluate_ssh_attempt(_attempt(encryption_algorithms_server_to_client=None))["ssh_weak_cipher"]["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("cipher", ["AES128-CBC", "aes128-cbc-extra", "prefix-arcfour", "not-cbc"])
def test_cipher_policy_is_case_sensitive_exact_name_only(cipher):
    assert cipher not in PROHIBITED_CIPHERS
    assert evaluate_ssh_attempt(_attempt(encryption_algorithms_client_to_server=[cipher]))["ssh_weak_cipher"]["outcome"] == "NO_MATCH"


@pytest.mark.parametrize("direction", ["mac_algorithms_client_to_server", "mac_algorithms_server_to_client"])
def test_prohibited_exact_mac_in_either_direction_matches(direction):
    result = evaluate_ssh_attempt(_attempt(**{direction: ["hmac-md5"]}))["ssh_weak_mac"]
    assert result["outcome"] == "MATCH"


def test_complete_clean_mac_lists_no_match_and_missing_direction_indeterminate():
    assert evaluate_ssh_attempt(_attempt())["ssh_weak_mac"]["outcome"] == "NO_MATCH"
    assert evaluate_ssh_attempt(_attempt(mac_algorithms_server_to_client=None))["ssh_weak_mac"]["outcome"] == "INDETERMINATE"


def test_mac_field_confusion_and_exact_case_guards():
    confused = _attempt(kex_algorithms=["hmac-md5"], mac_algorithms_client_to_server=["HMAC-MD5"])
    assert evaluate_ssh_attempt(confused)["ssh_weak_mac"]["outcome"] == "NO_MATCH"
    assert "HMAC-MD5" not in PROHIBITED_MACS


@pytest.mark.parametrize("aead", ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"])
def test_aead_only_direction_with_empty_mac_list_is_clean(aead):
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=[aead],
        mac_algorithms_client_to_server=[],
    ))["ssh_weak_mac"]
    direction = result["direction_evaluations"][0]
    assert result["outcome"] == "NO_MATCH"
    assert direction["aead_only"] is True
    assert direction["standalone_mac_applicable"] is False
    assert direction["mac_ignored_aead"] == [aead]
    assert direction["paired_aead"] == []
    assert direction["paired_aead_consistent"] is None
    assert direction["prohibited_mac_matches"] == []
    assert direction["outcome"] == "NO_MATCH"


def test_aead_policy_is_versioned_and_exact_name_based():
    assert SSH_AEAD_POLICY_VERSION == "ssc-wave4a-ssh-aead-policy.v2"
    assert AEAD_CIPHERS == {
        "AEAD_AES_128_GCM",
        "AEAD_AES_256_GCM",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305",
        "chacha20-poly1305@openssh.com",
    }
    assert AEAD_CIPHER_MAC_MODES == {
        "AEAD_AES_128_GCM": PAIRED_AEAD_MAC,
        "AEAD_AES_256_GCM": PAIRED_AEAD_MAC,
        "aes128-gcm@openssh.com": MAC_IGNORED,
        "aes256-gcm@openssh.com": MAC_IGNORED,
        "chacha20-poly1305": MAC_IGNORED,
        "chacha20-poly1305@openssh.com": MAC_IGNORED,
    }


def test_aead_only_direction_does_not_match_advertised_weak_standalone_mac():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["aes256-gcm@openssh.com"],
        mac_algorithms_client_to_server=["hmac-md5"],
    ))["ssh_weak_mac"]
    direction = result["direction_evaluations"][0]
    assert result["outcome"] == "NO_MATCH"
    assert direction["prohibited_mac_matches"] == []
    assert direction["advertised_prohibited_mac_names"] == ["hmac-md5"]


@pytest.mark.parametrize("aead", ["AEAD_AES_128_GCM", "AEAD_AES_256_GCM"])
def test_rfc5647_paired_aead_with_matching_mac_is_clean(aead):
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=[aead],
        mac_algorithms_client_to_server=[aead],
    ))["ssh_weak_mac"]
    direction = result["direction_evaluations"][0]
    assert result["outcome"] == "NO_MATCH"
    assert direction["paired_aead"] == [aead]
    assert direction["paired_aead_consistent"] is True
    assert direction["standalone_mac_applicable"] is False


def test_rfc5647_paired_aead_with_empty_mac_is_indeterminate():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["AEAD_AES_128_GCM"],
        mac_algorithms_client_to_server=[],
    ))["ssh_weak_mac"]
    direction = result["direction_evaluations"][0]
    assert result["outcome"] == "INDETERMINATE"
    assert direction["paired_aead_consistent"] is False
    assert direction["prohibited_mac_matches"] == []


def test_rfc5647_paired_aead_with_only_weak_standalone_mac_is_indeterminate_not_match():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["AEAD_AES_128_GCM"],
        mac_algorithms_client_to_server=["hmac-md5"],
    ))["ssh_weak_mac"]
    direction = result["direction_evaluations"][0]
    assert result["outcome"] == "INDETERMINATE"
    assert direction["paired_aead_consistent"] is False
    assert direction["prohibited_mac_matches"] == []
    assert direction["advertised_prohibited_mac_names"] == ["hmac-md5"]


def test_mixed_aead_modes_require_complete_rfc5647_pairing():
    ciphers = ["aes256-gcm@openssh.com", "AEAD_AES_256_GCM"]
    clean = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=ciphers,
        mac_algorithms_client_to_server=["AEAD_AES_256_GCM"],
    ))["ssh_weak_mac"]
    assert clean["outcome"] == "NO_MATCH"
    assert clean["direction_evaluations"][0]["paired_aead_consistent"] is True

    incomplete = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=ciphers,
        mac_algorithms_client_to_server=[],
    ))["ssh_weak_mac"]
    assert incomplete["outcome"] == "INDETERMINATE"
    assert incomplete["direction_evaluations"][0]["paired_aead_consistent"] is False


def test_mixed_aead_and_non_aead_direction_with_weak_mac_matches():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["aes256-gcm@openssh.com", "aes256-ctr"],
        mac_algorithms_client_to_server=["hmac-md5"],
    ))["ssh_weak_mac"]
    direction = result["direction_evaluations"][0]
    assert result["outcome"] == "MATCH"
    assert direction["standalone_mac_applicable"] is True
    assert direction["prohibited_mac_matches"] == ["hmac-md5"]


def test_non_aead_direction_with_complete_clean_mac_list_is_negative():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["aes256-ctr"],
        mac_algorithms_client_to_server=["hmac-sha2-256"],
    ))["ssh_weak_mac"]
    direction = result["direction_evaluations"][0]
    assert direction["outcome"] == "NO_MATCH"
    assert direction["aead_only"] is False and direction["standalone_mac_applicable"] is True


@pytest.mark.parametrize("macs", [[], None])
def test_non_aead_direction_with_empty_or_missing_mac_list_is_indeterminate(macs):
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["aes256-ctr"],
        mac_algorithms_client_to_server=macs,
    ))["ssh_weak_mac"]
    assert result["outcome"] == "INDETERMINATE"
    assert result["direction_evaluations"][0]["outcome"] == "INDETERMINATE"


def test_both_directions_aead_only_and_empty_are_no_match():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["chacha20-poly1305@openssh.com"],
        encryption_algorithms_server_to_client=["aes256-gcm@openssh.com"],
        mac_algorithms_client_to_server=[],
        mac_algorithms_server_to_client=[],
    ))["ssh_weak_mac"]
    assert result["outcome"] == "NO_MATCH"
    assert all(item["aead_only"] is True for item in result["direction_evaluations"])


def test_aead_clean_direction_plus_non_aead_weak_direction_matches():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["chacha20-poly1305@openssh.com"],
        encryption_algorithms_server_to_client=["aes256-ctr"],
        mac_algorithms_client_to_server=[],
        mac_algorithms_server_to_client=["hmac-md5"],
    ))["ssh_weak_mac"]
    assert result["outcome"] == "MATCH"
    assert [item["outcome"] for item in result["direction_evaluations"]] == ["NO_MATCH", "MATCH"]


def test_unknown_cipher_applicability_is_indeterminate():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["future-private-cipher@example.test"],
        mac_algorithms_client_to_server=["hmac-md5"],
    ))["ssh_weak_mac"]
    direction = result["direction_evaluations"][0]
    assert result["outcome"] == "INDETERMINATE"
    assert direction["aead_only"] is None and direction["standalone_mac_applicable"] is None
    assert direction["prohibited_mac_matches"] == []


def test_unknown_cipher_plus_clean_aead_is_indeterminate():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=[
            "aes256-gcm@openssh.com", "future-private-cipher@example.test",
        ],
        mac_algorithms_client_to_server=[],
    ))["ssh_weak_mac"]
    direction = result["direction_evaluations"][0]
    assert result["outcome"] == "INDETERMINATE"
    assert direction["unknown_cipher_algorithms"] == ["future-private-cipher@example.test"]


def test_none_is_known_non_aead_but_not_a_prohibited_cipher():
    result = evaluate_ssh_attempt(_attempt(
        encryption_algorithms_client_to_server=["none"],
        mac_algorithms_client_to_server=["hmac-sha2-256"],
    ))
    assert "none" in KNOWN_NON_AEAD_CIPHERS
    assert "none" not in PROHIBITED_CIPHERS
    assert result["ssh_weak_cipher"]["outcome"] == "NO_MATCH"
    assert result["ssh_weak_cipher"]["prohibited_algorithms"] == []
    assert result["ssh_weak_mac"]["direction_evaluations"][0]["standalone_mac_applicable"] is True


def test_unknown_aead_policy_is_indeterminate_only_for_mac():
    attempt = _attempt()
    attempt["aead_policy_version"] = "unknown"
    result = evaluate_ssh_attempt(attempt)
    assert result["ssh_weak_mac"]["outcome"] == "INDETERMINATE"
    assert result["ssh_weak_cipher"]["outcome"] == "NO_MATCH"
    assert result["ssh_weak_protocol"]["outcome"] == "NO_MATCH"


def test_unknown_policy_and_banner_only_are_indeterminate_for_crypto():
    unknown = evaluate_ssh_attempt(_attempt(policy="unknown"))
    assert all(value["outcome"] == "INDETERMINATE" for value in unknown.values())
    banner_only = evaluate_ssh_attempt(_attempt(complete=False))
    assert banner_only["ssh_weak_cipher"]["outcome"] == "INDETERMINATE"
    assert banner_only["ssh_weak_mac"]["outcome"] == "INDETERMINATE"


def test_kexinit_parser_rejects_truncation_malformed_and_excessive_lists():
    payload = _kexinit_payload()
    assert parse_kexinit_payload(payload)["kex_algorithms"] == ["curve25519-sha256"]
    for malformed in (payload[:-1], b"\x15" + payload[1:]):
        with pytest.raises(SSHProtocolError):
            parse_kexinit_payload(malformed)
    excessive = _kexinit_payload(kex_algorithms=[f"a{index}" for index in range(MAX_ALGORITHMS_PER_LIST + 1)])
    with pytest.raises(SSHProtocolError, match="excessive_algorithm_list"):
        parse_kexinit_payload(excessive)
    with pytest.raises(SSHProtocolError, match="missing_required_algorithm_list"):
        parse_kexinit_payload(_kexinit_payload(mac_algorithms_client_to_server=[]))
    parsed_aead = parse_kexinit_payload(_kexinit_payload(
        encryption_algorithms_client_to_server=["chacha20-poly1305@openssh.com"],
        mac_algorithms_client_to_server=[],
    ))
    assert parsed_aead["mac_algorithms_client_to_server"] == []


def test_collector_completes_one_bounded_exchange_and_disconnects_before_auth():
    capture = []
    packet = _packet(_kexinit_payload(encryption_algorithms_client_to_server=["aes128-cbc"]))
    with _ssh_server(packets=[packet], capture=capture) as port:
        result = collect_ssh_negotiation("127.0.0.1", "localhost", port, timeout=1)
    assert result["kexinit_status"] == "complete"
    assert result["evaluations"]["ssh_weak_cipher"]["outcome"] == "MATCH"
    assert capture == [CLIENT_IDENTIFICATION]
    assert result["authentication_attempted"] is False and result["application_commands_sent"] == 0
    assert "identification" not in result or "identification_text" not in result


def test_collector_accepts_aead_only_empty_mac_lists_and_persists_applicability():
    packet = _packet(_kexinit_payload(
        encryption_algorithms_client_to_server=["chacha20-poly1305@openssh.com"],
        encryption_algorithms_server_to_client=["aes256-gcm@openssh.com"],
        mac_algorithms_client_to_server=[],
        mac_algorithms_server_to_client=[],
    ))
    with _ssh_server(packets=[packet]) as port:
        result = collect_ssh_negotiation("127.0.0.1", "localhost", port, timeout=1)
    mac = result["evaluations"]["ssh_weak_mac"]
    assert result["kexinit_status"] == "complete" and mac["outcome"] == "NO_MATCH"
    assert result["aead_policy_version"] == SSH_AEAD_POLICY_VERSION
    assert all(item["standalone_mac_applicable"] is False for item in mac["direction_evaluations"])


def test_collector_ssh1_sends_nothing_and_199_remains_protocol_indeterminate():
    with _ssh_server(identification=b"SSH-1.5-legacy\n") as port:
        ssh1 = collect_ssh_negotiation("127.0.0.1", "localhost", port, timeout=1)
    assert ssh1["evaluations"]["ssh_weak_protocol"]["outcome"] == "MATCH"
    with _ssh_server(identification=b"SSH-1.99-compat\n", packets=[_packet(_kexinit_payload())]) as port:
        compat = collect_ssh_negotiation("127.0.0.1", "localhost", port, timeout=1)
    assert compat["kexinit_status"] == "complete"
    assert compat["evaluations"]["ssh_weak_protocol"]["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize(("identification", "packets", "expected"), [
    (b"HTTP/1.1 200 OK\r\n", (), "non_ssh_service"),
    (b"SSH-2.0-bad\x00id\r\n", (), "malformed_identification"),
    (b"SSH-2.0-truncated", (), "truncated_identification"),
    (b"S" * 256, (), "oversized_identification"),
    (b"SSH-2.0-test\r\n", [(MAX_PACKET_BYTES + 1).to_bytes(4, "big")], "oversized_packet"),
    (b"SSH-2.0-test\r\n", [(11).to_bytes(4, "big")], "malformed_packet_length"),
])
def test_collector_fails_closed_on_foreign_malformed_truncated_and_oversized_data(identification, packets, expected):
    with _ssh_server(identification=identification, packets=packets) as port:
        result = collect_ssh_negotiation("127.0.0.1", "localhost", port, timeout=0.5)
    assert result["stop_reason"] == expected
    assert all(value["outcome"] == "INDETERMINATE" for value in result["evaluations"].values())


def test_timeout_reset_and_packet_count_budget_are_indeterminate(monkeypatch):
    with _ssh_server(identification=b"", delay=0.3) as port:
        timed_out = collect_ssh_negotiation("127.0.0.1", "localhost", port, timeout=0.05)
    assert timed_out["stop_reason"] == "timed_out"
    class ResetConnection:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def settimeout(self, _timeout):
            pass
        def recv(self, _size):
            raise ConnectionResetError
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: ResetConnection())
    reset = collect_ssh_negotiation("127.0.0.1", "localhost", 22, timeout=0.5)
    assert reset["stop_reason"] == "reset"
    monkeypatch.undo()
    ignores = [_packet(b"\x02") for _ in range(4)]
    with _ssh_server(packets=ignores) as port:
        limited = collect_ssh_negotiation("127.0.0.1", "localhost", port, timeout=1)
    assert limited["stop_reason"] == "packet_count_limit" and limited["packets_received"] == 4


def test_aggregation_applicability_boundary():
    unavailable = _attempt(complete=False, response_state="unavailable", stop_reason="timed_out")
    negative = _attempt()
    match = _attempt(encryption_algorithms_client_to_server=["3des-cbc"])
    ambiguous = _attempt(complete=False)
    assert aggregate_ssh_evaluations([unavailable, negative])["ssh_weak_cipher"]["outcome"] == "NO_MATCH"
    assert aggregate_ssh_evaluations([unavailable, match])["ssh_weak_cipher"]["outcome"] == "MATCH"
    assert aggregate_ssh_evaluations([ambiguous, negative])["ssh_weak_cipher"]["outcome"] == "INDETERMINATE"
    assert aggregate_ssh_evaluations([unavailable])["ssh_weak_cipher"]["outcome"] == "INDETERMINATE"
    assert aggregate_ssh_evaluations([])["ssh_weak_cipher"]["outcome"] == "INDETERMINATE"


def test_multiple_explicit_ssh_ports_use_tcp_executor_without_port_open_inference():
    target = InventoryScanTarget(
        target_type=ScanTargetTypeEnum.HOST, inventory_id=str(uuid4()), hostname="localhost",
        connect_host="127.0.0.1", domain_name="example.test", allow_sensitive_network_scan=True,
    )
    with _ssh_server(packets=[_packet(_kexinit_payload())]) as port1, _ssh_server(
        packets=[_packet(_kexinit_payload(encryption_algorithms_server_to_client=["arcfour"]))]
    ) as port2:
        observation = TCPExecutor().collect(target, {"ssh_ports": [port1, port2], "ssh_timeout_seconds": 1})
    assert observation.evidence["ports"] == {}
    assert len(observation.evidence["ssh_negotiations"]) == 2
    assert observation.evidence["evaluations"]["ssh_weak_cipher"]["outcome"] == "MATCH"


def test_ssh_configuration_is_explicit_and_bounded():
    config = validate_scan_config({"ssh_ports": [22, 2222, 22]})
    assert config["executors"][-1] == "tcp" and config["ssh_ports"] == [22, 2222]
    with pytest.raises(ValueError):
        validate_scan_config({"executors": ["tcp"], "ssh_ports": list(range(2200, 2207))})
    with pytest.raises(ValueError):
        validate_scan_config({"executors": ["tcp"], "ssh_ports": [0]})


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _wave4a_baseline():
    factors = {"network_security": {"key": "network_security", "name": "Network Security"}}
    issues = [{"key": spec.issue_key, "severity": "medium", "factor": "network_security", "title": spec.title}
              for spec in WAVE4A_RULES]
    raw = {}
    for endpoint, payload in ((FACTORS_ENDPOINT, {"entries": list(factors.values())}), (ISSUES_ENDPOINT, {"entries": issues})):
        body = json.dumps(payload)
        raw[API_ORIGIN + endpoint] = {
            "body": body, "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "captured_at": "2026-10-03T00:00:00+00:00",
        }
    return normalize_api_payloads(raw)


def test_wave4a_exact_version_activation_and_uncalibrated_e2e_finding(db):
    import_golden_baseline(db, _wave4a_baseline(), attest_real_source=True)
    mappings = active_wave4a_mappings(db)
    assert len(mappings) == len(WAVE4A_RULES) == 3
    assert {item["issue_key"] for item in mappings} == {spec.issue_key for spec in WAVE4A_RULES}
    for mapping in mappings:
        version = db.get(CatalogIssueTypeVersion, UUID(mapping["issue_version_id"]))
        assert version.source_type == SourceTypeEnum.SSC_API and mapping["primitive"] == "SSH_NEGOTIATION"

    rule = db.scalar(select(RuleEngineRule).where(RuleEngineRule.stable_key == "ssc.wave4a.ssh_weak_cipher"))
    assert rule.current_version.catalog_issue_type_version_id == rule.catalog_issue_type.current_version_id
    suffix = uuid4().hex[:12]
    target = add_inventory_target(
        db, organization="Wave 4A " + suffix, domain_name=suffix + ".test", hostname="localhost",
        ip="127.0.0.1", approved=True, allow_sensitive=True, approval_notes="Local SSH KEXINIT fixture",
    )
    with _ssh_server(packets=[_packet(_kexinit_payload(encryption_algorithms_client_to_server=["aes128-cbc"]))]) as port:
        result = scan_inventory_target(
            db, name="localhost", organization_id=UUID(target["organization_id"]),
            scan_config={"executors": ["tcp"], "ssh_ports": [port], "ssh_timeout_seconds": 1},
            model=ScoringDefinition(), rule_keys=[rule.stable_key],
        )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.ssc_issue_key == "ssh_weak_cipher" and finding.ssc_severity == "medium"
    assert finding.breach_risk == "UNKNOWN" and finding.affects_score is False and finding.score_impact == 0
    evidence = result.evidence[0].summary
    assert evidence["evaluations"]["ssh_weak_cipher"]["outcome"] == "MATCH"
    assert evidence["ssh_negotiations"][0]["identification_sha256"]
    assert "TestServer" not in json.dumps(evidence)


def test_wave4a_is_exactly_three_and_prior_wave_registries_remain_intact():
    assert {spec.issue_key for spec in WAVE4A_RULES} == {"ssh_weak_protocol", "ssh_weak_cipher", "ssh_weak_mac"}
    assert len(WAVE1_RULES) == 14 and len(WAVE2_RULES) == 7 and len(WAVE3A_RULES) == 6 and len(WAVE3B_RULES) == 7
    prior = {spec.issue_key for spec in WAVE1_RULES + WAVE2_RULES + WAVE3A_RULES + WAVE3B_RULES}
    assert prior.isdisjoint({spec.issue_key for spec in WAVE4A_RULES})
