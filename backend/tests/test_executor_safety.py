import ssl
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.models.scan_models import ScanTargetTypeEnum
from app.services import scan_executors as executors
from tests.test_scan_executors import SecurityHeadersHandler, _http_server


def local_target():
    return executors.InventoryScanTarget(ScanTargetTypeEnum.HOST, "test-id", "localhost", "127.0.0.1", "example.test", True)


@contextmanager
def tls_server(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30)).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    sni_names = []
    context.set_servername_callback(lambda sock, name, ctx: sni_names.append(name))
    server = ThreadingHTTPServer(("127.0.0.1", 0), SecurityHeadersHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], sni_names
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_tls_certificate_sni_and_https(tmp_path):
    with tls_server(tmp_path) as (port, names):
        evidence = executors.TLSExecutor().collect(local_target(), {"tls_ports": [port], "connect_timeout_seconds": 1}).evidence
        http = executors.HTTPExecutor().collect(local_target(), {"http_ports": [], "https_ports": [port]}).evidence
    assert evidence["status"] == "success"
    assert evidence["endpoint_available"] is True
    assert evidence["public_key_bits"] == 2048
    assert evidence["weak_signature_algorithm"] is False
    assert evidence["certificate_trusted"] is False
    assert evidence["certificate_fingerprint_sha256"]
    assert evidence["certificate_chain"][0]["self_signature_valid"] is True
    assert evidence["evaluations"]["tlscert_self_signed"]["matched"] is True
    assert evidence["evaluations"]["tlscert_expired"]["matched"] is False
    assert evidence["evaluations"]["insecure_server_certificate_key_size"]["matched"] is False
    assert evidence["evaluations"]["tlscert_weak_signature"]["matched"] is False
    assert evidence["evaluations"]["tlscert_no_revocation"]["matched"] is False
    assert 28 <= evidence["certificate_days_until_expiry"] <= 30
    assert evidence["tls10_supported"] is False
    assert evidence["tls11_supported"] is False
    assert http["status_code"] == 200
    assert http["hsts_present"] is True
    assert names and all(name == "localhost" for name in names)


@pytest.mark.parametrize("address", ["169.254.169.254", "100.100.100.200", "224.0.0.1", "0.0.0.0", "::", "::ffff:169.254.169.254"])
def test_prohibited_addresses_even_with_sensitive_approval(address):
    with pytest.raises(executors.ScanExecutorError):
        executors._pin_target(replace(local_target(), connect_host=address))


@pytest.mark.parametrize("config", [
    {"executors": ["http", "unknown"]}, {"executors": []}, {"tls_ports": []},
    {"tcp_ports": [True]}, {"request_timeout_seconds": float("nan")},
    {"request_timeout_seconds": float("inf")}, {"redirect_limit": True},
    {"tcp_ports": list(range(1, 12))},
])
def test_invalid_config_rejected_before_network(config, monkeypatch):
    monkeypatch.setattr(executors.HTTPExecutor, "collect", lambda *a: pytest.fail("unexpected network call"))
    with pytest.raises(executors.ScanExecutorError):
        executors.collect_scanner_observations(local_target(), config)


def test_http_pins_connection_to_checked_address(monkeypatch):
    from ipaddress import ip_address
    with _http_server(SecurityHeadersHandler) as port:
        resolutions = []
        def resolve(host):
            resolutions.append(host)
            assert host == "approved.test"
            return [ip_address("127.0.0.1")]
        monkeypatch.setattr(executors, "_resolve_addresses", resolve)
        observation = executors.HTTPExecutor().collect(replace(local_target(), hostname="approved.test", connect_host="approved.test"), {"http_ports": [port], "https_ports": []})
    assert resolutions == ["approved.test"]
    assert observation.evidence["status_code"] == 200


def test_dns_failure_is_unknown_not_missing(monkeypatch):
    def fail(name, *_args):
        return {"name": name, "record_type": "TXT", "status": "ERROR", "records": [], "error": "LifetimeTimeout"}
    monkeypatch.setattr(executors, "_query_txt_evidence", fail)
    evidence = executors.DNSExecutor().collect(local_target(), {}).evidence
    assert evidence["status"] == "error"
    assert evidence["spf_present"] is None
    assert evidence["dmarc_present"] is None


def test_cross_target_redirect_is_not_followed(monkeypatch):
    executor = executors.HTTPExecutor()
    requests = []
    def response(**kwargs):
        requests.append(kwargs)
        return {"endpoint_available": True, "status_code": 302, "headers": {}, "cookies": [], "location": "http://outside.test/"}
    monkeypatch.setattr(executor, "_single_request", response)
    evidence = executor.collect(local_target(), {"http_ports": [80], "https_ports": []}).evidence
    assert len(requests) == 1
    assert evidence["status"] == "error"
    assert "outside approved" in evidence["error"]


def test_redirect_to_unconfigured_port_is_not_followed(monkeypatch):
    executor = executors.HTTPExecutor()
    requests = []
    def response(**kwargs):
        requests.append(kwargs)
        return {"endpoint_available": True, "status_code": 302, "headers": {}, "cookies": [], "location": "http://localhost:8080/"}
    monkeypatch.setattr(executor, "_single_request", response)
    evidence = executor.collect(local_target(), {"http_ports": [80], "https_ports": []}).evidence
    assert len(requests) == 1
    assert "outside configured" in evidence["error"]


def test_http_without_ports_is_rejected():
    with pytest.raises(executors.ScanExecutorError, match="at least one"):
        executors.validate_scan_config({"executors": ["http"], "http_ports": [], "https_ports": []})


def test_ipv6_target_url_is_bracketed(monkeypatch):
    executor = executors.HTTPExecutor()
    calls = []
    def respond(**kwargs):
        calls.append(kwargs)
        return {"endpoint_available": True, "status_code": 200, "headers": {}, "cookies": []}
    monkeypatch.setattr(executor, "_single_request", respond)
    evidence = executor.collect(replace(local_target(), hostname="::1"), {"http_ports": [8080], "https_ports": []}).evidence
    assert calls[0]["port"] == 8080
    assert evidence["status_code"] == 200
    assert evidence["redirect_chain"][0]["host"] == "::1"


def test_http_redirect_summary_survives_https_response_selection(monkeypatch):
    executor = executors.HTTPExecutor()
    def response(target, scheme, port, *args):
        chain = [{"scheme": scheme, "location_scheme": None}]
        if scheme == "http":
            chain = [{"scheme": "http", "location_scheme": "https"}, {"scheme": "https", "location_scheme": "http"}, {"scheme": "http", "location_scheme": None}]
        return {"endpoint_available": True, "status_code": 200, "headers": {}, "cookies": [], "redirect_chain": chain}
    monkeypatch.setattr(executor, "_request_chain", response)
    evidence = executor.collect(local_target(), {}).evidence
    assert evidence["redirect_chain"][0]["scheme"] == "https"
    assert evidence["http_to_https_redirect"] is True
    assert evidence["redirect_chain_contains_insecure_http"] is True
