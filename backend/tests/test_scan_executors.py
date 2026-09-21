import socketserver
import struct
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _suffix() -> str:
    return uuid4().hex[:12]


def _approved_local_host(*, approved: bool = True, allow_sensitive: bool = True):
    suffix = _suffix()
    org = client.post(
        "/api/v1/inventory/organizations",
        json={
            "name": f"Phase 4B Org {suffix}",
            "approved_for_scan": True,
            "allow_sensitive_network_scan": allow_sensitive,
        },
    ).json()
    domain = client.post(
        "/api/v1/inventory/domains",
        json={
            "organization_id": org["id"],
            "name": f"phase4b-{suffix}.test",
            "approved_for_scan": True,
            "allow_sensitive_network_scan": allow_sensitive,
        },
    ).json()
    host = client.post(
        "/api/v1/inventory/hosts",
        json={
            "domain_id": domain["id"],
            "hostname": "localhost",
            "ip": "127.0.0.1",
            "approved_for_scan": approved,
            "allow_sensitive_network_scan": allow_sensitive,
        },
    ).json()
    return org, domain, host


def _rule(path: str, value, *, operator: str = "equals"):
    suffix = _suffix()
    rule = client.post("/api/v1/rules", json={"stable_key": f"phase4b.rule.{suffix}"}).json()
    version = client.post(
        f"/api/v1/rules/{rule['id']}/versions",
        json={
            "name": f"Phase 4B {path}",
            "target_type": "HOST",
            "rule_expression": {"operator": operator, "path": path, "value": value},
            "evidence_schema": {"source": "scanner"},
            "source_type": "INTERNAL",
            "make_current": True,
        },
    ).json()
    return rule, version


@contextmanager
def _http_server(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class SecurityHeadersHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        return

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "sessionid=redacted; Secure; HttpOnly; SameSite=Lax")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RedirectHandler(BaseHTTPRequestHandler):
    redirect_port = 0

    def log_message(self, _format, *args):
        return

    def do_GET(self):
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.redirect_port}/next")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"redirected"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SlowHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        return

    def do_GET(self):
        time.sleep(0.4)
        body = b"slow"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LocalDNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        query_id = struct.unpack("!H", data[:2])[0]
        qname, question_end = _decode_qname(data, 12)
        record = "v=DMARC1; p=none" if qname.startswith("_dmarc.") else "v=spf1 -all"
        question = data[12:question_end + 4]
        txt = bytes([len(record)]) + record.encode("ascii")
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(txt)) + txt
        response = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + question + answer
        sock.sendto(response, self.client_address)


def _decode_qname(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length
    return ".".join(labels), offset


@contextmanager
def _dns_server():
    server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), LocalDNSHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _create_and_run_scanner_job(host_id: str, rule_id: str, scan_config: dict):
    job_resp = client.post(
        "/api/v1/scans/jobs",
        json={
            "name": f"Phase 4B scanner {_suffix()}",
            "rule_ids": [rule_id],
            "collect_observations": True,
            "targets": [{"target_type": "HOST", "host_id": host_id, "scan_config": scan_config}],
        },
    )
    assert job_resp.status_code == 201, job_resp.text
    job = job_resp.json()
    run_resp = client.post(f"/api/v1/scans/jobs/{job['id']}/run")
    assert run_resp.status_code == 201, run_resp.text
    return job, run_resp.json()


def test_unapproved_scanner_target_is_rejected():
    _org, _domain, host = _approved_local_host(approved=False, allow_sensitive=True)
    rule, _version = _rule("http.endpoint_available", True)
    response = client.post(
        "/api/v1/scans/jobs",
        json={
            "name": "Rejected scanner target",
            "rule_ids": [rule["id"]],
            "collect_observations": True,
            "targets": [{"target_type": "HOST", "host_id": host["id"], "scan_config": {"executors": ["http"]}}],
        },
    )
    assert response.status_code == 400
    assert "not approved" in response.text


def test_sensitive_localhost_target_requires_explicit_approval():
    _org, _domain, host = _approved_local_host(approved=True, allow_sensitive=False)
    rule, _version = _rule("http.endpoint_available", True)
    response = client.post(
        "/api/v1/scans/jobs",
        json={
            "name": "Rejected localhost target",
            "rule_ids": [rule["id"]],
            "collect_observations": True,
            "targets": [{"target_type": "HOST", "host_id": host["id"], "scan_config": {"executors": ["http"]}}],
        },
    )
    assert response.status_code == 400
    assert "sensitive network" in response.text


def test_authorized_http_executor_observation_feeds_rule_pipeline():
    _org, _domain, host = _approved_local_host()
    rule, _version = _rule("http.endpoint_available", True)
    with _http_server(SecurityHeadersHandler) as port:
        job, run = _create_and_run_scanner_job(
            host["id"],
            rule["id"],
            {
                "executors": ["http"],
                "http_ports": [port],
                "https_ports": [],
                "request_timeout_seconds": 2,
                "redirect_limit": 2,
            },
        )

    assert run["status"] == "COMPLETED"
    assert run["summary"]["evidence_mode"] == "SCANNER"
    assert run["summary"]["observations_created"] == 1
    assert run["summary"]["findings_created"] == 1

    observations = client.get(f"/api/v1/scans/runs/{run['id']}/observations").json()
    assert observations[0]["evidence_source"] == "SCANNER_HTTP"
    evidence = observations[0]["evidence"]
    assert evidence["endpoint_available"] is True
    assert evidence["hsts_present"] is None
    assert evidence["csp_present"] is True
    assert evidence["x_content_type_options_present"] is True
    assert evidence["clickjacking_protection_present"] is True
    assert evidence["all_cookies_secure"] is True
    assert evidence["all_cookies_httponly"] is True
    assert "sessionid" not in str(evidence["cookies"])
    assert evidence["target_identity"]["inventory_id"] == host["id"]

    findings = client.get(f"/api/v1/scans/runs/{run['id']}/findings").json()
    assert findings[0]["evidence_source"] == "SCANNER_HTTP"
    assert findings[0]["scan_job_id"] == job["id"]


def test_redirect_observation_records_insecure_http_chain():
    _org, _domain, host = _approved_local_host()
    rule, _version = _rule("http.redirect_chain_contains_insecure_http", True)
    with _http_server(RedirectHandler) as port:
        RedirectHandler.redirect_port = port
        _job, run = _create_and_run_scanner_job(
            host["id"],
            rule["id"],
            {
                "executors": ["http"],
                "http_ports": [port],
                "https_ports": [],
                "request_timeout_seconds": 2,
                "redirect_limit": 2,
            },
        )

    observations = client.get(f"/api/v1/scans/runs/{run['id']}/observations").json()
    evidence = observations[0]["evidence"]
    assert evidence["redirect_chain_contains_insecure_http"] is True
    assert len(evidence["redirect_chain"]) == 2
    assert run["summary"]["findings_created"] == 1


def test_http_timeout_is_recorded_as_scanner_evidence():
    _org, _domain, host = _approved_local_host()
    rule, _version = _rule("http.endpoint_available", False)
    with _http_server(SlowHandler) as port:
        _job, run = _create_and_run_scanner_job(
            host["id"],
            rule["id"],
            {
                "executors": ["http"],
                "http_ports": [port],
                "https_ports": [],
                "request_timeout_seconds": 0.1,
            },
        )

    observations = client.get(f"/api/v1/scans/runs/{run['id']}/observations").json()
    assert observations[0]["evidence_source"] == "SCANNER_HTTP"
    assert observations[0]["evidence"]["endpoint_available"] is False
    assert observations[0]["evidence"]["error"] in {"TimeoutError", "timeout"}
    assert run["summary"]["findings_created"] == 1


def test_dns_executor_normalizes_spf_and_dmarc_records():
    _org, _domain, host = _approved_local_host()
    rule, _version = _rule("dns.dmarc_present", True)
    with _dns_server() as dns_port:
        _job, run = _create_and_run_scanner_job(
            host["id"],
            rule["id"],
            {
                "executors": ["dns"],
                "dns_server_host": "127.0.0.1",
                "dns_server_port": dns_port,
                "dns_timeout_seconds": 2,
            },
        )

    observations = client.get(f"/api/v1/scans/runs/{run['id']}/observations").json()
    evidence = observations[0]["evidence"]
    assert evidence["spf_present"] is True
    assert evidence["dmarc_present"] is True
    assert evidence["spf_records"] == ["v=spf1 -all"]
    assert evidence["dmarc_records"] == ["v=DMARC1; p=none"]
    assert run["summary"]["findings_created"] == 1


def test_tcp_executor_uses_only_explicit_configured_ports():
    _org, _domain, host = _approved_local_host()
    with _http_server(SecurityHeadersHandler) as port:
        rule, _version = _rule(f"tcp.ports.{port}.open", True)
        _job, run = _create_and_run_scanner_job(
            host["id"],
            rule["id"],
            {"executors": ["tcp"], "tcp_ports": [port], "connect_timeout_seconds": 1},
        )

    observations = client.get(f"/api/v1/scans/runs/{run['id']}/observations").json()
    evidence = observations[0]["evidence"]
    assert list(evidence["ports"].keys()) == [str(port)]
    assert evidence["ports"][str(port)]["open"] is True
    assert run["summary"]["findings_created"] == 1


def test_tls_executor_records_bounded_tls_evidence_without_internet():
    _org, _domain, host = _approved_local_host()
    rule, _version = _rule("tls.tls10_supported", False)
    with _http_server(SecurityHeadersHandler) as port:
        _job, run = _create_and_run_scanner_job(
            host["id"],
            rule["id"],
            {"executors": ["tls"], "tls_ports": [port], "connect_timeout_seconds": 1},
        )

    observations = client.get(f"/api/v1/scans/runs/{run['id']}/observations").json()
    evidence = observations[0]["evidence"]
    assert observations[0]["evidence_source"] == "SCANNER_TLS"
    assert evidence["tls10_supported"] is None
    assert evidence["tls11_supported"] is None
    assert evidence["certificate_error"]
    assert run["summary"]["findings_created"] == 0


def test_revoked_approval_after_queue_rejects_run_and_preserves_failed_history():
    _org, _domain, host = _approved_local_host()
    rule, _ = _rule("http.endpoint_available", True)
    job = client.post("/api/v1/scans/jobs", json={"name": "Revoke after queue", "rule_ids": [rule["id"]], "collect_observations": True,
                      "targets": [{"target_type": "HOST", "host_id": host["id"], "scan_config": {"executors": ["http"]}}]}).json()
    client.patch(f"/api/v1/inventory/hosts/{host['id']}", json={"approved_for_scan": False})
    response = client.post(f"/api/v1/scans/jobs/{job['id']}/run")
    assert response.status_code == 400
    assert "not approved" in response.text
    assert client.get(f"/api/v1/scans/jobs/{job['id']}").json()["status"] == "FAILED"
    runs = [r for r in client.get("/api/v1/scans/runs").json() if r["scan_job_id"] == job["id"]]
    assert len(runs) == 1 and runs[0]["status"] == "FAILED"
    assert client.get(f"/api/v1/scans/runs/{runs[0]['id']}/observations").json() == []


def test_dns_only_domain_does_not_require_address_record(monkeypatch):
    from app.services import scan_executors
    org, domain, _host = _approved_local_host()
    domain_rule = client.post("/api/v1/rules", json={"stable_key": "dns-only-" + _suffix()}).json()
    client.post(f"/api/v1/rules/{domain_rule['id']}/versions", json={"name": "DNS only", "target_type": "DOMAIN", "rule_expression": {"operator": "equals", "path": "dns.spf_present", "value": True}, "make_current": True})
    monkeypatch.setattr(scan_executors, "_resolve_addresses", lambda *args: (_ for _ in ()).throw(AssertionError("Address resolution is unnecessary for DNS-only target")))
    with _dns_server() as port:
        job = client.post("/api/v1/scans/jobs", json={"name": "DNS only", "rule_ids": [domain_rule["id"]], "collect_observations": True,
                          "targets": [{"target_type": "DOMAIN", "domain_id": domain["id"], "scan_config": {"executors": ["dns"], "dns_server_port": port}}]}).json()
        # Use mocked TXT transport to isolate absence of target address resolution.
        monkeypatch.setattr(scan_executors, "_query_txt_evidence", lambda name, *args: {
            "name": name, "record_type": "TXT", "status": "ANSWER",
            "records": ["v=spf1 -all"], "error": None,
        })
        run_response = client.post(f"/api/v1/scans/jobs/{job['id']}/run")
    assert run_response.status_code == 201, run_response.text
    assert run_response.json()["summary"]["findings_created"] == 1
