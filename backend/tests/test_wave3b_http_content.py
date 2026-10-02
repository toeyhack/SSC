import base64
import hashlib
import json
from http.server import BaseHTTPRequestHandler
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import engine
from app.models.catalog_models import CatalogIssueTypeVersion, SourceTypeEnum
from app.models.rule_models import RuleEngineRule
from app.services.cli_scan import scan_inventory_target
from app.services.cli_setup import add_inventory_target
from app.services.golden_baseline_importer import import_golden_baseline
from app.services.http_content import (
    HTTP_CONTENT_ISSUE_KEYS,
    complete_sri_candidate,
    evaluate_http_content,
    inspect_http_content,
)
from app.services.internal_risk_calibration import resolve_ssc_internal_risk
from app.services.scan_engine import _not_assessed_reason
from app.services.scan_executors import HTTPExecutor, InventoryScanTarget, validate_scan_config
from app.services.scoring_engine import ScoringDefinition
from app.services.ssc_api_baseline import API_ORIGIN, FACTORS_ENDPOINT, ISSUES_ENDPOINT, normalize_api_payloads
from app.services.wave3b_rules import WAVE3B_RULES, active_wave3b_mappings
from app.models.scan_models import ScanTargetTypeEnum
from tests.test_scan_executors import _http_server


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _attempt(
    body: bytes,
    content_type: str = "text/html; charset=utf-8",
    *,
    status: int = 200,
    attempt_number: int = 1,
    body_complete: bool = True,
):
    content = inspect_http_content(
        body,
        content_type,
        "https://example.test:443/covered",
        body_complete=body_complete,
        content_encoding=None,
    )
    return {
        "endpoint_available": True,
        "status_code": status,
        "request_scheme": "https",
        "request_port": 443,
        "request_path": "/covered",
        "terminal_scheme": "https",
        "stop_reason": "terminal_response",
        "content_type": content_type,
        "body_complete": body_complete,
        "coverage_declared": True,
        "attempt_number": attempt_number,
        "response_headers_sha256": "a" * 64,
        "observed_at": f"2026-10-02T00:00:0{attempt_number}+00:00",
        "content": content,
    }


def test_all_http_content_evaluators_match_positive_conditions():
    html = b"""<html><head><script src='/missing-sri.js'></script></head><body>
        <a href='ftp://files.example.test/archive'>ftp</a>
        <a href='mailto:security@example.test'>contact</a>
        <a href='file:///etc/example'>file</a>
        <a href='http://outside.example.test/'>http</a>
    </body></html>"""
    first = _attempt(html, attempt_number=1)
    second = _attempt(html, attempt_number=2)
    evaluated = evaluate_http_content([first, second])
    for key in (
        "unsafe_sri_v2", "insecure_ftp", "contact_information_detected",
        "local_file_path_exposed_via_url_scheme", "links_to_insecure_website",
    ):
        assert evaluated[key]["outcome"] == "MATCH"
    assert evaluated["server_error"]["outcome"] == "NO_MATCH"
    assert evaluated["service_soap"]["outcome"] == "NO_MATCH"
    serialized = json.dumps(evaluated)
    assert "security@example.test" not in serialized
    assert "files.example.test" not in serialized
    assert "outside.example.test" not in serialized

    soap = b"<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'><soap:Body/></soap:Envelope>"
    soap_result = evaluate_http_content([
        _attempt(soap, "application/soap+xml", attempt_number=1),
        _attempt(soap, "application/soap+xml", attempt_number=2),
    ])
    assert soap_result["service_soap"]["outcome"] == "MATCH"

    wsdl = b"""<wsdl:definitions xmlns:wsdl='http://schemas.xmlsoap.org/wsdl/'
        xmlns:soap='http://schemas.xmlsoap.org/wsdl/soap/'><wsdl:binding><soap:binding/></wsdl:binding></wsdl:definitions>"""
    wsdl_result = evaluate_http_content([
        _attempt(wsdl, "application/wsdl+xml", attempt_number=1),
        _attempt(wsdl, "application/wsdl+xml", attempt_number=2),
    ])
    assert wsdl_result["service_soap"]["outcome"] == "MATCH"

    errors = evaluate_http_content([
        _attempt(b"error", status=503, attempt_number=1),
        _attempt(b"error", status=503, attempt_number=2),
    ])
    assert errors["server_error"]["outcome"] == "MATCH"


def test_all_http_content_evaluators_have_deterministic_no_match():
    safe = b"<html><body><a href='https://example.test/safe'>safe</a></body></html>"
    evaluated = evaluate_http_content([
        _attempt(safe, attempt_number=1),
        _attempt(safe, attempt_number=2),
    ])
    assert set(evaluated) == set(HTTP_CONTENT_ISSUE_KEYS)
    assert all(item["outcome"] == "NO_MATCH" for item in evaluated.values())


def test_missing_failed_malformed_and_unsupported_evidence_is_indeterminate():
    failed = {
        "endpoint_available": False,
        "status_code": None,
        "request_scheme": "https",
        "request_port": 443,
        "request_path": "/covered",
        "stop_reason": "request_error",
        "coverage_declared": True,
        "attempt_number": 1,
    }
    failed_results = evaluate_http_content([failed])
    assert all(item["outcome"] == "INDETERMINATE" for item in failed_results.values())

    malformed = [_attempt(b"<html><a href='https://safe'>\xff</a></html>", attempt_number=index) for index in (1, 2)]
    malformed_results = evaluate_http_content(malformed)
    for key in HTTP_CONTENT_ISSUE_KEYS:
        if key != "server_error":
            assert malformed_results[key]["outcome"] == "INDETERMINATE"

    malformed_url = [
        _attempt(b"<html><script src='http://[invalid' integrity='sha384-Zm9v'></script></html>", attempt_number=index)
        for index in (1, 2)
    ]
    malformed_url_results = evaluate_http_content(malformed_url)
    for key in HTTP_CONTENT_ISSUE_KEYS:
        if key != "server_error":
            assert malformed_url_results[key]["outcome"] == "INDETERMINATE"

    binary = [_attempt(b"\x00\x01", "application/octet-stream", attempt_number=index) for index in (1, 2)]
    binary_results = evaluate_http_content(binary)
    for key in HTTP_CONTENT_ISSUE_KEYS:
        if key != "server_error":
            assert binary_results[key]["outcome"] == "INDETERMINATE"

    malformed_xml = [_attempt(b"<Envelope>", "application/soap+xml", attempt_number=index) for index in (1, 2)]
    assert evaluate_http_content(malformed_xml)["service_soap"]["outcome"] == "INDETERMINATE"

    blocked = [_attempt(b"blocked", status=403, attempt_number=index) for index in (1, 2)]
    blocked_results = evaluate_http_content(blocked)
    for key in HTTP_CONTENT_ISSUE_KEYS:
        if key != "server_error":
            assert blocked_results[key]["outcome"] == "INDETERMINATE"

    one_error = evaluate_http_content([
        _attempt(b"error", status=503, attempt_number=1),
        _attempt(b"ok", status=200, attempt_number=2),
    ])
    assert one_error["server_error"]["outcome"] == "INDETERMINATE"


def test_actual_malformed_content_maps_to_malformed_evidence():
    malformed = [
        _attempt(b"<html><body>\xff</body></html>", attempt_number=index)
        for index in (1, 2)
    ]
    evaluation = evaluate_http_content(malformed)["contact_information_detected"]
    assert evaluation["outcome"] == "INDETERMINATE"
    assert all(item["parse_reason"] == "html_decode_error" for item in evaluation["evidence"])
    assert _not_assessed_reason({"status": "success"}, evaluation) == "malformed_evidence"


def test_sri_digest_match_mismatch_and_cross_origin_boundaries():
    resource = b"console.log('bounded');"
    encoded = base64.b64encode(hashlib.sha384(resource).digest()).decode()
    content = inspect_http_content(
        f"<script src='/app.js' integrity='sha384-{encoded}'></script>".encode(),
        "text/html", "https://example.test:443/", body_complete=True, content_encoding=None,
    )
    candidate = content["sri_candidates"][0]
    complete_sri_candidate(candidate, {
        "endpoint_available": True, "status_code": 200, "stop_reason": "terminal_response",
        "body_complete": True, "_body": resource,
    })
    assert candidate["outcome"] == "NO_MATCH"

    mismatch_content = inspect_http_content(
        f"<script src='/app.js' integrity='sha384-{encoded}'></script>".encode(),
        "text/html", "https://example.test:443/", body_complete=True, content_encoding=None,
    )
    complete_sri_candidate(mismatch_content["sri_candidates"][0], {
        "endpoint_available": True, "status_code": 200, "stop_reason": "terminal_response",
        "body_complete": True, "_body": b"changed",
    })
    assert mismatch_content["sri_candidates"][0]["outcome"] == "MATCH"

    cross_origin = inspect_http_content(
        f"<script src='https://cdn.example.test/app.js' integrity='sha384-{encoded}' crossorigin='secret-value'></script>".encode(),
        "text/html", "https://example.test:443/", body_complete=True, content_encoding=None,
    )
    assert cross_origin["sri_candidates"][0]["outcome"] == "INDETERMINATE"
    assert cross_origin["sri_candidates"][0]["crossorigin_mode"] == "invalid"

    compressed_content = inspect_http_content(
        f"<script src='/app.js' integrity='sha384-{encoded}'></script>".encode(),
        "text/html", "https://example.test:443/", body_complete=True, content_encoding=None,
    )
    complete_sri_candidate(compressed_content["sri_candidates"][0], {
        "endpoint_available": True, "status_code": 200, "stop_reason": "terminal_response",
        "body_complete": True, "_body": resource, "headers": {"content-encoding": ["gzip"]},
    })
    assert compressed_content["sri_candidates"][0]["outcome"] == "INDETERMINATE"

    redirected_content = inspect_http_content(
        f"<script src='/app.js' integrity='sha384-{encoded}'></script>".encode(),
        "text/html", "https://example.test:443/", body_complete=True, content_encoding=None,
    )
    complete_sri_candidate(redirected_content["sri_candidates"][0], {
        "endpoint_available": True, "status_code": 200, "stop_reason": "terminal_response",
        "body_complete": True, "_body": resource, "headers": {}, "_sri_cross_origin_redirect": True,
    })
    assert redirected_content["sri_candidates"][0]["outcome"] == "INDETERMINATE"

    invalid = inspect_http_content(
        b"<script src='/app.js' integrity='sha384-not-base64!'></script>",
        "text/html", "https://example.test:443/", body_complete=True, content_encoding=None,
    )
    assert invalid["sri_candidates"][0]["outcome"] == "MATCH"
    disallowed = inspect_http_content(
        b"<link rel='stylesheet' href='/app.css' integrity='md5-Zm9v'>",
        "text/html", "https://example.test:443/", body_complete=True, content_encoding=None,
    )
    assert disallowed["sri_candidates"][0]["outcome"] == "MATCH"


def test_sri_uses_only_the_strongest_supported_integrity_algorithm():
    resource = b"console.log('strongest');"

    def outcome(*tokens: str) -> tuple[str, str]:
        content = inspect_http_content(
            f"<script src='/app.js' integrity='{' '.join(tokens)}'></script>".encode(),
            "text/html", "https://example.test:443/", body_complete=True, content_encoding=None,
        )
        candidate = content["sri_candidates"][0]
        complete_sri_candidate(candidate, {
            "endpoint_available": True, "status_code": 200, "stop_reason": "terminal_response",
            "body_complete": True, "_body": resource, "headers": {},
        })
        return candidate["outcome"], candidate["resource_check"]["selected_integrity_algorithm"]

    correct256 = base64.b64encode(hashlib.sha256(resource).digest()).decode()
    correct512 = base64.b64encode(hashlib.sha512(resource).digest()).decode()
    incorrect256 = base64.b64encode(hashlib.sha256(b"wrong").digest()).decode()
    incorrect512 = base64.b64encode(hashlib.sha512(b"wrong").digest()).decode()
    second_incorrect512 = base64.b64encode(hashlib.sha512(b"also wrong").digest()).decode()

    assert outcome(f"sha256-{correct256}", f"sha512-{incorrect512}") == ("MATCH", "sha512")
    assert outcome(f"sha256-{incorrect256}", f"sha512-{correct512}") == ("NO_MATCH", "sha512")
    assert outcome(f"sha512-{incorrect512}", f"sha512-{correct512}", f"sha512-{second_incorrect512}") == (
        "NO_MATCH", "sha512",
    )
    assert outcome(f"sha256-{correct256}") == ("NO_MATCH", "sha256")
    assert outcome("md5-Zm9v", f"sha512-{correct512}") == ("NO_MATCH", "sha512")


class BoundedContentHandler(BaseHTTPRequestHandler):
    body = b""
    content_type = "text/html"
    request_count = 0

    def log_message(self, _format, *args):
        return

    def do_GET(self):
        type(self).request_count += 1
        self.send_response(200)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)


def _local_target():
    return InventoryScanTarget(
        ScanTargetTypeEnum.HOST, "target", "localhost", "127.0.0.1", "example.test", True,
    )


class DeclaredPathHandler(BaseHTTPRequestHandler):
    body = b"<html><body><a href='https://example.test/safe'>safe</a></body></html>"
    requested_paths: list[str] = []

    def log_message(self, _format, *args):
        return

    def do_GET(self):
        type(self).requested_paths.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)


def test_default_http_content_scope_declares_only_root_and_collects_two_attempts():
    config = validate_scan_config({})
    assert config["http_paths"] == ["/"]

    DeclaredPathHandler.requested_paths = []
    with _http_server(DeclaredPathHandler) as port:
        config = validate_scan_config({
            "executors": ["http"], "http_ports": [port], "https_ports": [],
        })
        evidence = HTTPExecutor().collect(_local_target(), config).evidence

    assert evidence["declared_paths"] == ["/"]
    assert DeclaredPathHandler.requested_paths == ["/", "/"]
    assert len(evidence["attempts"]) == 2
    assert all(attempt["coverage_declared"] is True for attempt in evidence["attempts"])
    assert [attempt["attempt_number"] for attempt in evidence["attempts"]] == [1, 2]
    assert all(evidence["evaluations"][key]["outcome"] == "NO_MATCH" for key in HTTP_CONTENT_ISSUE_KEYS)


def test_explicit_http_paths_replace_the_default_declared_root_scope():
    DeclaredPathHandler.requested_paths = []
    with _http_server(DeclaredPathHandler) as port:
        config = validate_scan_config({
            "executors": ["http"],
            "http_ports": [port],
            "https_ports": [],
            "http_paths": ["/login", "/health"],
        })
        evidence = HTTPExecutor().collect(_local_target(), config).evidence

    assert config["http_paths"] == ["/login", "/health"]
    assert evidence["declared_paths"] == ["/login", "/health"]
    assert DeclaredPathHandler.requested_paths == ["/login", "/login", "/health", "/health"]
    assert all(attempt["coverage_declared"] is True for attempt in evidence["attempts"])


def test_http_body_limit_is_enforced_and_cannot_create_false_no_match():
    BoundedContentHandler.body = b"<html>" + b"x" * 4096 + b"</html>"
    BoundedContentHandler.content_type = "text/html"
    BoundedContentHandler.request_count = 0
    with _http_server(BoundedContentHandler) as port:
        evidence = HTTPExecutor().collect(_local_target(), {
            "http_ports": [port], "https_ports": [], "http_paths": ["/"],
            "response_size_limit_bytes": 1024,
        }).evidence
    assert BoundedContentHandler.request_count == 2
    assert all(attempt["body_bytes_captured"] == 1024 for attempt in evidence["attempts"])
    assert all(attempt["body_complete"] is False for attempt in evidence["attempts"])
    for key in HTTP_CONTENT_ISSUE_KEYS:
        if key != "server_error":
            assert evidence["evaluations"][key]["outcome"] == "INDETERMINATE"


class SRIHandler(BaseHTTPRequestHandler):
    resource = b"console.log('verified');"
    page_requests = 0
    resource_requests = 0

    def log_message(self, _format, *args):
        return

    def do_GET(self):
        if self.path == "/app.js":
            type(self).resource_requests += 1
            body, content_type = self.resource, "application/javascript"
        else:
            type(self).page_requests += 1
            digest = base64.b64encode(hashlib.sha384(self.resource).digest()).decode()
            body = f"<html><script src='/app.js' integrity='sha384-{digest}'></script></html>".encode()
            content_type = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_sri_resource_fetch_is_same_origin_nonrecursive_and_bounded():
    SRIHandler.page_requests = SRIHandler.resource_requests = 0
    with _http_server(SRIHandler) as port:
        evidence = HTTPExecutor().collect(_local_target(), {
            "http_ports": [port], "https_ports": [], "http_paths": ["/"],
            "http_sri_resource_limit": 1,
        }).evidence
    assert SRIHandler.page_requests == 2
    assert SRIHandler.resource_requests == 1
    assert evidence["evaluations"]["unsafe_sri_v2"]["outcome"] == "NO_MATCH"
    assert SRIHandler.resource not in json.dumps(evidence).encode()


class CrossOriginSRIHandler(BaseHTTPRequestHandler):
    request_count = 0

    def log_message(self, _format, *args):
        return

    def do_GET(self):
        type(self).request_count += 1
        digest = base64.b64encode(hashlib.sha384(b"not-fetched").digest()).decode()
        body = f"<script src='https://outside.example/app.js' integrity='sha384-{digest}'></script>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_cross_origin_sri_resource_is_not_followed():
    CrossOriginSRIHandler.request_count = 0
    with _http_server(CrossOriginSRIHandler) as port:
        evidence = HTTPExecutor().collect(_local_target(), {
            "http_ports": [port], "https_ports": [], "http_paths": ["/"],
        }).evidence
    assert CrossOriginSRIHandler.request_count == 2
    assert evidence["evaluations"]["unsafe_sri_v2"]["outcome"] == "INDETERMINATE"


class SRIOriginRedirectDestinationHandler(BaseHTTPRequestHandler):
    final_requests = 0

    def log_message(self, _format, *args):
        return

    def do_GET(self):
        if self.path == "/final.js":
            type(self).final_requests += 1
        body = b"<html></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SRIOriginRedirectSourceHandler(BaseHTTPRequestHandler):
    destination_port = 0
    resource_requests = 0
    resource = b"console.log('redirected');"

    def log_message(self, _format, *args):
        return

    def do_GET(self):
        if self.path == "/app.js":
            type(self).resource_requests += 1
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.destination_port}/final.js")
            self.end_headers()
            return
        digest = base64.b64encode(hashlib.sha512(self.resource).digest()).decode()
        body = f"<script src='/app.js' integrity='sha512-{digest}'></script>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_sri_cross_origin_redirect_is_stopped_before_redirected_get():
    SRIOriginRedirectDestinationHandler.final_requests = 0
    SRIOriginRedirectSourceHandler.resource_requests = 0
    with _http_server(SRIOriginRedirectDestinationHandler) as destination_port:
        SRIOriginRedirectSourceHandler.destination_port = destination_port
        with _http_server(SRIOriginRedirectSourceHandler) as source_port:
            evidence = HTTPExecutor().collect(_local_target(), {
                "http_ports": [source_port, destination_port], "https_ports": [], "http_paths": ["/"],
            }).evidence
    assert SRIOriginRedirectSourceHandler.resource_requests == 1
    assert SRIOriginRedirectDestinationHandler.final_requests == 0
    assert evidence["evaluations"]["unsafe_sri_v2"]["outcome"] == "INDETERMINATE"
    resources = evidence["evaluations"]["unsafe_sri_v2"]["evidence"][0]["resources"]
    assert resources[0]["resource_check"]["stop_reason"] == "sri_cross_origin_redirect_blocked"


class SRISameOriginRedirectHandler(BaseHTTPRequestHandler):
    initial_resource_requests = 0
    final_resource_requests = 0
    resource = b"console.log('budgeted');"

    def log_message(self, _format, *args):
        return

    def do_GET(self):
        if self.path == "/app.js":
            type(self).initial_resource_requests += 1
            self.send_response(302)
            self.send_header("Location", "/final.js")
            self.end_headers()
            return
        if self.path == "/final.js":
            type(self).final_resource_requests += 1
            body, content_type = self.resource, "application/javascript"
        else:
            digest = base64.b64encode(hashlib.sha512(self.resource).digest()).decode()
            body = f"<script src='/app.js' integrity='sha512-{digest}'></script>".encode()
            content_type = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_sri_actual_get_budget_counts_redirects_and_exhaustion_is_indeterminate():
    SRISameOriginRedirectHandler.initial_resource_requests = 0
    SRISameOriginRedirectHandler.final_resource_requests = 0
    with _http_server(SRISameOriginRedirectHandler) as port:
        exhausted = HTTPExecutor().collect(_local_target(), {
            "http_ports": [port], "https_ports": [], "http_paths": ["/"],
            "http_sri_resource_limit": 1,
        }).evidence
    assert SRISameOriginRedirectHandler.initial_resource_requests == 1
    assert SRISameOriginRedirectHandler.final_resource_requests == 0
    assert exhausted["evaluations"]["unsafe_sri_v2"]["outcome"] == "INDETERMINATE"
    resources = exhausted["evaluations"]["unsafe_sri_v2"]["evidence"][0]["resources"]
    assert resources[0]["resource_check"]["stop_reason"] == "sri_request_budget_exhausted"

    SRISameOriginRedirectHandler.initial_resource_requests = 0
    SRISameOriginRedirectHandler.final_resource_requests = 0
    with _http_server(SRISameOriginRedirectHandler) as port:
        complete = HTTPExecutor().collect(_local_target(), {
            "http_ports": [port], "https_ports": [], "http_paths": ["/"],
            "http_sri_resource_limit": 2,
        }).evidence
    assert SRISameOriginRedirectHandler.initial_resource_requests == 1
    assert SRISameOriginRedirectHandler.final_resource_requests == 1
    assert complete["evaluations"]["unsafe_sri_v2"]["outcome"] == "NO_MATCH"


def _wave3b_baseline():
    factors = {
        "application_security": {"key": "application_security", "name": "Application Security"},
        "network_security": {"key": "network_security", "name": "Network Security"},
    }
    rows = [{
        "key": spec.issue_key,
        "severity": "medium" if spec.issue_key in {"insecure_ftp", "service_soap"} else "low",
        "factor": "network_security" if spec.issue_key == "service_soap" else "application_security",
        "title": spec.title,
    } for spec in WAVE3B_RULES]
    payloads = {FACTORS_ENDPOINT: {"entries": list(factors.values())}, ISSUES_ENDPOINT: {"entries": rows}}
    raw = {}
    for endpoint, payload in payloads.items():
        body = json.dumps(payload)
        raw[API_ORIGIN + endpoint] = {
            "body": body,
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "captured_at": "2026-10-02T00:00:00+00:00",
        }
    return normalize_api_payloads(raw)


class FTPLinkHandler(BaseHTTPRequestHandler):
    request_count = 0

    def log_message(self, _format, *args):
        return

    def do_GET(self):
        type(self).request_count += 1
        body = b"<html><a href='ftp://files.example.test/archive'>archive</a></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_default_cli_scan_scope_exact_mapping_and_uncalibrated_finding_fail_closed(db):
    import_golden_baseline(db, _wave3b_baseline(), attest_real_source=True)
    mappings = active_wave3b_mappings(db)
    assert len(mappings) == len(WAVE3B_RULES) == 7
    assert {item["issue_key"] for item in mappings} == set(HTTP_CONTENT_ISSUE_KEYS)
    for mapping in mappings:
        issue_version = db.get(CatalogIssueTypeVersion, UUID(mapping["issue_version_id"]))
        assert issue_version.source_type == SourceTypeEnum.SSC_API
        risk = resolve_ssc_internal_risk(mapping["issue_key"])
        assert risk.breach_risk == "UNKNOWN"
        assert risk.affects_score is False

    rule = db.scalar(select(RuleEngineRule).where(RuleEngineRule.stable_key == "ssc.wave3b.insecure_ftp"))
    suffix = uuid4().hex[:12]
    target = add_inventory_target(
        db,
        organization="Wave 3B " + suffix,
        domain_name=suffix + ".test",
        hostname="localhost",
        ip="127.0.0.1",
        approved=True,
        allow_sensitive=True,
        approval_notes="Local deterministic Wave 3B fixture",
    )
    FTPLinkHandler.request_count = 0
    with _http_server(FTPLinkHandler) as port:
        result = scan_inventory_target(
            db,
            name="localhost",
            organization_id=UUID(target["organization_id"]),
            scan_config={"executors": ["http"], "http_ports": [port], "https_ports": []},
            model=ScoringDefinition(),
            rule_keys=[rule.stable_key],
        )
    assert FTPLinkHandler.request_count == 2
    assert result.evidence[0].summary["declared_paths"] == ["/"]
    assert len(result.evidence[0].summary["attempts"]) == 2
    assert all(attempt["coverage_declared"] is True for attempt in result.evidence[0].summary["attempts"])
    assert result.evidence[0].summary["evaluations"]["insecure_ftp"]["outcome"] == "MATCH"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.ssc_issue_key == "insecure_ftp"
    assert finding.breach_risk == "UNKNOWN"
    assert finding.affects_score is False
    assert finding.score_impact == 0
