import hashlib
import json
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import engine
from app.models.catalog_models import CatalogIssueTypeVersion, SourceTypeEnum
from app.models.rule_models import RuleEngineRule
from app.outputs.report import render_html
from app.services.cli_scan import scan_inventory_target
from app.services.cli_setup import add_inventory_target
from app.services.golden_baseline_importer import import_golden_baseline
from app.services.scan_executors import (
    WAVE1_POLICY_VERSION,
    _domain_missing_https,
    _evaluate_http_wave1,
    _evaluate_tls_certificate,
)
from app.services.scoring_engine import ScoringDefinition
from app.services.ssc_api_baseline import API_ORIGIN, FACTORS_ENDPOINT, ISSUES_ENDPOINT, normalize_api_payloads
from app.services.wave1_rules import WAVE1_RULES, active_wave1_mappings
from tests.test_scan_executors import _http_server


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _terminal(headers, *, scheme="https", content_type="text/html; charset=utf-8", path="/"):
    return {
        "endpoint_available": True,
        "status_code": 200,
        "request_scheme": scheme,
        "request_port": 443 if scheme == "https" else 80,
        "request_path": path,
        "terminal_scheme": scheme,
        "stop_reason": "terminal_response",
        "redirect_chain": [{"scheme": scheme, "status_code": 200, "location_scheme": None}],
        "headers": {**headers, "content-type": [content_type]},
        "content_type": content_type,
        "csp_meta_policies": [],
        "certificate_trusted": True if scheme == "https" else None,
        "coverage_declared": True,
    }


def test_http_header_evaluators_positive_negative_and_malformed_boundaries():
    positive = _evaluate_http_wave1([_terminal({
        "content-security-policy": ["default-src *; script-src 'unsafe-inline'"],
        "strict-transport-security": ["max-age=100"],
        "x-content-type-options": ["no-sniff"],
    })])
    for key in (
        "csp_unsafe_policy_v2", "csp_too_broad_v2", "hsts_incorrect_v2",
        "x_content_type_options_incorrect_v2", "x_frame_options_incorrect_v2",
    ):
        assert positive[key]["matched"] is True
    assert positive["csp_no_policy_v2"]["matched"] is False

    missing = _evaluate_http_wave1([_terminal({
        "strict-transport-security": ["max-age=31536000; includeSubDomains"],
        "x-content-type-options": ["nosniff"],
        "x-frame-options": ["DENY"],
    })])
    assert missing["csp_no_policy_v2"]["matched"] is True

    safe = _evaluate_http_wave1([_terminal({
        "content-security-policy": ["default-src 'none'; script-src 'nonce-AbC'; object-src 'none'; frame-ancestors 'none'"],
        "strict-transport-security": ["max-age=31536000; includeSubDomains"],
        "x-content-type-options": ["nosniff"],
    })])
    assert all(safe[key]["matched"] is False for key in (
        "csp_no_policy_v2", "csp_unsafe_policy_v2", "csp_too_broad_v2",
        "hsts_incorrect_v2", "x_content_type_options_incorrect_v2", "x_frame_options_incorrect_v2",
    ))

    malformed = _evaluate_http_wave1([_terminal({
        "content-security-policy": ["??? invalid"],
        "strict-transport-security": ["max-age=31536000; includeSubDomains"],
        "x-content-type-options": ["nosniff"],
    })])
    assert malformed["csp_no_policy_v2"]["matched"] is None
    assert malformed["csp_unsafe_policy_v2"]["matched"] is None
    assert malformed["csp_too_broad_v2"]["matched"] is None
    assert malformed["x_frame_options_incorrect_v2"]["matched"] is None

    implicit_root = _terminal({})
    implicit_root["coverage_declared"] = False
    implicit = _evaluate_http_wave1([implicit_root])
    assert implicit["csp_no_policy_v2"]["matched"] is None
    assert implicit["hsts_incorrect_v2"]["matched"] is None
    assert implicit["x_content_type_options_incorrect_v2"]["matched"] is None
    assert implicit["x_frame_options_incorrect_v2"]["matched"] is None


def test_csp_multiple_policy_and_nonce_false_positive_boundaries():
    evidence = _terminal({
        "content-security-policy": [
            "default-src *; script-src 'unsafe-inline' *",
            "default-src 'none'; script-src 'nonce-good'; object-src 'none'; frame-ancestors 'self'",
        ],
        "strict-transport-security": ["max-age=31536000; includeSubDomains"],
        "x-content-type-options": ["nosniff"],
    })
    evaluated = _evaluate_http_wave1([evidence])
    assert evaluated["csp_unsafe_policy_v2"]["matched"] is False
    assert evaluated["csp_too_broad_v2"]["matched"] is False
    assert evaluated["x_frame_options_incorrect_v2"]["matched"] is False


def test_redirect_evaluators_positive_negative_and_insufficient_boundaries():
    downgrade = {
        "endpoint_available": True, "request_scheme": "https", "request_port": 443, "request_path": "/",
        "terminal_scheme": "http", "stop_reason": "terminal_response", "certificate_trusted": False,
        "redirect_chain": [
            {"scheme": "https", "status_code": 302, "location_scheme": "http"},
            {"scheme": "http", "status_code": 200, "location_scheme": None},
        ], "coverage_declared": True,
    }
    evaluated = _evaluate_http_wave1([downgrade])
    assert evaluated["redirect_chain_contains_http_v2"]["matched"] is True
    assert evaluated["insecure_https_redirect_pattern_v2"]["matched"] is True

    ordinary_http = {
        "endpoint_available": True, "request_scheme": "http", "request_port": 80, "request_path": "/",
        "terminal_scheme": "http", "stop_reason": "terminal_response", "certificate_trusted": None,
        "redirect_chain": [{"scheme": "http", "status_code": 200, "location_scheme": None}],
        "coverage_declared": True,
    }
    unavailable_https = {
        "endpoint_available": False, "request_scheme": "https", "request_port": 443, "request_path": "/",
        "terminal_scheme": None, "stop_reason": "request_error", "certificate_trusted": None,
        "redirect_chain": [], "coverage_declared": True,
    }
    ordinary = _evaluate_http_wave1([ordinary_http, unavailable_https])
    assert ordinary["redirect_chain_contains_http_v2"]["matched"] is False
    assert ordinary["insecure_https_redirect_pattern_v2"]["matched"] is True
    assert ordinary["domain_missing_https_v2"]["matched"] is True

    permanent = {
        "endpoint_available": True, "request_scheme": "http", "request_port": 80, "request_path": "/",
        "terminal_scheme": "https", "stop_reason": "terminal_response", "certificate_trusted": True,
        "redirect_chain": [
            {"scheme": "http", "status_code": 301, "location_scheme": "https"},
            {"scheme": "https", "status_code": 200, "location_scheme": None},
        ], "coverage_declared": True,
    }
    https = {**_terminal({}, scheme="https"), "certificate_trusted": True}
    secure = _evaluate_http_wave1([permanent, https])
    assert secure["domain_missing_https_v2"]["matched"] is False
    assert secure["insecure_https_redirect_pattern_v2"]["matched"] is False
    assert _domain_missing_https([{"request_path": "/", "request_scheme": "http", "endpoint_available": False}]) is None


def _tls_metadata(**changes):
    now = datetime(2026, 9, 21, tzinfo=timezone.utc)
    leaf = {
        "position": 0, "fingerprint_sha256": "a" * 64,
        "not_before": (now - timedelta(days=30)).isoformat(),
        "not_after": (now + timedelta(days=30)).isoformat(),
        "public_key_algorithm": "RSA", "public_key_bits": 2048, "public_key_curve": None,
        "signature_oid": "1.2.840.113549.1.1.11", "signature_hash": "sha256", "weak_signature": False,
        "self_issued": False, "self_signature_valid": False,
        "ocsp_uris": ["http://ocsp.example.test"], "crl_distribution_uris": [],
    }
    metadata = {
        "certificate_chain": [leaf], "chain_capture_complete": True,
        "certificate_lifetime_days": 60, "self_signed_explicitly_trusted": False,
    }
    metadata.update(changes)
    return now, metadata


def test_tls_certificate_evaluators_positive_negative_and_boundary_cases():
    now, safe_metadata = _tls_metadata()
    safe = _evaluate_tls_certificate(safe_metadata, now)
    assert all(item["matched"] is False for item in safe.values())

    leaf = dict(safe_metadata["certificate_chain"][0])
    leaf.update({
        "not_after": (now - timedelta(seconds=1)).isoformat(), "public_key_bits": 1024,
        "signature_hash": "sha1", "weak_signature": True, "ocsp_uris": [],
    })
    positive = _evaluate_tls_certificate({**safe_metadata, "certificate_chain": [leaf]}, now)
    assert positive["tlscert_expired"]["matched"] is True
    assert positive["insecure_server_certificate_key_size"]["matched"] is True
    assert positive["tlscert_weak_signature"]["matched"] is True
    assert positive["tlscert_no_revocation"]["matched"] is True

    self_signed = dict(leaf)
    self_signed.update({"self_issued": True, "self_signature_valid": True, "signature_hash": "sha256", "weak_signature": False})
    self_result = _evaluate_tls_certificate({**safe_metadata, "certificate_chain": [self_signed]}, now)
    assert self_result["tlscert_self_signed"]["matched"] is True
    assert self_result["tlscert_no_revocation"]["matched"] is False
    trusted_result = _evaluate_tls_certificate({**safe_metadata, "certificate_chain": [self_signed], "self_signed_explicitly_trusted": True}, now)
    assert trusted_result["tlscert_self_signed"]["matched"] is False

    short_lived = _evaluate_tls_certificate({**safe_metadata, "certificate_lifetime_days": 7, "certificate_chain": [{**safe_metadata["certificate_chain"][0], "ocsp_uris": []}]}, now)
    assert short_lived["tlscert_no_revocation"]["matched"] is False
    incomplete = _evaluate_tls_certificate({**safe_metadata, "chain_capture_complete": False}, now)
    assert incomplete["tlscert_weak_signature"]["matched"] is None


def _wave1_baseline():
    factors = {
        "application_security": {"key": "application_security", "name": "Application Security"},
        "network_security": {"key": "network_security", "name": "Network Security"},
    }
    rows = []
    for spec in WAVE1_RULES:
        factor = "network_security" if spec.issue_key.startswith("tlscert_") else "application_security"
        rows.append({"key": spec.issue_key, "severity": "low", "factor": factor, "title": spec.title})
    payloads = {FACTORS_ENDPOINT: {"entries": list(factors.values())}, ISSUES_ENDPOINT: {"entries": rows}}
    raw = {}
    for endpoint, payload in payloads.items():
        body = json.dumps(payload)
        raw[API_ORIGIN + endpoint] = {
            "body": body,
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "captured_at": "2026-09-21T00:00:00+00:00",
        }
    return normalize_api_payloads(raw)


class MissingCSPHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        return

    def do_GET(self):
        body = b"<html><title>covered</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SafeCSPHandler(MissingCSPHandler):
    def do_GET(self):
        body = b"<html><title>covered</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-good'; object-src 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_real_baseline_activation_linkage_observation_finding_and_report(db):
    import_golden_baseline(db, _wave1_baseline(), attest_real_source=True)
    mappings = active_wave1_mappings(db)
    assert len(mappings) == len(WAVE1_RULES) == 14
    assert {item["issue_key"] for item in mappings} == {spec.issue_key for spec in WAVE1_RULES}
    for mapping in mappings:
        issue_version = db.get(CatalogIssueTypeVersion, UUID(mapping["issue_version_id"]))
        assert issue_version.source_type == SourceTypeEnum.SSC_API
        assert mapping["ssc_severity"] == "low"
    rule = db.scalar(select(RuleEngineRule).where(RuleEngineRule.stable_key == "ssc.wave1.csp_no_policy_v2"))
    assert rule.current_version.catalog_issue_type_version_id == rule.catalog_issue_type.current_version_id

    suffix = uuid4().hex[:12]
    target = add_inventory_target(
        db,
        organization="Wave 1 " + suffix,
        domain_name=suffix + ".test",
        hostname="localhost",
        ip="127.0.0.1",
        approved=True,
        allow_sensitive=True,
        approval_notes="Local deterministic Wave 1 fixture",
    )
    with _http_server(MissingCSPHandler) as port:
        result = scan_inventory_target(
            db,
            name="localhost",
            organization_id=UUID(target["organization_id"]),
            scan_config={"executors": ["http"], "http_ports": [port], "https_ports": [], "http_paths": ["/"]},
            model=ScoringDefinition(),
            rule_keys=[rule.stable_key],
        )
    assert len(result.findings) == 1
    evaluation = result.evidence[0].summary["evaluations"]["csp_no_policy_v2"]
    assert evaluation["outcome"] == "MATCH" and evaluation["policy_version"] == WAVE1_POLICY_VERSION
    finding = result.findings[0]
    assert finding.ssc_issue_key == "csp_no_policy_v2"
    assert finding.ssc_severity == "low"
    assert finding.catalog_issue_type_version_id == str(rule.current_version.catalog_issue_type_version_id)
    assert finding.breach_risk == "UNKNOWN" and finding.score_impact == 0
    html = render_html(result)
    assert "csp_no_policy_v2" in html and "SSC severity: low" in html

    with _http_server(SafeCSPHandler) as port:
        negative = scan_inventory_target(
            db,
            name="localhost",
            organization_id=UUID(target["organization_id"]),
            scan_config={"executors": ["http"], "http_ports": [port], "https_ports": [], "http_paths": ["/"]},
            model=ScoringDefinition(),
            rule_keys=[rule.stable_key],
        )
    assert negative.findings == []
    assert negative.evidence[0].summary["evaluations"]["csp_no_policy_v2"]["outcome"] == "NO_MATCH"
