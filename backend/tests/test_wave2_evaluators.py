import hashlib
import json
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
    WAVE2_EMAIL_POLICY_VERSION,
    WAVE2_TLS_POLICY_VERSION,
    _analyze_dmarc,
    _analyze_spf,
    _collect_tls_handshake_evidence,
    _evaluate_email_security,
    _evaluate_tls_handshake,
    _aggregate_evaluations,
    _parse_spf_record,
)
from app.services.scoring_engine import ScoringDefinition
from app.services.ssc_api_baseline import API_ORIGIN, FACTORS_ENDPOINT, ISSUES_ENDPOINT, normalize_api_payloads
from app.services.wave2_rules import WAVE2_RULES, active_wave2_mappings


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _dns(name, status="ANSWER", records=None, error=None):
    return {"name": name, "record_type": "TXT", "status": status, "records": records or [], "error": error}


def _email_evaluations(
    *, spf_records=None, dmarc_records=None, nonce=None, subdomains=None,
):
    root = _dns("example.test", records=spf_records or [])
    dmarc_txt = _dns("_dmarc.example.test", records=dmarc_records or [])
    spf = _analyze_spf("example.test", root, None, 53, 1.0)
    dmarc = _analyze_dmarc(dmarc_txt)
    nonce = nonce or [_dns("n1.example.test", "NXDOMAIN"), _dns("n2.example.test", "NXDOMAIN")]
    return _evaluate_email_security("example.test", root, spf, dmarc_txt, dmarc, nonce, subdomains or [])


def test_tls_handshake_evaluators_positive_negative_and_insufficient_boundaries():
    positive = {
        "protocols": {
            "TLSv1.0": {"accepted": True}, "TLSv1.1": {"accepted": False},
            "TLSv1.2": {"accepted": True}, "TLSv1.3": {"accepted": True},
        },
        "weak_cipher_catalog_complete": True,
        "weak_cipher_catalog_hash": "abc",
        "weak_cipher_attempts": [{"accepted": True, "negotiated_cipher": "ADH-AES128-GCM-SHA256"}],
    }
    result = _evaluate_tls_handshake(positive)
    assert result["tls_weak_protocol"]["matched"] is True
    assert result["tls_weak_cipher"]["matched"] is True
    assert result["tls_weak_protocol"]["policy_version"] == WAVE2_TLS_POLICY_VERSION

    negative = {
        "protocols": {
            "TLSv1.0": {"accepted": False}, "TLSv1.1": {"accepted": False},
            "TLSv1.2": {"accepted": True}, "TLSv1.3": {"accepted": True},
        },
        "weak_cipher_catalog_complete": True,
        "weak_cipher_catalog_hash": "abc",
        "weak_cipher_attempts": [{"accepted": False}, {"accepted": False}],
    }
    result = _evaluate_tls_handshake(negative)
    assert result["tls_weak_protocol"]["matched"] is False
    assert result["tls_weak_cipher"]["matched"] is False

    insufficient = {**negative, "protocols": {key: {"accepted": None} for key in negative["protocols"]}}
    insufficient["weak_cipher_attempts"] = [{"accepted": None}]
    result = _evaluate_tls_handshake(insufficient)
    assert result["tls_weak_protocol"]["matched"] is None
    assert result["tls_weak_cipher"]["matched"] is None

    incomplete_but_positive = {**positive, "weak_cipher_catalog_complete": False}
    assert _evaluate_tls_handshake(incomplete_but_positive)["tls_weak_cipher"]["matched"] is True
    incomplete_negative = {**negative, "weak_cipher_catalog_complete": False}
    assert _evaluate_tls_handshake(incomplete_negative)["tls_weak_cipher"]["matched"] is None
    aggregated = _aggregate_evaluations([{"evaluations": result}])
    assert aggregated["tls_weak_protocol"]["policy_version"] == WAVE2_TLS_POLICY_VERSION


def test_tls_collector_actively_probes_four_versions_and_constrained_cipher_groups(monkeypatch):
    calls = []

    def fake_attempt(_host, _name, _port, _timeout, *, version_name, cipher_name=None):
        calls.append((version_name, cipher_name))
        return {
            "offered_version": version_name, "offered_cipher": cipher_name,
            "outcome": "ACCEPTED" if version_name in {"TLSv1.2", "TLSv1.3"} else "REJECTED",
            "accepted": version_name in {"TLSv1.2", "TLSv1.3"},
            "negotiated_version": version_name if version_name in {"TLSv1.2", "TLSv1.3"} else None,
            "negotiated_cipher": "TLS_AES_128_GCM_SHA256" if version_name == "TLSv1.3" else "ECDHE-RSA-AES128-GCM-SHA256",
            "error_class": None, "error_reason": None,
        }

    monkeypatch.setattr("app.services.scan_executors._tls_attempt", fake_attempt)
    monkeypatch.setattr("app.services.scan_executors._weak_cipher_catalog", lambda: ([{
        "name": "ADH-AES128-GCM-SHA256", "protocol": "TLSv1.2", "strength_bits": 128,
        "aead": True, "symmetric": "aes-128-gcm", "kea": "kx-dhe", "auth": "auth-null",
        "policy_reasons": ["anonymous_authentication"],
    }], "hash"))
    evidence = _collect_tls_handshake_evidence("127.0.0.1", "example.test", 443, 1.0)
    assert set(evidence["protocols"]) == {"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
    assert evidence["weak_cipher_attempts"][-1]["offered_ciphers"] == ["ADH-AES128-GCM-SHA256"]
    assert evidence["weak_cipher_catalog_complete"] is False
    assert calls[:4] == [("TLSv1.0", None), ("TLSv1.1", None), ("TLSv1.2", None), ("TLSv1.3", None)]


def test_email_evaluators_positive_negative_malformed_and_false_positive_boundaries(monkeypatch):
    positive = _email_evaluations(
        spf_records=["v=spf1 ~all"],
        dmarc_records=["v=DMARC1; p=none"],
        nonce=[
            _dns("n1.example.test", records=["v=spf1 -all"]),
            _dns("n2.example.test", records=["v=spf1 -all"]),
        ],
        subdomains=[{"subdomain": "mail.example.test", "query": _dns("_dmarc.mail.example.test", "NXDOMAIN")}],
    )
    assert positive["spf_record_softfail"]["matched"] is True
    assert positive["spf_record_wildcard"]["matched"] is True
    assert positive["dmarc_contains_none"]["matched"] is True
    assert positive["subdomain_dmarc_contains_none"]["matched"] is True

    safe = _email_evaluations(spf_records=["v=spf1 -all"], dmarc_records=["v=DMARC1; p=reject; sp=quarantine"])
    assert safe["spf_record_missing"]["matched"] is False
    assert safe["spf_record_malformed"]["matched"] is False
    assert safe["spf_record_softfail"]["matched"] is False
    assert safe["spf_record_wildcard"]["matched"] is False
    assert safe["dmarc_record_missing"]["matched"] is False
    assert safe["dmarc_contains_none"]["matched"] is False

    malformed = _email_evaluations(
        spf_records=["v=spf1 -all", "v=spf1 include"],
        dmarc_records=["v=DMARC1; p=none", "v=DMARC1; p=reject"],
    )
    assert malformed["spf_record_malformed"]["matched"] is True
    assert malformed["spf_record_missing"]["matched"] is False
    assert malformed["dmarc_record_missing"]["matched"] is False
    assert malformed["dmarc_contains_none"]["matched"] is None

    differing_nonce = _email_evaluations(
        spf_records=["v=spf1 -all"], dmarc_records=["v=DMARC1; p=reject"],
        nonce=[_dns("n1", records=["v=spf1 -all"]), _dns("n2", records=["v=spf1 ~all"])],
    )
    assert differing_nonce["spf_record_wildcard"]["matched"] is None
    assert _parse_spf_record("v=spf1 ip4:192.0.2.1/33 -all")["valid"] is False

    pct_zero = _email_evaluations(spf_records=["v=spf1 ~all"], dmarc_records=["v=DMARC1; p=reject; pct=0"])
    assert pct_zero["spf_record_softfail"]["matched"] is True
    non_spf_version = _email_evaluations(spf_records=["v=spf10 -all"], dmarc_records=["v=DMARC1; p=reject"])
    assert non_spf_version["spf_record_missing"]["matched"] is True


def test_email_timeout_is_indeterminate_not_missing():
    failed = _dns("example.test", status="ERROR", error="LifetimeTimeout")
    dmarc_failed = _dns("_dmarc.example.test", status="ERROR", error="LifetimeTimeout")
    evaluations = _evaluate_email_security(
        "example.test", failed, _analyze_spf("example.test", failed, None, 53, 1.0),
        dmarc_failed, _analyze_dmarc(dmarc_failed),
        [_dns("n1", status="ERROR", error="LifetimeTimeout"), _dns("n2", status="ERROR", error="LifetimeTimeout")], [],
    )
    assert all(item["matched"] is None for item in evaluations.values())


def _wave2_baseline():
    factors = {
        "network_security": {"key": "network_security", "name": "Network Security"},
        "dns_health": {"key": "dns_health", "name": "DNS Health"},
    }
    tls_keys = {"tls_weak_protocol", "tls_weak_cipher"}
    issues = [{
        "key": spec.issue_key,
        "severity": "high" if spec.issue_key == "tls_weak_protocol" else "medium",
        "factor": "network_security" if spec.issue_key in tls_keys else "dns_health",
        "title": spec.title,
    } for spec in WAVE2_RULES]
    raw = {}
    for endpoint, payload in ((FACTORS_ENDPOINT, {"entries": list(factors.values())}), (ISSUES_ENDPOINT, {"entries": issues})):
        body = json.dumps(payload)
        raw[API_ORIGIN + endpoint] = {"body": body, "sha256": hashlib.sha256(body.encode()).hexdigest(), "captured_at": "2026-09-21T00:00:00+00:00"}
    return normalize_api_payloads(raw)


def test_real_baseline_exact_linkage_observation_finding_and_report(db, monkeypatch):
    import_golden_baseline(db, _wave2_baseline(), attest_real_source=True)
    mappings = active_wave2_mappings(db)
    assert len(mappings) == len(WAVE2_RULES) == 7
    assert {item["issue_key"] for item in mappings} == {spec.issue_key for spec in WAVE2_RULES}
    for mapping in mappings:
        issue_version = db.get(CatalogIssueTypeVersion, UUID(mapping["issue_version_id"]))
        assert issue_version.source_type == SourceTypeEnum.SSC_API
    rule = db.scalar(select(RuleEngineRule).where(RuleEngineRule.stable_key == "ssc.wave2.dmarc_contains_none"))
    assert rule.current_version.catalog_issue_type_version_id == rule.catalog_issue_type.current_version_id

    suffix = uuid4().hex[:12]
    target = add_inventory_target(
        db, organization="Wave 2 " + suffix, domain_name=suffix + ".test",
        hostname=None, ip=None, approved=True, allow_sensitive=False,
        approval_notes="Deterministic Wave 2 DNS fixture",
    )

    def fake_query(name, _server, _port, _timeout):
        if name.startswith("_dmarc."):
            return _dns(name, records=["v=DMARC1; p=none"])
        if name.startswith("_ssc-spf-"):
            return _dns(name, "NXDOMAIN")
        return _dns(name, records=["v=spf1 -all"])

    monkeypatch.setattr("app.services.scan_executors._query_txt_evidence", fake_query)
    result = scan_inventory_target(
        db, name=target["name"], organization_id=UUID(target["organization_id"]),
        scan_config={"executors": ["dns"]}, model=ScoringDefinition(), rule_keys=[rule.stable_key],
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.ssc_issue_key == "dmarc_contains_none"
    assert finding.ssc_severity == "medium"
    assert finding.catalog_issue_type_version_id == str(rule.current_version.catalog_issue_type_version_id)
    assert finding.breach_risk == "UNKNOWN" and finding.score_impact == 0
    evaluation = result.evidence[0].summary["evaluations"]["dmarc_contains_none"]
    assert evaluation["outcome"] == "MATCH" and evaluation["policy_version"] == WAVE2_EMAIL_POLICY_VERSION
    html = render_html(result)
    assert "dmarc_contains_none" in html and "SSC severity: medium" in html

    monkeypatch.setattr("app.services.scan_executors._query_txt_evidence", lambda name, *_: (
        _dns(name, "NXDOMAIN") if name.startswith("_ssc-spf-") else
        _dns(name, records=["v=DMARC1; p=reject"]) if name.startswith("_dmarc.") else
        _dns(name, records=["v=spf1 -all"])
    ))
    negative = scan_inventory_target(
        db, name=target["name"], organization_id=UUID(target["organization_id"]),
        scan_config={"executors": ["dns"]}, model=ScoringDefinition(), rule_keys=[rule.stable_key],
    )
    assert negative.findings == []
    assert negative.evidence[0].summary["evaluations"]["dmarc_contains_none"]["outcome"] == "NO_MATCH"
