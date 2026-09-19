"""Synthetic SSC responses only: no live credentials or SSC Internet access."""
import hashlib
import json
import logging
import threading
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.cli.ssc import main
from app.db.session import engine
from app.models.catalog_models import (
    BreachRiskEnum, CatalogIssueType, CatalogSnapshot, SourceTypeEnum,
)
from app.services.golden_baseline_importer import GoldenBaselineImportError, compute_baseline_content_hash, import_golden_baseline
from app.services.ssc_api_baseline import (
    API_ORIGIN, API_SCHEMA_VERSION, DETAIL_MAX_WORKERS, DETAIL_SAMPLE_KEYS, FACTORS_ENDPOINT, ISSUES_ENDPOINT,
    SSCAcquisitionError, acquire_baseline, discover_issue_details, normalize_api_payloads, taxonomy_status,
)
from tests.test_golden_baseline_importer import _baseline

FAKE_TOKEN = "synthetic-test-api-token"


@pytest.fixture
def db():
    # Imports commit savepoints; each test still rolls back all of its own data.
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


@pytest.fixture
def payloads():
    suffix = uuid4().hex[:12]
    factor = "api_network_" + suffix
    return {
        FACTORS_ENDPOINT: {"entries": [
            {"key": factor, "name": "Network", "description": "Short text", "long_description": "Long text"},
            {"key": "api_empty_" + suffix, "name": "Empty factor", "description": "No issues", "long_description": "Still a member"},
        ]},
        ISSUES_ENDPOINT: {"entries": [
            {"key": "api_tls_" + suffix, "severity": "high", "factor": factor, "title": "Weak TLS"},
            {"key": "api_cookie_" + suffix, "severity": "info", "factor": factor, "title": "Cookie flag"},
        ]},
    }


def raw_source(payloads, *, capture="2026-09-19T00:00:00+00:00", indent=None):
    result = {}
    for endpoint, payload in payloads.items():
        body = json.dumps(payload, indent=indent)
        result[API_ORIGIN + endpoint] = {"body": body, "sha256": hashlib.sha256(body.encode()).hexdigest(), "captured_at": capture}
    return result


def mock_transport(payloads, *, fail=None):
    def handle(request):
        assert request.method == "GET"
        assert request.url.host == "api.securityscorecard.io"
        assert request.headers["Authorization"] == "Token " + FAKE_TOKEN
        if fail is not None and request.url.path == ISSUES_ENDPOINT:
            return httpx.Response(fail, text=FAKE_TOKEN)
        return httpx.Response(200, json=payloads[request.url.path])
    return httpx.MockTransport(handle)


def detail_payload(row):
    return {
        **row,
        "short_description": "Short description for " + row["key"],
        "long_description": "Long description for " + row["key"],
        "recommendation": "Recommendation for " + row["key"],
    }


def test_api_normalization_keeps_severity_separate_and_empty_factors(payloads):
    baseline = normalize_api_payloads(raw_source(payloads))
    assert baseline.source_type == "SSC_API" and baseline.schema_version == API_SCHEMA_VERSION
    assert len(baseline.factors) == 2
    assert any(not factor.issues for factor in baseline.factors)
    factor = next(factor for factor in baseline.factors if factor.issues)
    assert factor.long_description == "Long text"
    assert {issue.ssc_severity for issue in factor.issues} == {"high", "info"}
    for issue in factor.issues:
        assert issue.breach_risk == BreachRiskEnum.UNKNOWN and issue.threat_level is None
        assert issue.ssc_metadata["severity"] == issue.ssc_severity
        assert issue.source_reference == API_ORIGIN + ISSUES_ENDPOINT + "#" + issue.stable_key
        assert issue.affects_score  # Conservative existing UNKNOWN-risk review gate.


def test_optional_detail_enrichment_is_versioned_vendor_metadata(db, payloads, monkeypatch):
    monkeypatch.setenv("SSC_TOKEN", FAKE_TOKEN)
    details = {row["key"]: detail_payload(row) for row in payloads[ISSUES_ENDPOINT]["entries"]}

    def handle(request):
        if request.url.path in payloads:
            return httpx.Response(200, json=payloads[request.url.path])
        key = request.url.path.removeprefix(ISSUES_ENDPOINT + "/")
        return httpx.Response(200, json=details[key])

    baseline = acquire_baseline(enrich_details=True, transport=httpx.MockTransport(handle))
    assert baseline.detail_enrichment_requested and not baseline.detail_enrichment_failures
    assert len(baseline.raw_source) == 2 + len(details)
    for issue in (issue for factor in baseline.factors for issue in factor.issues):
        assert set(issue.ssc_metadata) == {
            "key", "severity", "factor", "title", "short_description", "long_description", "recommendation",
        }
        assert issue.description == issue.ssc_metadata["short_description"]
        assert issue.ssc_severity == issue.ssc_metadata["severity"]
        assert issue.breach_risk == BreachRiskEnum.UNKNOWN
        assert issue.threat_level is None
        assert issue.source_reference == API_ORIGIN + ISSUES_ENDPOINT + "/" + issue.stable_key

    imported = import_golden_baseline(db, baseline, attest_real_source=True)
    snapshot = db.get(CatalogSnapshot, imported.snapshot_id)
    for item in snapshot.items:
        version = item.issue_version
        assert set(version.ssc_metadata) == set(details[version.issue_type.stable_key])
        assert version.description == version.ssc_metadata["short_description"]
        assert version.ssc_severity == version.ssc_metadata["severity"]
        assert version.breach_risk == BreachRiskEnum.UNKNOWN and version.threat_level is None


def test_detail_enrichment_retries_only_transient_failures_and_keeps_baseline(payloads, monkeypatch):
    monkeypatch.setenv("SSC_TOKEN", FAKE_TOKEN)
    rows = {row["key"]: row for row in payloads[ISSUES_ENDPOINT]["entries"]}
    retry_key, permanent_key = rows
    attempts = {retry_key: 0, permanent_key: 0}
    delays = []
    lock = threading.Lock()

    def handle(request):
        if request.url.path in payloads:
            return httpx.Response(200, json=payloads[request.url.path])
        key = request.url.path.removeprefix(ISSUES_ENDPOINT + "/")
        with lock:
            attempts[key] += 1
            attempt = attempts[key]
        if key == retry_key and attempt < 3:
            return httpx.Response(429, headers={"Retry-After": "0"})
        if key == permanent_key:
            return httpx.Response(404)
        return httpx.Response(200, json=detail_payload(rows[key]))

    monkeypatch.setattr("app.services.ssc_api_baseline.time.sleep", delays.append)
    baseline = acquire_baseline(enrich_details=True, transport=httpx.MockTransport(handle))
    issues = {issue.stable_key: issue for factor in baseline.factors for issue in factor.issues}

    assert DETAIL_MAX_WORKERS == 4
    assert attempts == {retry_key: 3, permanent_key: 1}
    assert delays == [0, 0]
    assert set(baseline.detail_enrichment_failures) == {permanent_key}
    assert set(issues[retry_key].ssc_metadata) == {
        "key", "severity", "factor", "title", "short_description", "long_description", "recommendation",
    }
    assert issues[permanent_key].ssc_metadata == rows[permanent_key]
    assert issues[permanent_key].description is None
    assert all(issue.breach_risk == BreachRiskEnum.UNKNOWN and issue.threat_level is None for issue in issues.values())


def test_detail_enrichment_does_not_retry_before_long_retry_after(payloads, monkeypatch):
    monkeypatch.setenv("SSC_TOKEN", FAKE_TOKEN)
    attempts = {}

    def handle(request):
        if request.url.path in payloads:
            return httpx.Response(200, json=payloads[request.url.path])
        key = request.url.path.removeprefix(ISSUES_ENDPOINT + "/")
        attempts[key] = attempts.get(key, 0) + 1
        return httpx.Response(429, headers={"Retry-After": "120"})

    baseline = acquire_baseline(enrich_details=True, transport=httpx.MockTransport(handle))
    issue_keys = {row["key"] for row in payloads[ISSUES_ENDPOINT]["entries"]}

    assert attempts == {key: 1 for key in issue_keys}
    assert set(baseline.detail_enrichment_failures) == issue_keys
    assert all(
        set(issue.ssc_metadata) == {"key", "severity", "factor", "title"}
        for factor in baseline.factors for issue in factor.issues
    )


def test_enrichment_changes_hash_but_list_only_remains_a_complete_baseline(payloads):
    list_only = normalize_api_payloads(raw_source(payloads))
    enriched_raw = raw_source(payloads)
    row = payloads[ISSUES_ENDPOINT]["entries"][0]
    body = json.dumps(detail_payload(row))
    enriched_raw[API_ORIGIN + ISSUES_ENDPOINT + "/" + row["key"]] = {
        "body": body,
        "sha256": hashlib.sha256(body.encode()).hexdigest(),
        "captured_at": "2026-09-19T00:01:00+00:00",
    }
    enriched = normalize_api_payloads(enriched_raw, detail_enrichment_requested=True)

    assert sum(len(factor.issues) for factor in list_only.factors) == sum(len(factor.issues) for factor in enriched.factors)
    assert compute_baseline_content_hash(list_only) != compute_baseline_content_hash(enriched)
    assert not list_only.detail_enrichment_requested


@pytest.mark.parametrize("fault", ["duplicate_factor", "duplicate_issue", "missing_factor", "missing_severity", "missing_title", "empty", "unknown_factor", "pagination", "bad_hash"])
def test_invalid_payload_is_rejected(payloads, fault):
    if fault == "duplicate_factor":
        payloads[FACTORS_ENDPOINT]["entries"].append(payloads[FACTORS_ENDPOINT]["entries"][0])
    elif fault == "duplicate_issue":
        payloads[ISSUES_ENDPOINT]["entries"].append(payloads[ISSUES_ENDPOINT]["entries"][0])
    elif fault.startswith("missing_"):
        del payloads[ISSUES_ENDPOINT]["entries"][0][fault.removeprefix("missing_")]
    elif fault == "empty":
        payloads[ISSUES_ENDPOINT]["entries"] = []
    elif fault == "unknown_factor":
        payloads[ISSUES_ENDPOINT]["entries"][0]["factor"] = "not_a_factor"
    elif fault == "pagination":
        payloads[ISSUES_ENDPOINT]["next"] = "another_page"
    raw = raw_source(payloads)
    if fault == "bad_hash":
        raw[API_ORIGIN + ISSUES_ENDPOINT]["sha256"] = "wrong"
    with pytest.raises(SSCAcquisitionError):
        normalize_api_payloads(raw)


def test_factor_issue_import_provenance_membership_and_immutability(db, payloads):
    baseline = normalize_api_payloads(raw_source(payloads))
    result = import_golden_baseline(db, baseline, attest_real_source=True)
    snapshot = db.get(CatalogSnapshot, result.snapshot_id)
    assert result.factors_created == 2 and result.issues_created == result.versions_created == 2
    assert snapshot.source_type == SourceTypeEnum.SSC_API
    assert snapshot.raw_source == baseline.raw_source
    assert snapshot.normalized_schema_version == API_SCHEMA_VERSION
    assert len(snapshot.normalized_payload["factors"]) == 2
    assert snapshot.captured_at == baseline.captured_at
    assert len(snapshot.items) == 2
    for item in snapshot.items:
        assert item.issue_version.source_type == SourceTypeEnum.SSC_API
        assert item.issue_version.source_snapshot_hash == result.content_hash
        assert item.issue_version.ssc_metadata["key"] == item.issue_version.issue_type.stable_key
    # Database rejects mutations even outside the append-only importer service.
    with pytest.raises(DBAPIError, match="immutable"):
        with db.begin_nested():
            db.execute(text("UPDATE catalog_snapshots SET notes = 'tampered' WHERE id = :id"), {"id": snapshot.id})


def test_content_hash_ignores_capture_whitespace_and_list_order(db, payloads):
    first = normalize_api_payloads(raw_source(payloads))
    for response in payloads.values():
        response["entries"].reverse()
    second = normalize_api_payloads(raw_source(payloads, capture="2026-09-20T00:00:00+00:00", indent=2))
    assert compute_baseline_content_hash(first) == compute_baseline_content_hash(second)
    imported = import_golden_baseline(db, first, attest_real_source=True)
    repeated = import_golden_baseline(db, second, attest_real_source=True)
    assert repeated.snapshot_id == imported.snapshot_id and repeated.versions_created == 0
    assert db.get(CatalogSnapshot, imported.snapshot_id).raw_source == first.raw_source


@pytest.mark.parametrize("field,value", [("title", "Renamed issue"), ("severity", "unfamiliar-vendor-value"), ("future_field", {"unmapped": True})])
def test_changed_issue_metadata_creates_new_version_and_snapshot(db, payloads, field, value):
    baseline = normalize_api_payloads(raw_source(payloads))
    first = import_golden_baseline(db, baseline)
    old_snapshot = db.get(CatalogSnapshot, first.snapshot_id)
    old_versions = {item.issue_type_version_id for item in old_snapshot.items}
    payloads[ISSUES_ENDPOINT]["entries"][0][field] = value
    changed = normalize_api_payloads(raw_source(payloads))
    second = import_golden_baseline(db, changed)
    assert second.snapshot_id != first.snapshot_id and second.versions_created == 1
    assert {item.issue_type_version_id for item in old_snapshot.items} == old_versions
    assert import_golden_baseline(db, changed).snapshot_id == second.snapshot_id


def test_factor_change_and_removed_issue_preserve_historical_membership(db, payloads):
    first = import_golden_baseline(db, normalize_api_payloads(raw_source(payloads)))
    payloads[FACTORS_ENDPOINT]["entries"][0]["long_description"] = "Changed factor metadata"
    payloads[ISSUES_ENDPOINT]["entries"].pop()
    second = import_golden_baseline(db, normalize_api_payloads(raw_source(payloads)))
    assert second.versions_created == 0 and second.snapshot_id != first.snapshot_id
    old = db.get(CatalogSnapshot, first.snapshot_id)
    new = db.get(CatalogSnapshot, second.snapshot_id)
    assert len(old.items) == 2 and len(new.items) == 1
    assert any(f["long_description"] == "Long text" for f in old.normalized_payload["factors"])
    assert any(f["long_description"] == "Changed factor metadata" for f in new.normalized_payload["factors"])


def test_real_baseline_gate_and_manual_fallback(db, payloads):
    assert taxonomy_status(db) == "INTERNAL_ONLY"
    manual = _baseline()
    import_golden_baseline(db, manual)
    assert taxonomy_status(db) == "INTERNAL_ONLY"  # A source label/fixture isn't evidence of a real capture.
    baseline = normalize_api_payloads(raw_source(payloads))
    import_golden_baseline(db, baseline, dry_run=True, attest_real_source=True)
    assert taxonomy_status(db) == "INTERNAL_ONLY"
    import_golden_baseline(db, baseline, attest_real_source=True)
    assert taxonomy_status(db) == "SSC_ALIGNED"
    assert import_golden_baseline(db, manual).snapshot_action == "reused_existing"


def test_attested_real_manual_capture_can_align(db):
    baseline = _baseline()
    import_golden_baseline(db, baseline, attest_real_source=True)
    assert taxonomy_status(db) == "SSC_ALIGNED"


def test_unattested_snapshot_cannot_be_relabelled(db):
    baseline = _baseline()
    import_golden_baseline(db, baseline)
    with pytest.raises(GoldenBaselineImportError, match="cannot be relabeled"):
        import_golden_baseline(db, baseline, attest_real_source=True)
    assert taxonomy_status(db) == "INTERNAL_ONLY"


def test_failure_during_commit_rolls_back_issue_versions_and_current_pointers(db, payloads, monkeypatch):
    baseline = normalize_api_payloads(raw_source(payloads))
    first = import_golden_baseline(db, baseline, attest_real_source=True)
    key = payloads[ISSUES_ENDPOINT]["entries"][0]["key"]
    issue = db.scalar(select(CatalogIssueType).where(CatalogIssueType.stable_key == key))
    original_version = issue.current_version_id
    original_flush = db.flush
    def fail_new_snapshot(*args, **kwargs):
        if any(isinstance(row, CatalogSnapshot) for row in db.new):
            raise IntegrityError("synthetic constraint failure", {}, Exception("test"))
        return original_flush(*args, **kwargs)
    payloads[ISSUES_ENDPOINT]["entries"][0]["title"] = "Changed title"
    monkeypatch.setattr(db, "flush", fail_new_snapshot)
    with pytest.raises(GoldenBaselineImportError, match="database constraint"):
        import_golden_baseline(db, normalize_api_payloads(raw_source(payloads)), attest_real_source=True)
    db.refresh(issue)
    assert issue.current_version_id == original_version and len(issue.versions) == 1
    assert db.get(CatalogSnapshot, first.snapshot_id) and taxonomy_status(db) == "SSC_ALIGNED"


def test_token_not_persisted_or_logged(db, payloads, monkeypatch, caplog):
    monkeypatch.setenv("SSC_TOKEN", FAKE_TOKEN)
    with caplog.at_level(logging.DEBUG):
        baseline = acquire_baseline(transport=mock_transport(payloads))
        result = import_golden_baseline(db, baseline, attest_real_source=True)
    snapshot = db.get(CatalogSnapshot, result.snapshot_id)
    serialized = json.dumps({"raw": snapshot.raw_source, "normalized": snapshot.normalized_payload})
    assert FAKE_TOKEN not in serialized and FAKE_TOKEN not in caplog.text
    assert "Authorization" not in serialized


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_auth_and_partial_acquisition_failure_preserve_baseline(db, payloads, monkeypatch, status):
    previous = import_golden_baseline(db, normalize_api_payloads(raw_source(payloads)), attest_real_source=True)
    before = db.scalar(select(func.count()).select_from(CatalogSnapshot))
    monkeypatch.setenv("SSC_TOKEN", FAKE_TOKEN)
    with pytest.raises(SSCAcquisitionError, match=f"HTTP {status}") as error:
        acquire_baseline(transport=mock_transport(payloads, fail=status))
    assert FAKE_TOKEN not in str(error.value)
    assert db.scalar(select(func.count()).select_from(CatalogSnapshot)) == before
    assert db.get(CatalogSnapshot, previous.snapshot_id) and taxonomy_status(db) == "SSC_ALIGNED"


def test_missing_token_fails_before_request(monkeypatch):
    monkeypatch.delenv("SSC_TOKEN", raising=False)
    def fail_request(_request):
        pytest.fail("Must not send a request without a token")
    with pytest.raises(SSCAcquisitionError, match="SSC_TOKEN"):
        acquire_baseline(transport=httpx.MockTransport(fail_request))


@pytest.mark.parametrize("failure", ["redirect", "timeout", "echo", "malformed_json", "pagination", "size_limit", "duplicate_json_key"])
def test_safe_transport_errors(monkeypatch, failure):
    monkeypatch.setenv("SSC_TOKEN", FAKE_TOKEN)
    monkeypatch.setattr("app.services.ssc_api_baseline.MAX_RESPONSE_BYTES", 512)
    requests = []
    def handle(request):
        requests.append(request)
        if failure == "redirect":
            return httpx.Response(302, headers={"Location": "https://other.test"})
        if failure == "timeout":
            raise httpx.ReadTimeout(FAKE_TOKEN)
        if failure == "echo":
            return httpx.Response(200, json={"echo": FAKE_TOKEN})
        if failure == "pagination":
            return httpx.Response(200, headers={"Link": '<https://other.test>; rel="next"'}, json={})
        if failure == "size_limit":
            return httpx.Response(200, text="x" * 513)
        if failure == "duplicate_json_key":
            return httpx.Response(200, text='{"entries": [], "entries": []}')
        return httpx.Response(200, text="not json")
    with pytest.raises(SSCAcquisitionError) as error:
        acquire_baseline(transport=httpx.MockTransport(handle))
    assert FAKE_TOKEN not in str(error.value) and len(requests) == 1


def test_detail_discovery_reports_all_fields_without_values(monkeypatch):
    monkeypatch.setenv("SSC_TOKEN", FAKE_TOKEN)
    payload = {"key": "example", "severity": "high", "factor": "network", "title": "title",
               "short_description": "short", "long_description": "long", "recommendation": "advice",
               "future": {"nested": [{"value": 1}]}}
    requested = []
    def handle(request):
        requested.append(request.url.path)
        return httpx.Response(200, json=payload)
    results = discover_issue_details(transport=httpx.MockTransport(handle))
    assert requested == [ISSUES_ENDPOINT + "/" + key for key in DETAIL_SAMPLE_KEYS]
    for result in results.values():
        assert result["fields"] == sorted(payload)
        assert "future.nested[].value" in result["field_paths"]
        assert "advice" not in json.dumps(result)


def test_cli_preview_approval_hash_and_offline_status(db, payloads, monkeypatch, capsys):
    import app.cli.ssc_baseline as cli
    baseline = normalize_api_payloads(raw_source(payloads))
    monkeypatch.setattr(cli, "SessionLocal", lambda: Session(bind=db.bind, join_transaction_mode="create_savepoint"))
    acquisition_options = []
    monkeypatch.setattr(cli, "acquire_baseline", lambda **options: acquisition_options.append(options) or baseline)
    assert main(["baseline", "status"]) == 0
    assert "INTERNAL_ONLY" in capsys.readouterr().out
    assert main(["baseline", "pull-ssc", "--dry-run"]) == 0
    assert acquisition_options[-1] == {"enrich_details": False}
    preview = capsys.readouterr().out
    for label in ("Source", "Factors", "Issue Types", "Captured At", "Content Hash", "Existing Match"):
        assert label in preview
    assert taxonomy_status(db) == "INTERNAL_ONLY"
    assert main(["baseline", "pull-ssc", "--dry-run", "--enrich-details"]) == 0
    assert acquisition_options[-1] == {"enrich_details": True}
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["baseline", "pull-ssc"]) == 1
    assert main(["baseline", "pull-ssc", "--yes", "--expect-hash", "wrong"]) == 1
    assert taxonomy_status(db) == "INTERNAL_ONLY"
    assert main(["baseline", "pull-ssc", "--yes", "--expect-hash", compute_baseline_content_hash(baseline)]) == 0
    assert taxonomy_status(db) == "SSC_ALIGNED"
    assert main(["baseline", "pull-ssc", "--yes"]) == 0
    assert "Existing Match  : yes" in capsys.readouterr().out
    monkeypatch.setattr(cli, "acquire_baseline", lambda: pytest.fail("Status must remain offline"))
    assert main(["baseline", "status"]) == 0


def test_cli_does_not_accept_a_token_argument():
    with pytest.raises(SystemExit) as error:
        main(["baseline", "pull-ssc", "--token", FAKE_TOKEN])
    assert error.value.code == 2
