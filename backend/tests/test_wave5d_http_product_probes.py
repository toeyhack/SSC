import json
import socketserver
import threading
from copy import deepcopy
from contextlib import contextmanager

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import engine
from app.models.catalog_models import (
    BreachRiskEnum, CatalogFactor, CatalogIssueType, CatalogIssueTypeVersion,
    CatalogSnapshot, CatalogSnapshotItem, SourceTypeEnum,
)
from app.models.rule_models import RuleEngineRule, RuleEngineRuleVersion
from app.models.scan_models import ScanTargetTypeEnum
from app.services.public_exposure_consumers import (
    PUBLIC_EXPOSURE_CONSUMER_POLICY_V1,
    PUBLIC_EXPOSURE_CONSUMER_POLICY_V2,
    PUBLIC_EXPOSURE_CONSUMER_POLICY_V3,
    PUBLIC_EXPOSURE_CONSUMER_REGISTRY_VERSIONS,
    get_pinned_public_exposure_consumer,
)
from app.services.scan_executors import HTTPExecutor, InventoryScanTarget, ScanExecutorError, validate_scan_config
from app.services.service_probe_http_product import (
    COUCHDB_IDENTITY_POLICY_VERSION,
    ELASTICSEARCH_IDENTITY_POLICY_VERSION,
    HTTP_PRODUCT_EVIDENCE_SCHEMA_VERSION,
    HTTP_PRODUCT_FRAMEWORK_VERSION,
    MAX_HTTP_PRODUCT_RESPONSE_BYTES,
    aggregate_http_product_evaluations,
    evaluate_http_product_response,
)
from app.services.wave5d_rules import (
    WAVE5D_ACTIVE_KEYS, WAVE5D_BY_KEY, WAVE5D_CLOSURE_BLOCKERS,
    activate_wave5d_rules, active_wave5d_mappings,
)
from app.services.public_exposure_consumers import PINNED_SSC_BASELINE_HASH


COUCH = {"couchdb": "Welcome", "version": "3.4.3", "vendor": {"name": "The Apache Software Foundation"}}
ELASTIC = {
    "name": "private-node", "cluster_name": "private-cluster", "cluster_uuid": "private-uuid",
    "version": {
        "number": "8.15.0", "build_flavor": "default", "build_type": "docker",
        "build_hash": "private-hash", "build_date": "2026-01-01", "build_snapshot": False,
        "lucene_version": "9.11.1", "minimum_wire_compatibility_version": "7.17.0",
        "minimum_index_compatibility_version": "7.0.0",
    },
    "tagline": "You Know, for Search",
}
OPENSEARCH = {
    "name": "private-node", "cluster_name": "private-cluster", "cluster_uuid": "private-uuid",
    "version": {
        "distribution": "opensearch", "number": "2.19.1", "build_type": "tar",
        "build_hash": "private-opensearch-hash", "build_date": "2026-01-01",
        "build_snapshot": False, "lucene_version": "9.12.1",
        "minimum_wire_compatibility_version": "7.10.0",
        "minimum_index_compatibility_version": "7.0.0",
    },
    "tagline": "The OpenSearch Project: https://opensearch.org/",
}


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _seed_baseline(db):
    factor = CatalogFactor(code="network_security", name="Network Security")
    snapshot = CatalogSnapshot(
        name="Pinned Wave 5D baseline", source_type=SourceTypeEnum.SSC_API,
        content_hash=PINNED_SSC_BASELINE_HASH, normalized_schema_version="ssc.api.metadata.v2",
        is_real_baseline=True,
    )
    db.add_all([factor, snapshot]); db.flush()
    issues = {}
    for position, spec in enumerate(WAVE5D_BY_KEY.values()):
        issue = CatalogIssueType(stable_key=spec.issue_key, factor_id=factor.id)
        db.add(issue); db.flush()
        version = CatalogIssueTypeVersion(
            issue_type_id=issue.id, version_number=1, name=spec.title,
            breach_risk=BreachRiskEnum.UNKNOWN, ssc_severity="medium", affects_score=False,
            source_type=SourceTypeEnum.SSC_API, source_snapshot_hash=PINNED_SSC_BASELINE_HASH,
        )
        db.add(version); db.flush(); issue.current_version_id = version.id
        db.add(CatalogSnapshotItem(
            catalog_snapshot_id=snapshot.id, issue_type_version_id=version.id,
            factor_position=0, issue_position=position,
        ))
        issues[spec.issue_key] = issue
    db.flush()
    return issues


def _observation(body, *, headers=None, status=200, complete=True, error=None):
    raw = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode()
    return {
        "_body": raw,
        "_header_pairs": headers or [("Content-Type", "application/json")],
        "status_code": status,
        "body_complete": complete,
        "stop_reason": "terminal_response",
        "error": error,
        "request_scheme": "http",
        "request_port": 9200,
        "terminal_scheme": "http",
        "terminal_port": 9200,
        "redirect_chain": [{"status_code": status}],
        "elapsed_ms": 1,
    }


def test_versions_and_independent_activation_gate():
    assert HTTP_PRODUCT_FRAMEWORK_VERSION == "http-product-probe-framework.v1"
    assert HTTP_PRODUCT_EVIDENCE_SCHEMA_VERSION == "ssc-wave5d-http-product-evidence.v1"
    assert COUCHDB_IDENTITY_POLICY_VERSION == "ssc-wave5d-couchdb-identity.v1"
    assert ELASTICSEARCH_IDENTITY_POLICY_VERSION == "ssc-wave5d-elasticsearch-identity.v1"
    assert WAVE5D_ACTIVE_KEYS == {"service_couchdb", "service_elasticsearch"}
    assert WAVE5D_CLOSURE_BLOCKERS == {}
    assert WAVE5D_BY_KEY["service_couchdb"].expression["path"] == "http.evaluations.service_couchdb.exposure_context.composition.matched"


def test_activation_is_exact_independent_and_idempotent(db):
    assert set(activate_wave5d_rules(db, commit=False)["unavailable"]) == {
        "service_couchdb", "service_elasticsearch",
    }
    issues = _seed_baseline(db)
    first = activate_wave5d_rules(db, commit=False)
    assert first["activated"] == ["service_couchdb", "service_elasticsearch"]
    assert first["inactive"] == []
    versions_before = db.scalar(select(func.count()).select_from(RuleEngineRuleVersion))
    second = activate_wave5d_rules(db, commit=False)
    assert second["rules_created"] == second["rule_versions_created"] == 0
    assert db.scalar(select(func.count()).select_from(RuleEngineRuleVersion)) == versions_before
    mappings = active_wave5d_mappings(db)
    assert [item["issue_key"] for item in mappings] == ["service_couchdb", "service_elasticsearch"]
    assert all(item["issue_version_number"] == 1 for item in mappings)


def test_activation_deactivates_only_drifted_elasticsearch_definition(db):
    issues = _seed_baseline(db)
    activate_wave5d_rules(db, commit=False)
    elastic_rule = db.scalar(select(RuleEngineRule).where(
        RuleEngineRule.stable_key == "ssc.wave5d.service_elasticsearch"
    ))
    stale = CatalogIssueTypeVersion(
        issue_type_id=issues["service_elasticsearch"].id,
        version_number=2,
        name="Stale Elasticsearch definition",
        breach_risk=BreachRiskEnum.UNKNOWN,
        ssc_severity="medium",
        affects_score=False,
        source_type=SourceTypeEnum.SSC_API,
    )
    db.add(stale); db.flush()
    issues["service_elasticsearch"].current_version_id = stale.id
    result = activate_wave5d_rules(db, commit=False)
    assert result["activated"] == ["service_couchdb"]
    assert set(result["unavailable"]) == {"service_elasticsearch"}
    assert result["rules_deactivated"] == 1 and elastic_rule.is_active is False


def test_registry_v3_is_additive_and_scanner_http_only():
    v1 = PUBLIC_EXPOSURE_CONSUMER_REGISTRY_VERSIONS[PUBLIC_EXPOSURE_CONSUMER_POLICY_V1]
    v2 = PUBLIC_EXPOSURE_CONSUMER_REGISTRY_VERSIONS[PUBLIC_EXPOSURE_CONSUMER_POLICY_V2]
    v3 = PUBLIC_EXPOSURE_CONSUMER_REGISTRY_VERSIONS[PUBLIC_EXPOSURE_CONSUMER_POLICY_V3]
    assert v2[:len(v1)] == v1
    assert v3[:len(v2)] == v2
    assert v3[-2:] == ("service_couchdb", "service_elasticsearch")
    for key in v3[-2:]:
        consumer = get_pinned_public_exposure_consumer(key)
        assert (consumer.evidence_root, consumer.required_evidence_source) == ("http", "SCANNER_HTTP")
    assert "minecraft_server" not in v3


def test_couchdb_exact_signature_is_match_and_private_values_are_not_retained():
    result = evaluate_http_product_response("couchdb", _observation(COUCH, headers=[
        ("Content-Type", "text/plain; charset=utf-8"), ("Server", "CouchDB/3.4.3")
    ]))
    assert (result["outcome"], result["identity_class"]) == ("MATCH", "APACHE_COUCHDB")
    assert result["marker_facts"] == {
        "couchdb_welcome_exact": True, "apache_vendor_exact": True,
        "version_format_valid": True, "server_header_couchdb": True,
    }
    rendered = json.dumps(result)
    assert "3.4.3" not in rendered and "private" not in rendered


@pytest.mark.parametrize("body", [
    {"couchdb": "Welcome"},
    {"couchdb": "Welcome", "version": "3.4.3", "vendor": {"name": "Fork"}},
    {"couchdb": "Welcome", "version": "not-version", "vendor": {"name": "The Apache Software Foundation"}},
    {"hello": "world"},
])
def test_couchdb_partial_or_generic_is_indeterminate(body):
    assert evaluate_http_product_response("couchdb", _observation(body))["outcome"] == "INDETERMINATE"


def test_couchdb_missing_vendor_version_and_welcome_are_each_indeterminate():
    for key in ("couchdb", "version", "vendor"):
        body = deepcopy(COUCH)
        body.pop(key)
        assert evaluate_http_product_response("couchdb", _observation(body))["outcome"] == "INDETERMINATE"


def test_elasticsearch_exact_signature_is_match_without_persisting_identifiers():
    result = evaluate_http_product_response("elasticsearch", _observation(
        ELASTIC, headers=[("Content-Type", "application/vnd.elasticsearch+json; compatible-with=8"), ("X-Elastic-Product", "Elasticsearch")]
    ))
    assert (result["outcome"], result["identity_class"]) == ("MATCH", "ELASTICSEARCH")
    rendered = json.dumps(result)
    for secret in ("private-node", "private-cluster", "private-uuid", "8.15.0", "private-hash"):
        assert secret not in rendered


@pytest.mark.parametrize("headers,mutation", [
    ([("Content-Type", "application/json")], {}),
    ([("Content-Type", "application/json"), ("X-Elastic-Product", "Wrong")], {}),
    ([("Content-Type", "application/json"), ("X-Elastic-Product", "Elasticsearch"), ("x-elastic-product", "Elasticsearch")], {}),
    ([("Content-Type", "application/json"), ("X-Elastic-Product", "Elasticsearch")], {"tagline": "wrong"}),
])
def test_elasticsearch_missing_duplicate_wrong_or_bad_tagline_is_indeterminate(headers, mutation):
    body = {**ELASTIC, **mutation}
    assert evaluate_http_product_response("elasticsearch", _observation(body, headers=headers))["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize(
    "path",
    [
        ("name",), ("cluster_name",), ("cluster_uuid",), ("version", "build_flavor"),
        ("version", "build_type"), ("version", "build_hash"), ("version", "build_date"),
        ("version", "build_snapshot"), ("version", "lucene_version"),
        ("version", "minimum_wire_compatibility_version"),
        ("version", "minimum_index_compatibility_version"),
    ],
)
def test_elasticsearch_requires_complete_typed_identity_structure(path):
    body = deepcopy(ELASTIC)
    parent = body
    for key in path[:-1]:
        parent = parent[key]
    parent.pop(path[-1])
    headers = [("Content-Type", "application/json"), ("X-Elastic-Product", "Elasticsearch")]
    assert evaluate_http_product_response("elasticsearch", _observation(body, headers=headers))["outcome"] == "INDETERMINATE"


def test_header_alone_and_root_json_alone_are_insufficient():
    header_only = evaluate_http_product_response("elasticsearch", _observation(
        {"ok": True}, headers=[("Content-Type", "application/json"), ("X-Elastic-Product", "Elasticsearch")]
    ))
    root_only = evaluate_http_product_response("elasticsearch", _observation(ELASTIC))
    assert header_only["outcome"] == root_only["outcome"] == "INDETERMINATE"


def test_opensearch_compatibility_version_is_deterministic_different_product():
    result = evaluate_http_product_response("elasticsearch", _observation(OPENSEARCH))
    assert (result["outcome"], result["matched"], result["identity_class"]) == ("NO_MATCH", False, "OPENSEARCH")


def test_opensearch_with_injected_elastic_header_is_conflicting():
    result = evaluate_http_product_response("elasticsearch", _observation(
        OPENSEARCH, headers=[("Content-Type", "application/json"), ("X-Elastic-Product", "Elasticsearch")]
    ))
    assert (result["outcome"], result["identity_class"], result["reason_code"]) == (
        "INDETERMINATE", "CONFLICTING", "conflicting_product_markers",
    )


def test_incomplete_opensearch_overlap_is_indeterminate_not_no_match():
    incomplete = {
        "name": "node", "cluster_name": "cluster", "cluster_uuid": "uuid",
        "version": {"distribution": "opensearch", "number": "2.19.1"},
        "tagline": "The OpenSearch Project: https://opensearch.org/",
    }
    result = evaluate_http_product_response("elasticsearch", _observation(incomplete))
    assert (result["outcome"], result["identity_class"]) == ("INDETERMINATE", "UNKNOWN")


def test_elasticsearch_with_opensearch_marker_is_indeterminate():
    body = json.loads(json.dumps(ELASTIC))
    body["version"]["distribution"] = "opensearch"
    result = evaluate_http_product_response("elasticsearch", _observation(
        body, headers=[("Content-Type", "application/json"), ("X-Elastic-Product", "Elasticsearch")]
    ))
    assert result["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("body,headers,status,complete", [
    (b'{"a":1,"a":2}', [("Content-Type", "application/json")], 200, True),
    (b'\xff', [("Content-Type", "application/json")], 200, True),
    (b'{bad', [("Content-Type", "application/json")], 200, True),
    (b'<html>proxy</html>', [("Content-Type", "text/html")], 200, True),
    (json.dumps(COUCH).encode(), [("Content-Type", "application/json")], 401, True),
    (json.dumps(COUCH).encode(), [("Content-Type", "application/json")], 403, True),
    (json.dumps(COUCH).encode(), [("Content-Type", "application/json"), ("Content-Encoding", "gzip")], 200, True),
    (json.dumps(COUCH).encode(), [("Content-Type", "application/json")], 200, False),
])
def test_ambiguous_failure_classes_are_indeterminate(body, headers, status, complete):
    assert evaluate_http_product_response("couchdb", _observation(body, headers=headers, status=status, complete=complete))["outcome"] == "INDETERMINATE"


def test_json_structural_limits_are_indeterminate():
    nested = {"leaf": True}
    for _ in range(9):
        nested = {"n": nested}
    nodes = list(range(33))
    assert evaluate_http_product_response("couchdb", _observation(nested))["outcome"] == "INDETERMINATE"
    assert evaluate_http_product_response("couchdb", _observation(nodes))["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1} trailing',
        b'{"value":"\\ud800"}',
    ],
)
def test_strict_json_rejects_non_finite_trailing_and_invalid_scalar(raw):
    assert evaluate_http_product_response("couchdb", _observation(raw))["outcome"] == "INDETERMINATE"


def test_all_json_and_header_bounds_fail_closed():
    cases = [
        {"x" * 65: True},
        {"value": "x" * 257},
        {f"k{i}": i for i in range(65)},
        list(range(33)),
    ]
    for body in cases:
        assert evaluate_http_product_response("couchdb", _observation(body))["outcome"] == "INDETERMINATE"
    too_many = [("X-Test", "x")] * 65 + [("Content-Type", "application/json")]
    assert evaluate_http_product_response("couchdb", _observation(COUCH, headers=too_many))["outcome"] == "INDETERMINATE"
    too_large = [("Content-Type", "application/json"), ("X-Test", "x" * 8193)]
    assert evaluate_http_product_response("couchdb", _observation(COUCH, headers=too_large))["outcome"] == "INDETERMINATE"


def test_cross_product_deterministic_negatives_and_aggregation():
    elastic = evaluate_http_product_response("couchdb", _observation(
        ELASTIC, headers=[("Content-Type", "application/json"), ("X-Elastic-Product", "Elasticsearch")]
    ))
    couch = evaluate_http_product_response("elasticsearch", _observation(COUCH))
    assert elastic["outcome"] == couch["outcome"] == "NO_MATCH"
    assert aggregate_http_product_evaluations("couchdb", [elastic])["outcome"] == "NO_MATCH"
    ambiguous = evaluate_http_product_response("couchdb", _observation({"ok": True}))
    assert aggregate_http_product_evaluations("couchdb", [elastic, ambiguous])["outcome"] == "INDETERMINATE"


def test_cross_product_negatives_honor_the_other_products_reviewed_content_type():
    elastic = evaluate_http_product_response("couchdb", _observation(
        ELASTIC, headers=[
            ("Content-Type", "application/vnd.elasticsearch+json"),
            ("X-Elastic-Product", "Elasticsearch"),
        ],
    ))
    couch = evaluate_http_product_response("elasticsearch", _observation(
        COUCH, headers=[("Content-Type", "text/plain; charset=utf-8")],
    ))
    assert (elastic["outcome"], elastic["identity_class"]) == ("NO_MATCH", "ELASTICSEARCH")
    assert (couch["outcome"], couch["identity_class"]) == ("NO_MATCH", "APACHE_COUCHDB")


def test_config_is_exact_bounded_deduplicated_and_scheme_is_not_inferred():
    config = validate_scan_config({"executors": ["http"], "http_product_probes": [
        {"product": "couchdb", "scheme": "http", "port": 5984},
        {"product": "couchdb", "scheme": "http", "port": 5984},
        {"product": "elasticsearch", "scheme": "https", "port": 9200},
    ]})
    assert config["http_product_probes"] == [
        {"product": "couchdb", "scheme": "http", "port": 5984},
        {"product": "elasticsearch", "scheme": "https", "port": 9200},
    ]
    for bad in (
        {"product": "couchdb", "port": 5984},
        {"product": "couchdb", "scheme": "http", "port": 5984, "path": "/"},
        {"product": "opensearch", "scheme": "http", "port": 9200},
    ):
        with pytest.raises(ScanExecutorError):
            validate_scan_config({"executors": ["http"], "http_product_probes": [bad]})
    duplicates = [{"product": "couchdb", "scheme": "http", "port": 5984}] * 10
    assert len(validate_scan_config({"http_product_probes": duplicates})["http_product_probes"]) == 1
    with pytest.raises(ScanExecutorError):
        validate_scan_config({"http_product_probes": [
            {"product": "couchdb", "scheme": "http", "port": 5984 + index}
            for index in range(5)
        ]})


@contextmanager
def _http_server(response: bytes):
    state = {"requests": []}
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data = b""
            while b"\r\n\r\n" not in data:
                data += self.request.recv(4096)
            state["requests"].append(data)
            self.request.sendall(response)
    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], state
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_executor_sends_one_exact_root_request_and_stops_after_match(monkeypatch):
    body = json.dumps(COUCH).encode()
    response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    with _http_server(response) as (port, state):
        monkeypatch.setattr("app.services.scan_executors._pin_target", lambda target: target)
        target = InventoryScanTarget(ScanTargetTypeEnum.HOST, "id", "localhost", "127.0.0.1", "localhost", True)
        observation = HTTPExecutor().collect(target, {
            "http_ports": [], "https_ports": [], "http_paths": ["/"],
            "http_product_probes": [
                {"product": "couchdb", "scheme": "http", "port": port},
                {"product": "couchdb", "scheme": "http", "port": port},
            ],
        })
    evaluation = observation.evidence["evaluations"]["service_couchdb"]
    assert evaluation["outcome"] == "MATCH"
    assert len(state["requests"]) == 1
    request = state["requests"][0]
    assert request.startswith(b"GET / HTTP/1.1\r\n")
    assert b"Accept: application/json\r\n" in request
    assert b"Accept-Encoding: identity\r\n" in request
    assert b"Connection: close\r\n" in request
    assert b"Range:" not in request and b"Authorization:" not in request and b"Cookie:" not in request


def test_same_target_redirect_requires_an_explicit_same_product_root_endpoint(monkeypatch):
    executor = HTTPExecutor()
    target = InventoryScanTarget(
        ScanTargetTypeEnum.HOST, "id", "localhost", "127.0.0.1", "localhost", True
    )
    calls = []

    def request(**kwargs):
        calls.append((kwargs["scheme"], kwargs["port"], kwargs["path"], kwargs["query"]))
        if len(calls) == 1:
            return {
                "status_code": 302, "location": "http://127.0.0.1:5985/",
                "body_complete": True, "completion_reason": "response_complete",
            }
        body = json.dumps(COUCH).encode()
        return {
            "status_code": 200, "location": None, "body_complete": True,
            "completion_reason": "response_complete", "_body": body,
            "_header_pairs": [("Content-Type", "application/json")],
        }

    monkeypatch.setattr(executor, "_single_request", request)
    result = executor._request_chain(
        target, "http", 5984, "/", 5.0, 1, MAX_HTTP_PRODUCT_RESPONSE_BYTES,
        {5984, 5985}, set(), product_request=True,
        product_endpoints={("http", 5984), ("http", 5985)}, chain_deadline_seconds=5.0,
    )
    assert result["stop_reason"] == "terminal_response"
    assert result["terminal_port"] == 5985
    assert calls == [("http", 5984, "/", ""), ("http", 5985, "/", "")]


@pytest.mark.parametrize(
    "location",
    [
        "http://example.invalid:5985/", "http://localhost:5999/",
        "http://localhost:5985/not-root", "http://localhost:5985/?query=1",
        "http://localhost:5985/#fragment", "http://user:pass@localhost:5985/",
        "ftp://localhost:5985/",
    ],
)
def test_product_redirect_block_classes_stop_before_second_request(monkeypatch, location):
    executor = HTTPExecutor()
    target = InventoryScanTarget(
        ScanTargetTypeEnum.HOST, "id", "localhost", "127.0.0.1", "localhost", True
    )
    calls = []

    def request(**kwargs):
        calls.append(kwargs)
        return {
            "status_code": 302, "location": location, "body_complete": True,
            "completion_reason": "response_complete",
        }

    monkeypatch.setattr(executor, "_single_request", request)
    result = executor._request_chain(
        target, "http", 5984, "/", 5.0, 1, MAX_HTTP_PRODUCT_RESPONSE_BYTES,
        {5984, 5985}, set(), product_request=True,
        product_endpoints={("http", 5984), ("http", 5985)}, chain_deadline_seconds=5.0,
    )
    assert len(calls) == 1
    assert result["stop_reason"] != "terminal_response"


def test_explicit_https_is_preserved_and_plaintext_on_https_is_indeterminate(monkeypatch):
    executor = HTTPExecutor()
    target = InventoryScanTarget(
        ScanTargetTypeEnum.HOST, "id", "localhost", "127.0.0.1", "localhost", True
    )
    observed = []

    def request(**kwargs):
        observed.append(kwargs["scheme"])
        raise OSError("plaintext endpoint rejected TLS")

    monkeypatch.setattr(executor, "_single_request", request)
    result = executor._request_chain(
        target, "https", 9200, "/", 5.0, 1, MAX_HTTP_PRODUCT_RESPONSE_BYTES,
        set(), {9200}, product_request=True,
        product_endpoints={("https", 9200)}, chain_deadline_seconds=5.0,
    )
    evaluated = evaluate_http_product_response("elasticsearch", result)
    assert observed == ["https"]
    assert evaluated["outcome"] == "INDETERMINATE"
    assert evaluated["terminal_transport"] is None


def test_response_bound_is_indeterminate():
    body = b"{" + b" " * MAX_HTTP_PRODUCT_RESPONSE_BYTES
    result = evaluate_http_product_response("couchdb", _observation(body, complete=False))
    assert result["outcome"] == "INDETERMINATE"
    oversized = evaluate_http_product_response(
        "couchdb", _observation(b" " * (MAX_HTTP_PRODUCT_RESPONSE_BYTES + 1), complete=True)
    )
    assert (oversized["outcome"], oversized["reason_code"]) == ("INDETERMINATE", "response_body_limit")


def test_compact_evidence_contains_no_raw_identity_or_error_prose():
    observation = _observation(ELASTIC, headers=[
        ("Content-Type", "application/json"), ("X-Elastic-Product", "Elasticsearch")
    ], error="server returned secret auth realm prose")
    observation["stop_reason"] = "transport_failure"
    result = evaluate_http_product_response("elasticsearch", observation)
    rendered = json.dumps(result)
    assert "private-node" not in rendered
    assert "secret auth realm" not in rendered
    assert result["error_class"] == "transport_failure"
    assert all(isinstance(value, bool) for value in result["marker_facts"].values())
