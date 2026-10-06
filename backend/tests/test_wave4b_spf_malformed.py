import hashlib
import json

import pytest

from app.cli.ssc import build_parser
from app.db.session import engine
from app.services.golden_baseline_importer import import_golden_baseline
from app.services.internal_risk_calibration import resolve_ssc_internal_risk
from app.services.spf import (
    SPFAnalysisLimits,
    SPF_PARSER_VERSION,
    SPF_POLICY_VERSION,
    analyze_spf,
    expand_supported_domain,
    parse_spf_record,
    selected_spf_records,
)
from app.services.ssc_api_baseline import API_ORIGIN, FACTORS_ENDPOINT, ISSUES_ENDPOINT, normalize_api_payloads
from app.services.wave1_rules import WAVE1_RULES
from app.services.wave2_rules import WAVE2_RULES
from app.services.wave3a_rules import WAVE3A_RULES
from app.services.wave3b_rules import WAVE3B_RULES
from app.services.wave4a_rules import WAVE4A_RULES
from app.services.wave4b_rules import WAVE4B_RULES, active_wave4b_mappings
from sqlalchemy.orm import Session


def _dns(name, record_type="TXT", status="ANSWER", records=None, *, response_size=128):
    values = list(records or [])
    return {
        "name": name,
        "record_type": record_type,
        "status": status,
        "records": values,
        "invalid_records": [],
        "answer_count": len(values),
        "response_size": response_size,
        "error_class": None if status in {"ANSWER", "NODATA", "NXDOMAIN"} else status.casefold(),
    }


def _root(record=None, *, status="ANSWER", records=None):
    if records is None:
        records = [] if record is None else [record]
    return _dns("example.test", status=status, records=records)


class DNSFixture:
    def __init__(self, values=None, default_status="NODATA"):
        self.values = values or {}
        self.default_status = default_status
        self.calls = []

    def __call__(self, name, record_type, timeout):
        self.calls.append((name, record_type, timeout))
        value = self.values.get((name, record_type))
        if value is not None:
            return value
        return _dns(name, record_type, self.default_status)


def _analyze(record=None, values=None, *, root_status="ANSWER", root_records=None, limits=None, clock=None, started_at=None):
    fixture = DNSFixture(values)
    kwargs = {"limits": limits}
    if clock is not None:
        kwargs.update(clock=clock, started_at=started_at)
    result = analyze_spf("example.test", _root(record, status=root_status, records=root_records), fixture, **kwargs)
    return result, fixture


@pytest.mark.parametrize(
    ("record", "outcome", "reason"),
    [
        ("v=spf1 -all", "NO_MATCH", "complete_without_permerror"),
        ("v=spf1 wat -all", "MATCH", "unknown_mechanism"),
        ("v=spf1 ip4:192.0.2.1/33 -all", "MATCH", "invalid_network_or_cidr"),
        ("v=spf1 ip6:2001:db8::1/129 -all", "MATCH", "invalid_network_or_cidr"),
        ("v=spf1 ip4:192.0.2.1/032 -all", "NO_MATCH", "complete_without_permerror"),
        ("v=spf1 exists:%(d).example.test -all", "MATCH", "invalid_macro_escape"),
        ("v=spf1 exists:%{d0}.example.test -all", "MATCH", "zero_macro_transformer"),
        ("v=spf1 redirect=a.example.test redirect=b.example.test", "MATCH", "duplicate_redirect"),
        ("v=spf1 exp=a.example.test exp=b.example.test -all", "MATCH", "duplicate_exp"),
        ("v=spf1 -all wat", "MATCH", "unknown_mechanism"),
    ],
)
def test_selection_and_complete_grammar(record, outcome, reason):
    result, _ = _analyze(record)
    assert result["outcome"] == outcome
    assert result["error_class"] == reason


def test_exact_record_selection_and_missing_policy_separation():
    evidence = _root(records=["v=spf1 -all", "v=spf10 -all", "v=spf1\t-all", "x-v=spf1 -all"])
    assert selected_spf_records(evidence) == ["v=spf1 -all"]
    for status, records in (("ANSWER", ["v=spf10 -all"]), ("NODATA", []), ("NXDOMAIN", [])):
        result = analyze_spf("example.test", _root(status=status, records=records), DNSFixture())
        assert result["outcome"] == "NO_MATCH"
        assert result["error_class"] == "record_missing"


def test_multiple_and_non_ascii_selected_records_are_permerror():
    result, _ = _analyze(root_records=["v=spf1 -all", "V=SPF1 ~all"])
    assert result["outcome"] == "MATCH" and result["error_class"] == "multiple_spf_records"
    root = _root(records=[])
    root["invalid_records"] = [{
        "sha256": "a" * 64, "octet_length": 10, "spf1_prefix": True,
    }]
    result = analyze_spf("example.test", root, DNSFixture())
    assert result["outcome"] == "MATCH" and result["error_class"] == "non_ascii_spf_record"


def test_repeated_unknown_modifier_is_allowed_and_term_after_all_is_not_executed():
    result, fixture = _analyze("v=spf1 -all foo=one foo=two include:unused.example.test")
    assert result["outcome"] == "NO_MATCH"
    assert fixture.calls == []


def test_valid_include_and_deterministic_nested_malformed_policy():
    valid = {("child.example.test", "TXT"): _dns("child.example.test", records=["v=spf1 -all"])}
    result, _ = _analyze("v=spf1 include:child.example.test -all", valid)
    assert result["outcome"] == "NO_MATCH"
    malformed = {("child.example.test", "TXT"): _dns("child.example.test", records=["v=spf1 nope"])}
    result, _ = _analyze("v=spf1 include:child.example.test -all", malformed)
    assert result["outcome"] == "MATCH" and result["error_class"] == "unknown_mechanism"


def test_conditional_include_with_possible_earlier_match_is_indeterminate():
    values = {("broken.example.test", "TXT"): _dns("broken.example.test", records=["v=spf1 nope"])}
    result, _ = _analyze("v=spf1 ip4:192.0.2.1 include:broken.example.test -all", values)
    assert result["outcome"] == "INDETERMINATE"
    assert set(result["traversal"]["terminal_states"]) == {"PASS", "PERMERROR"}


def test_include_and_redirect_cycles_match_only_through_rfc_term_limit():
    include_values = {("example.test", "TXT"): _root("v=spf1 include:example.test")}
    include_result, _ = _analyze("v=spf1 include:example.test", include_values)
    assert include_result["outcome"] == "MATCH"
    assert include_result["error_class"] == "dns_term_limit_exceeded"
    assert include_result["traversal"]["loop_observed"] is True

    redirect_values = {("example.test", "TXT"): _root("v=spf1 redirect=example.test")}
    redirect_result, _ = _analyze("v=spf1 redirect=example.test", redirect_values)
    assert redirect_result["outcome"] == "MATCH"
    assert redirect_result["error_class"] == "dns_term_limit_exceeded"
    assert redirect_result["traversal"]["loop_observed"] is True


def test_redirect_valid_missing_and_ignored_by_all():
    valid = {("child.example.test", "TXT"): _dns("child.example.test", records=["v=spf1 -all"])}
    result, _ = _analyze("v=spf1 redirect=child.example.test", valid)
    assert result["outcome"] == "NO_MATCH"
    missing = {("child.example.test", "TXT"): _dns("child.example.test", status="NXDOMAIN")}
    result, _ = _analyze("v=spf1 redirect=child.example.test", missing)
    assert result["outcome"] == "MATCH" and result["error_class"] == "redirect_missing_spf"
    result, fixture = _analyze("v=spf1 -all redirect=child.example.test", missing)
    assert result["outcome"] == "NO_MATCH" and fixture.calls == []


def test_a_paths_are_bounded_and_path_sensitive():
    values = {
        ("example.test", "A"): _dns("example.test", "A", records=["192.0.2.10"]),
        ("example.test", "AAAA"): _dns("example.test", "AAAA", records=["2001:db8::10"]),
    }
    result, fixture = _analyze("v=spf1 a -all", values)
    assert result["outcome"] == "NO_MATCH"
    assert {(name, rrtype) for name, rrtype, _ in fixture.calls} == {("example.test", "A"), ("example.test", "AAAA")}

    values[("broken.example.test", "TXT")] = _dns("broken.example.test", records=["v=spf1 nope"])
    result, _ = _analyze("v=spf1 a include:broken.example.test -all", values)
    assert result["outcome"] == "INDETERMINATE"


def test_mx_safe_and_exchange_host_limit():
    hosts = [f"mx{index}.example.test" for index in range(1, 11)]
    values = {("example.test", "MX"): _dns("example.test", "MX", records=hosts)}
    for host in hosts:
        values[(host, "A")] = _dns(host, "A", records=["192.0.2.1"])
        values[(host, "AAAA")] = _dns(host, "AAAA", records=["2001:db8::1"])
    result, _ = _analyze("v=spf1 mx -all", values)
    assert result["outcome"] == "NO_MATCH"

    too_many = hosts + ["mx11.example.test"]
    values[("example.test", "MX")] = _dns("example.test", "MX", records=too_many)
    result, _ = _analyze("v=spf1 mx -all", values)
    assert result["outcome"] == "MATCH" and result["error_class"] == "mx_host_limit_exceeded"


def test_exists_positive_negative_and_ptr_context():
    positive = {("present.example.test", "A"): _dns("present.example.test", "A", records=["192.0.2.4"])}
    result, _ = _analyze("v=spf1 exists:present.example.test -all", positive)
    assert result["outcome"] == "NO_MATCH"
    negative = {("absent.example.test", "A"): _dns("absent.example.test", "A", status="NXDOMAIN")}
    result, _ = _analyze("v=spf1 exists:absent.example.test -all", negative)
    assert result["outcome"] == "NO_MATCH"
    result, fixture = _analyze("v=spf1 ptr -all")
    assert result["outcome"] == "INDETERMINATE"
    assert fixture.calls == []


def test_dns_term_and_void_limits_are_rfc_permerror_limits():
    targets = [f"i{index}.example.test" for index in range(1, 12)]
    values = {(target, "TXT"): _dns(target, records=["v=spf1 -all"]) for target in targets}
    ten = "v=spf1 " + " ".join(f"include:{target}" for target in targets[:10]) + " -all"
    result, _ = _analyze(ten, values)
    assert result["outcome"] == "NO_MATCH" and result["limits"]["dns_terms"] == 10
    eleven = "v=spf1 " + " ".join(f"include:{target}" for target in targets) + " -all"
    result, _ = _analyze(eleven, values)
    assert result["outcome"] == "MATCH" and result["error_class"] == "dns_term_limit_exceeded"

    void_values = {(f"v{index}.example.test", "A"): _dns(f"v{index}.example.test", "A", status="NXDOMAIN") for index in range(1, 4)}
    two = "v=spf1 exists:v1.example.test exists:v2.example.test -all"
    result, _ = _analyze(two, void_values)
    assert result["outcome"] == "NO_MATCH" and result["limits"]["void_lookups"] == 2
    three = "v=spf1 exists:v1.example.test exists:v2.example.test exists:v3.example.test -all"
    result, _ = _analyze(three, void_values)
    assert result["outcome"] == "MATCH" and result["error_class"] == "void_lookup_limit_exceeded"


@pytest.mark.parametrize("status", ["TIMEOUT", "SERVFAIL", "REFUSED", "FORMERR", "TRUNCATED_OR_MALFORMED"])
def test_dns_uncertainty_is_indeterminate(status):
    values = {("lookup.example.test", "A"): _dns("lookup.example.test", "A", status=status)}
    result, _ = _analyze("v=spf1 exists:lookup.example.test -all", values)
    assert result["outcome"] == "INDETERMINATE"
    root_result, _ = _analyze(root_status=status)
    assert root_result["outcome"] == "INDETERMINATE"


def test_operational_query_elapsed_state_and_trace_limits_are_indeterminate():
    record = "v=spf1 exists:lookup.example.test -all"
    values = {("lookup.example.test", "A"): _dns("lookup.example.test", "A", records=["192.0.2.1"])}
    for limits, expected in (
        (SPFAnalysisLimits(logical_queries=1), "logical_query_limit"),
        (SPFAnalysisLimits(query_trace=1), "query_trace_limit"),
        (SPFAnalysisLimits(abstract_states=0), "abstract_state_limit"),
    ):
        candidate = record if expected != "abstract_state_limit" else "v=spf1 ip4:192.0.2.1 -all"
        result, _ = _analyze(candidate, values, limits=limits)
        assert result["outcome"] == "INDETERMINATE"
        assert result["traversal"]["operational_stop_reason"] == expected

    response_values = {
        ("lookup.example.test", "A"): _dns(
            "lookup.example.test", "A", records=["192.0.2.1"], response_size=101,
        ),
    }
    result, _ = _analyze(record, response_values, limits=SPFAnalysisLimits(response_bytes=100))
    assert result["outcome"] == "INDETERMINATE"
    assert result["traversal"]["operational_stop_reason"] == "dns_response_size_limit"

    result, _ = _analyze("v=spf1 -all", limits=SPFAnalysisLimits(record_bytes=8))
    assert result["outcome"] == "INDETERMINATE"
    assert result["traversal"]["operational_stop_reason"] == "spf_record_size_limit"

    result, _ = _analyze("v=spf1 -all", limits=SPFAnalysisLimits(evaluator_steps=0))
    assert result["outcome"] == "INDETERMINATE"
    assert result["traversal"]["operational_stop_reason"] == "evaluator_step_limit"

    class Clock:
        def __init__(self):
            self.value = 0.0

        def __call__(self):
            self.value += 21.0
            return self.value

    clock = Clock()
    result, _ = _analyze(record, values, clock=clock, started_at=0.0)
    assert result["outcome"] == "INDETERMINATE"
    assert result["traversal"]["operational_stop_reason"] == "elapsed_time_limit"


def test_macro_support_and_context_boundaries():
    assert parse_spf_record("v=spf1 include:%{D2}.example.test -all").valid is True
    tokens = parse_spf_record("v=spf1 include:%{d2} -all").terms[0].macro_tokens
    assert expand_supported_domain(tokens, "mail.example.test") == ("example.test", None)
    reverse_tokens = parse_spf_record("v=spf1 include:%{d2r} -all").terms[0].macro_tokens
    assert expand_supported_domain(reverse_tokens, "mail.example.test") == ("test.example", None)

    values = {("example.test", "TXT"): _dns("example.test", records=["v=spf1 -all"])}
    result, _ = _analyze("v=spf1 include:%{d2} -all", values)
    assert result["outcome"] == "NO_MATCH"
    for macro in ("%{s}", "%{l}", "%{o}", "%{i}", "%{p}", "%{h}", "%{v}"):
        result, fixture = _analyze(f"v=spf1 include:{macro}.example.test -all")
        assert result["outcome"] == "INDETERMINATE"
        assert fixture.calls == []
    for escape in ("%%", "%_", "%-"):
        result, _ = _analyze(f"v=spf1 include:{escape}.example.test -all")
        assert result["outcome"] == "INDETERMINATE"
    result, _ = _analyze("v=spf1 include:foo..example.test -all")
    assert result["outcome"] == "INDETERMINATE"
    result, fixture = _analyze("v=spf1 -all exp=%{s}.example.test")
    assert result["outcome"] == "NO_MATCH" and fixture.calls == []


def test_versions_registry_cli_and_uncalibrated_risk_contract():
    assert SPF_PARSER_VERSION == "ssc-wave4b-spf-parser.v1"
    assert SPF_POLICY_VERSION == "ssc-wave4b-spf-malformed-policy.v1"
    assert [spec.issue_key for spec in WAVE4B_RULES] == ["spf_record_malformed"]
    assert len(WAVE1_RULES) == 14
    assert len(WAVE2_RULES) == 7
    assert len(WAVE3A_RULES) == 6
    assert len(WAVE3B_RULES) == 7
    assert len(WAVE4A_RULES) == 3
    args = build_parser().parse_args(["baseline", "activate-wave4b", "--yes"])
    assert args.baseline_command == "activate-wave4b" and args.yes is True
    decision = resolve_ssc_internal_risk("spf_record_malformed")
    assert decision.breach_risk == "UNKNOWN" and decision.affects_score is False


def _wave4b_baseline():
    factors = {"dns_health": {"key": "dns_health", "name": "DNS Health"}}
    issues = [{
        "key": "spf_record_malformed", "severity": "medium", "factor": "dns_health", "title": "Malformed SPF Record",
    }]
    raw = {}
    for endpoint, payload in ((FACTORS_ENDPOINT, {"entries": list(factors.values())}), (ISSUES_ENDPOINT, {"entries": issues})):
        body = json.dumps(payload)
        raw[API_ORIGIN + endpoint] = {
            "body": body,
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "captured_at": "2026-10-05T00:00:00+00:00",
        }
    return normalize_api_payloads(raw)


def test_wave4b_exact_version_activation_during_attested_baseline_import():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as db:
            import_golden_baseline(db, _wave4b_baseline(), attest_real_source=True)
            mappings = active_wave4b_mappings(db)
            assert len(mappings) == 1
            assert mappings[0]["issue_key"] == "spf_record_malformed"
            assert mappings[0]["rule_key"] == "ssc.wave4b.spf_record_malformed"
        transaction.rollback()
