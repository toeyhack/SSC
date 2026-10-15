from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.db.session import engine
from app.models.catalog_models import (
    BreachRiskEnum,
    CatalogFactor,
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
    SourceTypeEnum,
)
from app.models.models import Domain, Host, Organization
from app.models.rule_models import (
    RuleEngineRule,
    RuleEngineRuleVersion,
    RuleSourceTypeEnum,
    RuleTargetTypeEnum,
)
from app.models.scan_models import (
    EvidenceSourceEnum,
    ScanJob,
    ScanJobTarget,
    ScanTargetTypeEnum,
)
from app.services import scan_engine
from app.services.public_exposure import (
    AttestationSource,
    ExecutionContext,
    VantageClass,
    api_inline_execution_context,
    attach_exposure_contexts,
    local_cli_execution_context,
    unknown_execution_context,
)
from app.services.public_exposure_consumers import (
    PINNED_SSC_BASELINE_HASH,
    get_pinned_public_exposure_consumer,
    public_exposure_rule_expression,
)
from app.services.scan_engine import run_scan_job
from app.services.scan_executors import ExecutorObservation


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _external_context() -> ExecutionContext:
    return ExecutionContext(
        VantageClass.EXTERNAL_PUBLIC,
        "edge-bkk-01",
        AttestationSource.DEPLOYMENT_MANIFEST,
        manifest_digest="a" * 64,
    )


def _seed_job(
    db: Session,
    issue_key: str,
    *,
    address: str = "8.8.8.8",
    collect_observations: bool = True,
    manual_evidence: dict | None = None,
) -> ScanJob:
    suffix = uuid4().hex[:12]
    factor = CatalogFactor(code=f"network_{suffix}", name="Network Security")
    db.add(factor)
    db.flush()
    issue = CatalogIssueType(stable_key=issue_key, factor_id=factor.id)
    db.add(issue)
    db.flush()
    issue_version = CatalogIssueTypeVersion(
        issue_type_id=issue.id,
        version_number=1,
        name=issue_key,
        breach_risk=BreachRiskEnum.UNKNOWN,
        ssc_severity="medium",
        affects_score=False,
        source_type=SourceTypeEnum.SSC_API,
        source_snapshot_hash=PINNED_SSC_BASELINE_HASH,
    )
    db.add(issue_version)
    db.flush()
    issue.current_version_id = issue_version.id
    snapshot = CatalogSnapshot(
        name="Pinned test baseline",
        source_type=SourceTypeEnum.SSC_API,
        content_hash=PINNED_SSC_BASELINE_HASH,
        normalized_schema_version="ssc.api.metadata.v2",
        is_real_baseline=True,
    )
    db.add(snapshot)
    db.flush()
    db.add(CatalogSnapshotItem(
        catalog_snapshot_id=snapshot.id,
        issue_type_version_id=issue_version.id,
        factor_position=1,
        issue_position=1,
    ))

    consumer = get_pinned_public_exposure_consumer(issue_key)
    rule = RuleEngineRule(stable_key=f"ssc.test.{issue_key}.{suffix}", catalog_issue_type_id=issue.id)
    db.add(rule)
    db.flush()
    rule_version = RuleEngineRuleVersion(
        rule_id=rule.id,
        catalog_issue_type_version_id=issue_version.id,
        version_number=1,
        name=issue_key,
        target_type=RuleTargetTypeEnum.HOST,
        rule_expression=public_exposure_rule_expression(issue_key) or {
            "operator": "equals", "path": f"tcp.evaluations.{issue_key}.matched", "value": True,
        },
        evidence_schema=(
            {"consumer_policy_version": consumer.consumer_policy_version}
            if consumer is not None else {"semantic_class": "PROTOCOL_IDENTITY_ONLY"}
        ),
        source_type=RuleSourceTypeEnum.SSC_REFERENCE,
    )
    db.add(rule_version)
    db.flush()
    rule.current_version_id = rule_version.id

    organization = Organization(name=f"Exposure {suffix}", active=True)
    db.add(organization)
    db.flush()
    domain = Domain(organization_id=organization.id, name=f"{suffix}.test", active=True)
    db.add(domain)
    db.flush()
    host = Host(
        domain_id=domain.id,
        hostname=f"host.{suffix}.test",
        ip=address,
        active=True,
        approved_for_scan=True,
        allow_sensitive_network_scan=address.startswith("10."),
    )
    db.add(host)
    db.flush()

    job = ScanJob(
        name=f"Exposure job {suffix}",
        requested_by="pytest",
        selected_rule_ids=[str(rule.id)],
        collect_observations=collect_observations,
    )
    db.add(job)
    db.flush()
    root = consumer.evidence_root if consumer is not None else "tcp"
    target = ScanJobTarget(
        scan_job_id=job.id,
        target_type=ScanTargetTypeEnum.HOST,
        organization_id=organization.id,
        domain_id=domain.id,
        host_id=host.id,
        evidence=manual_evidence,
        scan_config={"executors": [root]},
    )
    db.add(target)
    db.commit()
    return job


def _scanner_observation(issue_key, source, *, protocol_outcome="MATCH", stale=False):
    def collect(target, _config, execution_context):
        evidence = {
            "target_identity": {"connect_host": target.connect_host},
            "evaluations": {
                issue_key: {
                    "outcome": protocol_outcome,
                    "matched": True if protocol_outcome == "MATCH" else None,
                    "policy_version": "protocol-policy.v1",
                }
            },
        }
        attach_exposure_contexts(evidence, target.connect_host, execution_context)
        if stale:
            evidence["evaluations"][issue_key]["exposure_context"]["composition"]["policy_version"] = "stale"
        return [ExecutorObservation(source, evidence)]

    return collect


@pytest.mark.parametrize(
    ("issue_key", "source"),
    [
        ("service_rsync", EvidenceSourceEnum.SCANNER_TCP),
        ("service_soap", EvidenceSourceEnum.SCANNER_HTTP),
        ("service_rdp", EvidenceSourceEnum.SCANNER_TCP),
        ("service_couchdb", EvidenceSourceEnum.SCANNER_HTTP),
        ("service_elasticsearch", EvidenceSourceEnum.SCANNER_HTTP),
    ],
)
def test_external_public_scanner_match_creates_explained_finding(db, monkeypatch, issue_key, source):
    job = _seed_job(db, issue_key)
    monkeypatch.setattr(scan_engine, "collect_scanner_observations", _scanner_observation(issue_key, source))
    run = run_scan_job(db, job.id, _external_context())
    assert run.summary["findings_created"] == 1
    assert run.summary["rule_assessments"][0]["evaluation_outcome"] == "MATCH"
    finding = run.findings[0]
    assert finding.evidence_source == source
    matched = finding.evidence["target_evidence"]
    assert matched["protocol_evaluation"]["outcome"] == "MATCH"
    context = matched["exposure_context"]
    assert context["address_scope"]["outcome"] == "PUBLIC_ROUTABLE"
    assert context["vantage"]["vantage_class"] == "EXTERNAL_PUBLIC"
    assert context["vantage"]["attestation_source"] == "DEPLOYMENT_MANIFEST"
    assert context["composition"]["outcome"] == "MATCH"


def test_minecraft_protocol_match_creates_finding_without_external_vantage(db, monkeypatch):
    job = _seed_job(db, "minecraft_server")
    monkeypatch.setattr(
        scan_engine,
        "collect_scanner_observations",
        _scanner_observation("minecraft_server", EvidenceSourceEnum.SCANNER_TCP),
    )
    run = run_scan_job(db, job.id, local_cli_execution_context())
    assert run.summary["findings_created"] == 1
    assessment = run.summary["rule_assessments"][0]
    assert assessment["status"] == "evaluated"
    assert assessment["evaluation_outcome"] == "MATCH"
    assert run.findings[0].evidence["target_evidence"] == {
        "path": "tcp.evaluations.minecraft_server.matched",
        "found": True,
        "value": True,
    }


@pytest.mark.parametrize(
    "execution_context",
    [local_cli_execution_context(), api_inline_execution_context(), unknown_execution_context()],
)
@pytest.mark.parametrize(
    ("issue_key", "source"),
    [
        ("service_rsync", EvidenceSourceEnum.SCANNER_TCP),
        ("service_rdp", EvidenceSourceEnum.SCANNER_TCP),
        ("service_couchdb", EvidenceSourceEnum.SCANNER_HTTP),
        ("service_elasticsearch", EvidenceSourceEnum.SCANNER_HTTP),
    ],
)
def test_unknown_local_api_and_default_worker_vantage_are_not_assessed(
    db, monkeypatch, execution_context, issue_key, source
):
    job = _seed_job(db, issue_key)
    monkeypatch.setattr(
        scan_engine,
        "collect_scanner_observations",
        _scanner_observation(issue_key, source),
    )
    run = run_scan_job(db, job.id, execution_context)
    assessment = run.summary["rule_assessments"][0]
    assert assessment["status"] == "skipped"
    assert assessment["evaluation_outcome"] == "INDETERMINATE"
    assert run.summary["findings_created"] == 0


@pytest.mark.parametrize(
    ("address", "context", "protocol_outcome"),
    [
        ("8.8.8.8", ExecutionContext(VantageClass.INTERNAL, "inside", AttestationSource.UNCONFIGURED), "MATCH"),
        ("10.0.0.1", _external_context(), "MATCH"),
        ("8.8.8.8", _external_context(), "INDETERMINATE"),
    ],
)
@pytest.mark.parametrize(
    ("issue_key", "source"),
    [
        ("service_rsync", EvidenceSourceEnum.SCANNER_TCP),
        ("service_rdp", EvidenceSourceEnum.SCANNER_TCP),
        ("service_couchdb", EvidenceSourceEnum.SCANNER_HTTP),
        ("service_elasticsearch", EvidenceSourceEnum.SCANNER_HTTP),
    ],
)
def test_internal_vantage_non_public_target_and_protocol_indeterminate_are_not_assessed(
    db, monkeypatch, address, context, protocol_outcome, issue_key, source
):
    job = _seed_job(db, issue_key, address=address)
    monkeypatch.setattr(
        scan_engine,
        "collect_scanner_observations",
        _scanner_observation(
            issue_key, source, protocol_outcome=protocol_outcome
        ),
    )
    run = run_scan_job(db, job.id, context)
    assert run.summary["rule_assessments"][0]["status"] == "skipped"
    assert run.summary["findings_created"] == 0


@pytest.mark.parametrize(
    ("issue_key", "right_source", "wrong_source"),
    [
        ("service_rsync", EvidenceSourceEnum.SCANNER_TCP, EvidenceSourceEnum.SCANNER_HTTP),
        ("service_rdp", EvidenceSourceEnum.SCANNER_TCP, EvidenceSourceEnum.SCANNER_HTTP),
        ("service_couchdb", EvidenceSourceEnum.SCANNER_HTTP, EvidenceSourceEnum.SCANNER_TCP),
        ("service_elasticsearch", EvidenceSourceEnum.SCANNER_HTTP, EvidenceSourceEnum.SCANNER_TCP),
    ],
)
@pytest.mark.parametrize("stale", [True, False])
def test_stale_policy_and_wrong_scanner_source_fail_closed(
    db, monkeypatch, issue_key, right_source, wrong_source, stale
):
    job = _seed_job(db, issue_key)
    source = right_source if stale else wrong_source
    monkeypatch.setattr(
        scan_engine,
        "collect_scanner_observations",
        _scanner_observation(issue_key, source, stale=stale),
    )
    run = run_scan_job(db, job.id, _external_context())
    expected = "missing_or_stale_exposure_policy" if stale else "untrusted_observation_source"
    assert run.summary["rule_assessments"][0]["reason_code"] == expected
    assert run.summary["findings_created"] == 0


@pytest.mark.parametrize(
    "issue_key",
    ["service_rsync", "service_rdp", "service_couchdb", "service_elasticsearch"],
)
def test_manual_protocol_shaped_match_is_rejected_by_source_identity(db, issue_key):
    consumer = get_pinned_public_exposure_consumer(issue_key)
    evidence = {
        consumer.evidence_root: {
            "evaluations": {
                issue_key: {"outcome": "MATCH", "matched": True},
            }
        }
    }
    job = _seed_job(
        db,
        issue_key,
        collect_observations=False,
        manual_evidence=evidence,
    )
    run = run_scan_job(db, job.id, _external_context())
    assessment = run.summary["rule_assessments"][0]
    assert assessment["status"] == "skipped"
    assert assessment["reason_code"] == "untrusted_observation_source"
    assert run.summary["findings_created"] == 0
