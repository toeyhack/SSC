import json
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.cli.ssc import main
from app.db.session import SessionLocal
from app.main import app
from app.models.scan_models import ScanJob
from app.outputs.report import render_html, write_report
from app.schemas.results import NormalizedResult
from app.services.cli_setup import add_inventory_target, load_detector_bundle
from app.services.cli_scan import scan_inventory_target
from app.services.scoring_engine import ScoringDefinition
from tests.test_scan_executors import _approved_local_host, _http_server, SecurityHeadersHandler
from tests.test_score_results import linked_rule

client = TestClient(app)


def test_cli_scans_real_http_and_writes_same_normalized_result(tmp_path, capsys):
    org, _, host = _approved_local_host()
    _, _, _, rule, _ = linked_rule("http.csp_present", True)
    with _http_server(SecurityHeadersHandler) as port:
        config_path = tmp_path / "scan.json"
        config_path.write_text(json.dumps({"executors": ["http"], "http_ports": [port], "https_ports": []}))
        command = [str(Path(sys.executable).with_name("ssc")), "scan", "--target", "localhost", "--organization-id", org["id"], "--output", "report", "--output-dir", str(tmp_path / "out"), "--scan-config", str(config_path), "--rule-key", rule["stable_key"]]
        process = subprocess.run(command, capture_output=True, text=True, timeout=20)
    assert process.returncode == 0, process.stderr
    captured = process.stdout
    paths = dict(line.split("=", 1) for line in captured.splitlines() if line.startswith(("html=", "json=")))
    result = NormalizedResult.model_validate_json(Path(paths["json"]).read_text())
    assert result.overall_score == 85
    assert result.findings[0].score_impact == 15
    assert result.targets[0].inventory_id == host["id"]
    html = Path(paths["html"]).read_text()
    assert "85 / 100" in html and "Original remediation" in html
    assert "localhost" in html and "Evidence summary" in html
    from app.services.score_results import build_score_result
    with SessionLocal() as db:
        assert build_score_result(db, UUID(result.scan_run_id)).model_dump() == result.model_dump()
    assert main(["report", "--run-id", result.scan_run_id, "--output-dir", str(tmp_path / "rerender")]) == 0


def test_sygnos_rejected_before_database_or_network(capsys):
    assert main(["scan", "--target", "unapproved.test", "--output", "sygnos"]) == 2
    assert "No scan was started" in capsys.readouterr().err


def test_cli_unapproved_target_creates_no_job(tmp_path):
    org, _, host = _approved_local_host(approved=False)
    with SessionLocal() as db:
        before = len(db.execute(select(ScanJob)).scalars().all())
    assert main(["scan", "--target", "localhost", "--organization-id", org["id"], "--executors", "http", "--output-dir", str(tmp_path)]) == 1
    with SessionLocal() as db:
        assert len(db.execute(select(ScanJob)).scalars().all()) == before
    assert not list(tmp_path.glob("scan-*"))


def test_report_escapes_findings_remediation_and_evidence(tmp_path):
    from tests.test_scoring_engine import score, finding
    payload = '<script>alert("x")</script>'
    result = score([finding(title=payload, remediation=payload, evidence_summary={"value": payload})])
    document = render_html(result)
    assert payload not in document
    assert "&lt;script&gt;" in document
    _, json_path = write_report(result, tmp_path)
    assert NormalizedResult.model_validate_json(json_path.read_text()).model_dump() == result.model_dump()
    write_report(result, tmp_path)
    assert len(list(tmp_path.iterdir())) == 2  # Preserve previous artifacts.


def test_cli_target_registration_and_rule_bundle_idempotency():
    suffix = uuid4().hex[:12]
    bundle = json.loads((Path(__file__).parents[1] / "examples/internal-detectors.json").read_text())
    for detector in bundle["detectors"]:
        detector["stable_key"] += "." + suffix
        detector["factor"]["code"] += "-" + suffix
    with SessionLocal() as db:
        target = add_inventory_target(db, organization="CLI " + suffix, domain_name=f"{suffix}.test", hostname="localhost", ip="127.0.0.1",
                                      approved=True, allow_sensitive=True, approval_notes="Local fixture authorized")
        assert target["approved_for_scan"] and target["allow_sensitive_network_scan"]
        created = load_detector_bundle(db, bundle)
        assert created["rules_created"] == len(bundle["detectors"])
        assert all(value == 0 for value in load_detector_bundle(db, bundle).values())


def test_console_command_help_runs_without_web_server():
    result = subprocess.run([str(Path(sys.executable).with_name("ssc")), "scan", "--help"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert "--target" in result.stdout and "--output" in result.stdout


def test_all_real_executors_flow_through_findings_scoring_and_report(tmp_path):
    from tests.test_executor_safety import tls_server
    from tests.test_scan_executors import _dns_server
    org, _, host = _approved_local_host()
    with _http_server(SecurityHeadersHandler) as http_port, tls_server(tmp_path) as (tls_port, _), _dns_server() as dns_port:
        definitions = [linked_rule("http.csp_present", True), linked_rule("tls.certificate_trusted", False),
                       linked_rule("dns.spf_present", True), linked_rule(f"tcp.ports.{http_port}.open", True)]
        keys = [d[3]["stable_key"] for d in definitions]
        config = {"executors": ["http", "tls", "dns", "tcp"], "http_ports": [http_port], "https_ports": [tls_port],
                  "tls_ports": [tls_port], "tcp_ports": [http_port], "dns_server_host": "127.0.0.1", "dns_server_port": dns_port,
                  "request_timeout_seconds": 1, "connect_timeout_seconds": 1, "dns_timeout_seconds": 1}
        with SessionLocal() as db:
            result = scan_inventory_target(db, name="localhost", organization_id=UUID(org["id"]), scan_config=config,
                                           model=ScoringDefinition(), rule_keys=keys)
    assert result.status == "complete"
    assert result.overall_score == 85
    assert len(result.findings) == 4 and len(result.evidence) == 4
    assert {e.source for e in result.evidence} == {"SCANNER_HTTP", "SCANNER_TLS", "SCANNER_DNS", "SCANNER_TCP"}
    assert {f.rule_version_id for f in result.findings} == {d[4]["id"] for d in definitions}
    assert {f.catalog_issue_type_version_id for f in result.findings} == {d[2]["id"] for d in definitions}
    assert all(f.remediation == "Original remediation" for f in result.findings)
    assert sum(f.overall_score_impact for f in result.findings) == 15
    html_path, json_path = write_report(result, tmp_path / "combined")
    assert "SCANNER_DNS" in html_path.read_text()
    assert NormalizedResult.model_validate_json(json_path.read_text()).model_dump() == result.model_dump()


def test_incomplete_report_exit_has_no_perfect_score(tmp_path, capsys):
    org, _, _ = _approved_local_host()
    _, _, _, rule, _ = linked_rule("http.hsts_present", False)
    with _http_server(SecurityHeadersHandler) as port:
        config_path = tmp_path / "http-only.json"
        config_path.write_text(json.dumps({"executors": ["http"], "http_ports": [port], "https_ports": []}))
        code = main(["scan", "--target", "localhost", "--organization-id", org["id"], "--output-dir", str(tmp_path / "out"),
                     "--scan-config", str(config_path), "--rule-key", rule["stable_key"]])
    assert code == 3
    assert "overall_score=unassessed" in capsys.readouterr().out
    path = next((tmp_path / "out").glob("*/result.json"))
    result = NormalizedResult.model_validate_json(path.read_text())
    assert result.overall_score is None
    assert result.coverage["rules_skipped"] == 1
    assert len(result.findings) == 0
