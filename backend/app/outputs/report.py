"""Self-contained human HTML and machine JSON adapters for one normalized result."""
import html
import json
import tempfile
from pathlib import Path

from app.schemas.results import NormalizedResult


def _escape(value) -> str:
    return html.escape(str(value), quote=True)


def _score(value) -> str:
    return "Unassessed" if value is None else f"{value:g} / 100"


def _json(value) -> str:
    return _escape(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False))


def render_html(result: NormalizedResult) -> str:
    targets = {t.scan_job_target_id: t.name for t in result.targets}
    target_list = "".join(f"<li>{_escape(t.name)} ({_escape(t.target_type)})</li>" for t in result.targets)
    factors = "".join(
        f"<tr><td>{_escape(f.name)} <small>{_escape(f.code)}</small></td><td>{_score(f.score)}</td>"
        f"<td>{_escape(f.total_issues)}</td><td>{_escape(f.assessed_count)}</td>"
        f"<td>{_escape(f.not_assessed_count)}</td><td>{_escape(f.supported_capability_count)}</td>"
        f"<td>{_escape(f.assessment_state or f.status)}</td><td>{_escape(f.weight)}</td>"
        f"<td>{_escape(f.score_impact)}</td></tr>"
        for f in result.factor_scores
    )
    completeness = ""
    issue_assessments = ""
    if result.assessment_profile and result.assessment_completeness:
        summary = result.assessment_completeness
        completeness = f"""<h2>V1 assessment completeness</h2>
<p>Profile: {_escape(result.assessment_profile.name)} v{_escape(result.assessment_profile.version)} · State: <strong>{_escape(summary.state)}</strong></p>
<ul><li>Total V1 issues: {_escape(summary.total_issues_in_profile)}</li><li>ASSESSED: {_escape(summary.assessed_count)}</li><li>NOT_ASSESSED: {_escape(summary.not_assessed_count)}</li><li>OUT_OF_SCOPE: {_escape(summary.out_of_scope_count)}</li></ul>"""
        rows = []
        for item in result.issue_assessments:
            targets_summary = ", ".join(
                f"{targets.get(target.target_id, target.target_id)}: {target.state}"
                + (f" ({target.evaluator_outcome})" if target.evaluator_outcome else "")
                for target in item.target_assessments
            ) or "—"
            rows.append(
                f"<tr><td>{_escape(item.ssc_issue_key)}</td><td>{_escape(item.factor_code)}</td>"
                f"<td>{_escape(item.state)}</td><td>{_escape(item.reason_code)}</td>"
                f"<td>{_escape('yes' if item.supported_capability else 'no')}</td>"
                f"<td>{_escape(targets_summary)}</td></tr>"
            )
        issue_assessments = (
            "<details><summary>Issue assessment states (" + str(len(result.issue_assessments)) + ")</summary>"
            "<table><thead><tr><th>Issue</th><th>Factor</th><th>State</th><th>Reason</th>"
            "<th>Supported capability</th><th>Targets</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></details>"
        )
    findings = []
    for f in result.findings:
        findings.append(f"""<article><h3>{_escape(f.title)}</h3>
<p>Affected target: <strong>{_escape(targets.get(f.target_id, f.target_id))}</strong></p>
<p>Factor: {_escape(f.factor_name)} · Internal risk: {_escape(f.breach_risk)} · SSC severity: {_escape(f.ssc_severity or 'not supplied')} · Status: {_escape(f.status)} · Evidence source: {_escape(f.evidence_source or 'unknown')}</p>
<p>Factor score impact: −{f.score_impact:g} points · Overall score impact: −{f.overall_score_impact:g} points</p>
<h4>Evidence summary</h4><pre>{_json(f.evidence_summary)}</pre>
<h4>Remediation</h4><p class="remediation">{_escape(f.remediation or 'Remediation is not defined for this rule; review its exact version.')}</p>
<small>SSC issue: {_escape(f.ssc_issue_key or 'unlinked')} · Rule version: {_escape(f.rule_version_id)} · Catalog issue version: {_escape(f.catalog_issue_type_version_id or 'unlinked')}</small></article>""")
    evidence = "".join(f"<details><summary>{_escape(e.source)} · {_escape(targets.get(e.target_id, e.target_id))} · {_escape(e.status)}</summary><pre>{_json(e.summary)}</pre></details>" for e in result.evidence)
    warnings = "".join(f"<li>{_escape(w)}</li>" for w in result.warnings)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Authorized scan report</title><style>
body{{font:16px/1.5 system-ui,sans-serif;color:#17202a;background:#f7f9fb;margin:0}}main{{max-width:1100px;margin:auto;padding:32px}}
h1,h2,h3{{line-height:1.2}}.score{{font-size:32px;font-weight:700}}table{{width:100%;border-collapse:collapse;background:white}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #dce1e7}}
article,details{{background:white;padding:20px;margin:16px 0;border:1px solid #dce1e7;border-radius:8px}}pre{{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}}small{{color:#52606d}}.remediation{{white-space:pre-wrap}}summary{{cursor:pointer}}@media print{{body{{background:white}}main{{padding:0}}article{{break-inside:avoid}}}}
</style></head><body><main><h1>Authorized scan report</h1>
<p>Run: {_escape(result.scan_run_id)} · Generated: {_escape(result.generated_at.isoformat())} · Result: {_escape(result.status)}</p>
<p class="score">Overall score: {_score(result.overall_score)}</p>
<p>Internal model: {_escape(result.scoring_model_name)} v{_escape(result.scoring_model_version)}. This score is an internal assessment using the configured rules.</p>
<ul>{warnings}</ul>{completeness}{issue_assessments}<h2>Targets</h2><ul>{target_list}</ul>
<h2>Factor scores</h2><table><thead><tr><th>Factor</th><th>Score</th><th>Total issues</th><th>ASSESSED</th><th>NOT_ASSESSED</th><th>Supported capability</th><th>Assessment state</th><th>Weight</th><th>Observed impact</th></tr></thead><tbody>{factors}</tbody></table>
<h2>Findings ({len(result.findings)})</h2>{''.join(findings) or '<p>No findings matched the evaluated rules. Review coverage before interpreting this result.</p>'}
<h2>Evidence</h2>{evidence or '<p>No observations recorded.</p>'}
<h2>Coverage</h2><pre>{_json(result.coverage)}</pre>
<p>Impacts on incomplete factors represent observed penalties only. An incomplete result has no overall score or overall impact.</p>
<small>Result schema: {_escape(result.schema_version)} · Scoring definition SHA-256: {_escape(result.scoring_model_hash)}</small>
</main></body></html>"""


def write_report(result: NormalizedResult, output_dir: str | Path) -> tuple[Path, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    # Each output gets a fresh directory; never overwrite previous evidence or results.
    run_dir = Path(tempfile.mkdtemp(prefix=f"scan-{result.scan_run_id}-", dir=directory))
    json_path, html_path = run_dir / "result.json", run_dir / "report.html"
    json_path.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    html_path.write_text(render_html(result), encoding="utf-8")
    return html_path, json_path
