#!/usr/bin/env python3
"""Recalculate SSC coverage from exact active evaluator mappings."""
import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "docs" / "SSC_ISSUE_COVERAGE.csv"
MD_PATH = ROOT / "docs" / "SSC_ISSUE_COVERAGE.md"
BASELINE_HASH = "0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Write CSV and Markdown coverage documents")
    parser.add_argument(
        "--verify-database", action="store_true",
        help="Require exact active mappings from DATABASE_URL instead of using the reviewed registry",
    )
    args = parser.parse_args()

    import sys
    sys.path.insert(0, str(ROOT / "backend"))
    from app.models import models  # noqa: F401 - register inventory ORM relationships
    from app.services.wave1_rules import WAVE1_BY_KEY, WAVE1_PARTIAL_REASONS, WAVE1_RULES
    from app.services.wave2_rules import WAVE2_BY_KEY, WAVE2_PARTIAL_REASONS, WAVE2_RULES

    all_by_key = {**WAVE1_BY_KEY, **WAVE2_BY_KEY}
    all_partial_reasons = {**WAVE1_PARTIAL_REASONS, **WAVE2_PARTIAL_REASONS}

    mappings = []
    if args.verify_database:
        from app.db.session import SessionLocal
        from app.services.wave1_rules import active_wave1_mappings
        from app.services.wave2_rules import active_wave2_mappings
        with SessionLocal() as db:
            mappings = active_wave1_mappings(db) + active_wave2_mappings(db)
        active_keys = {item["issue_key"] for item in mappings}
        expected = set(all_by_key)
        if active_keys != expected:
            missing = sorted(expected - active_keys)
            extra = sorted(active_keys - expected)
            raise SystemExit(f"active Wave 1/2 mappings differ: missing={missing} extra={extra}")
    else:
        active_keys = set(all_by_key)

    with CSV_PATH.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
        fields = list(rows[0])
    if len(rows) != 202 or not active_keys.issubset({row["ssc_issue_key"] for row in rows}):
        raise SystemExit("coverage CSV does not match the reviewed 202-issue baseline")
    for row in rows:
        if row["ssc_issue_key"] in active_keys:
            spec = all_by_key[row["ssc_issue_key"]]
            wave = "Wave 1" if row["ssc_issue_key"] in WAVE1_BY_KEY else "Wave 2"
            row["current_platform_support"] = "SUPPORTED"
            row["required_executor"] = spec.primitive
            row["proposed_test_method"] = spec.evidence_requirement
            row["exact_observation_or_evidence"] = spec.evidence_requirement
            row["proposed_rule_logic"] = spec.logic
            row["authoritative_reference"] = spec.reference
            row["notes"] = (
                f"{wave} active evaluator {spec.rule_key} uses method {spec.evidence_schema['schema_version']} "
                f"and policy {spec.evidence_schema['policy_version']}, pinned to the exact attested SSC_API issue version; "
                "SSC severity remains separate and no SSC score impact is inferred."
            )
        elif row["current_platform_support"] == "SUPPORTED":
            row["current_platform_support"] = "PARTIAL"
        if row["ssc_issue_key"] in all_partial_reasons and row["ssc_issue_key"] not in active_keys:
            row["current_platform_support"] = "PARTIAL"
            row["notes"] = all_partial_reasons[row["ssc_issue_key"]]

    coverage = Counter(row["current_platform_support"] for row in rows)
    feasibility = Counter(row["feasibility_category"] for row in rows)
    if coverage != {"SUPPORTED": 21, "PARTIAL": 101, "NOT_SUPPORTED": 80}:
        raise SystemExit(f"unexpected coverage totals: {dict(coverage)}")

    if args.write:
        with CSV_PATH.open("w", newline="", encoding="utf-8") as target:
            writer = csv.DictWriter(target, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        MD_PATH.write_text(
            render_markdown(
                rows, feasibility, coverage,
                WAVE1_RULES, WAVE1_PARTIAL_REASONS,
                WAVE2_RULES, WAVE2_PARTIAL_REASONS,
            ),
            encoding="utf-8",
        )

    print(f"SUPPORTED={coverage['SUPPORTED']} PARTIAL={coverage['PARTIAL']} NOT_SUPPORTED={coverage['NOT_SUPPORTED']}")
    for mapping in mappings:
        print(
            f"{mapping['issue_key']} issue-v{mapping['issue_version_number']}={mapping['issue_version_id']} "
            f"rule-v{mapping['rule_version_number']}={mapping['rule_version_id']}"
        )
    return 0


def render_markdown(rows, feasibility, coverage, wave1_rules, wave1_partial, wave2_rules, wave2_partial) -> str:
    factors = defaultdict(Counter)
    for row in rows:
        factor = factors[row["factor"]]
        factor["total"] += 1
        factor[row["feasibility_category"]] += 1
        factor[row["current_platform_support"]] += 1

    lines = [
        "# SSC 202-Issue Coverage Mapping",
        "",
        f"Snapshot content hash: `{BASELINE_HASH}`",
        "Source: immutable real `SSC_API` Golden Baseline",
        "Implementation state: Wave 1 (`HTTP_HEADERS`, `HTTP_REDIRECT`, `TLS_CERTIFICATE`) plus Wave 2 (`TLS_HANDSHAKE`, `EMAIL_SECURITY`)",
        "Total mapped issues: **202**",
        "",
        "> This is an independent implementation mapped to SSC taxonomy. It does not reproduce or claim knowledge of SSC collection, aggregation, severity, scoring, or proprietary detection logic. `ssc_severity` remains source metadata and is not mapped to internal risk or score impact.",
        "",
        "## Support gate",
        "",
        "`SUPPORTED` requires collected sufficient evidence, an active deterministic evaluator, an immutable link to the exact `SSC_API` issue version, positive and negative tests, and false-positive boundary tests. Acquisition or parsing failure is `INDETERMINATE`, not a non-finding.",
        "",
        "## Coverage summary",
        "",
        "| Coverage | Before Wave 2 | After Wave 2 | Percentage after |",
        "|---|---:|---:|---:|",
        f"| `SUPPORTED` | 14 | {coverage['SUPPORTED']} | {coverage['SUPPORTED']/202:.1%} |",
        f"| `PARTIAL` | 105 | {coverage['PARTIAL']} | {coverage['PARTIAL']/202:.1%} |",
        f"| `NOT_SUPPORTED` | 83 | {coverage['NOT_SUPPORTED']} | {coverage['NOT_SUPPORTED']/202:.1%} |",
        "| **Total** | **202** | **202** | **100.0%** |",
        "",
        "### Feasibility (unchanged)",
        "",
        "| Category | Count | Percentage |",
        "|---|---:|---:|",
    ]
    for category in ("DIRECTLY_TESTABLE", "TESTABLE_WITH_ENRICHMENT", "EXTERNAL_DATA_REQUIRED", "NOT_REPRODUCIBLE"):
        lines.append(f"| `{category}` | {feasibility[category]} | {feasibility[category]/202:.1%} |")
    lines += [
        "",
        "### Coverage by SSC factor",
        "",
        "| Factor | Total | Direct | Enrichment | External | Not reproducible | Supported | Partial | Not supported |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name in sorted(factors):
        value = factors[name]
        lines.append(
            f"| `{name}` | {value['total']} | {value['DIRECTLY_TESTABLE']} | {value['TESTABLE_WITH_ENRICHMENT']} | "
            f"{value['EXTERNAL_DATA_REQUIRED']} | {value['NOT_REPRODUCIBLE']} | {value['SUPPORTED']} | "
            f"{value['PARTIAL']} | {value['NOT_SUPPORTED']} |"
        )

    lines += [
        "",
        "## Active Wave 1 evaluator mappings",
        "",
        "Every listed rule uses stable key `ssc.wave1.<issue-key>`, method schema `ssc-wave1-observation.v1`, policy `ssc-wave1-security-policy.v1`, source type `SSC_REFERENCE`, and a rule-version foreign key to the exact current issue definition from an attested real `SSC_API` snapshot.",
        "",
        "| SSC issue key | Primitive | Exact positive condition | Authoritative reference |",
        "|---|---|---|---|",
    ]
    for spec in wave1_rules:
        lines.append(f"| `{spec.issue_key}` | `{spec.primitive}` | {spec.logic} | {spec.reference} |")

    lines += [
        "",
        "## Attempted Wave 1 issues remaining `PARTIAL`",
        "",
        "| SSC issue key | Reason |",
        "|---|---|",
    ]
    for key, reason in wave1_partial.items():
        lines.append(f"| `{key}` | {reason} |")

    lines += [
        "",
        "## Active Wave 2 evaluator mappings",
        "",
        "Every listed rule uses stable key `ssc.wave2.<issue-key>`, method schema `ssc-wave2-observation.v1`, source type `SSC_REFERENCE`, and a rule-version foreign key to the exact current issue definition from an attested real `SSC_API` snapshot. TLS and email policy versions are retained independently in the rule evidence schema.",
        "",
        "| SSC issue key | Primitive | Exact positive condition | Authoritative reference |",
        "|---|---|---|---|",
    ]
    for spec in wave2_rules:
        lines.append(f"| `{spec.issue_key}` | `{spec.primitive}` | {spec.logic} | {spec.reference} |")

    lines += [
        "",
        "## Attempted Wave 2 issues remaining `PARTIAL`",
        "",
        "| SSC issue key | Reason |",
        "|---|---|",
    ]
    for key, reason in wave2_partial.items():
        lines.append(f"| `{key}` | {reason} |")

    lines += [
        "",
        "## Per-issue index",
        "",
        "The CSV remains normative for exact evidence requirements, proposed logic, dependencies, references, and notes.",
        "",
        "| SSC issue key | Title | Factor | SSC severity | Feasibility | Executor | Current support |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        title = row["title"].replace("|", "\\|")
        lines.append(
            f"| `{row['ssc_issue_key']}` | {title} | `{row['factor']}` | `{row['ssc_severity']}` | "
            f"`{row['feasibility_category']}` | `{row['required_executor']}` | `{row['current_platform_support']}` |"
        )
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
