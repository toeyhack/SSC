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
V1_FACTORS = {"application_security", "network_security", "dns_health", "patching_cadence"}


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
    from app.services.wave3a_rules import WAVE3A_BY_KEY, WAVE3A_RULES
    from app.services.wave3b_rules import WAVE3B_BY_KEY, WAVE3B_RULES
    from app.services.wave4a_rules import WAVE4A_BY_KEY, WAVE4A_RULES
    from app.services.wave4b_rules import WAVE4B_BY_KEY, WAVE4B_RULES
    from app.services.wave5a_rules import WAVE5A_BY_KEY, WAVE5A_RULES
    from app.services.wave5b_rules import (
        WAVE5B_ACTIVE_BY_KEY,
        WAVE5B_ACTIVE_RULES,
        WAVE5B_PARTIAL_REASONS,
        WAVE5B_PENDING_RULES,
    )

    all_by_key = {
        **WAVE1_BY_KEY, **WAVE2_BY_KEY, **WAVE3A_BY_KEY,
        **WAVE3B_BY_KEY, **WAVE4A_BY_KEY, **WAVE4B_BY_KEY, **WAVE5A_BY_KEY, **WAVE5B_ACTIVE_BY_KEY,
    }
    all_partial_reasons = {
        **WAVE1_PARTIAL_REASONS,
        **WAVE2_PARTIAL_REASONS,
        **WAVE5B_PARTIAL_REASONS,
    }

    mappings = []
    if args.verify_database:
        from app.db.session import SessionLocal
        from app.services.wave1_rules import active_wave1_mappings
        from app.services.wave2_rules import active_wave2_mappings
        from app.services.wave3a_rules import active_wave3a_mappings
        from app.services.wave3b_rules import active_wave3b_mappings
        from app.services.wave4a_rules import active_wave4a_mappings
        from app.services.wave4b_rules import active_wave4b_mappings
        from app.services.wave5a_rules import active_wave5a_mappings
        from app.services.wave5b_rules import active_wave5b_mappings
        with SessionLocal() as db:
            mappings = (
                active_wave1_mappings(db) + active_wave2_mappings(db)
                + active_wave3a_mappings(db) + active_wave3b_mappings(db)
                + active_wave4a_mappings(db) + active_wave4b_mappings(db)
                + active_wave5a_mappings(db)
                + active_wave5b_mappings(db)
            )
        active_keys = {item["issue_key"] for item in mappings}
        expected = set(all_by_key)
        if active_keys != expected:
            missing = sorted(expected - active_keys)
            extra = sorted(active_keys - expected)
            raise SystemExit(f"active Wave 1/2/3A/3B/4A/4B/5A/5B.1 mappings differ: missing={missing} extra={extra}")
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
            wave = (
                "Wave 1" if row["ssc_issue_key"] in WAVE1_BY_KEY else
                "Wave 2" if row["ssc_issue_key"] in WAVE2_BY_KEY else
                "Wave 3A" if row["ssc_issue_key"] in WAVE3A_BY_KEY else
                "Wave 3B" if row["ssc_issue_key"] in WAVE3B_BY_KEY else
                "Wave 4A" if row["ssc_issue_key"] in WAVE4A_BY_KEY else
                "Wave 4B" if row["ssc_issue_key"] in WAVE4B_BY_KEY else
                "Wave 5A" if row["ssc_issue_key"] in WAVE5A_BY_KEY else
                "Wave 5B.1"
            )
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
    v1_coverage = Counter(
        row["current_platform_support"] for row in rows if row["factor"] in V1_FACTORS
    )
    feasibility = Counter(row["feasibility_category"] for row in rows)
    if coverage != {"SUPPORTED": 43, "PARTIAL": 84, "NOT_SUPPORTED": 75}:
        raise SystemExit(f"unexpected coverage totals: {dict(coverage)}")
    if v1_coverage != {"SUPPORTED": 42, "PARTIAL": 82, "NOT_SUPPORTED": 36}:
        raise SystemExit(f"unexpected V1 coverage totals: {dict(v1_coverage)}")

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
                WAVE3A_RULES,
                WAVE3B_RULES,
                WAVE4A_RULES,
                WAVE4B_RULES,
                WAVE5A_RULES,
                WAVE5B_ACTIVE_RULES,
                WAVE5B_PENDING_RULES,
            ),
            encoding="utf-8",
        )

    print(
        f"V1 SUPPORTED={v1_coverage['SUPPORTED']} PARTIAL={v1_coverage['PARTIAL']} "
        f"NOT_SUPPORTED={v1_coverage['NOT_SUPPORTED']} TOTAL={sum(v1_coverage.values())}"
    )
    print(
        f"FULL SUPPORTED={coverage['SUPPORTED']} PARTIAL={coverage['PARTIAL']} "
        f"NOT_SUPPORTED={coverage['NOT_SUPPORTED']} TOTAL={sum(coverage.values())}"
    )
    for mapping in mappings:
        print(
            f"{mapping['issue_key']} issue-v{mapping['issue_version_number']}={mapping['issue_version_id']} "
            f"rule-v{mapping['rule_version_number']}={mapping['rule_version_id']}"
        )
    return 0


def render_markdown(rows, feasibility, coverage, wave1_rules, wave1_partial, wave2_rules, wave2_partial, wave3a_rules, wave3b_rules, wave4a_rules, wave4b_rules, wave5a_rules, wave5b_active_rules, wave5b_pending_rules) -> str:
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
        "Implementation state: Waves 1-2, Wave 3A first-batch `SERVICE_PROTOCOL_IDENTIFICATION`, Wave 3B `HTTP_CONTENT`, Wave 4A `SSH_NEGOTIATION`, Wave 4B bounded SPF permanent-error analysis, Wave 5A staged plaintext FTP/IMAP/POP3/SMTP identification, and Wave 5B.1 closed LDAP identification; Oracle Net is implemented pending real interoperability and remains inactive/PARTIAL",
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
        "| Coverage | Before Wave 5B.1 | After Wave 5B.1 | Percentage after |",
        "|---|---:|---:|---:|",
        f"| `SUPPORTED` | 42 | {coverage['SUPPORTED']} | {coverage['SUPPORTED']/202:.1%} |",
        f"| `PARTIAL` | 85 | {coverage['PARTIAL']} | {coverage['PARTIAL']/202:.1%} |",
        f"| `NOT_SUPPORTED` | 75 | {coverage['NOT_SUPPORTED']} | {coverage['NOT_SUPPORTED']/202:.1%} |",
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
        "## Active Wave 3A evaluator mappings",
        "",
        "Every listed rule uses stable key `ssc.wave3a.<issue-key>`, method schema `ssc-wave3a-service-observation.v1`, policy `ssc-wave3a-service-identification.v1`, source type `SSC_REFERENCE`, and an immutable rule-version link to the exact attested `SSC_API` issue version. This is the first six-protocol batch, not the full service-identification ceiling.",
        "",
        "| SSC issue key | Protocol | Primitive | Exact MATCH condition | Exact NO_MATCH boundary | INDETERMINATE boundary | Authoritative reference |",
        "|---|---|---|---|---|---|---|",
    ]
    for spec in wave3a_rules:
        lines.append(
            f"| `{spec.issue_key}` | `{spec.protocol}` | `{spec.primitive}` | {spec.match_condition} | "
            f"{spec.no_match_boundary} | {spec.indeterminate_boundary} | {spec.reference} |"
        )

    lines += [
        "",
        "## Active Wave 3B evaluator mappings",
        "",
        "Every listed rule uses stable key `ssc.wave3b.<issue-key>`, method schema `ssc-http-content-observation.v1`, policy `ssc-http-content-policy.v1`, source type `SSC_REFERENCE`, and an immutable link to the exact attested `SSC_API` issue version. Bodies and clear contact values are not persisted.",
        "",
        "| SSC issue key | Primitive | MATCH condition | NO_MATCH boundary | INDETERMINATE boundary | Authoritative reference |",
        "|---|---|---|---|---|---|",
    ]
    for spec in wave3b_rules:
        lines.append(
            f"| `{spec.issue_key}` | `{spec.primitive}` | {spec.match_condition} | "
            f"{spec.no_match_boundary} | {spec.indeterminate_boundary} | {spec.reference} |"
        )

    lines += [
        "",
        "## Active Wave 4A evaluator mappings",
        "",
        "Every listed rule uses stable key `ssc.wave4a.<issue-key>`, method schema `ssc-wave4a-ssh-observation.v1`, policy `ssc-wave4a-ssh-crypto-policy.v1`, source type `SSC_REFERENCE`, and an immutable link to the exact attested `SSC_API` issue version. The bounded collector stops after server KEXINIT and never authenticates or sends application commands.",
        "",
        "| SSC issue key | Primitive | MATCH condition | NO_MATCH boundary | INDETERMINATE boundary | Authoritative reference |",
        "|---|---|---|---|---|---|",
    ]
    for spec in wave4a_rules:
        lines.append(
            f"| `{spec.issue_key}` | `{spec.primitive}` | {spec.match_condition} | "
            f"{spec.no_match_boundary} | {spec.indeterminate_boundary} | {spec.reference} |"
        )

    lines += [
        "",
        "## Active Wave 4B evaluator mappings",
        "",
        "The single Wave 4B rule uses stable key `ssc.wave4b.spf_record_malformed`, method schema `ssc-wave4b-spf-observation.v1`, policy `ssc-wave4b-spf-malformed-policy.v1`, source type `SSC_REFERENCE`, and an immutable link to the exact attested `SSC_API` issue version. It analyzes only deterministic RFC 7208 permanent errors and does not expose sender authorization results.",
        "",
        "| SSC issue key | Primitive | Exact logic | Authoritative reference |",
        "|---|---|---|---|",
    ]
    for spec in wave4b_rules:
        lines.append(f"| `{spec.issue_key}` | `{spec.primitive}` | {spec.logic} | {spec.reference} |")

    lines += [
        "",
        "## Active Wave 5A evaluator mappings",
        "",
        "Wave 5A uses method schema `ssc-wave5a-staged-text-service-observation.v1`, policy `ssc-wave5a-text-service-identification.v1`, source type `SSC_REFERENCE`, and immutable links to exact attested `SSC_API` issue versions. Each adapter performs one plaintext server greeting, one fixed non-authenticating command, and one bounded completion read on the same declared TCP endpoint. SMTP unusual-port evaluation additionally pins `smtp-standard-ports.v1` to 25, 465, and 587.",
        "",
        "| SSC issue key | Protocol | Primitive | Exact MATCH condition | Exact NO_MATCH boundary | INDETERMINATE boundary | Authoritative reference |",
        "|---|---|---|---|---|---|---|",
    ]
    for spec in wave5a_rules:
        lines.append(
            f"| `{spec.issue_key}` | `{spec.protocol}` | `{spec.primitive}` | {spec.match_condition} | "
            f"{spec.no_match_boundary} | {spec.indeterminate_boundary} | {spec.reference} |"
        )

    lines += [
        "",
        "## Active Wave 5B.1 evaluator mappings",
        "",
        "The approved Wave 5B.1 activation set contains only `service_ldap`. Its no-Bind RootDSE evaluator is linked to the exact attested issue version. Oracle Net remains implemented and tested but inactive/PARTIAL pending real interoperability. The adapters define no deterministic NO_MATCH, perform no authentication/session/query, and never follow Oracle redirects. The five product-ambiguous database keys remain PARTIAL.",
        "",
        "| SSC issue key | Protocol | Primitive | Exact MATCH condition | Exact NO_MATCH boundary | INDETERMINATE boundary | Authoritative reference |",
        "|---|---|---|---|---|---|---|",
    ]
    for spec in wave5b_active_rules:
        lines.append(
            f"| `{spec.issue_key}` | `{spec.protocol}` | `{spec.primitive}` | {spec.match_condition} | "
            f"{spec.no_match_boundary} | {spec.indeterminate_boundary} | {spec.reference} |"
        )

    lines += [
        "",
        "## Wave 5B.1 implemented pending interoperability",
        "",
        "These adapters and deterministic tests remain available, but they have no approved active evaluator and are not counted as `SUPPORTED`.",
        "",
        "| SSC issue key | Protocol | Current state | Closure blocker |",
        "|---|---|---|---|",
    ]
    for spec in wave5b_pending_rules:
        lines.append(
            f"| `{spec.issue_key}` | `{spec.protocol}` | `IMPLEMENTED_PENDING_INTEROP` / `PARTIAL` | "
            "Real protocol interoperability has not been validated. |"
        )

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
