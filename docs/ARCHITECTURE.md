# Architecture

The primary interface is CLI-first. The platform remains a modular monolith with a separate optional scanner worker. Completed Phase 0–4 functionality and the existing FastAPI/React interfaces are preserved. Dashboard-centric development is paused.

```text
ssc scan --target <approved-inventory-target> --output report
  -> Authorized Target
  -> HTTP / TLS / DNS / TCP Executors
  -> Evidence
  -> Rule Engine
  -> Findings
  -> Scoring Engine
  -> NormalizedResult (ssc.result.v1)
  -> Output Adapter
       REPORT: report.html + result.json
       SYGNOS: future structured log/event mapping; transport deferred
```

SecurityScorecard is a benchmark, public taxonomy/reference, optional comparison source and optional integration. It is not a runtime dependency. The internal scoring model is explicitly documented and does not represent proprietary SSC algorithms.

## Initial taxonomy acquisition

Preferred initial SSC baseline: SSC API metadata endpoints (`GET /metadata/factors` and `GET /metadata/issue-types`) → raw immutable `CatalogSnapshot` provenance → normalization → existing versioned Internal Catalog → Golden Baseline. Fallback: licensed UI/manual canonical JSON through the preserved Phase 1B importer. Future taxonomy updates: SSC API and/or reviewed public SSC methodology changes; no automatic production overwrite. Runtime: no SSC dependency.

`ssc baseline pull-ssc` explicitly acquires and previews metadata, then imports only after approval. Its minimum baseline uses only the two list endpoints. `--enrich-details` optionally adds bounded per-issue detail requests; it is not required for import or taxonomy alignment, and an individual detail failure leaves the list-based issue definition available. `SSC_TOKEN` comes only from the process environment. Acquisition is outside scanner/rules/scoring/report execution. `ssc baseline status` reads persisted provenance: `INTERNAL_ONLY` until a real baseline has been imported, then `SSC_ALIGNED`. A real taxonomy baseline is required once before making an SSC alignment claim; synthetic/internal catalogs do not qualify. Both states support the existing runtime normally without SSC credentials.

Migration `0008_ssc_api_baseline` preserves raw endpoint responses, hashes, capture times, normalizer version and complete factor/issue membership on snapshots. It adds separate raw SSC issue metadata/severity to immutable issue versions. Successful detail enrichment stores the exact response in versioned `ssc_metadata`, and also exposes `short_description` through the existing issue-version description. Factor history lives in snapshot payloads; shared factor metadata is not overwritten. PostgreSQL protects API snapshot rows against update/delete and enforces unique API content hashes. SSC severity is not reinterpreted as internal risk, breach risk, threat level, score impact or scoring relevance; API versions retain `breach_risk=UNKNOWN` and `threat_level=null`. See `GOLDEN_BASELINE_IMPORTER.md` for mapping and operator attestation.

## Primary runtime

The CLI calls services directly, using PostgreSQL for inventory, immutable catalog/rule versions, jobs, observations, findings and score snapshots. Running FastAPI, React or Redis is unnecessary for a CLI scan. An optional Docker Compose `cli` profile provides the console command and mounts `/reports` for output. The existing default Web/API services remain available for compatibility; start only `postgres` when using the CLI.

## Separate layers

| Layer | Implementation | Responsibilities |
| --- | --- | --- |
| CLI | `app.cli.ssc` | Parse options, load configuration, invoke services and select adapter; no rule evaluation or scoring logic |
| Authorization/inventory | `app.services.scan_executors.load_authorized_scan_target`, `app.services.cli_setup` | Resolve a unique registered domain/host; require its approval and active parent inventory; support explicit sensitive network approval |
| Executors | `app.services.scan_executors` | Bounded port lists, request/read limits, socket timeouts and same-target/configured-port redirects; collect observations with source and status |
| Evidence | `ScanObservation`, `EvidenceSourceEnum` | Preserve manual or scanner observations separately from findings; distinguish success, error and skipped collection |
| Rule evaluation | `app.services.rule_evaluation` | Existing deterministic JSON evaluator, extracted without replacing its supported expressions; no database/network/output dependency |
| Scan orchestration | `app.services.scan_engine`, `app.services.cli_scan` | Reuse existing scan jobs/runs; collect evidence, evaluate selected rules and create version-linked findings; save rule assessment and target snapshots |
| Findings | `ScanFinding`, `app.services.finding_results` | Normalize exact historical rule/catalog versions, remediation, factor identity, target and matched evidence |
| Scoring | `app.services.scoring_engine`, `app.services.score_results` | Pure internal scoring, model definition/version/hash, observed impacts and append-only saved normalized results |
| Output | `app.outputs.report` | Render the saved `NormalizedResult` to escaped self-contained HTML and JSON; never probe or score |

Executors pin connections to a checked IP while retaining the inventory hostname for HTTP Host and TLS SNI. Mixed sensitive/public resolution requires sensitive-network permission. Metadata, link-local, multicast and unspecified addresses are prohibited even with that permission. Only concrete inventory targets can execute scanners; organizations alone cannot.

HTTP probes use configured HTTP/HTTPS ports, bounded response reads, redacted cookie attributes and constrained redirects. TLS records certificate metadata and trust verification, probes configured TLS ports and observes legacy protocol support. Unsupported or inconclusive probes are `null`, not evidence of safety. DNS uses dnspython with resolver lifetimes and system resolvers by default; an explicit resolver can be configured. DNS-only targets do not need A/AAAA records. TCP performs connections only to explicit ports, with no automatic range scan. OS hostname resolution and aggregate scan duration are not a global deadline; further scheduling/concurrency/operational controls belong to hardening.

Collection errors do not become absent security headers or absent SPF/DMARC findings. Rules using unavailable evidence are skipped; endpoint-availability rules can still observe a failed connection. Coverage travels with the result. Missing/skipped rules, unlinked catalog definitions, unknown risk and failed evidence prevent an assessed overall score.

## Historical versioning and normalized results

Catalog changes create `catalog_issue_type_versions`; rule changes create `rule_engine_rule_versions`. Findings reference exact versions. Each new scan summary captures rule assessment statuses, factor identity and affected target identity, so current metadata changes cannot alter normalization of a completed run.

`ssc.result.v1` includes targets, evidence summaries, findings and remediation, coverage, factor scores, overall score, factor/overall impacts, scoring model name/version/hash and its full definition. Migration `0007_phase5_score_results` stores a unique snapshot for each run/model hash. Repeated generation returns that stored result; a changed model creates another snapshot. Older Phase 4 runs remain readable and may yield an unassessed normalized result because they lack new coverage metadata; they are not silently upgraded into fully assessed scans.

REPORT renders this contract to `report.html` and `result.json` in a fresh output directory. Future SYGNOS events must reuse exactly this contract. Sygnos ingestion mapping, credentials, endpoints, batching and transport are unknown and remain unimplemented.

## Preserved optional interfaces

React/Vite → FastAPI → PostgreSQL/Redis remains available. Existing API prefixes are `/api/v1/catalog`, `/api/v1/inventory`, `/api/v1/rules` and `/api/v1/scans`. Existing administration, catalog history/import, inventory, rules, scans and worker behavior are retained. These interfaces consume the core layers; their dashboard requirements do not drive the scanner/scoring/result architecture.

Phase 0 foundation, Phase 1A catalog, Phase 1B Golden Baseline importer, Phase 1C catalog administration, Phase 2 inventory, Phase 3 rule definitions and Phase 4 supplied-evidence scanning remain completed historical milestones. Phase 4B adds actual network execution; Phase 5 adds scoring; Phases 6A/6B add the primary CLI and REPORT adapter. See `ROADMAP.md` and `IMPLEMENTATION_STATUS.md` for status and validation.
