# CLI-first Roadmap

The primary product interface is the `ssc` CLI. The completed Phase 0–4 core, existing API, React frontend and scanner worker are preserved. Web administration remains optional. Dashboard-centric work is paused.

## Implementation order

| Phase | Scope | Direction |
| --- | --- | --- |
| 0–4 | Foundation, versioned catalog/importer, inventory, rules, scan jobs and findings | Completed work preserved; historical validation remains recorded |
| 1B acquisition extension | Preferred real SSC Golden Baseline from API metadata; manual JSON fallback retained | Read-only acquisition, review, provenance and versioning; no runtime SSC dependency |
| 4B | Real authorized HTTP/TLS/DNS/TCP execution and normalized evidence | Complete and validate before scoring |
| 5 | Internal versioned scoring with factor scores, overall score and traceable impacts | Complete and validate before CLI output |
| 6A | CLI orchestration and setup independent of Web/API | `ssc scan --target <target> --output report` |
| 6B | REPORT adapter | Self-contained HTML and machine-readable JSON using `ssc.result.v1` |
| 6C | SYGNOS adapter | Structured logs/events using exactly `ssc.result.v1`; ingestion mapping and transport deferred until interface is known |
| 6D | Optional Web dashboard | Paused; no dashboard work before 4B, 5, 6A and 6B pass |
| 7 | SSC public reference sync | Review/approval workflow; never automatic production catalog overwrite |
| 8 | Broader optional SSC API integration | Initial metadata acquisition is brought forward into Phase 1B; other integrations remain deferred |
| 9 | SSC comparison/calibration | Clearly distinguish internal scoring from proprietary SSC scoring |
| 10 | Production hardening | Authentication/authorization, scheduling, operational limits, immutable storage enforcement and deployment validation |

The old dashboard-first Phase 6 is superseded by 6A–6D. Phases 7–10 remain incomplete; they do not supersede the current scanner/scoring/CLI/REPORT priorities.

## Layer boundaries

Authorized target → HTTP/TLS/DNS/TCP executors → evidence → rule evaluation → findings → scoring → output adapter.

Scanner code must not render reports or calculate scores. The scoring engine must not probe networks or require a browser. Output adapters must consume the same saved normalized result and must not recompute scores or findings.

REPORT is implemented first. `--output sygnos` currently fails before database or network activity. Its future event format must contain or reference the shared normalized result rather than define a parallel scoring/result model. No Sygnos transport is implemented.

## Next work

A real SSC taxonomy baseline is required once before claiming `SSC_ALIGNED`. Preferred initial SSC baseline: SSC API metadata endpoints. Fallback: licensed UI/manual canonical JSON. Future taxonomy updates: SSC API and/or reviewed public SSC methodology changes. Runtime: no SSC dependency. Without a real baseline, status is `INTERNAL_ONLY` and scanner/rules/scoring/report remain functional.

The Phase 1B acquisition extension does not start Phase 7 public sync, company-score comparison, calibration, Sygnos transport, dashboard work or new scanner checks. Live read-only detail discovery is complete; the production baseline remains deliberately unimported. Optional bounded detail enrichment does not change the two-list-endpoint minimum baseline or alignment requirement. Starter detectors and synthetic fixtures cannot establish SSC alignment.
