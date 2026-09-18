# CLI-first Roadmap

The primary product interface is the `ssc` CLI. The completed Phase 0–4 core, existing API, React frontend and scanner worker are preserved. Web administration remains optional. Dashboard-centric work is paused.

## Implementation order

| Phase | Scope | Direction |
| --- | --- | --- |
| 0–4 | Foundation, versioned catalog/importer, inventory, rules, scan jobs and findings | Completed work preserved; historical validation remains recorded |
| 4B | Real authorized HTTP/TLS/DNS/TCP execution and normalized evidence | Complete and validate before scoring |
| 5 | Internal versioned scoring with factor scores, overall score and traceable impacts | Complete and validate before CLI output |
| 6A | CLI orchestration and setup independent of Web/API | `ssc scan --target <target> --output report` |
| 6B | REPORT adapter | Self-contained HTML and machine-readable JSON using `ssc.result.v1` |
| 6C | SYGNOS adapter | Structured logs/events using exactly `ssc.result.v1`; ingestion mapping and transport deferred until interface is known |
| 6D | Optional Web dashboard | Paused; no dashboard work before 4B, 5, 6A and 6B pass |
| 7 | SSC public reference sync | Review/approval workflow; never automatic production catalog overwrite |
| 8 | Optional SSC API integration | No dependency on SSC credentials for normal operation |
| 9 | SSC comparison/calibration | Clearly distinguish internal scoring from proprietary SSC scoring |
| 10 | Production hardening | Authentication/authorization, scheduling, operational limits, immutable storage enforcement and deployment validation |

The old dashboard-first Phase 6 is superseded by 6A–6D. Phases 7–10 remain incomplete; they do not supersede the current scanner/scoring/CLI/REPORT priorities.

## Layer boundaries

Authorized target → HTTP/TLS/DNS/TCP executors → evidence → rule evaluation → findings → scoring → output adapter.

Scanner code must not render reports or calculate scores. The scoring engine must not probe networks or require a browser. Output adapters must consume the same saved normalized result and must not recompute scores or findings.

REPORT is implemented first. `--output sygnos` currently fails before database or network activity. Its future event format must contain or reference the shared normalized result rather than define a parallel scoring/result model. No Sygnos transport is implemented.

## Next work

Finalize Sygnos ingestion requirements when available. Until then, focus on broader detector coverage and CLI operating experience; keep the dashboard paused. The starter detectors are internal examples and do not constitute the real licensed SSC Golden Baseline, which still awaits source data.
