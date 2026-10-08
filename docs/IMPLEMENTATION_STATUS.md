# Implementation Status

CLI-FIRST MVP — COMPLETE / PASS

Current phase: Phase 6B - CLI-first REPORT Output

Wave 5C bounded framed service identification: IMPLEMENTED / INACTIVE (2026-10-08). Exactly `minecraft_server`, `service_pptp`, and `service_rdp` now have protocol builders, incremental completion parsers, v3 acquisition wiring, executor target pinning, compact evidence, and an independently gated implementation registry. The repository has no authoritative contract proving both that a target is public-routable/Internet-facing and that an observation came from an approved external/public scan vantage. Protocol identity, inventory approval, connectivity, DNS, port number, and loopback interoperability do not prove those facts. Therefore all three stable `ssc.wave5c.*` keys remain inactive and `PARTIAL` with `IMPLEMENTED_PENDING_EXPOSURE_CONTEXT`; reconciliation deactivates any stale managed Wave 5C rule and creates no active mapping. No public-exposure field or schema migration was invented.

Minecraft sends only one endpoint-aware Java status handshake (`protocol=-1`, declared hostname/port, status state) followed by one status request and accepts only a complete bounded packet-ID-zero JSON response with a valid version object. PPTP sends one fixed 156-byte SCCRQ and accepts structurally valid 156-byte SCCRP success or protocol-specific rejection results, then stops before calls, GRE, PPP, or authentication. RDP sends the fixed 19-byte TPKT/X.224/RDP negotiation request and accepts only a Connection Confirm containing a legal negotiation response or failure; a bare X.224 confirm is indeterminate, and the client never continues into TLS, NLA, CredSSP, MCS, authentication, or a session. Wave 5C v1 defines no deterministic `NO_MATCH`. All three reuse `service-probe-adapter.v3`, one monotonic connect/write/read deadline, the six-probe cap, 4096-byte response cap, and 1024-byte outbound cap.

Real loopback interoperability succeeded against a vanilla Java Edition server without login and against xrdp through negotiation only; xrdp logged EOF before its TLS handshake. An additional Cuberite build reset the `protocol=-1` discovery request and remains an honest compatible-implementation limitation, not a false match. A real PPTP fixture was not run because available implementations require unavailable/unsafe privileged PPP/PPTP kernel setup; synthetic SCCRP tests do not close interoperability, so `service_pptp` additionally remains `IMPLEMENTED_PENDING_INTEROP`. No external or corporate target was scanned. Supported/CLOSED accounting therefore remains **39/53 VERIFIED_DIRECT**, V1 **42/160**, and full baseline **43/202**. With all three Wave 5C primitives plus pending Oracle, the implementation ceiling is **43/53**, **46/160**, and **47/202**; Oracle remains inactive `IMPLEMENTED_PENDING_INTEROP` and is not counted as CLOSED.

Validation used fresh isolated PostgreSQL databases `ssc_wave5c_20261008_focus` and `ssc_wave5c_20261008_full`, never `ssc_e2e`. The focused Wave 5C matrix passed **464 tests**. Exactly one complete backend-suite run passed **1,108 tests** with the two existing dependency deprecation warnings. Dependency checking and bytecode compilation passed, coverage regenerated at V1 **42 SUPPORTED / 82 PARTIAL / 36 NOT_SUPPORTED** and full **43 / 84 / 75**, and Alembic reported no new upgrade operations when run against the current source. No migration was added.

Wave 5B.1 identity-safe database service identification: LDAP CLOSED / ORACLE IMPLEMENTED_PENDING_INTEROP (2026-10-08). Exactly `service_ldap` and `service_oracle_db` are implemented in `ssc.wave5b.*`, but the approved active set contains only `service_ldap`. `service_oracle_db` remains implemented, deterministically fixture-tested, and available for future activation after real Oracle interoperability; it is inactive and `PARTIAL`. `service_cassandra`, `service_microsoft_sql`, `service_mongodb`, `service_mysql`, and `service_postgresql` remain partial pending product-identity semantics. `service-probe-adapter.v3` is attached only to the two implemented database adapters. Wave 3A and Wave 5A attempts remain `service-probe-adapter.v2`. The six-probe, 4096-byte response, and 1024-byte outbound limits are unchanged.

LDAP sends exactly one message-ID-1 RootDSE base-object SearchRequest with no Bind, validates bounded definite-length BER and a legal correlated sequence ending in SearchResultDone, and discards all DNs, entries, attributes, referrals, controls, diagnostics, and server values. Oracle builds one inline TNS CONNECT descriptor from only the canonical pinned numeric IP, validated port, and fixed `SSC_PROBE_DO_NOT_CREATE_V1` service identifier. It matches only a structurally valid ACCEPT, REFUSE, or REDIRECT, never follows REDIRECT, and never authenticates or continues into a database session. Neither adapter defines deterministic NO_MATCH. Evidence is limited to versions, request model, byte counts/hash, response class, correlation/completion state, declared size, bounded structural counts, timing, and stop/error state.

The activation reconciler now activates only `service_ldap` and deactivates any previously active managed Oracle rule. Assessment-profile and generated coverage accounting use the approved active subset rather than the implementation registry. Closed support is **39/53 VERIFIED_DIRECT**, V1 **42/160**, and full baseline **43/202**; the implementation ceiling remains **40/53**, **43/160**, and **44/202** respectively. Both keys remain absent from internal-risk calibration and fail closed to `UNKNOWN`/`affects_score=false` when evaluated.

Real OpenLDAP 2.4.57 loopback interoperability completed the exact no-Bind RootDSE request through SearchResultDone, `MATCH`, rule evaluation, finding, and report with byte-identical pre/post directory state. The remediation full suite passed **645 tests** against isolated database `ssc_wave5b1_20261008_remediation_full`. Oracle Database Free was not started because available memory made multi-gigabyte infrastructure impractical; synthetic TNS fixtures remain parser/wiring evidence only and real Oracle interoperability is still required before activation. No external or corporate endpoint was scanned.

Wave 5A staged plaintext service identification: COMPLETE / PASS (2026-10-06). Exactly `service_ftp`, `service_imap`, `service_pop3`, and `mail_server_unusual_port` are implemented in the distinct `ssc.wave5a.*` tranche; historical Wave 3A membership remains six rules. `service-probe-adapter.v2` adds one reusable two-stage TCP path on a single explicitly declared endpoint: read and validate a server greeting, optionally send one fixed command, read and validate one completion response, then stop. The connect, reads, and write share one monotonic deadline. The unchanged caps are six declared probes and 4096 total response bytes; Wave 5A additionally enforces 1024 outbound bytes, 512 bytes per complete or partial line including terminators, 64 total parsed lines, and two stages. Per-stage evidence retains only direction, byte counts, SHA-256, normalized class/count/hash markers, completion reason, versions, and stop/error state. Raw greetings, host banners, capability/extension text, usernames, credentials, mail data, and transcripts are not persisted.

FTP requires a complete RFC-style 220 reply, exact `NOOP`, and complete 200 reply with same-code multiline termination. IMAP requires a legal OK/PREAUTH greeting, exact tagged `A001 CAPABILITY`, one valid untagged CAPABILITY response, and matching `A001 OK`. POP3 requires a complete `+OK` greeting, exact `CAPA`, syntactically bounded capability lines, and exact dot termination. SMTP requires a legal 220 greeting, exact `EHLO scanner.invalid`, and complete 250 response before `smtp-standard-ports.v1` applies its immutable TCP set `{25,465,587}`: verified SMTP outside the set is `MATCH`, while verified SMTP inside is the issue-specific `NO_MATCH`. A greeting alone, wrong or arbitrary bytes, malformed/truncated framing, connection refusal, timeout, reset, peer close, write/read failure, or byte/line budget exhaustion remains `INDETERMINATE`. FTP and SMTP 220 greetings are never treated as phase-blind foreign negatives. Wave 5A is plaintext-only and neither infers TLS from a port nor attempts STARTTLS or implicit TLS; encrypted-only endpoints remain indeterminate.

The approved-baseline importer and `ssc baseline activate-wave5a --yes` reconcile only current issue versions from an attested real `SSC_API` snapshot. Exact isolated reconciliation in `ssc_wave5a_20261006_activation2` reproduced baseline hash `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`, found active mapping counts `14+7+6+7+3+1+4=42`, activated all four Wave 5A keys with zero unavailable definitions, and then idempotently reused all four rules and versions. The supported-capability profile resolves V1 **41/160** (16 Application Security, 18 Network Security, 7 DNS Health, 0 Patching Cadence) and full baseline **42/202** because `mail_server_unusual_port` remains in out-of-scope `ip_reputation`; the dashboard direct audit moves **34/53 → 38/53 VERIFIED_DIRECT**. At the scanner milestone all four keys intentionally lacked explicit internal calibration and failed closed to `UNKNOWN`/`affects_score=false`; they were subsequently approved as explicit UNKNOWN/non-scoring decisions in internal-risk calibration v1.4 without changing scanner behavior or coverage. No schema or migration was added; Alembic reports no new upgrade operations and `0010_v1_assessment` remains head.

Validation used isolated databases `ssc_wave5a_20261006_focus`, `ssc_wave5a_20261006_activation2`, and `ssc_wave5a_20261006_full`, never `ssc_e2e`, and contacted no external or corporate service. The broader focused integration gate passed **180 tests**; after tightening the line cap to include CRLF, the final service-probe/Wave 3A compatibility gate passed **51 tests**. The one and only complete backend-suite execution passed **331 tests** with the two existing dependency deprecation warnings and the read-only pytest-cache warning. Database-backed coverage verification passed at V1 **41 SUPPORTED / 83 PARTIAL / 36 NOT_SUPPORTED / 160** and full **42 / 85 / 75 / 202**. Later real E2E remains a post-review activity restricted to loopback-only controlled fixtures: a no-credential FTP daemon/pyftpdlib-style fixture and GreenMail-style SMTP/IMAP/POP3 fixture, with a second implementation used to cross-check parser interoperability where practical. No mailbox, message, or file content is needed for identification, and fixture ports must not bind beyond loopback.

Wave 5A internal risk calibration v1.4: COMPLETE / PASS (2026-10-06). The versioned `ssc-supported-internal-risk` registry contains 42 explicit mappings while preserving all 38 v1.3 decisions unchanged. `service_ftp`, `service_imap`, `service_pop3`, and `mail_server_unusual_port` are explicit reviewed UNKNOWN/non-scoring decisions; qualifying MATCH findings remain visible with zero impact. Deterministic service identity supports inventory, attack-surface visibility, and follow-up assessment but does not prove weak authentication, unsafe transport, unauthorized access, public exposure, open relay, vulnerable software, exploitation, or compromise. The scoring formula, global penalties, assessment profile, result schema, scanner collection, service parsers, Wave 5A evaluator semantics, activation, taxonomy, schema, migrations, and capability coverage are unchanged. Validation used new isolated databases `ssc_wave5a_calibration_v14_focus` and `ssc_wave5a_calibration_v14_full`, never `ssc_e2e`: the final focused calibration/Wave 5A gate passed **58 tests**, followed by exactly one complete backend suite with **342 tests passed** and the two existing dependency deprecation warnings. Alembic reported no new upgrade operations. Coverage remains **38/53 VERIFIED_DIRECT**, V1 **41/160 SUPPORTED**, and full baseline **42/202 SUPPORTED**.

Wave 4B bounded SPF permanent-error analysis: COMPLETE / PASS (2026-10-05). Exactly `spf_record_malformed` is implemented in the distinct `ssc.wave4b.spf_record_malformed` tranche; historical Wave 2 membership remains seven rules. The dedicated `ssc-wave4b-spf-parser.v1` service strictly selects case-insensitive `v=spf1` followed only by ASCII space or end-of-record, validates the complete selected policy before evaluation, and performs bounded path-sensitive include/redirect/A/AAAA/MX/exists analysis solely to decide deterministic RFC 7208 permanent error. It does not expose sender authorization results, invent sender/IP/HELO identity, or evaluate PTR without real client-IP context. Missing policy is independently `NO_MATCH` here and remains `MATCH` for the existing `spf_record_missing` rule. Mixed branches, runtime-context dependencies, DNS uncertainty, undefined expansion behavior, unsupported states, and operational exhaustion remain `INDETERMINATE`.

The pinned `ssc-wave4b-spf-malformed-policy.v1` applies RFC permanent-error limits of 10 reached DNS-causing terms, 2 void lookups, and 10 MX exchange hosts per applicable path. Separate scanner limits are 256 logical DNS queries, 20 seconds total, 16 KiB per DNS response representation, 8 KiB per selected SPF record, 64 abstract states, 512 evaluator steps, and 256 compact trace entries; operational limits never become findings. The approved-baseline importer and `ssc baseline activate-wave4b --yes` reconcile only an exact current version from an attested real `SSC_API` snapshot. No schema change or migration was added; `0010_v1_assessment` remains head. At the scanner milestone the key was intentionally absent from internal-risk calibration v1.2 and failed closed to `UNKNOWN`/`affects_score=false`; it was subsequently approved in internal-risk calibration v1.3 below without changing scanner behavior or coverage.

Wave 4B validation used isolated databases `ssc_wave4b_20261005_final` and `ssc_wave4b_20261005_full`, never `ssc_e2e`. The final focused Wave 4B/Wave 2/DMARC/activation/completeness gate passed **119 tests**. The one complete backend-suite execution produced **304 passed / 2 failed** because the temporary virtual environment had dependencies but lacked the project-installed `ssc` console script; after installing the unchanged local package, exactly those two CLI tests passed. No implementation assertion failed, and the complete suite was not rerun in order to preserve the exactly-once constraint. Alembic reported no new upgrade operations, dependency checking passed, isolated bytecode compilation passed, coverage regeneration produced V1 **38 SUPPORTED / 86 PARTIAL / 36 NOT_SUPPORTED / 160 total** and full baseline **38 / 89 / 75 / 202**, and the dashboard direct audit moves **33/53 → 34/53 VERIFIED_DIRECT**. The isolated attested-baseline activation test activated the one Wave 4B definition and verified its exact stable key/version linkage.

Wave 4B internal risk calibration v1.3: COMPLETE / PASS (2026-10-06). The single versioned `ssc-supported-internal-risk` registry now contains 38 explicit mappings while preserving all 37 v1.2 decisions unchanged. `spf_record_malformed` is LOW/scoring, and the unchanged scoring engine derives a 2-point factor deduction for one qualifying OPEN MATCH; the registry contains no issue-specific penalty. SSC severity remains vendor metadata only, and absent registry keys still fail closed to UNKNOWN/non-scoring. SPF parsing and analysis, DNS collection, Wave 4B outcomes and rule definitions, activation, taxonomy, assessment profiles, supported counts, schema, migrations, scoring formula, weights, and global penalties are unchanged. Existing absence and valid E2E evidence remain NO_MATCH with no finding; the prior controlled malformed fixture remains MATCH evidence, with its post-calibration scoring/report rerun intentionally left as a manual post-merge check. Validation used isolated database `ssc_wave4b_calibration_20261006`, never `ssc_e2e`: **56 focused calibration/Wave 4B tests passed**, followed by exactly one complete backend suite with **309 tests passed**. The full suite emitted the two existing dependency deprecation warnings plus a read-only pytest-cache warning. No migration was added, and coverage remains V1 **38/160 SUPPORTED** and **34/53 VERIFIED_DIRECT**.

Wave 4A `SSH_NEGOTIATION` VERIFIED_DIRECT batch: COMPLETE / PASS (2026-10-03). Exactly `ssh_weak_protocol`, `ssh_weak_cipher`, and `ssh_weak_mac` now have active deterministic evaluators pinned to exact attested `SSC_API` issue versions. The existing TCP executor accepts at most six explicitly declared `ssh_ports`; each receives one bounded connection, a validated/hash-only identification exchange, and—for SSH2—at most four packets ending at a complete valid server `SSH_MSG_KEXINIT`. The collector sends only its SSH-2.0 identification, disconnects before authentication, sends no credentials or application commands, and persists normalized algorithm lists plus compact limits/stop/error evidence rather than banners or packets.

The pinned `ssc-wave4a-ssh-crypto-policy.v1` uses the immutable SSC details as category authority: exact standardized/documented Arcfour and CBC cipher names for `ssh_weak_cipher`, exact MD5 MAC names for `ssh_weak_mac`, and valid protocol versions below 2 for `ssh_weak_protocol`. Matching is exact and case-sensitive. Algorithm advertisement is protocol evidence of server support, not proof of successful exploitation or downgrade. SSH-1.99 remains `INDETERMINATE` without safe SSH1 compatibility confirmation. The exact-name `ssc-wave4a-ssh-aead-policy.v2` distinguishes `MAC_IGNORED` OpenSSH/ChaCha20-Poly1305 ciphers from RFC 5647 `PAIRED_AEAD_MAC` ciphers. An exclusively MAC-ignored AEAD direction is clean with an empty MAC list. RFC 5647 AEAD requires each advertised encryption name to appear in the complete MAC list; empty, missing, or inconsistent pairing is indeterminate, including mixed AEAD-mode directions. A known non-AEAD cipher evaluates its complete standalone MAC list normally; an empty applicable list or unclassified cipher applicability is indeterminate. A prohibited standalone MAC name never matches unless at least one known non-AEAD cipher makes it selectable. Both directions must be conclusive for MAC `NO_MATCH`. Unavailable/recognized non-SSH endpoints do not poison a conclusive response-bearing SSH endpoint, but zero usable endpoints and ambiguous responsive SSH endpoints remain indeterminate unless another endpoint matches.

Wave 4A validation used isolated database `ssc_wave4a_rfc5647_20261003`, never `ssc_e2e`: the final focused Wave 4A suite passed **54 tests**, followed by the full backend suite passing **270 tests** with the same two dependency deprecation warnings. Exact reconciliation against isolated attested-baseline clone `ssc_wave4a_real_baseline_20261003` activated all three Wave 4A definitions with zero unavailable and database verification found all **37** exact active mappings. Coverage is V1 **37 SUPPORTED / 87 PARTIAL / 36 NOT_SUPPORTED / 160 total** and full baseline **37 / 90 / 75 / 202**. The dashboard direct audit moves **30/53 → 33/53 VERIFIED_DIRECT**; `spf_record_malformed` remains separate and partial, so this wave does not claim 34/53. At the scanner milestone all three new issues intentionally lacked internal calibration and failed closed to `UNKNOWN`/`affects_score=false`; they were subsequently approved in internal-risk calibration v1.2 below without changing scanner behavior or coverage. No schema change or migration was added; `0010_v1_assessment` remains head.

Wave 4A internal risk calibration v1.2: COMPLETE / PASS (2026-10-05). The single versioned `ssc-supported-internal-risk` registry now contains 37 explicit mappings while preserving all 34 v1.1 decisions unchanged. The Wave 4A subset is 0 HIGH, 1 MEDIUM, 2 LOW and 0 UNKNOWN; all three affect score. `ssh_weak_protocol` is MEDIUM/scoring, while `ssh_weak_cipher` and `ssh_weak_mac` are LOW/scoring. The unchanged scoring engine derives one-finding factor deductions of 7, 2, and 2 points respectively; the registry contains no issue-specific penalties. SSC severity remains vendor metadata only, and absent registry keys still fail closed to UNKNOWN/non-scoring. Scanner collection, SSH evaluation and aggregation semantics, rule definitions, activation, assessment coverage, supported counts, taxonomy, schema, migrations, scoring formula, weights, global penalties, and the clean real E2E evidence are unchanged. Real E2E run `28f74bb8-7af8-40cf-bdeb-0d641b554096` remains a deterministic three-rule `NO_MATCH` pipeline validation and is not represented as finding or penalty validation. Validation used isolated database `ssc_wave4a_calibration_20261005`, never `ssc_e2e`: **80 focused calibration/Wave 4A tests passed**, followed by exactly one complete backend suite with **276 tests passed** and the same two dependency deprecation warnings. No migration was added.

Wave 3B `HTTP_CONTENT` VERIFIED_DIRECT batch: COMPLETE / PASS (2026-10-02). The exact keys `unsafe_sri_v2`, `insecure_ftp`, `contact_information_detected`, `local_file_path_exposed_via_url_scheme`, `server_error`, `links_to_insecure_website`, and `service_soap` now have active deterministic evaluators pinned to exact attested `SSC_API` issue versions. The existing HTTP executor now performs bounded body inspection for explicitly declared paths, exactly two safe GET attempts per declared endpoint, redacted URL/contact observations, parseable SOAP/WSDL identification, and at most 20 actual same-origin nonrecursive SRI resource GETs including redirects. SRI redirects that change origin stop before the redirected GET. Full bodies and clear contact values are not persisted. Failed, blocked, truncated, unsupported, malformed, out-of-scope, ambiguous, or budget-incomplete evidence is `INDETERMINATE`/`NOT_ASSESSED`, never a false pass.

Wave 3B validation used isolated databases including final clean release database `ssc_wave3b_release_20261002_01`. The broader focused set passed **76 tests**; a final HTTP/SRI/Wave 1 safety set passed **35 tests** after compressed-resource, cross-origin-redirect, and malformed-URL ambiguity was closed. The finalized tree's full backend suite passed **190 tests** with the same two dependency deprecation warnings. Coverage is V1 **34 SUPPORTED / 90 PARTIAL / 36 NOT_SUPPORTED / 160 total** and full baseline **34 / 93 / 75 / 202**. The dashboard direct audit moves from **23 to 30 of 53 VERIFIED_DIRECT**. No schema or persistence change was needed, no migration was added, and `0010_v1_assessment` remains the migration head. The existing 202-issue baseline, scoring formula, penalties, factor weights, and provisional-score semantics were not changed. At this scanner milestone the seven new keys were uncalibrated and failed closed; they were subsequently approved in internal-risk calibration v1.1 below without changing scanner behavior or coverage.

Wave 3B internal risk calibration v1.1: COMPLETE / PASS (2026-10-02). The single versioned `ssc-supported-internal-risk` registry now contains 34 explicit mappings while preserving the original 27 v1.0 decisions unchanged. The Wave 3B subset is 0 HIGH, 0 MEDIUM, 4 LOW and 3 UNKNOWN; 4 affect score and 3 remain visible but non-scoring. `unsafe_sri_v2`, `insecure_ftp`, `local_file_path_exposed_via_url_scheme`, and `links_to_insecure_website` are LOW/scoring and each qualifying OPEN MATCH deducts 2 factor points. `contact_information_detected`, `server_error`, and `service_soap` are UNKNOWN/non-scoring. SSC severity remains metadata only: `unsafe_sri_v2` is internally LOW despite SSC severity high, and any absent registry key still fails closed to UNKNOWN/non-scoring. Existing penalties, weights, formulas, provisional scoring, deduplication, caps, taxonomy, coverage, scanner behavior, and the 202-issue baseline are unchanged. Validation used isolated database `ssc_wave3b_calibration_20261002_01`, never `ssc_e2e`: **20 focused calibration tests passed**, followed by exactly one full backend suite with **216 passed** and two dependency deprecation warnings. No migration was added.

Internal risk calibration v1.0: COMPLETE / PASS (2026-10-02). The original 27 keys resolve through the separate versioned registry with 0 HIGH, 6 MEDIUM, 17 LOW and 4 UNKNOWN; 23 affect score and 4 remain visible but non-scoring. Those exact decisions remain unchanged in v1.1. The original validation used isolated database `ssc_risk_calibration_20261001`: **25 targeted tests passed**, followed by one full backend suite with **182 passed** and two dependency deprecation warnings. The database upgraded from empty through `0010_v1_assessment`; Alembic metadata check found no new upgrade operations and reported only the known cyclic-foreign-key warning. No migration was added and no `ssc_e2e` database was used.

Coverage-aware provisional scoring: COMPLETE / PASS (2026-10-01). `ssc-v1` profile v1.1 retains the immutable 160-issue V1 denominator and 42 explicit `OUT_OF_SCOPE` issues while distinguishing score from coverage. Zero-assessed factors are `NOT_RATED` with null scores; factors with assessed issues receive an internal score from exact-version deterministic MATCH findings and are `PROVISIONAL` until the existing completeness/scoring prerequisites hold. The overall score weights only rated factors and is `PROVISIONAL` while V1 is incomplete, `NOT_RATED` when no factor is rated, and `COMPLETE` under the prior full-profile gate. `NO_MATCH` adds no penalty; `NOT_ASSESSED` remains visible and never becomes a pass. Penalty values, deduplication, caps, factor weights, SSC severity separation, taxonomy, and scanner capabilities are unchanged. JSON/HTML expose factor and overall score status and coverage. Existing append-only `score_results.result` JSONB persists these fields, and the profile-version change keeps old v1.0 snapshots distinct. Trend comparison remains future work.

Validation used isolated database `ssc_provisional_20261001`: **40 targeted scoring/completeness/report/persistence tests passed**, followed by one full backend suite with **171 passed** and one dependency deprecation warning. The database upgraded from empty through `0010_v1_assessment`; Alembic metadata check found no new upgrade operations and reported only the known cyclic-foreign-key warning. No migration was added. Python compilation and `git diff --check` passed. No `ssc_e2e` database was used.

V1 Assessment Completeness Fix: COMPLETE / PASS. Versioned profile `ssc-v1` v1.0 resolves the immutable baseline hash into 160 in-scope exact issue versions and 42 explicit `OUT_OF_SCOPE` issue versions. Missing, unsupported, partial, unselected, skipped, errored, timed-out, malformed and indeterminate V1 issues are `NOT_ASSESSED`; only deterministic exact-version `MATCH`/`NO_MATCH` outcomes are `ASSESSED`. Factor and overall scores are withheld until the full required V1 denominator is assessed. Penalty arithmetic, deduplication, capping, weighting, SSC severity separation, Golden Baseline content, and Wave 1/2 evaluator mappings remain unchanged by Wave 3A.

Completeness validation on 2026-09-23 used isolated database `ssc_v1_completeness_20260923`; the finalized migration round trip also passed from empty on `ssc_v1_completeness_final_20260923`. Focused gates passed with 14 completeness/profile tests and 42 scan, Wave 1/2, scoring, persistence and report tests; the final persistence/schema adjustment passed 15 focused tests. Migration `0010_v1_assessment` upgraded from empty, downgraded to `0009_wave1_ssc_evaluators`, re-upgraded, and Alembic metadata check reported no new operations apart from the known cyclic-foreign-key warning. That milestone's full suite passed with **135 tests** and the two existing dependency deprecation warnings.

Wave 3A `SERVICE_PROTOCOL_IDENTIFICATION`: COMPLETE / PASS. One bounded adapter framework on the TCP executor now supports VNC/RFB, rsync daemon, Redis RESP, SOCKS5, Telnet option negotiation, and SMB2 negotiate. The six exact active rules are pinned to attested `SSC_API` issue versions. Protocol-valid evidence is required for `MATCH`; `NO_MATCH` is limited to a complete recognized foreign-protocol response; TCP-open, arbitrary banners, timeout, reset, malformed/truncated responses, unsupported transports, and incomplete exchanges are `INDETERMINATE`. Probes have fixed time/byte/request budgets and perform no authentication, enumeration, relaying, state-changing command, or exploitation.

Wave 3A validation on 2026-09-23 passed **82 focused tests**, followed by the single final full suite with **164 passed** and the same two dependency deprecation warnings. Python compilation, generated coverage, database-backed exact-mapping verification, and `git diff --check` passed. At that milestone coverage was V1 **27 SUPPORTED / 92 PARTIAL / 41 NOT_SUPPORTED / 160 total** and full baseline **27 / 95 / 80 / 202**; V2 remained 42 `OUT_OF_SCOPE` issues in a V1 assessment. No schema change or new migration was required; `0010_v1_assessment` remains the migration head introduced by the preceding correctness milestone. The remaining service-protocol candidates stay `PARTIAL` except for the separately completed Wave 3B declared-path `service_soap` capability.

SSC-aligned Wave 1 scanner primitives (`HTTP_HEADERS`, `HTTP_REDIRECT`, `TLS_CERTIFICATE`): COMPLETE / PASS. Fourteen reviewed direct issues have sufficient normalized evidence and active deterministic evaluators pinned to exact issue versions from the attested real `SSC_API` baseline. Eight enrichment-dependent candidates remain `PARTIAL`.

SSC-aligned Wave 2 scanner primitives (`TLS_HANDSHAKE`, `EMAIL_SECURITY`): COMPLETE / PASS. Seven additional issues are truly supported: `tls_weak_protocol`, `spf_record_missing`, `spf_record_softfail`, `spf_record_wildcard`, `dmarc_record_missing`, `dmarc_contains_none`, and `subdomain_dmarc_contains_none`. `tls_weak_cipher`, `tls_ocsp_stapling`, `spf_record_malformed`, and three DKIM issues remain `PARTIAL` at their explicit evidence boundaries. No service identification, external intelligence, Golden Baseline mutation, or scoring-methodology work is included.

Wave 1 validation on 2026-09-21 used an isolated PostgreSQL database plus an isolated clone of real Golden Baseline `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`. Exact activation created 14 rule/version mappings with zero unavailable definitions. Phase 4B, Phase 5, and Phase 6 gates passed with 97, 108, and 116 tests. Downgrade to `0005_phase4_scan_engine`, re-upgrade to `0009_wave1_ssc_evaluators`, Alembic schema check, the final full suite (**116 passed**), compileall, pip check, coverage regeneration, and `git diff --check` passed. Validation logs: `reports/phase4b-validation-20260921-030512.txt`, `reports/phase5-validation-20260921-030512.txt`, and `reports/phase6-validation-20260921-030512.txt`. The two existing dependency deprecation warnings and the known mutually dependent foreign-key sorting warning remain.

Wave 2 validation on 2026-09-21 used isolated database `ssc_wave2_20260921` and the existing isolated clone of the same real Golden Baseline. Exact activation created 7 Wave 2 rule/version mappings with zero unavailable definitions. Phase 4B, Phase 5, and Phase 6 gates passed with **102**, **113**, and **121** tests. Downgrade to `0005_phase4_scan_engine`, re-upgrade to `0009_wave1_ssc_evaluators`, Alembic schema check, compileall with an isolated bytecode cache, pip check, database-verified coverage regeneration, and `git diff --check` passed. Coverage is **21 SUPPORTED / 101 PARTIAL / 80 NOT_SUPPORTED**. Validation logs: `reports/phase4b-validation-20260921-135900.txt`, `reports/phase5-validation-20260921-135900.txt`, and `reports/phase6-validation-20260921-135900.txt`. The two dependency deprecation warnings, read-only pytest-cache warnings, and known mutually dependent foreign-key sorting warning remain.

Direction correction: Phase 1B SSC API baseline acquisition extension; CLI-FIRST MVP behavior preserved.

Primary product interface: CLI (`ssc`). Web/API/frontend: OPTIONAL / PRESERVED.

Dashboard-centric work: PAUSED. Implementation sequence: Phase 4B PASS → Phase 5 PASS → Phase 6A CLI → Phase 6B REPORT. SYGNOS ingestion mapping and transport wait for its interface definition.

Phase 0–4 completion and historical validation below are preserved. Completed Phases 4B, 5, 6A and 6B form the CLI-first MVP milestone. This milestone closes the validated implementation; no production deployment or runtime data migration is performed. The preceding Phase 4 commit is `bb11f1b3557a190842eee33b31a1ab137771c026` (`Phase 4: implement scan engine`, 2026-08-10 15:29:45 +07:00). Use Git history for the exact MVP commit hash.

## Phase Status

Phase 0 - Foundation: COMPLETE / PASS

Phase 1A - Issue Catalog Data Model + Catalog API: COMPLETE / PASS

Phase 1B - Golden Baseline Importer: COMPLETE / PASS

Real SSC Golden Baseline: API availability verified by the operator; production import NOT PERFORMED in this implementation. Live read-only issue-detail discovery COMPLETE on 2026-09-19; no catalog or database write was performed.

Phase 1C - Catalog Administration / Review UI: COMPLETE / PASS

Phase 2 - Asset Inventory: COMPLETE / PASS

Phase 3 - Rule Engine: COMPLETE / PASS

Phase 4 - Scan Engine: COMPLETE / PASS

Phase 4B - Authorized HTTP/TLS/DNS/TCP Scan Executors: COMPLETE / PASS

Phase 5 - Scoring Engine: COMPLETE / PASS

Phase 6A - Primary CLI Interface: COMPLETE / PASS

Phase 6B - REPORT HTML/JSON Output: COMPLETE / PASS

V1 Assessment Completeness Fix: COMPLETE / PASS

Phase 6C - SYGNOS Structured Event Adapter: NOT STARTED / DEFERRED UNTIL INGESTION INTERFACE IS KNOWN

Phase 6D - Optional Web Dashboard: PAUSED / NOT STARTED

The former dashboard-first Phase 6 is superseded by 6A–6D. Existing Web administration through Phase 4 remains preserved.

Phase 7 - SSC Public Reference Sync: NOT STARTED

Phase 8 - Broader Optional SSC API Integration: NOT STARTED; initial metadata acquisition brought forward into Phase 1B

Phase 9 - SSC Comparison / Calibration: NOT STARTED

Phase 10 - Production Hardening: NOT STARTED

## Phase 0 Validation

Phase 0 runtime validation: COMPLETE / PASS

Last locally verified report:

```text
reports/phase0-validation-20260806-172053.txt
```

Validated Phase 0 checks included Docker Compose build/start, Alembic migration, backend tests, root and health endpoints, PostgreSQL health, Redis health, frontend HTTP, and frontend production build.

## Phase 1A Implemented Scope

Phase 1A adds:

- `catalog_factors`
- `catalog_issue_types`
- `catalog_issue_type_versions`
- `catalog_snapshots`
- `catalog_snapshot_items`
- Alembic revision `0002_phase1a_catalog`
- `/api/v1/catalog` backend API
- Pydantic v2 catalog schemas
- backend tests for catalog creation, duplicates, immutable versions, current-version behavior, informational and positive breach risks, snapshots, and duplicate snapshot items
- minimal frontend Issue Catalog page
- `scripts/phase1a_validate.sh`

Immutable history rule:

Issue definition changes create new `catalog_issue_type_versions` rows. Historical version rows and snapshot references are not overwritten.

## Phase 1A Validation

Phase 1A runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase1a-validation-20260806-183254.txt
```

Validated Phase 1A checks included Docker Compose build/start, backend container exec, Alembic version detection, Alembic upgrade to head, backend pytest, root and health endpoints, OpenAPI docs, catalog list endpoints, frontend HTTP, frontend production build, storage diagnostics, and container logs.

## Phase 1B Implemented Scope

Phase 1B adds:

- canonical JSON input schema `phase1b.ssc_licensed_ui.v1`
- validation for source type, factor codes, issue stable keys, breach risk, threat level, capture timestamp, duplicate issues, and source ordering
- `app.services.golden_baseline_importer` import service
- `python -m app.cli.import_golden_baseline` CLI with dry-run/preview mode
- SHA-256 content hashing over normalized canonical JSON
- exact-content idempotency by `SSC_LICENSED_UI` snapshot content hash
- factor creation/reuse by code without metadata overwrite
- issue type creation/reconciliation by explicit `stable_key`
- issue version creation only when definition fields change
- immutable `CatalogSnapshot` and `CatalogSnapshotItem` creation using Phase 1A tables
- preservation of factor and issue source ordering in snapshot item positions
- controlled rename/unknown handling that rejects ambiguous name collisions instead of merging by name
- synthetic validation fixture at `backend/tests/fixtures/phase1b_sample_baseline.json`
- importer documentation at `docs/GOLDEN_BASELINE_IMPORTER.md`
- backend tests for dry-run, idempotency, version changes, ordering, and ambiguous rename handling
- `scripts/phase1b_validate.sh`

The original Phase 1B milestone used licensed-UI JSON only and did not add SSC API integration, SSC public-web scraping, scanners, scoring, or asset inventory. The acquisition extension documented below adds the preferred API metadata source.

The repository does not contain a real captured SSC catalog. The real Golden Baseline can now be acquired through SSC API metadata; an external JSON file matching `docs/GOLDEN_BASELINE_IMPORTER.md` remains the fallback.

## Phase 1B Validation

### SSC API acquisition extension (2026-09-19)

Preferred initial SSC baseline: SSC API metadata endpoints. Fallback: licensed UI/manual canonical JSON. Future taxonomy updates: SSC API and/or reviewed public SSC methodology changes. Runtime: no SSC dependency.

The extension adds `ssc baseline pull-ssc`, optional `--enrich-details`, `status` and read-only `discover-details`; environment-only authentication; immutable raw API responses and normalized membership; API content hashing/idempotency; separate SSC severity metadata; migration `0008_ssc_api_baseline`; and mocked regression tests. A real baseline is required once for `SSC_ALIGNED`; otherwise the platform remains `INTERNAL_ONLY` with all existing CLI/scanner/rules/scoring/report functionality available. Manual real captures support explicit `--attest-real-source`; internal/synthetic/legacy unattested snapshots do not silently establish alignment.

The complete minimum baseline uses `GET https://api.securityscorecard.io/metadata/factors` and `GET https://api.securityscorecard.io/metadata/issue-types`. Optional enrichment uses `/metadata/issue-types/{type}` with four workers, a 20-second timeout, bounded safe-transient retries and per-issue failure isolation; it is not required for taxonomy alignment. Successful details preserve the exact response in versioned `ssc_metadata`; `short_description` also populates the existing issue-version description.

Live discovery verified HTTP 200 for `tls_weak_protocol`, `cookie_missing_http_only` and `csp_no_policy_v2`. Every response contained exactly `key`, `severity`, `factor`, `title`, `short_description`, `long_description` and `recommendation`, with no additional or nested fields. No returned field explicitly represented internal risk, Breach Risk, Threat Level, score impact or scoring relevance. SSC severity remains separate and unmapped; API issue versions remain `breach_risk=UNKNOWN` and `threat_level=null` unless another authoritative source explicitly provides them.

Validation: COMPLETE / PASS. `scripts/validate_cli_first.sh` passed against isolated PostgreSQL on Python 3.14: **111 tests passed** (71 existing + 40 SSC acquisition/enrichment cases), with the same two dependency deprecation warnings. Phase 4B and Phase 5 regression gates passed with 92 and 103 tests respectively. Downgrade to `0005_phase4_scan_engine`, re-upgrade, Alembic schema check (no new operations), compileall and pip check passed. Alembic reports the existing mutually dependent foreign-key sorting warning. Test HTTP responses are mocked; no live SSC access is required. Validation logs: `reports/phase4b-validation-20260919-224128.txt`, `reports/phase5-validation-20260919-224128.txt`, `reports/phase6-validation-20260919-224128.txt`.

New coverage includes normalization and unknown fields, factor/issue membership, provenance and raw immutability, hash/order/time idempotency, changed issue/factor metadata, alignment gating and real manual attestation, secret exclusion, authentication/partial-response failures, transaction rollback, redirects/pagination/size bounds, detail field discovery and CLI review/approval/hash checks. Historical validation below is preserved. No production migration, baseline import, push, company score comparison, calibration, public sync, dashboard, Sygnos transport or new scanner checks are part of this extension.

Final regression after optional enrichment passed 111 tests in 12.21s with two dependency warnings. The preserved frontend production build had already passed in an isolated temporary copy (Vite 5.4.21); no frontend source or dependency manifest changed. Installing that existing manifest reported two dependency advisories (one moderate, one high); dependency upgrades remain outside this change. `git diff --check` passed. Live detail discovery is complete. Production baseline acquisition remains pending by explicit instruction.

Phase 1B runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase1b-validation-20260810-092229.txt
```

Validated Phase 1B checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, importer dry-run, importer import, exact-content idempotency, root and health endpoints, catalog snapshot endpoint, and container log diagnostics.

## Phase 1C Implemented Scope

Phase 1C adds:

- catalog administration workspace in the React frontend
- issue catalog search and breach-risk filtering
- factor creation and active-state management
- issue identity creation and active-state management
- issue-version creation with current-version selection
- version-history review for selected issues
- catalog snapshot review
- Golden Baseline JSON preview/import UI backed by Phase 1B importer service
- backend preview/import endpoints:
  - `POST /api/v1/catalog/golden-baseline/preview`
  - `POST /api/v1/catalog/golden-baseline/import`
- backend tests for the admin preview/import endpoint behavior and idempotency
- `scripts/phase1c_validate.sh`

SecurityScorecard remains a reference source only. Phase 1C does not add SSC API integration, SSC public-web scraping, scanners, scoring, asset inventory, or public reference sync.

## Phase 1C Validation

Phase 1C runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase1c-validation-20260810-094850.txt
```

Validated Phase 1C checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, Golden Baseline preview endpoint, root and health endpoints, catalog list endpoints, frontend HTTP, frontend production build, and container log diagnostics.

## Phase 2 Implemented Scope

Phase 2 adds:

- formalized asset inventory metadata on the Phase 0 scaffold tables
- Alembic revision `0003_phase2_asset_inventory`
- inventory models for organizations, domains, hosts, host groups, and group members
- Pydantic inventory schemas
- REST API module at `/api/v1/inventory`
- uniqueness constraints for organization names, domain names per organization, hostnames per domain, host group names per organization, and host group membership
- same-organization validation for host group membership
- frontend Inventory tab for manual organization, domain, host, host group, and group member management
- backend tests for inventory lifecycle, duplicate handling, active-state updates, and membership validation
- `scripts/phase2_validate.sh`

Phase 2 is manual asset inventory only. It does not add scanning, discovery, findings, scoring, SSC API integration, or SSC public-web scraping.

## Phase 2 Validation

Phase 2 runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase2-validation-20260810-143424.txt
```

Validated Phase 2 checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, root and health endpoints, inventory list endpoints, frontend HTTP, frontend production build, and container log diagnostics.

## Phase 3 Implemented Scope

Phase 3 adds:

- versioned rule-engine definition tables
- Alembic revision `0004_phase3_rule_engine`
- `rule_engine_rules`
- `rule_engine_rule_versions`
- rule source types `MANUAL`, `INTERNAL`, and `SSC_REFERENCE`
- rule target types `DOMAIN`, `HOST`, `URL`, `CERTIFICATE`, `IP`, and `ORGANIZATION`
- optional linkage from rule identities to catalog issue types
- immutable rule-version creation with current-version selection
- REST API module at `/api/v1/rules`
- frontend Rules tab for rule identities, rule versions, JSON rule expressions, and version-history review
- backend tests for rule lifecycle, duplicate handling, catalog linkage, current-version validation, and expression validation
- `scripts/phase3_validate.sh`

Phase 3 stores rule definitions only. It does not add scan execution, scanner workers, findings, scoring, SSC API integration, SSC public-web scraping, or proprietary SSC logic.

## Phase 3 Validation

Phase 3 runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase3-validation-20260810-150157.txt
```

Validated Phase 3 checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, root and health endpoints, rule list endpoint, catalog and inventory list endpoints, frontend HTTP, frontend production build, and container log diagnostics.

## Phase 4 Implemented Scope

Phase 4 adds:

- scan job, scan target, scan run, and scan finding tables
- Alembic revision `0005_phase4_scan_engine`
- `scan_jobs`
- `scan_job_targets`
- `scan_runs`
- `scan_findings`
- deterministic JSON rule-expression evaluation for supplied evidence
- exact finding references to immutable rule versions
- exact finding references to linked catalog issue versions when available at scan time
- REST API module at `/api/v1/scans`
- synchronous scan run endpoint for explicit admin-triggered execution
- scanner worker CLI `python -m app.cli.scan_worker`
- optional Docker Compose `scanner_worker` service under the `workers` profile
- frontend Scans tab for queueing jobs, running jobs, and reviewing findings
- backend tests for scan job lifecycle, rule evaluation, findings, exact rule-version references, and validation errors
- `scripts/phase4_validate.sh`

Phase 4 does not add scoring, external network probing, automated asset discovery, SSC API integration, SSC public-web scraping, or proprietary SSC logic.

## Phase 4 Validation

Phase 4 runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase4-validation-20260810-152733.txt
```

Validated Phase 4 checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, scanner worker once, root and health endpoints, scan/rule/inventory endpoints, frontend HTTP, frontend production build, and container log diagnostics.


## Phase 4B Implemented Scope

Phase 4B completes the pre-existing uncommitted executor draft after Phase 4:

- real HTTP/HTTPS, TLS, DNS TXT and explicit-port TCP executors in `app.services.scan_executors`
- manual inventory authorization (`approved_for_scan`, sensitive-network permission and approval notes)
- active inventory and concrete-target approval checks at queueing and execution; revocation blocks queued scans
- checked-IP connection pinning, HTTP Host and TLS SNI preservation, prohibited-address checks and constrained redirects
- bounded port lists, socket/resolver timeouts, redirect count and HTTP response reads
- redacted cookie attributes, security header/redirect observations, certificate metadata/trust/legacy TLS probes, SPF/DMARC TXT normalization and TCP connection observations
- evidence-source provenance and `scan_observations`, `scan_config`, finding source fields
- Alembic file `0006_phase4b_authorized_scan_executors.py`, with revision ID `0006_phase4b_executors` (within Alembic's default version-column length)
- observation API at `GET /api/v1/scans/runs/{scan_run_id}/observations`
- rule assessment/factor and target identity snapshots in new scan summaries
- deterministic evaluator extracted to `app.services.rule_evaluation`, with Phase 4 compatibility imports retained
- failed scan history preserved after transaction rollback
- existing optional frontend draft preserved; no new dashboard development
- `scripts/phase4b_validate.sh`

Unsuccessful collection is distinct from absent protection. Unavailable evidence skips applicable detection rules and does not silently produce missing-header/SPF/DMARC findings. Legacy TLS support is unknown when local capability or probe failure is inconclusive. DNS-only domains need no target A/AAAA record. No discovery, range scanning, SSC API calls or SSC scraping is added.

## Phase 4B Validation

Phase 4B local validation: COMPLETE / PASS.

First gate passed before scoring implementation: 45 backend tests and worker-once validation after migrations from empty PostgreSQL through `0006_phase4b_executors`.

Final Phase 4B/legacy subset: 51 tests passed. Validation report: `reports/phase4b-validation-20260918-160055.txt`.

Fixtures perform real authorized local HTTP/HTTPS/DNS/TCP operations. Checks include successful TLS certificate extraction and SNI, trust failure, legacy protocol rejection, configured ports, redaction, sensitive/prohibited addresses, address pinning, redirect boundaries, invalid configuration, timeouts, DNS collection failure semantics, DNS-only targets and approval revoked after queueing. No external target was scanned.

## Phase 5 Implemented Scope

- pure internal scoring engine `app.services.scoring_engine`
- documented `internal-exposure` v1.0 policy, default HIGH/MEDIUM/LOW penalties and factor weighting
- per-factor and overall scores, deduplicated/capped per-finding factor impact and weighted overall impact
- informational/positive/opt-out/resolved findings do not deduct points
- no assessed overall score when evidence/rule/catalog coverage is incomplete
- normalization using exact historical rule/catalog versions, captured factor identity, affected targets, evidence and remediation
- complete model definition, exact model name/version and canonical SHA-256 preserved in results
- append-only service snapshots in `score_results`, unique by run/model hash; changed model definitions create additional results
- Alembic revision `0007_phase5_score_results`
- shared Pydantic contract `ssc.result.v1` in `app.schemas.results`
- `docs/SCORING.md` and `scripts/phase5_validate.sh`

This is an explicitly defined internal model, not proprietary SSC scoring. Historical Phase 4 runs are preserved; absent new assessment metadata yields an unassessed result rather than an invented score.

## Phase 5 Validation

Phase 5 local validation: COMPLETE / PASS.

The scoring gate passed before CLI/REPORT implementation: 55 tests, including persisted score snapshots and historical-version retention after current rule/catalog/factor changes.

Final Phase 5/legacy subset: 62 tests passed. Validation report: `reports/phase5-validation-20260918-160055.txt`.

Checks include weighted scores, penalty allocation/deduplication/capping, risk exemptions, unknown/unlinked definitions, incomplete coverage, configuration validation, deterministic hashes, idempotent snapshots and separate snapshots on model changes.

## Phase 6A/6B Implemented Scope

- installable primary `ssc` console command, with `python -m app.cli.ssc` equivalent
- `ssc scan --target <target> --output report` using approved registered inventory and shared services directly
- CLI target registration/approval and versioned internal detector-bundle loading; idempotent definitions preserve old versions
- rule selection, executor configuration, scoring configuration and organization disambiguation
- report regeneration from saved scan results without network probes
- independent REPORT adapter producing escaped, self-contained `report.html` and `result.json` in a fresh output directory
- overall/factor scores, findings, score impact, affected target, evidence summary, coverage and remediation in outputs
- both outputs consume the same validated, saved `ssc.result.v1` model
- explicit incomplete-result exit code with report written and unassessed overall score
- `--output sygnos` reserved and rejected before database/network activity; no Sygnos event mapping or transport implemented
- optional Docker Compose `cli` service and registered CLI in the Python 3.12 backend image; existing API command/services retained
- `docs/CLI.md`, `docs/ROADMAP.md`, CLI-first architecture and `scripts/phase6_validate.sh`

## Phase 6A/6B and Overall Validation

Phase 6A/6B local validation: COMPLETE / PASS.

Full suite: 71 tests passed, with 2 dependency deprecation warnings, on Python 3.14 and Python 3.12.

Validation reports:

- `reports/phase6-validation-20260918-160055.txt`
- `reports/cli-first-validation-20260918.txt`
- `reports/cli-first-final-tests-20260918.txt`
- `reports/docker-cli-build-20260918.txt`
- `reports/docker-cli-tests-20260918.txt`

The full suite includes the installed `ssc` subprocess, real four-executor pipeline → evidence → findings → scoring → HTML/JSON, matching persisted normalized results, report regeneration, HTML escaping, retained artifacts, incomplete-report behavior, rejected unapproved targets and SYGNOS preflight rejection. The optional Compose configuration parses successfully. Final executor regression verifies that redirects from all HTTP attempts remain visible when HTTPS is selected for header assessment. Python 3.12 Docker build succeeds with the console command installed.

Migration downgrade to Phase 4 and re-upgrade to `0007` pass on the disposable database; the full suite passes again afterward. Alembic metadata check reports no new upgrade operations, with a warning about pre-existing cyclic catalog/rule foreign keys. Python compilation and dependency checks pass.

Validation uses a separate temporary PostgreSQL database and local fixtures. Existing SSC data and running services were not migrated or replaced. Existing Web/frontend Phase 0–4 runtime validation is historical; no new browser/dashboard validation is claimed. Production deployment and hardening remain incomplete.


## CLI-first MVP Milestone Closeout

CLI-FIRST MVP — COMPLETE / PASS

Closeout review confirms the authorized HTTP/TLS/DNS/TCP executors, deterministic rule evaluation, version-linked findings, versioned internal scoring, installed CLI scan command, self-contained HTML report and JSON normalized result remain intact. Completed Phase 0–4 work and the existing optional Web/API/frontend are preserved.

The implementation matches the validated source: 71 tests pass on Python 3.12 and Python 3.14, with two dependency deprecation warnings. Docker build, migration downgrade/upgrade, metadata, compilation, dependency and Compose checks passed. Closeout changes only mark the milestone and exclude local artifacts; no new product feature is added.

Commit contents are limited to source, migrations, synthetic detector definitions/tests, configuration, documentation and validation scripts. Generated reports, caches, build output, secrets and local runtime data are excluded. Validation report paths above reference local evidence intentionally ignored by Git.

Final CLI command: `ssc scan --target <approved-target> --output report`.

Deferred items remain: SYGNOS event mapping/transport pending its ingestion interface; optional dashboard development paused; real SSC Golden Baseline waiting for source data; Phases 7–10 (public reference sync, optional SSC integration, comparison/calibration and production hardening) not started.
