# Wave 5A internal risk calibration approval record

**Status:** approved and implemented in internal calibration v1.4 on 2026-10-06. **Scope:** exactly `service_ftp`, `service_imap`, `service_pop3`, and `mail_server_unusual_port`. Calibration v1.4 preserves all 38 v1.3 decisions unchanged and adds these four reviewed decisions. SSC severity remains vendor metadata and is not an input to internal risk or score relevance.

The calibration uses the existing internal model without modification: `HIGH = 15`, `MEDIUM = 7`, and `LOW = 2`. Those values remain owned by the scoring engine; the calibration registry stores only `breach_risk` and `affects_score`. No UNKNOWN penalty exists. Missing registry entries continue to fail closed to `UNKNOWN`, `affects_score=false`, and zero score impact.

## Approved decisions

| Exact SSC issue key | Factor | SSC severity | Pre-v1.4 internal risk | Pre-v1.4 `affects_score` | Approved internal risk | Approved `affects_score` | Derived one-MATCH factor deduction |
|---|---|---|---|---:|---|---:|---:|
| `service_ftp` | `network_security` | medium | UNKNOWN | false | UNKNOWN | false | 0 |
| `service_imap` | `network_security` | medium | UNKNOWN | false | UNKNOWN | false | 0 |
| `service_pop3` | `network_security` | medium | UNKNOWN | false | UNKNOWN | false | 0 |
| `mail_server_unusual_port` | `ip_reputation` | medium | UNKNOWN | false | UNKNOWN | false | 0 |

These explicit mappings distinguish reviewed UNKNOWN decisions from unconfigured keys that happen to receive the same fail-closed runtime values.

## Evidence boundary

Wave 5A MATCH establishes deterministic service identity on one explicitly declared TCP endpoint. FTP requires a complete 220 greeting, exact `NOOP`, and complete 200 response. IMAP requires a legal greeting, valid untagged CAPABILITY response, and matching tagged OK completion. POP3 requires a valid `+OK` greeting and complete dot-terminated CAPA response. Unusual-port SMTP requires a legal 220 greeting and complete EHLO/250 response before applying `smtp-standard-ports.v1` `{25,465,587}`.

MATCH does not establish weak or bypassable authentication, anonymous access, unauthorized resource access, missing TLS for sensitive operations, plaintext credential submission, Internet exposure, weak firewall or ACL policy, open relay, vulnerable software, exploitation, or compromise. The scanner does not authenticate, access mailboxes or files, retrieve messages, submit mail, issue STARTTLS, or negotiate implicit TLS. Reachability is proven only from the authorized scanner's network vantage point.

## Per-issue rationale

### `service_ftp`

FTP identification proves that the listener accepts a harmless plaintext control command. It does not prove anonymous login, USER/PASS acceptance, unprotected credentials, readable or writable files, lack of AUTH TLS enforcement, or unsafe authorization. Protocol age and plaintext capability alone do not justify a fixed breach-risk penalty.

### `service_imap`

IMAP CAPABILITY is a normal pre-authentication exchange. It does not prove mailbox access, LOGIN or AUTH weakness, plaintext credential acceptance, missing TLS requirements, or unauthorized PREAUTH access. Because the combined issue includes ordinary OK and PREAUTH greetings without proving materially unsafe authorization, a stable penalty is not defensible.

### `service_pop3`

POP3 CAPA identifies the service without testing USER/PASS, message retrieval, mailbox access, authentication strength, or transport policy. The protocol's age does not itself establish breach risk.

### `mail_server_unusual_port`

The finding proves SMTP identity and a port outside the versioned standard set. Alternate ports may be intentional. Port choice does not prove open relay, filtering bypass, unauthorized submission, absent TLS, malicious infrastructure, weak authentication, or public exposure.

## Security use and scoring treatment

The four findings remain useful for inventory, attack-surface visibility, and follow-up assessment. They are not demonstrated vulnerabilities or deterministic security weaknesses. Stronger evidence—such as public reachability combined with unsafe authentication or transport, unauthorized file or mailbox access, or successful unauthorized relay—should be represented by a separate evidence-bearing finding rather than inferred from service presence.

Every qualifying MATCH remains visible with `breach_risk=UNKNOWN`, `affects_score=false`, and zero score impact. Verified SMTP on ports 25, 465, or 587 remains `NO_MATCH` for `mail_server_unusual_port` and creates no finding. Scanner, parser, evaluator, scoring formula, global penalties, assessment coverage, and result schema are unchanged.

## Registry totals

Calibration v1.4 contains 42 mappings: 0 HIGH, 7 MEDIUM, 24 LOW, and 11 UNKNOWN. Exactly 31 mappings have `affects_score=true`; 11 have `affects_score=false`. Capability coverage remains 38/53 VERIFIED_DIRECT, 41/160 V1 supported, and 42/202 full-baseline supported.
