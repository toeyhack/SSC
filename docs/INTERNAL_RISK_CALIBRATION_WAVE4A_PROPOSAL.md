# Wave 4A internal risk calibration approval record

**Status:** approved and implemented in internal calibration v1.2 on 2026-10-05. **Scope:** only `ssh_weak_protocol`, `ssh_weak_cipher`, and `ssh_weak_mac`. Calibration v1.2 preserves all 34 v1.1 decisions unchanged and adds these three Wave 4A decisions. SSC severity remains vendor metadata and is not an input to internal risk or score relevance.

The calibration uses the existing internal model without modification: `HIGH = 15`, `MEDIUM = 7`, and `LOW = 2`. Those values remain owned by the scoring engine; the calibration registry stores only `breach_risk` and `affects_score`. Missing registry entries continue to fail closed to `UNKNOWN`, `affects_score=false`, and zero score impact.

## Approved decisions

| Exact SSC issue key | Factor | SSC severity | Pre-v1.2 internal risk | Pre-v1.2 `affects_score` | Approved internal risk | Approved `affects_score` | Derived one-MATCH factor deduction |
|---|---|---|---|---:|---|---:|---:|
| `ssh_weak_protocol` | `network_security` | medium | UNKNOWN | false | MEDIUM | true | 7 |
| `ssh_weak_cipher` | `network_security` | medium | UNKNOWN | false | LOW | true | 2 |
| `ssh_weak_mac` | `network_security` | medium | UNKNOWN | false | LOW | true | 2 |

A deduction assumes an OPEN finding backed by the exact-version deterministic MATCH, no prior same-issue-version/target deduction in the run, and room under the factor's 100-point cap. It is an internal factor deduction, not an SSC score or penalty.

### `ssh_weak_protocol`

- **MATCH proves:** a valid server identification deterministically declares SSH protocol 1.x below version 2. Ambiguous SSH-1.99 does not match.
- **MATCH does not prove:** authentication bypass, credential compromise, successful login, or an exploited implementation vulnerability.
- **Practical preconditions:** a compatible legacy client must connect and establish a meaningful session. Attack impact depends on the obsolete protocol weakness or a separate implementation weakness and, for interception or manipulation, normally an attacker with relevant network position.
- **Primary character:** direct obsolete transport-protocol weakness, with secondary compatibility exposure.
- **Decision:** MEDIUM/scoring. This is analogous in internal-risk strength to the existing `tls_weak_protocol` MEDIUM decision: the MATCH establishes an obsolete transport capability with plausible confidentiality or integrity impact, but not compromise. One qualifying finding derives a 7-point factor deduction from the unchanged scoring engine.

### `ssh_weak_cipher`

- **MATCH proves:** complete SSH2 KEXINIT evidence advertises at least one exact policy-prohibited Arcfour or CBC cipher in either direction.
- **MATCH does not prove:** that the cipher was negotiated, a downgrade succeeded, a session was compromised, or authentication is weak.
- **Practical preconditions:** a client must offer the prohibited cipher, the peers must share the other required algorithms, and a session must actually select it. Attack-specific traffic and adversary capabilities are then required.
- **Primary character:** cryptographic hardening weakness and compatibility exposure.
- **Decision:** LOW/scoring. Advertisement establishes real server capability but is weaker evidence than successful weak-protocol negotiation. One qualifying finding derives a 2-point factor deduction from the unchanged scoring engine.

### `ssh_weak_mac`

- **MATCH proves:** an exact prohibited MD5 standalone MAC is deterministically selectable in at least one direction containing a known non-AEAD cipher. AEAD-only non-selectable advertisement does not match.
- **MATCH does not prove:** that the MAC was negotiated, a practical HMAC forgery, a downgrade, or session compromise.
- **Practical preconditions:** a client must offer the prohibited MAC, a compatible non-AEAD cipher and remaining algorithms must be selected, and an established session must encounter an adversary capable of exploiting a practical integrity weakness.
- **Primary character:** obsolete cryptographic hardening weakness and compatibility exposure.
- **Decision:** LOW/scoring. Selectability is stronger than an irrelevant inventory signal, but no exploitation evidence justifies MEDIUM. One qualifying finding derives a 2-point factor deduction from the unchanged scoring engine.

## Boundaries and consistency

The three MATCH conditions establish security-relevant obsolete capability, so none remains UNKNOWN. This differs from inventory-only UNKNOWN observations such as `service_rsync` or `service_soap`, whose MATCH conditions do not themselves establish a weakness. The two algorithm findings remain LOW because the scanner does not complete or observe selection; `ssh_weak_protocol` is MEDIUM because the server directly identifies as a pre-SSH2 protocol endpoint.

Calibration changes finding metadata and existing score eligibility only. It does not change SSH collection, evaluation, aggregation, rule definitions, activation, assessment coverage, taxonomy, schema, scoring arithmetic, weights, or global risk penalties.

The real E2E run `28f74bb8-7af8-40cf-bdeb-0d641b554096` produced deterministic `NO_MATCH` for all three checks. It validates the scanner/evaluator pipeline but correctly produced no finding and no penalty. Controlled local MATCH fixtures provide the deterministic finding-normalization and score-impact coverage for this calibration; the clean real run is not represented as penalty validation.
