# PUBLIC_EXPOSURE_CONTEXT v1

This foundation records three independent facts for an already authorized,
exact-target scan:

1. the scope of the numeric destination pinned by the executor;
2. the scan runtime's trusted vantage attestation; and
3. the composition of those facts with one protocol evaluation.

It does not discover assets, expand root domains, authorize scans, bypass
sensitive-network controls, or change scoring. Inventory
`approved_for_scan` is operator authorization. `allow_sensitive_network_scan`
permits an approved scan to reach sensitive address space. Neither field says
that a target is Internet-facing or that an observation came from the public
Internet.

`PUBLIC_ROUTABLE` describes only the pinned destination address. It does not
prove that a service is publicly exposed. Likewise, a protocol `MATCH` proves
service identity/reachability only from the executing vantage. Public exposure
is `MATCH` only when both facts are present and the runtime has a trusted
`EXTERNAL_PUBLIC` deployment attestation. All other v1 compositions are
`INDETERMINATE`; v1 emits no clean `NO_MATCH`.

## Trusted worker manifest

Direct `ssc scan`, synchronous API `/run`, and an ordinary worker are always
`UNKNOWN`. Only the worker entry point can load an external-vantage manifest,
once at process startup, from the path named by
`SCANNER_VANTAGE_MANIFEST_PATH`. The path setting is not an attestation.

The JSON manifest has exactly these fields:

```json
{
  "schema_version": "ssc-scanner-deployment-manifest.v1",
  "vantage_id": "edge-bkk-01",
  "vantage_class": "EXTERNAL_PUBLIC",
  "deployment_boundary_assertion": "approved-external-public-scanner",
  "deployment_boundary_version": "ssc-external-deployment-boundary.v1"
}
```

The file must be regular (not a symlink) and not writable by group or others.
It must either be root-owned or be worker-owned and read-only to the worker.
Deployments should mount it read-only. It contains no credentials. Invalid,
unrecognized, oversized, absent, or insufficiently protected manifests fail
closed to `UNKNOWN`. Deployment administrators are responsible for ensuring
that the named worker actually runs outside the assessed organization's trust
boundary and does not use a private route to the target.

The immutable execution context is copied into `ScanRun.summary` under
`public_exposure_context_v1`. Connection-observation protocol evaluations get
a self-contained `exposure_context` referencing the already persisted
`target_identity.connect_host`; the IP is not duplicated. Job `scan_config`
and manual evidence cannot establish trusted vantage.

## Foundation-only status

No SSC rule consumes this evidence yet. Wave 5C stays inactive, Oracle stays
pending/inactive, assessment coverage remains unchanged, and Wave 3A/3B/5A
consumer reconciliation remains pending. A later reviewed tranche must select
eligible issue semantics and change rule/evaluator integration explicitly.
