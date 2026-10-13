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

## Reviewed consumer status

The immutable consumer registry `ssc-public-exposure-consumers.v1` is keyed by
the attested baseline content hash and SSC stable issue key. It contains exactly
`service_rsync`, `service_redis`, `service_socks_proxy`, `service_smb`,
`service_soap`, `service_ftp`, `service_imap`, `service_pop3`, and
`service_ldap`. Their current rules consume
`<root>.evaluations.<issue>.exposure_context.composition.matched`; protocol
identity remains independently visible but is necessary and insufficient.

TCP consumers require `SCANNER_TCP`, and SOAP requires `SCANNER_HTTP`.
Manual evidence and a wrong scanner source fail closed with
`untrusted_observation_source`, independently of trust-key stripping. Missing
or stale policy versions fail closed with `missing_or_stale_exposure_policy`.
Local CLI, inline API, and ordinary/default worker execution retain `UNKNOWN`
vantage and therefore produce `INDETERMINATE` / `NOT_ASSESSED` for these rules.
An approved external worker can produce a finding only for protocol `MATCH` +
`PUBLIC_ROUTABLE` + trusted `EXTERNAL_PUBLIC` deployment-manifest vantage.

`service_vnc` and `service_telnet` deliberately retain protocol-identity-only
rules. `mail_server_unusual_port` is not registered and remains
`SEPARATE_SEMANTIC_REVIEW_REQUIRED`. Wave 5C remains inactive and Oracle remains
pending/inactive. Capability support accounting is unchanged: 39/53
VERIFIED_DIRECT, 42/160 V1 supported, and 43/202 full supported.
