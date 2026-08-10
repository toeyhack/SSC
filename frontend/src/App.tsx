import React, { FormEvent, useEffect, useMemo, useState } from 'react'
import './App.css'

type Factor = {
  id: string
  code: string
  name: string
  description: string | null
  display_order: number
  is_active: boolean
}

type IssueVersion = {
  id: string
  issue_type_id: string
  version_number: number
  name: string
  description: string | null
  breach_risk: string
  threat_level: string | null
  affects_score: boolean
  source_type: string
  source_reference: string | null
  source_snapshot_hash: string | null
  effective_from: string
  created_at: string
}

type IssueType = {
  id: string
  stable_key: string
  factor_id: string
  current_version_id: string | null
  is_active: boolean
  factor: Factor | null
  current_version: IssueVersion | null
}

type Snapshot = {
  id: string
  name: string
  source_type: string
  source_reference: string | null
  captured_at: string
  imported_at: string
  content_hash: string
  notes: string | null
  items: SnapshotItem[]
}

type SnapshotItem = {
  id: string
  factor_position: number | null
  issue_position: number | null
  issue_version: IssueVersion | null
}

type ImportResult = {
  dry_run: boolean
  content_hash: string
  snapshot_action: string
  snapshot_id: string | null
  factors_created: number
  factors_reused: number
  issues_created: number
  issues_reused: number
  versions_created: number
  versions_reused: number
  snapshot_items: number
  warnings: string[]
}

type Organization = {
  id: string
  name: string
  description: string | null
  active: boolean
}

type DomainAsset = {
  id: string
  organization_id: string
  name: string
  description: string | null
  active: boolean
  organization: Organization | null
}

type HostAsset = {
  id: string
  domain_id: string
  hostname: string
  ip: string | null
  description: string | null
  active: boolean
  domain: DomainAsset | null
}

type HostGroup = {
  id: string
  organization_id: string
  name: string
  description: string | null
  active: boolean
  organization: Organization | null
}

type RuleVersion = {
  id: string
  rule_id: string
  version_number: number
  name: string
  description: string | null
  target_type: string
  rule_expression: Record<string, unknown>
  evidence_schema: Record<string, unknown> | null
  remediation: string | null
  source_type: string
  source_reference: string | null
  effective_from: string
  created_at: string
}

type DetectionRule = {
  id: string
  stable_key: string
  catalog_issue_type_id: string | null
  current_version_id: string | null
  is_active: boolean
  catalog_issue_type: IssueType | null
  current_version: RuleVersion | null
}

type ScanJobTarget = {
  id: string
  scan_job_id: string
  target_type: string
  organization_id: string | null
  domain_id: string | null
  host_id: string | null
  evidence: Record<string, unknown> | null
}

type ScanJob = {
  id: string
  name: string
  status: string
  requested_by: string | null
  notes: string | null
  selected_rule_ids: string[] | null
  created_at: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  targets: ScanJobTarget[]
}

type ScanRun = {
  id: string
  scan_job_id: string
  status: string
  started_at: string
  completed_at: string | null
  summary: Record<string, unknown> | null
  error_message: string | null
}

type ScanFinding = {
  id: string
  scan_run_id: string
  target_type: string
  host_id: string | null
  domain_id: string | null
  organization_id: string | null
  rule_id: string
  rule_version_id: string
  status: string
  evidence: Record<string, unknown> | null
  rule_version: RuleVersion | null
}

type Tab = 'issues' | 'factors' | 'snapshots' | 'baseline' | 'inventory' | 'rules' | 'scans'

const API_BASE = 'http://localhost:8000'
const riskOptions = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'POSITIVE', 'UNKNOWN']
const sourceOptions = ['MANUAL', 'SSC_LICENSED_UI']
const ruleSourceOptions = ['MANUAL', 'INTERNAL', 'SSC_REFERENCE']
const ruleTargetOptions = ['DOMAIN', 'HOST', 'URL', 'CERTIFICATE', 'IP', 'ORGANIZATION']

const emptyFactor = {
  code: '',
  name: '',
  description: '',
  display_order: 0,
  is_active: true,
}

const emptyIssue = {
  stable_key: '',
  factor_id: '',
  is_active: true,
}

const emptyVersion = {
  name: '',
  description: '',
  breach_risk: 'UNKNOWN',
  threat_level: '',
  affects_score: true,
  source_type: 'MANUAL',
  source_reference: '',
  make_current: true,
}

const emptyOrganization = {
  name: '',
  description: '',
  active: true,
}

const emptyDomain = {
  organization_id: '',
  name: '',
  description: '',
  active: true,
}

const emptyHost = {
  domain_id: '',
  hostname: '',
  ip: '',
  description: '',
  active: true,
}

const emptyHostGroup = {
  organization_id: '',
  name: '',
  description: '',
  active: true,
}

const emptyMembership = {
  host_group_id: '',
  host_id: '',
}

const emptyRule = {
  stable_key: '',
  catalog_issue_type_id: '',
  is_active: true,
}

const emptyRuleVersion = {
  name: '',
  description: '',
  target_type: 'HOST',
  rule_expression: '{\n  "operator": "exists",\n  "path": "example.field"\n}',
  evidence_schema: '',
  remediation: '',
  source_type: 'MANUAL',
  source_reference: '',
  make_current: true,
}

const emptyScanJob = {
  name: '',
  requested_by: '',
  notes: '',
  target_type: 'HOST',
  target_id: '',
  rule_id: '',
  evidence: '{\n  "service": {\n    "exposed": true\n  }\n}',
}

export default function App() {
  const [tab, setTab] = useState<Tab>('issues')
  const [factors, setFactors] = useState<Factor[]>([])
  const [issues, setIssues] = useState<IssueType[]>([])
  const [snapshots, setSnapshots] = useState<Snapshot[]>([])
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [domains, setDomains] = useState<DomainAsset[]>([])
  const [hosts, setHosts] = useState<HostAsset[]>([])
  const [hostGroups, setHostGroups] = useState<HostGroup[]>([])
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [scanJobs, setScanJobs] = useState<ScanJob[]>([])
  const [scanRuns, setScanRuns] = useState<ScanRun[]>([])
  const [scanFindings, setScanFindings] = useState<ScanFinding[]>([])
  const [versions, setVersions] = useState<IssueVersion[]>([])
  const [ruleVersions, setRuleVersions] = useState<RuleVersion[]>([])
  const [selectedIssueId, setSelectedIssueId] = useState<string | null>(null)
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null)
  const [selectedScanRunId, setSelectedScanRunId] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [riskFilter, setRiskFilter] = useState('ALL')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [factorForm, setFactorForm] = useState(emptyFactor)
  const [issueForm, setIssueForm] = useState(emptyIssue)
  const [versionForm, setVersionForm] = useState(emptyVersion)
  const [baselineJson, setBaselineJson] = useState('')
  const [importResult, setImportResult] = useState<ImportResult | null>(null)
  const [organizationForm, setOrganizationForm] = useState(emptyOrganization)
  const [domainForm, setDomainForm] = useState(emptyDomain)
  const [hostForm, setHostForm] = useState(emptyHost)
  const [hostGroupForm, setHostGroupForm] = useState(emptyHostGroup)
  const [membershipForm, setMembershipForm] = useState(emptyMembership)
  const [ruleForm, setRuleForm] = useState(emptyRule)
  const [ruleVersionForm, setRuleVersionForm] = useState(emptyRuleVersion)
  const [scanJobForm, setScanJobForm] = useState(emptyScanJob)

  const selectedIssue = useMemo(
    () => issues.find((issue) => issue.id === selectedIssueId) ?? null,
    [issues, selectedIssueId],
  )

  const selectedRule = useMemo(
    () => rules.find((rule) => rule.id === selectedRuleId) ?? null,
    [rules, selectedRuleId],
  )

  const filteredIssues = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return issues.filter((issue) => {
      const version = issue.current_version
      const haystack = [
        issue.stable_key,
        issue.factor?.name ?? '',
        version?.name ?? '',
        version?.description ?? '',
      ].join(' ').toLowerCase()
      const matchesQuery = !normalized || haystack.includes(normalized)
      const matchesRisk = riskFilter === 'ALL' || version?.breach_risk === riskFilter
      return matchesQuery && matchesRisk
    })
  }, [issues, query, riskFilter])

  useEffect(() => {
    refreshAll()
  }, [])

  useEffect(() => {
    if (!selectedIssueId) {
      setVersions([])
      return
    }
    loadVersions(selectedIssueId)
  }, [selectedIssueId])

  useEffect(() => {
    if (!selectedRuleId) {
      setRuleVersions([])
      return
    }
    loadRuleVersions(selectedRuleId)
  }, [selectedRuleId])

  useEffect(() => {
    if (!selectedScanRunId) {
      setScanFindings([])
      return
    }
    loadScanFindings(selectedScanRunId)
  }, [selectedScanRunId])

  async function refreshAll() {
    setLoading(true)
    try {
      const [
        factorData,
        issueData,
        snapshotData,
        organizationData,
        domainData,
        hostData,
        hostGroupData,
        ruleData,
        scanJobData,
        scanRunData,
      ] = await Promise.all([
        api<Factor[]>('/api/v1/catalog/factors'),
        api<IssueType[]>('/api/v1/catalog/issues'),
        api<Snapshot[]>('/api/v1/catalog/snapshots'),
        api<Organization[]>('/api/v1/inventory/organizations'),
        api<DomainAsset[]>('/api/v1/inventory/domains'),
        api<HostAsset[]>('/api/v1/inventory/hosts'),
        api<HostGroup[]>('/api/v1/inventory/host-groups'),
        api<DetectionRule[]>('/api/v1/rules'),
        api<ScanJob[]>('/api/v1/scans/jobs'),
        api<ScanRun[]>('/api/v1/scans/runs'),
      ])
      setFactors(factorData)
      setIssues(issueData)
      setSnapshots(snapshotData)
      setOrganizations(organizationData)
      setDomains(domainData)
      setHosts(hostData)
      setHostGroups(hostGroupData)
      setRules(ruleData)
      setScanJobs(scanJobData)
      setScanRuns(scanRunData)
      setIssueForm((current) => ({
        ...current,
        factor_id: current.factor_id || factorData[0]?.id || '',
      }))
      setDomainForm((current) => ({ ...current, organization_id: current.organization_id || organizationData[0]?.id || '' }))
      setHostGroupForm((current) => ({ ...current, organization_id: current.organization_id || organizationData[0]?.id || '' }))
      setHostForm((current) => ({ ...current, domain_id: current.domain_id || domainData[0]?.id || '' }))
      setMembershipForm((current) => ({
        ...current,
        host_group_id: current.host_group_id || hostGroupData[0]?.id || '',
        host_id: current.host_id || hostData[0]?.id || '',
      }))
      setRuleForm((current) => ({ ...current, catalog_issue_type_id: current.catalog_issue_type_id || '' }))
      setScanJobForm((current) => ({
        ...current,
        target_id: current.target_id || hostData[0]?.id || domainData[0]?.id || organizationData[0]?.id || '',
        rule_id: current.rule_id || ruleData[0]?.id || '',
      }))
      setError(null)
    } catch (err) {
      setError(toErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  async function loadVersions(issueId: string) {
    try {
      setVersions(await api<IssueVersion[]>(`/api/v1/catalog/issues/${issueId}/versions`))
    } catch (err) {
      setError(toErrorMessage(err))
    }
  }

  async function loadRuleVersions(ruleId: string) {
    try {
      setRuleVersions(await api<RuleVersion[]>(`/api/v1/rules/${ruleId}/versions`))
    } catch (err) {
      setError(toErrorMessage(err))
    }
  }

  async function loadScanFindings(scanRunId: string) {
    try {
      setScanFindings(await api<ScanFinding[]>(`/api/v1/scans/runs/${scanRunId}/findings`))
    } catch (err) {
      setError(toErrorMessage(err))
    }
  }

  async function createFactor(event: FormEvent) {
    event.preventDefault()
    await submit(async () => {
      await api<Factor>('/api/v1/catalog/factors', {
        method: 'POST',
        body: JSON.stringify({
          ...factorForm,
          description: blankToNull(factorForm.description),
          display_order: Number(factorForm.display_order),
        }),
      })
      setFactorForm(emptyFactor)
      await refreshAll()
      setMessage('Factor created')
    })
  }

  async function updateFactor(factor: Factor, updates: Partial<Factor>) {
    await submit(async () => {
      await api<Factor>(`/api/v1/catalog/factors/${factor.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      })
      await refreshAll()
      setMessage('Factor updated')
    })
  }

  async function createIssue(event: FormEvent) {
    event.preventDefault()
    await submit(async () => {
      const issue = await api<IssueType>('/api/v1/catalog/issues', {
        method: 'POST',
        body: JSON.stringify(issueForm),
      })
      setIssueForm({ ...emptyIssue, factor_id: factors[0]?.id || '' })
      setSelectedIssueId(issue.id)
      await refreshAll()
      setMessage('Issue identity created')
    })
  }

  async function updateIssue(issue: IssueType, updates: Partial<IssueType>) {
    await submit(async () => {
      await api<IssueType>(`/api/v1/catalog/issues/${issue.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      })
      await refreshAll()
      setMessage('Issue updated')
    })
  }

  async function createVersion(event: FormEvent) {
    event.preventDefault()
    if (!selectedIssueId) {
      setError('Select an issue first')
      return
    }
    await submit(async () => {
      await api<IssueVersion>(`/api/v1/catalog/issues/${selectedIssueId}/versions`, {
        method: 'POST',
        body: JSON.stringify({
          ...versionForm,
          description: blankToNull(versionForm.description),
          threat_level: blankToNull(versionForm.threat_level),
          source_reference: blankToNull(versionForm.source_reference),
        }),
      })
      setVersionForm(emptyVersion)
      await refreshAll()
      await loadVersions(selectedIssueId)
      setMessage('Version created')
    })
  }

  async function runBaselineImport(dryRun: boolean) {
    await submit(async () => {
      const payload = JSON.parse(baselineJson)
      const result = await api<ImportResult>(
        dryRun ? '/api/v1/catalog/golden-baseline/preview' : '/api/v1/catalog/golden-baseline/import',
        {
          method: 'POST',
          body: JSON.stringify(payload),
        },
      )
      setImportResult(result)
      if (!dryRun) {
        await refreshAll()
      }
      setMessage(dryRun ? 'Preview generated' : 'Baseline import completed')
    })
  }

  async function createOrganization(event: FormEvent) {
    event.preventDefault()
    await submit(async () => {
      await api<Organization>('/api/v1/inventory/organizations', {
        method: 'POST',
        body: JSON.stringify({
          ...organizationForm,
          description: blankToNull(organizationForm.description),
        }),
      })
      setOrganizationForm(emptyOrganization)
      await refreshAll()
      setMessage('Organization created')
    })
  }

  async function updateOrganization(organization: Organization, updates: Partial<Organization>) {
    await submit(async () => {
      await api<Organization>(`/api/v1/inventory/organizations/${organization.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      })
      await refreshAll()
      setMessage('Organization updated')
    })
  }

  async function createDomain(event: FormEvent) {
    event.preventDefault()
    await submit(async () => {
      await api<DomainAsset>('/api/v1/inventory/domains', {
        method: 'POST',
        body: JSON.stringify({
          ...domainForm,
          description: blankToNull(domainForm.description),
        }),
      })
      setDomainForm({ ...emptyDomain, organization_id: organizations[0]?.id || '' })
      await refreshAll()
      setMessage('Domain created')
    })
  }

  async function updateDomain(domain: DomainAsset, updates: Partial<DomainAsset>) {
    await submit(async () => {
      await api<DomainAsset>(`/api/v1/inventory/domains/${domain.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      })
      await refreshAll()
      setMessage('Domain updated')
    })
  }

  async function createHost(event: FormEvent) {
    event.preventDefault()
    await submit(async () => {
      await api<HostAsset>('/api/v1/inventory/hosts', {
        method: 'POST',
        body: JSON.stringify({
          ...hostForm,
          ip: blankToNull(hostForm.ip),
          description: blankToNull(hostForm.description),
        }),
      })
      setHostForm({ ...emptyHost, domain_id: domains[0]?.id || '' })
      await refreshAll()
      setMessage('Host created')
    })
  }

  async function updateHost(host: HostAsset, updates: Partial<HostAsset>) {
    await submit(async () => {
      await api<HostAsset>(`/api/v1/inventory/hosts/${host.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      })
      await refreshAll()
      setMessage('Host updated')
    })
  }

  async function createHostGroup(event: FormEvent) {
    event.preventDefault()
    await submit(async () => {
      await api<HostGroup>('/api/v1/inventory/host-groups', {
        method: 'POST',
        body: JSON.stringify({
          ...hostGroupForm,
          description: blankToNull(hostGroupForm.description),
        }),
      })
      setHostGroupForm({ ...emptyHostGroup, organization_id: organizations[0]?.id || '' })
      await refreshAll()
      setMessage('Host group created')
    })
  }

  async function updateHostGroup(hostGroup: HostGroup, updates: Partial<HostGroup>) {
    await submit(async () => {
      await api<HostGroup>(`/api/v1/inventory/host-groups/${hostGroup.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      })
      await refreshAll()
      setMessage('Host group updated')
    })
  }

  async function addHostGroupMember(event: FormEvent) {
    event.preventDefault()
    await submit(async () => {
      await api(`/api/v1/inventory/host-groups/${membershipForm.host_group_id}/members`, {
        method: 'POST',
        body: JSON.stringify({ host_id: membershipForm.host_id }),
      })
      await refreshAll()
      setMessage('Host added to group')
    })
  }

  async function createRule(event: FormEvent) {
    event.preventDefault()
    await submit(async () => {
      const rule = await api<DetectionRule>('/api/v1/rules', {
        method: 'POST',
        body: JSON.stringify({
          ...ruleForm,
          catalog_issue_type_id: blankToNull(ruleForm.catalog_issue_type_id),
        }),
      })
      setRuleForm(emptyRule)
      setSelectedRuleId(rule.id)
      await refreshAll()
      setMessage('Rule identity created')
    })
  }

  async function updateRule(rule: DetectionRule, updates: Partial<DetectionRule>) {
    await submit(async () => {
      await api<DetectionRule>(`/api/v1/rules/${rule.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      })
      await refreshAll()
      setMessage('Rule updated')
    })
  }

  async function createRuleVersion(event: FormEvent) {
    event.preventDefault()
    if (!selectedRuleId) {
      setError('Select a rule first')
      return
    }
    await submit(async () => {
      await api<RuleVersion>(`/api/v1/rules/${selectedRuleId}/versions`, {
        method: 'POST',
        body: JSON.stringify({
          name: ruleVersionForm.name,
          description: blankToNull(ruleVersionForm.description),
          target_type: ruleVersionForm.target_type,
          rule_expression: parseJsonObject(ruleVersionForm.rule_expression, 'Rule expression'),
          evidence_schema: blankToNull(ruleVersionForm.evidence_schema)
            ? parseJsonObject(ruleVersionForm.evidence_schema, 'Evidence schema')
            : null,
          remediation: blankToNull(ruleVersionForm.remediation),
          source_type: ruleVersionForm.source_type,
          source_reference: blankToNull(ruleVersionForm.source_reference),
          make_current: ruleVersionForm.make_current,
        }),
      })
      setRuleVersionForm(emptyRuleVersion)
      await refreshAll()
      await loadRuleVersions(selectedRuleId)
      setMessage('Rule version created')
    })
  }

  async function createScanJob(event: FormEvent) {
    event.preventDefault()
    await submit(async () => {
      const target = buildScanTarget(scanJobForm.target_type, scanJobForm.target_id)
      const job = await api<ScanJob>('/api/v1/scans/jobs', {
        method: 'POST',
        body: JSON.stringify({
          name: scanJobForm.name,
          requested_by: blankToNull(scanJobForm.requested_by),
          notes: blankToNull(scanJobForm.notes),
          rule_ids: scanJobForm.rule_id ? [scanJobForm.rule_id] : null,
          targets: [
            {
              ...target,
              evidence: parseJsonObject(scanJobForm.evidence, 'Evidence'),
            },
          ],
        }),
      })
      setScanJobForm({ ...emptyScanJob, target_id: hosts[0]?.id || domains[0]?.id || organizations[0]?.id || '', rule_id: rules[0]?.id || '' })
      await refreshAll()
      setMessage(`Scan job queued: ${job.name}`)
    })
  }

  async function runScanJob(job: ScanJob) {
    await submit(async () => {
      const run = await api<ScanRun>(`/api/v1/scans/jobs/${job.id}/run`, { method: 'POST' })
      setSelectedScanRunId(run.id)
      await refreshAll()
      await loadScanFindings(run.id)
      setMessage('Scan job completed')
    })
  }

  async function submit(action: () => Promise<void>) {
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      await action()
    } catch (err) {
      setError(toErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="app-shell">
      <nav className="topbar">
        <div className="brand">Internal Security Rating</div>
        <div className="tabs">
          <button className={tabClass(tab, 'issues')} onClick={() => setTab('issues')}>Issues</button>
          <button className={tabClass(tab, 'factors')} onClick={() => setTab('factors')}>Factors</button>
          <button className={tabClass(tab, 'snapshots')} onClick={() => setTab('snapshots')}>Snapshots</button>
          <button className={tabClass(tab, 'baseline')} onClick={() => setTab('baseline')}>Baseline</button>
          <button className={tabClass(tab, 'inventory')} onClick={() => setTab('inventory')}>Inventory</button>
          <button className={tabClass(tab, 'rules')} onClick={() => setTab('rules')}>Rules</button>
          <button className={tabClass(tab, 'scans')} onClick={() => setTab('scans')}>Scans</button>
        </div>
      </nav>

      <header className="workspace-header">
        <h1>Catalog Administration</h1>
        <div className="status-line">
          {loading ? 'Loading catalog' : `${issues.length} issues, ${rules.length} rules, ${hosts.length} hosts, ${snapshots.length} snapshots`}
        </div>
      </header>

      {(message || error) && (
        <div className={error ? 'notice error' : 'notice'}>
          {error || message}
        </div>
      )}

      {tab === 'issues' && (
        <section className="workspace-grid">
          <div className="primary-pane">
            <div className="toolbar">
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search catalog" />
              <select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
                <option value="ALL">All risks</option>
                {riskOptions.map((risk) => <option key={risk} value={risk}>{risk}</option>)}
              </select>
              <button onClick={refreshAll} disabled={busy}>Refresh</button>
            </div>
            <IssueTable
              issues={filteredIssues}
              selectedIssueId={selectedIssueId}
              onSelect={setSelectedIssueId}
              onToggleActive={(issue) => updateIssue(issue, { is_active: !issue.is_active })}
            />
          </div>

          <aside className="side-pane">
            <form className="stack" onSubmit={createIssue}>
              <h2>Issue Identity</h2>
              <input
                required
                value={issueForm.stable_key}
                onChange={(event) => setIssueForm({ ...issueForm, stable_key: event.target.value })}
                placeholder="stable_key"
              />
              <select
                required
                value={issueForm.factor_id}
                onChange={(event) => setIssueForm({ ...issueForm, factor_id: event.target.value })}
              >
                <option value="">Select factor</option>
                {factors.map((factor) => <option key={factor.id} value={factor.id}>{factor.name}</option>)}
              </select>
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={issueForm.is_active}
                  onChange={(event) => setIssueForm({ ...issueForm, is_active: event.target.checked })}
                />
                Active
              </label>
              <button type="submit" disabled={busy || !issueForm.factor_id}>Create issue</button>
            </form>

            <form className="stack" onSubmit={createVersion}>
              <h2>Issue Version</h2>
              <div className="selected-line">{selectedIssue?.stable_key ?? 'No issue selected'}</div>
              <input
                required
                value={versionForm.name}
                onChange={(event) => setVersionForm({ ...versionForm, name: event.target.value })}
                placeholder="Issue name"
              />
              <textarea
                value={versionForm.description}
                onChange={(event) => setVersionForm({ ...versionForm, description: event.target.value })}
                placeholder="Definition"
              />
              <div className="form-row">
                <select value={versionForm.breach_risk} onChange={(event) => setVersionForm({ ...versionForm, breach_risk: event.target.value })}>
                  {riskOptions.map((risk) => <option key={risk} value={risk}>{risk}</option>)}
                </select>
                <input value={versionForm.threat_level} onChange={(event) => setVersionForm({ ...versionForm, threat_level: event.target.value })} placeholder="Threat level" />
              </div>
              <div className="form-row">
                <select value={versionForm.source_type} onChange={(event) => setVersionForm({ ...versionForm, source_type: event.target.value })}>
                  {sourceOptions.map((source) => <option key={source} value={source}>{source}</option>)}
                </select>
                <input value={versionForm.source_reference} onChange={(event) => setVersionForm({ ...versionForm, source_reference: event.target.value })} placeholder="Source reference" />
              </div>
              <label className="check-row">
                <input type="checkbox" checked={versionForm.affects_score} onChange={(event) => setVersionForm({ ...versionForm, affects_score: event.target.checked })} />
                Affects score
              </label>
              <label className="check-row">
                <input type="checkbox" checked={versionForm.make_current} onChange={(event) => setVersionForm({ ...versionForm, make_current: event.target.checked })} />
                Make current
              </label>
              <button type="submit" disabled={busy || !selectedIssueId}>Create version</button>
            </form>

            <VersionHistory versions={versions} />
          </aside>
        </section>
      )}

      {tab === 'factors' && (
        <section className="workspace-grid compact">
          <div className="primary-pane">
            <FactorTable factors={factors} onToggleActive={(factor) => updateFactor(factor, { is_active: !factor.is_active })} />
          </div>
          <aside className="side-pane">
            <form className="stack" onSubmit={createFactor}>
              <h2>Factor</h2>
              <input required value={factorForm.code} onChange={(event) => setFactorForm({ ...factorForm, code: event.target.value })} placeholder="code" />
              <input required value={factorForm.name} onChange={(event) => setFactorForm({ ...factorForm, name: event.target.value })} placeholder="Name" />
              <textarea value={factorForm.description} onChange={(event) => setFactorForm({ ...factorForm, description: event.target.value })} placeholder="Description" />
              <input type="number" value={factorForm.display_order} onChange={(event) => setFactorForm({ ...factorForm, display_order: Number(event.target.value) })} placeholder="Display order" />
              <label className="check-row">
                <input type="checkbox" checked={factorForm.is_active} onChange={(event) => setFactorForm({ ...factorForm, is_active: event.target.checked })} />
                Active
              </label>
              <button type="submit" disabled={busy}>Create factor</button>
            </form>
          </aside>
        </section>
      )}

      {tab === 'snapshots' && (
        <section className="single-pane">
          <SnapshotTable snapshots={snapshots} />
        </section>
      )}

      {tab === 'baseline' && (
        <section className="workspace-grid compact">
          <div className="primary-pane">
            <textarea
              className="json-editor"
              value={baselineJson}
              onChange={(event) => setBaselineJson(event.target.value)}
              spellCheck={false}
              placeholder="Paste canonical baseline JSON"
            />
            <div className="toolbar bottom">
              <button onClick={() => runBaselineImport(true)} disabled={busy || !baselineJson.trim()}>Preview</button>
              <button onClick={() => runBaselineImport(false)} disabled={busy || !baselineJson.trim()}>Import</button>
            </div>
          </div>
          <aside className="side-pane">
            <ImportPreview result={importResult} />
          </aside>
        </section>
      )}

      {tab === 'inventory' && (
        <section className="inventory-layout">
          <div className="inventory-tables">
            <InventoryTable
              title="Organizations"
              headers={['Name', 'Description', 'Active']}
              rows={organizations.map((organization) => [
                organization.name,
                organization.description ?? '-',
                <button onClick={() => updateOrganization(organization, { active: !organization.active })}>{yesNo(organization.active)}</button>,
              ])}
            />
            <InventoryTable
              title="Domains"
              headers={['Domain', 'Organization', 'Active']}
              rows={domains.map((domain) => [
                <span className="mono">{domain.name}</span>,
                domain.organization?.name ?? '-',
                <button onClick={() => updateDomain(domain, { active: !domain.active })}>{yesNo(domain.active)}</button>,
              ])}
            />
            <InventoryTable
              title="Hosts"
              headers={['Hostname', 'IP', 'Domain', 'Active']}
              rows={hosts.map((host) => [
                <span className="mono">{host.hostname}</span>,
                host.ip ?? '-',
                host.domain?.name ?? '-',
                <button onClick={() => updateHost(host, { active: !host.active })}>{yesNo(host.active)}</button>,
              ])}
            />
            <InventoryTable
              title="Host Groups"
              headers={['Name', 'Organization', 'Active']}
              rows={hostGroups.map((hostGroup) => [
                hostGroup.name,
                hostGroup.organization?.name ?? '-',
                <button onClick={() => updateHostGroup(hostGroup, { active: !hostGroup.active })}>{yesNo(hostGroup.active)}</button>,
              ])}
            />
          </div>

          <aside className="inventory-forms">
            <form className="stack" onSubmit={createOrganization}>
              <h2>Organization</h2>
              <input required value={organizationForm.name} onChange={(event) => setOrganizationForm({ ...organizationForm, name: event.target.value })} placeholder="Name" />
              <textarea value={organizationForm.description} onChange={(event) => setOrganizationForm({ ...organizationForm, description: event.target.value })} placeholder="Description" />
              <button type="submit" disabled={busy}>Create organization</button>
            </form>

            <form className="stack" onSubmit={createDomain}>
              <h2>Domain</h2>
              <select required value={domainForm.organization_id} onChange={(event) => setDomainForm({ ...domainForm, organization_id: event.target.value })}>
                <option value="">Select organization</option>
                {organizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}
              </select>
              <input required value={domainForm.name} onChange={(event) => setDomainForm({ ...domainForm, name: event.target.value })} placeholder="example.com" />
              <textarea value={domainForm.description} onChange={(event) => setDomainForm({ ...domainForm, description: event.target.value })} placeholder="Description" />
              <button type="submit" disabled={busy || !domainForm.organization_id}>Create domain</button>
            </form>

            <form className="stack" onSubmit={createHost}>
              <h2>Host</h2>
              <select required value={hostForm.domain_id} onChange={(event) => setHostForm({ ...hostForm, domain_id: event.target.value })}>
                <option value="">Select domain</option>
                {domains.map((domain) => <option key={domain.id} value={domain.id}>{domain.name}</option>)}
              </select>
              <input required value={hostForm.hostname} onChange={(event) => setHostForm({ ...hostForm, hostname: event.target.value })} placeholder="host.example.com" />
              <input value={hostForm.ip} onChange={(event) => setHostForm({ ...hostForm, ip: event.target.value })} placeholder="IP address" />
              <textarea value={hostForm.description} onChange={(event) => setHostForm({ ...hostForm, description: event.target.value })} placeholder="Description" />
              <button type="submit" disabled={busy || !hostForm.domain_id}>Create host</button>
            </form>

            <form className="stack" onSubmit={createHostGroup}>
              <h2>Host Group</h2>
              <select required value={hostGroupForm.organization_id} onChange={(event) => setHostGroupForm({ ...hostGroupForm, organization_id: event.target.value })}>
                <option value="">Select organization</option>
                {organizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}
              </select>
              <input required value={hostGroupForm.name} onChange={(event) => setHostGroupForm({ ...hostGroupForm, name: event.target.value })} placeholder="Group name" />
              <textarea value={hostGroupForm.description} onChange={(event) => setHostGroupForm({ ...hostGroupForm, description: event.target.value })} placeholder="Description" />
              <button type="submit" disabled={busy || !hostGroupForm.organization_id}>Create group</button>
            </form>

            <form className="stack" onSubmit={addHostGroupMember}>
              <h2>Group Member</h2>
              <select required value={membershipForm.host_group_id} onChange={(event) => setMembershipForm({ ...membershipForm, host_group_id: event.target.value })}>
                <option value="">Select group</option>
                {hostGroups.map((hostGroup) => <option key={hostGroup.id} value={hostGroup.id}>{hostGroup.name}</option>)}
              </select>
              <select required value={membershipForm.host_id} onChange={(event) => setMembershipForm({ ...membershipForm, host_id: event.target.value })}>
                <option value="">Select host</option>
                {hosts.map((host) => <option key={host.id} value={host.id}>{host.hostname}</option>)}
              </select>
              <button type="submit" disabled={busy || !membershipForm.host_group_id || !membershipForm.host_id}>Add member</button>
            </form>
          </aside>
        </section>
      )}

      {tab === 'rules' && (
        <section className="workspace-grid">
          <div className="primary-pane">
            <div className="toolbar">
              <button onClick={refreshAll} disabled={busy}>Refresh</button>
            </div>
            <RuleTable
              rules={rules}
              selectedRuleId={selectedRuleId}
              onSelect={setSelectedRuleId}
              onToggleActive={(rule) => updateRule(rule, { is_active: !rule.is_active })}
            />
          </div>

          <aside className="side-pane">
            <form className="stack" onSubmit={createRule}>
              <h2>Rule Identity</h2>
              <input
                required
                value={ruleForm.stable_key}
                onChange={(event) => setRuleForm({ ...ruleForm, stable_key: event.target.value })}
                placeholder="stable_key"
              />
              <select
                value={ruleForm.catalog_issue_type_id}
                onChange={(event) => setRuleForm({ ...ruleForm, catalog_issue_type_id: event.target.value })}
              >
                <option value="">No catalog issue link</option>
                {issues.map((issue) => (
                  <option key={issue.id} value={issue.id}>{issue.current_version?.name ?? issue.stable_key}</option>
                ))}
              </select>
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={ruleForm.is_active}
                  onChange={(event) => setRuleForm({ ...ruleForm, is_active: event.target.checked })}
                />
                Active
              </label>
              <button type="submit" disabled={busy}>Create rule</button>
            </form>

            <form className="stack" onSubmit={createRuleVersion}>
              <h2>Rule Version</h2>
              <div className="selected-line">{selectedRule?.stable_key ?? 'No rule selected'}</div>
              <input
                required
                value={ruleVersionForm.name}
                onChange={(event) => setRuleVersionForm({ ...ruleVersionForm, name: event.target.value })}
                placeholder="Rule name"
              />
              <textarea
                value={ruleVersionForm.description}
                onChange={(event) => setRuleVersionForm({ ...ruleVersionForm, description: event.target.value })}
                placeholder="Description"
              />
              <div className="form-row">
                <select value={ruleVersionForm.target_type} onChange={(event) => setRuleVersionForm({ ...ruleVersionForm, target_type: event.target.value })}>
                  {ruleTargetOptions.map((target) => <option key={target} value={target}>{target}</option>)}
                </select>
                <select value={ruleVersionForm.source_type} onChange={(event) => setRuleVersionForm({ ...ruleVersionForm, source_type: event.target.value })}>
                  {ruleSourceOptions.map((source) => <option key={source} value={source}>{source}</option>)}
                </select>
              </div>
              <textarea
                className="json-mini"
                required
                value={ruleVersionForm.rule_expression}
                onChange={(event) => setRuleVersionForm({ ...ruleVersionForm, rule_expression: event.target.value })}
                spellCheck={false}
                placeholder="Rule expression JSON"
              />
              <textarea
                className="json-mini"
                value={ruleVersionForm.evidence_schema}
                onChange={(event) => setRuleVersionForm({ ...ruleVersionForm, evidence_schema: event.target.value })}
                spellCheck={false}
                placeholder="Evidence schema JSON"
              />
              <textarea
                value={ruleVersionForm.remediation}
                onChange={(event) => setRuleVersionForm({ ...ruleVersionForm, remediation: event.target.value })}
                placeholder="Remediation"
              />
              <input
                value={ruleVersionForm.source_reference}
                onChange={(event) => setRuleVersionForm({ ...ruleVersionForm, source_reference: event.target.value })}
                placeholder="Source reference"
              />
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={ruleVersionForm.make_current}
                  onChange={(event) => setRuleVersionForm({ ...ruleVersionForm, make_current: event.target.checked })}
                />
                Make current
              </label>
              <button type="submit" disabled={busy || !selectedRuleId}>Create version</button>
            </form>

            <RuleVersionHistory versions={ruleVersions} />
          </aside>
        </section>
      )}

      {tab === 'scans' && (
        <section className="workspace-grid">
          <div className="primary-pane">
            <div className="toolbar">
              <button onClick={refreshAll} disabled={busy}>Refresh</button>
            </div>
            <ScanJobTable
              jobs={scanJobs}
              onRun={runScanJob}
            />
            <div className="split-block">
              <ScanRunTable
                runs={scanRuns}
                selectedScanRunId={selectedScanRunId}
                onSelect={setSelectedScanRunId}
              />
              <FindingTable findings={scanFindings} />
            </div>
          </div>

          <aside className="side-pane">
            <form className="stack" onSubmit={createScanJob}>
              <h2>Scan Job</h2>
              <input
                required
                value={scanJobForm.name}
                onChange={(event) => setScanJobForm({ ...scanJobForm, name: event.target.value })}
                placeholder="Job name"
              />
              <input
                value={scanJobForm.requested_by}
                onChange={(event) => setScanJobForm({ ...scanJobForm, requested_by: event.target.value })}
                placeholder="Requested by"
              />
              <textarea
                value={scanJobForm.notes}
                onChange={(event) => setScanJobForm({ ...scanJobForm, notes: event.target.value })}
                placeholder="Notes"
              />
              <div className="form-row">
                <select
                  value={scanJobForm.target_type}
                  onChange={(event) => setScanJobForm({ ...scanJobForm, target_type: event.target.value, target_id: firstTargetId(event.target.value, organizations, domains, hosts) })}
                >
                  <option value="HOST">HOST</option>
                  <option value="DOMAIN">DOMAIN</option>
                  <option value="ORGANIZATION">ORGANIZATION</option>
                </select>
                <select
                  required
                  value={scanJobForm.target_id}
                  onChange={(event) => setScanJobForm({ ...scanJobForm, target_id: event.target.value })}
                >
                  <option value="">Select target</option>
                  {targetOptions(scanJobForm.target_type, organizations, domains, hosts).map((target) => (
                    <option key={target.id} value={target.id}>{target.label}</option>
                  ))}
                </select>
              </div>
              <select
                value={scanJobForm.rule_id}
                onChange={(event) => setScanJobForm({ ...scanJobForm, rule_id: event.target.value })}
              >
                <option value="">All active matching rules</option>
                {rules.map((rule) => (
                  <option key={rule.id} value={rule.id}>{rule.current_version?.name ?? rule.stable_key}</option>
                ))}
              </select>
              <textarea
                className="json-mini"
                required
                value={scanJobForm.evidence}
                onChange={(event) => setScanJobForm({ ...scanJobForm, evidence: event.target.value })}
                spellCheck={false}
                placeholder="Evidence JSON"
              />
              <button type="submit" disabled={busy || !scanJobForm.target_id}>Queue scan</button>
            </form>
          </aside>
        </section>
      )}
    </main>
  )
}

function IssueTable({ issues, selectedIssueId, onSelect, onToggleActive }: {
  issues: IssueType[]
  selectedIssueId: string | null
  onSelect: (id: string) => void
  onToggleActive: (issue: IssueType) => void
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Factor</th>
            <th>Stable Key</th>
            <th>Issue</th>
            <th>Breach Risk</th>
            <th>Threat</th>
            <th>Version</th>
            <th>Active</th>
          </tr>
        </thead>
        <tbody>
          {issues.map((issue) => (
            <tr key={issue.id} className={issue.id === selectedIssueId ? 'selected-row' : ''} onClick={() => onSelect(issue.id)}>
              <td>{issue.factor?.name ?? '-'}</td>
              <td className="mono">{issue.stable_key}</td>
              <td>{issue.current_version?.name ?? '-'}</td>
              <td><span className={`risk risk-${(issue.current_version?.breach_risk ?? 'unknown').toLowerCase()}`}>{issue.current_version?.breach_risk ?? '-'}</span></td>
              <td>{issue.current_version?.threat_level ?? '-'}</td>
              <td>{issue.current_version?.version_number ?? '-'}</td>
              <td><button onClick={(event) => { event.stopPropagation(); onToggleActive(issue) }}>{yesNo(issue.is_active)}</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function FactorTable({ factors, onToggleActive }: { factors: Factor[], onToggleActive: (factor: Factor) => void }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Order</th>
            <th>Code</th>
            <th>Name</th>
            <th>Description</th>
            <th>Active</th>
          </tr>
        </thead>
        <tbody>
          {factors.map((factor) => (
            <tr key={factor.id}>
              <td>{factor.display_order}</td>
              <td className="mono">{factor.code}</td>
              <td>{factor.name}</td>
              <td>{factor.description ?? '-'}</td>
              <td><button onClick={() => onToggleActive(factor)}>{yesNo(factor.is_active)}</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function RuleTable({ rules, selectedRuleId, onSelect, onToggleActive }: {
  rules: DetectionRule[]
  selectedRuleId: string | null
  onSelect: (id: string) => void
  onToggleActive: (rule: DetectionRule) => void
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Stable Key</th>
            <th>Rule</th>
            <th>Target</th>
            <th>Catalog Issue</th>
            <th>Version</th>
            <th>Source</th>
            <th>Active</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((rule) => (
            <tr key={rule.id} className={rule.id === selectedRuleId ? 'selected-row' : ''} onClick={() => onSelect(rule.id)}>
              <td className="mono">{rule.stable_key}</td>
              <td>{rule.current_version?.name ?? '-'}</td>
              <td>{rule.current_version?.target_type ?? '-'}</td>
              <td>{rule.catalog_issue_type?.current_version?.name ?? rule.catalog_issue_type?.stable_key ?? '-'}</td>
              <td>{rule.current_version?.version_number ?? '-'}</td>
              <td>{rule.current_version?.source_type ?? '-'}</td>
              <td><button onClick={(event) => { event.stopPropagation(); onToggleActive(rule) }}>{yesNo(rule.is_active)}</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ScanJobTable({ jobs, onRun }: { jobs: ScanJob[], onRun: (job: ScanJob) => void }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Created</th>
            <th>Name</th>
            <th>Status</th>
            <th>Targets</th>
            <th>Rules</th>
            <th>Run</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((job) => (
            <tr key={job.id}>
              <td>{formatDate(job.created_at)}</td>
              <td>{job.name}</td>
              <td>{job.status}</td>
              <td>{job.targets.length}</td>
              <td>{job.selected_rule_ids?.length ?? 'All'}</td>
              <td><button onClick={() => onRun(job)} disabled={job.status !== 'QUEUED' && job.status !== 'FAILED'}>Run</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ScanRunTable({ runs, selectedScanRunId, onSelect }: {
  runs: ScanRun[]
  selectedScanRunId: string | null
  onSelect: (id: string) => void
}) {
  return (
    <div className="inventory-block">
      <h2>Runs</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Started</th>
              <th>Status</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr key={run.id} className={run.id === selectedScanRunId ? 'selected-row' : ''} onClick={() => onSelect(run.id)}>
                <td>{formatDate(run.started_at)}</td>
                <td>{run.status}</td>
                <td>{String(run.summary?.findings_created ?? '-')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function FindingTable({ findings }: { findings: ScanFinding[] }) {
  return (
    <div className="inventory-block">
      <h2>Findings</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Target</th>
              <th>Status</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.id}>
                <td>{finding.rule_version?.name ?? finding.rule_version_id}</td>
                <td>{finding.target_type}</td>
                <td>{finding.status}</td>
                <td><span className="mono">{JSON.stringify(finding.evidence?.matched_expression ?? {})}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function InventoryTable({ title, headers, rows }: {
  title: string
  headers: string[]
  rows: React.ReactNode[][]
}) {
  return (
    <div className="inventory-block">
      <h2>{title}</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {headers.map((header) => <th key={header}>{header}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={index}>
                {row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function RuleVersionHistory({ versions }: { versions: RuleVersion[] }) {
  return (
    <div className="history">
      <h2>Rule History</h2>
      {versions.length === 0 && <div className="empty">No versions</div>}
      {versions.map((version) => (
        <div className="history-item" key={version.id}>
          <div className="history-title">v{version.version_number} {version.name}</div>
          <div>{version.target_type} / {version.source_type}</div>
          <pre className="expression-preview">{JSON.stringify(version.rule_expression, null, 2)}</pre>
          <div className="muted">{formatDate(version.effective_from)}</div>
        </div>
      ))}
    </div>
  )
}

function SnapshotTable({ snapshots }: { snapshots: Snapshot[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Captured</th>
            <th>Name</th>
            <th>Source</th>
            <th>Items</th>
            <th>Content Hash</th>
          </tr>
        </thead>
        <tbody>
          {snapshots.map((snapshot) => (
            <tr key={snapshot.id}>
              <td>{formatDate(snapshot.captured_at)}</td>
              <td>{snapshot.name}</td>
              <td>{snapshot.source_type}</td>
              <td>{snapshot.items.length}</td>
              <td className="mono">{snapshot.content_hash.slice(0, 16)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function VersionHistory({ versions }: { versions: IssueVersion[] }) {
  return (
    <div className="history">
      <h2>Version History</h2>
      {versions.length === 0 && <div className="empty">No versions</div>}
      {versions.map((version) => (
        <div className="history-item" key={version.id}>
          <div className="history-title">v{version.version_number} {version.name}</div>
          <div>{version.breach_risk} / {version.threat_level ?? '-'}</div>
          <div className="muted">{version.source_type} {formatDate(version.effective_from)}</div>
        </div>
      ))}
    </div>
  )
}

function ImportPreview({ result }: { result: ImportResult | null }) {
  if (!result) {
    return (
      <div className="stack">
        <h2>Import Review</h2>
        <div className="empty">No preview</div>
      </div>
    )
  }

  return (
    <div className="stack">
      <h2>Import Review</h2>
      <dl className="metric-list">
        <Metric label="Action" value={result.snapshot_action} />
        <Metric label="Factors" value={`${result.factors_created} new / ${result.factors_reused} reused`} />
        <Metric label="Issues" value={`${result.issues_created} new / ${result.issues_reused} reused`} />
        <Metric label="Versions" value={`${result.versions_created} new / ${result.versions_reused} reused`} />
        <Metric label="Items" value={String(result.snapshot_items)} />
        <Metric label="Hash" value={result.content_hash.slice(0, 16)} mono />
      </dl>
      {result.warnings.length > 0 && (
        <div className="warnings">
          {result.warnings.map((warning) => <div key={warning}>{warning}</div>)}
        </div>
      )}
    </div>
  )
}

function Metric({ label, value, mono = false }: { label: string, value: string, mono?: boolean }) {
  return (
    <>
      <dt>{label}</dt>
      <dd className={mono ? 'mono' : ''}>{value}</dd>
    </>
  )
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.detail ? JSON.stringify(body.detail) : `HTTP ${response.status}`)
  }
  return response.json()
}

function tabClass(active: Tab, value: Tab) {
  return active === value ? 'tab active' : 'tab'
}

function yesNo(value: boolean) {
  return value ? 'Yes' : 'No'
}

function blankToNull(value: string) {
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

function parseJsonObject(value: string, label: string) {
  const parsed = JSON.parse(value)
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error(`${label} must be a JSON object`)
  }
  return parsed as Record<string, unknown>
}

function buildScanTarget(targetType: string, targetId: string) {
  if (targetType === 'ORGANIZATION') {
    return { target_type: targetType, organization_id: targetId }
  }
  if (targetType === 'DOMAIN') {
    return { target_type: targetType, domain_id: targetId }
  }
  return { target_type: targetType, host_id: targetId }
}

function firstTargetId(
  targetType: string,
  organizations: Organization[],
  domains: DomainAsset[],
  hosts: HostAsset[],
) {
  return targetOptions(targetType, organizations, domains, hosts)[0]?.id ?? ''
}

function targetOptions(
  targetType: string,
  organizations: Organization[],
  domains: DomainAsset[],
  hosts: HostAsset[],
) {
  if (targetType === 'ORGANIZATION') {
    return organizations.map((organization) => ({ id: organization.id, label: organization.name }))
  }
  if (targetType === 'DOMAIN') {
    return domains.map((domain) => ({ id: domain.id, label: domain.name }))
  }
  return hosts.map((host) => ({ id: host.id, label: host.hostname }))
}

function formatDate(value: string) {
  return new Date(value).toLocaleString()
}

function toErrorMessage(err: unknown) {
  if (err instanceof SyntaxError) {
    return 'Invalid JSON'
  }
  return err instanceof Error ? err.message : 'Request failed'
}
