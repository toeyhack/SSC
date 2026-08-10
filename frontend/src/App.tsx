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

type Tab = 'issues' | 'factors' | 'snapshots' | 'baseline'

const API_BASE = 'http://localhost:8000'
const riskOptions = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'POSITIVE', 'UNKNOWN']
const sourceOptions = ['MANUAL', 'SSC_LICENSED_UI']

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

export default function App() {
  const [tab, setTab] = useState<Tab>('issues')
  const [factors, setFactors] = useState<Factor[]>([])
  const [issues, setIssues] = useState<IssueType[]>([])
  const [snapshots, setSnapshots] = useState<Snapshot[]>([])
  const [versions, setVersions] = useState<IssueVersion[]>([])
  const [selectedIssueId, setSelectedIssueId] = useState<string | null>(null)
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

  const selectedIssue = useMemo(
    () => issues.find((issue) => issue.id === selectedIssueId) ?? null,
    [issues, selectedIssueId],
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

  async function refreshAll() {
    setLoading(true)
    try {
      const [factorData, issueData, snapshotData] = await Promise.all([
        api<Factor[]>('/api/v1/catalog/factors'),
        api<IssueType[]>('/api/v1/catalog/issues'),
        api<Snapshot[]>('/api/v1/catalog/snapshots'),
      ])
      setFactors(factorData)
      setIssues(issueData)
      setSnapshots(snapshotData)
      setIssueForm((current) => ({
        ...current,
        factor_id: current.factor_id || factorData[0]?.id || '',
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
        </div>
      </nav>

      <header className="workspace-header">
        <h1>Catalog Administration</h1>
        <div className="status-line">
          {loading ? 'Loading catalog' : `${issues.length} issues, ${factors.length} factors, ${snapshots.length} snapshots`}
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

function formatDate(value: string) {
  return new Date(value).toLocaleString()
}

function toErrorMessage(err: unknown) {
  if (err instanceof SyntaxError) {
    return 'Invalid JSON'
  }
  return err instanceof Error ? err.message : 'Request failed'
}
