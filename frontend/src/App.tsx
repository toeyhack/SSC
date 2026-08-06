import React, { useEffect, useState } from 'react'

type Factor = {
  id: string
  code: string
  name: string
}

type IssueVersion = {
  id: string
  version_number: number
  name: string
  breach_risk: string
  threat_level: string | null
  affects_score: boolean
}

type IssueType = {
  id: string
  stable_key: string
  is_active: boolean
  factor: Factor | null
  current_version: IssueVersion | null
}

const API_BASE = 'http://localhost:8000'

export default function App() {
  const [issues, setIssues] = useState<IssueType[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function loadCatalog() {
      try {
        const response = await fetch(`${API_BASE}/api/v1/catalog/issues`)
        if (!response.ok) {
          throw new Error(`Catalog request failed with HTTP ${response.status}`)
        }
        const data = await response.json()
        if (!cancelled) {
          setIssues(data)
          setError(null)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unable to load issue catalog')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    loadCatalog()
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <main style={styles.page}>
      <nav style={styles.nav}>
        <strong>Internal Security Rating</strong>
        <span style={styles.navItem}>Issue Catalog</span>
      </nav>

      <section style={styles.header}>
        <h1 style={styles.title}>Issue Catalog</h1>
      </section>

      {loading && <p style={styles.muted}>Loading catalog...</p>}
      {error && <p style={styles.error}>{error}</p>}
      {!loading && !error && issues.length === 0 && (
        <p style={styles.muted}>No catalog issues have been created yet.</p>
      )}

      {!loading && !error && issues.length > 0 && (
        <div style={styles.tableWrap}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Factor</th>
                <th style={styles.th}>Issue Name</th>
                <th style={styles.th}>Breach Risk</th>
                <th style={styles.th}>Threat Level</th>
                <th style={styles.th}>Affects Score</th>
                <th style={styles.th}>Version</th>
                <th style={styles.th}>Active</th>
              </tr>
            </thead>
            <tbody>
              {issues.map((issue) => (
                <tr key={issue.id}>
                  <td style={styles.td}>{issue.factor?.name ?? 'Unassigned'}</td>
                  <td style={styles.td}>{issue.current_version?.name ?? issue.stable_key}</td>
                  <td style={styles.td}>{issue.current_version?.breach_risk ?? '-'}</td>
                  <td style={styles.td}>{issue.current_version?.threat_level ?? '-'}</td>
                  <td style={styles.td}>{issue.current_version ? yesNo(issue.current_version.affects_score) : '-'}</td>
                  <td style={styles.td}>{issue.current_version?.version_number ?? '-'}</td>
                  <td style={styles.td}>{yesNo(issue.is_active)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  )
}

function yesNo(value: boolean) {
  return value ? 'Yes' : 'No'
}

const styles: Record<string, React.CSSProperties> = {
  page: {
    minHeight: '100vh',
    background: '#f6f8fb',
    color: '#162033',
    fontFamily: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  },
  nav: {
    height: 56,
    display: 'flex',
    alignItems: 'center',
    gap: 24,
    padding: '0 24px',
    borderBottom: '1px solid #d7dee8',
    background: '#ffffff',
  },
  navItem: {
    color: '#2d5f8b',
    fontWeight: 600,
  },
  header: {
    padding: '28px 24px 16px',
  },
  title: {
    margin: 0,
    fontSize: 28,
    fontWeight: 700,
  },
  muted: {
    margin: '8px 24px',
    color: '#5d6b7c',
  },
  error: {
    margin: '8px 24px',
    color: '#9a3412',
  },
  tableWrap: {
    margin: '0 24px 32px',
    overflowX: 'auto',
    border: '1px solid #d7dee8',
    background: '#ffffff',
  },
  table: {
    width: '100%',
    minWidth: 860,
    borderCollapse: 'collapse',
  },
  th: {
    padding: '12px 14px',
    textAlign: 'left',
    fontSize: 13,
    fontWeight: 700,
    borderBottom: '1px solid #d7dee8',
    background: '#eef3f8',
  },
  td: {
    padding: '12px 14px',
    borderBottom: '1px solid #edf1f5',
    fontSize: 14,
    verticalAlign: 'top',
  },
}
