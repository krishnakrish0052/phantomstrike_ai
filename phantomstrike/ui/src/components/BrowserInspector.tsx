// @ts-nocheck
import React, { useState } from 'react'
import { Globe, Camera, Shield, Code, AlertCircle, Wifi } from 'lucide-react'
import { api } from '../api'
import type { BrowserAgentResponse, PageInfo, SecurityAnalysis } from '../api/types'

type TabId = 'info' | 'forms' | 'links' | 'scripts' | 'security' | 'network'

const TABS: { id: TabId; label: string; icon: React.ReactNode }[] = [
  { id: 'info', label: 'Page Info', icon: <Globe size={14} /> },
  { id: 'forms', label: 'Forms', icon: <Code size={14} /> },
  { id: 'links', label: 'Links', icon: <Wifi size={14} /> },
  { id: 'scripts', label: 'Scripts', icon: <Code size={14} /> },
  { id: 'security', label: 'Security', icon: <Shield size={14} /> },
  { id: 'network', label: 'Network', icon: <Wifi size={14} /> },
]

function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return 'var(--red)'
    case 'high': return 'var(--orange)'
    case 'medium': return 'var(--amber)'
    case 'low': return 'var(--green)'
    case 'info': return 'var(--blue)'
    default: return 'var(--text-dim)'
  }
}

function securityScoreColor(score: number): string {
  if (score >= 80) return 'var(--green)'
  if (score >= 50) return 'var(--amber)'
  return 'var(--red)'
}

function PageInfoTab({ info }: { info: PageInfo }) {
  return (
    <div className="bi-section">
      <div className="bi-field">
        <span className="bi-field-label">Title</span>
        <span className="bi-field-value">{info.title || '—'}</span>
      </div>
      <div className="bi-field">
        <span className="bi-field-label">URL</span>
        <span className="bi-field-value mono">{info.url}</span>
      </div>
      {info.cookies && info.cookies.length > 0 && (
        <div className="bi-subsection">
          <div className="bi-subsection-title">Cookies ({info.cookies.length})</div>
          <div className="bi-table-wrap">
            <table className="bi-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Value</th>
                  <th>Domain</th>
                </tr>
              </thead>
              <tbody>
                {info.cookies.map((c, i) => (
                  <tr key={i}>
                    <td className="mono">{c.name}</td>
                    <td className="mono" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.value}</td>
                    <td className="mono">{c.domain}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

function FormsTab({ info }: { info: PageInfo }) {
  const forms = info.forms || []
  if (forms.length === 0) return <div className="bi-empty">No forms found</div>
  return (
    <div className="bi-table-wrap">
      <table className="bi-table">
        <thead>
          <tr>
            <th>Action</th>
            <th>Method</th>
            <th>Inputs</th>
          </tr>
        </thead>
        <tbody>
          {forms.map((f, i) => (
            <tr key={i}>
              <td className="mono" style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.action || '—'}</td>
              <td><span className={`bi-method-badge bi-method-${(f.method || 'get').toLowerCase()}`}>{f.method || 'GET'}</span></td>
              <td>{f.inputs?.length ?? 0}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function LinksTab({ info }: { info: PageInfo }) {
  const links = info.links || []
  if (links.length === 0) return <div className="bi-empty">No links found</div>
  return (
    <div className="bi-table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
      <table className="bi-table">
        <thead>
          <tr>
            <th>Text</th>
            <th>Href</th>
          </tr>
        </thead>
        <tbody>
          {links.map((l, i) => (
            <tr key={i}>
              <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.text || '—'}</td>
              <td className="mono" style={{ maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.href}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ScriptsTab({ info }: { info: PageInfo }) {
  const scripts = info.scripts || []
  if (scripts.length === 0) return <div className="bi-empty">No scripts found</div>
  return (
    <div className="bi-table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
      <table className="bi-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Source / Preview</th>
          </tr>
        </thead>
        <tbody>
          {scripts.map((s, i) => (
            <tr key={i}>
              <td><span className="bi-script-badge">{s.type}</span></td>
              <td className="mono" style={{ maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {s.type === 'external' ? s.src : (s.content || '').substring(0, 120)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SecurityTab({ analysis }: { analysis: SecurityAnalysis }) {
  const score = analysis.security_score
  const col = securityScoreColor(score)
  const radius = 36
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  return (
    <div className="bi-section">
      <div className="bi-score-gauge">
        <svg width={96} height={96} viewBox="0 0 96 96">
          <circle cx={48} cy={48} r={radius} fill="none" stroke="var(--border)" strokeWidth={6} />
          <circle
            cx={48} cy={48} r={radius}
            fill="none" stroke={col} strokeWidth={6}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform="rotate(-90 48 48)"
            style={{ transition: 'stroke-dashoffset 0.6s ease' }}
          />
          <text x={48} y={52} textAnchor="middle" fontSize={20} fontWeight={700} fill={col}>
            {score}
          </text>
        </svg>
      </div>

      <div className="bi-issues-header">
        <AlertCircle size={14} /> {analysis.total_issues} issue{analysis.total_issues !== 1 ? 's' : ''} found
      </div>

      {analysis.issues.length === 0 ? (
        <div className="bi-empty">No security issues detected</div>
      ) : (
        <div className="bi-issues-list">
          {analysis.issues.map((issue, i) => (
            <div key={i} className="bi-issue-card">
              <div className="bi-issue-top">
                <span className="bi-severity-badge" style={{ background: severityColor(issue.severity) }}>
                  {issue.severity}
                </span>
                <span className="bi-issue-type">{issue.type}</span>
              </div>
              <div className="bi-issue-desc">{issue.description}</div>
              {(issue.location || issue.form_action || issue.header) && (
                <div className="bi-issue-meta">
                  {issue.location && <span>Location: <code>{issue.location}</code></span>}
                  {issue.form_action && <span>Form: <code>{issue.form_action}</code></span>}
                  {issue.header && <span>Header: <code>{issue.header}</code></span>}
                  {issue.count != null && <span>Count: {issue.count}</span>}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function NetworkTab({ info }: { info: PageInfo }) {
  const reqs = info.network_requests || []
  if (reqs.length === 0) return <div className="bi-empty">No network requests captured</div>
  return (
    <div className="bi-table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
      <table className="bi-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>Status</th>
            <th>Type</th>
          </tr>
        </thead>
        <tbody>
          {reqs.map((r, i) => (
            <tr key={i}>
              <td className="mono" style={{ maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.url}</td>
              <td>
                <span className="bi-status-badge" style={{
                  background: r.status >= 400 ? 'var(--red)' : r.status >= 300 ? 'var(--amber)' : 'var(--green)',
                }}>
                  {r.status}
                </span>
              </td>
              <td className="mono" style={{ fontSize: 11 }}>{r.mimeType || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function BrowserInspector() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<BrowserAgentResponse | null>(null)
  const [activeTab, setActiveTab] = useState<TabId>('info')
  const [error, setError] = useState<string | null>(null)

  async function handleInspect() {
    const target = url.trim()
    if (!target) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await api.browserAgent.inspect(target)
      setResult(res)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Inspection failed')
    } finally {
      setLoading(false)
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter') handleInspect()
  }

  const pageInfo = result?.page_info
  const security = result?.security_analysis

  return (
    <div className="browser-inspector" style={{ maxWidth: 1000 }}>
      {/* ── URL Bar ─────────────────────────────────────────────────────── */}
      <div className="bi-url-bar">
        <Globe size={16} style={{ color: 'var(--text-dim)', flexShrink: 0 }} />
        <input
          className="bi-url-input"
          type="text"
          placeholder="https://example.com"
          value={url}
          onChange={e => setUrl(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={loading}
        />
        <button className="bi-inspect-btn" onClick={handleInspect} disabled={loading || !url.trim()}>
          {loading ? (
            <>
              <div className="bi-spinner" />
              Inspecting…
            </>
          ) : (
            <>
              <Camera size={14} />
              Inspect
            </>
          )}
        </button>
      </div>

      {/* ── Error ───────────────────────────────────────────────────────── */}
      {error && (
        <div className="bi-error">
          <AlertCircle size={14} />
          {error}
        </div>
      )}

      {/* ── Screenshot ──────────────────────────────────────────────────── */}
      {result?.screenshot && (
        <div className="bi-screenshot">
          <img src={`data:image/png;base64,${result.screenshot}`} alt="Page screenshot" />
        </div>
      )}

      {/* ── Result Area ─────────────────────────────────────────────────── */}
      {result && (
        <div className="bi-result">
          {/* ── Tab bar ─────────────────────────────────────────────────── */}
          <div className="bi-tabs">
            {TABS.map(tab => (
              <button
                key={tab.id}
                className={`bi-tab${activeTab === tab.id ? ' active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.icon}
                <span>{tab.label}</span>
              </button>
            ))}
          </div>

          {/* ── Tab content ─────────────────────────────────────────────── */}
          <div className="bi-tab-content">
            {activeTab === 'info' && pageInfo && <PageInfoTab info={pageInfo} />}
            {activeTab === 'forms' && pageInfo && <FormsTab info={pageInfo} />}
            {activeTab === 'links' && pageInfo && <LinksTab info={pageInfo} />}
            {activeTab === 'scripts' && pageInfo && <ScriptsTab info={pageInfo} />}
            {activeTab === 'security' && security && <SecurityTab analysis={security} />}
            {activeTab === 'network' && pageInfo && <NetworkTab info={pageInfo} />}
          </div>
        </div>
      )}
    </div>
  )
}
