// @ts-nocheck
import { useState, useMemo } from 'react'
import { Crosshair, Zap, List } from 'lucide-react'
import { api } from '../api/endpoints'
import type { HttpIntruderResult } from '../api/types'

type SortField = 'param' | 'payload' | 'status_code' | 'size' | 'reflected'
type SortDir = 'asc' | 'desc'

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const
const LOCATION_OPTIONS = [
  { value: 'query', label: 'Query String' },
  { value: 'body', label: 'Request Body' },
  { value: 'headers', label: 'Headers' },
  { value: 'cookie', label: 'Cookies' },
] as const

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    padding: '16px 0',
    fontFamily: 'var(--sans)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  },
  headerIcon: {
    color: 'var(--cyan)',
    flexShrink: 0,
  },
  headerTitle: {
    fontSize: '16px',
    fontWeight: 600,
    color: 'var(--text-h)',
    margin: 0,
  },
  headerBadge: {
    fontSize: '11px',
    color: 'var(--text-dim)',
    background: 'var(--cyan-dim)',
    padding: '2px 8px',
    borderRadius: 'var(--radius-xs)',
    fontWeight: 500,
  },
  row: {
    display: 'flex',
    gap: '10px',
    flexWrap: 'wrap' as const,
    alignItems: 'flex-end',
  },
  field: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '4px',
  },
  label: {
    fontSize: '12px',
    fontWeight: 500,
    color: 'var(--text-dim)',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
  },
  input: {
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-h)',
    padding: '7px 10px',
    fontSize: '13px',
    fontFamily: 'var(--mono)',
    outline: 'none',
    minWidth: '200px',
    transition: 'border-color 0.15s',
  },
  select: {
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-h)',
    padding: '7px 10px',
    fontSize: '13px',
    fontFamily: 'var(--mono)',
    outline: 'none',
    cursor: 'pointer',
  },
  textarea: {
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-h)',
    padding: '8px 10px',
    fontSize: '13px',
    fontFamily: 'var(--mono)',
    outline: 'none',
    resize: 'vertical' as const,
    minHeight: '80px',
    width: '100%',
    transition: 'border-color 0.15s',
  },
  textareaLabel: {
    fontSize: '12px',
    fontWeight: 500,
    color: 'var(--text-dim)',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
    marginBottom: '4px',
  },
  hint: {
    fontSize: '11px',
    color: 'var(--text-dim)',
    marginTop: '2px',
  },
  btn: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    background: 'var(--cyan)',
    color: 'var(--bg)',
    border: 'none',
    borderRadius: 'var(--radius-sm)',
    padding: '8px 18px',
    fontSize: '13px',
    fontWeight: 600,
    cursor: 'pointer',
    fontFamily: 'var(--sans)',
    transition: 'opacity 0.15s',
    whiteSpace: 'nowrap' as const,
    height: 'fit-content',
  },
  btnDisabled: {
    opacity: 0.5,
    cursor: 'not-allowed',
  },
  error: {
    background: 'var(--red-dim)',
    border: '1px solid var(--red)',
    borderRadius: 'var(--radius-sm)',
    padding: '10px 14px',
    color: 'var(--red)',
    fontSize: '13px',
  },
  summary: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '8px 0',
    fontSize: '13px',
    color: 'var(--text)',
  },
  summaryCount: {
    fontWeight: 600,
    color: 'var(--text-h)',
  },
  summaryInteresting: {
    fontWeight: 600,
    color: 'var(--amber)',
  },
  tableWrap: {
    maxHeight: '400px',
    overflowY: 'auto' as const,
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse' as const,
    fontSize: '13px',
    fontFamily: 'var(--mono)',
  },
  th: {
    position: 'sticky' as const,
    top: 0,
    background: 'var(--bg-card2)',
    padding: '8px 12px',
    textAlign: 'left' as const,
    fontSize: '11px',
    fontWeight: 600,
    color: 'var(--text-dim)',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
    borderBottom: '1px solid var(--border)',
    cursor: 'pointer',
    userSelect: 'none' as const,
    whiteSpace: 'nowrap' as const,
  },
  thSorted: {
    color: 'var(--cyan)',
  },
  td: {
    padding: '7px 12px',
    borderBottom: '1px solid var(--border)',
    color: 'var(--text)',
    whiteSpace: 'nowrap' as const,
  },
  trInteresting: {
    background: 'var(--amber-dim)',
  },
  badgeYes: {
    display: 'inline-block',
    background: 'var(--amber-dim)',
    color: 'var(--amber)',
    padding: '1px 8px',
    borderRadius: 'var(--radius-xs)',
    fontSize: '11px',
    fontWeight: 600,
  },
  badgeNo: {
    display: 'inline-block',
    background: 'var(--white-dim)',
    color: 'var(--text-dim)',
    padding: '1px 8px',
    borderRadius: 'var(--radius-xs)',
    fontSize: '11px',
  },
  sortIcon: {
    fontSize: '10px',
    marginLeft: '3px',
    verticalAlign: 'middle' as const,
  },
}

export function HTTPIntruder() {
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState<string>('GET')
  const [location, setLocation] = useState<string>('query')
  const [params, setParams] = useState('')
  const [payloads, setPayloads] = useState('')
  const [results, setResults] = useState<HttpIntruderResult[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tested, setTested] = useState(0)
  const [sortField, setSortField] = useState<SortField | null>(null)
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }

  const sortedResults = useMemo(() => {
    if (!sortField) return results
    const dir = sortDir === 'asc' ? 1 : -1
    return [...results].sort((a, b) => {
      const av = a[sortField]
      const bv = b[sortField]
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir
      if (typeof av === 'boolean' && typeof bv === 'boolean') return (av === bv ? 0 : av ? 1 : -1) * dir
      return String(av).localeCompare(String(bv)) * dir
    })
  }, [results, sortField, sortDir])

  const sortIndicator = (field: SortField) => {
    if (sortField !== field) return <span style={styles.sortIcon}>&#8201;</span>
    return <span style={styles.sortIcon}>{sortDir === 'asc' ? '▲' : '▼'}</span>
  }

  const handleStart = async () => {
    setError(null)
    setResults([])
    setTested(0)

    const paramList = params
      .split(',')
      .map(p => p.trim())
      .filter(Boolean)

    const payloadList = payloads
      .split('\n')
      .map(p => p.trim())
      .filter(Boolean)

    if (!url.trim()) {
      setError('URL is required')
      return
    }
    if (paramList.length === 0) {
      setError('At least one parameter is required')
      return
    }
    if (payloadList.length === 0) {
      setError('At least one payload is required')
      return
    }

    setLoading(true)
    try {
      const res = await api.httpFramework.intruder({
        url: url.trim(),
        method: method || 'GET',
        location: location as 'query' | 'body' | 'headers' | 'cookie',
        params: paramList,
        payloads: payloadList,
      })
      if (res.success) {
        setResults(res.interesting)
        setTested(res.tested)
      } else {
        setError(res.error || 'Intruder returned no results')
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Request failed'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const interestingCount = results.filter(r => r.reflected).length

  return (
    <div style={styles.wrapper}>
      {/* Header */}
      <div style={styles.header}>
        <Crosshair size={18} style={styles.headerIcon} />
        <h2 style={styles.headerTitle}>HTTP Intruder</h2>
        <span style={styles.headerBadge}>Fuzzer</span>
      </div>

      {/* URL + Method row */}
      <div style={styles.row}>
        <div style={styles.field}>
          <span style={styles.label}>Method</span>
          <select
            style={styles.select}
            value={method}
            onChange={e => setMethod(e.target.value)}
          >
            {METHOD_OPTIONS.map(m => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
        </div>
        <div style={{ ...styles.field, flex: 1 }}>
          <span style={styles.label}>Target URL</span>
          <input
            style={{ ...styles.input, width: '100%' }}
            type="text"
            placeholder="https://example.com/api/endpoint"
            value={url}
            onChange={e => setUrl(e.target.value)}
          />
        </div>
      </div>

      {/* Location + Params row */}
      <div style={styles.row}>
        <div style={styles.field}>
          <span style={styles.label}>Injection Location</span>
          <select
            style={styles.select}
            value={location}
            onChange={e => setLocation(e.target.value)}
          >
            {LOCATION_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>
        <div style={{ ...styles.field, flex: 1 }}>
          <span style={styles.label}>Parameters</span>
          <input
            style={{ ...styles.input, width: '100%' }}
            type="text"
            placeholder="q, search, id (comma separated)"
            value={params}
            onChange={e => setParams(e.target.value)}
          />
          <span style={styles.hint}>Comma-separated parameter names to fuzz</span>
        </div>
      </div>

      {/* Payloads textarea */}
      <div>
        <div style={styles.textareaLabel}>
          <List size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} />
          Payloads
        </div>
        <textarea
          style={styles.textarea}
          placeholder={"' OR 1=1--\n<script>alert(1)</script>\n../../etc/passwd\n${7*7}"}
          value={payloads}
          onChange={e => setPayloads(e.target.value)}
        />
        <span style={styles.hint}>One payload per line</span>
      </div>

      {/* Start button */}
      <div>
        <button
          style={{ ...styles.btn, ...(loading ? styles.btnDisabled : {}) }}
          onClick={handleStart}
          disabled={loading}
        >
          <Zap size={14} />
          {loading ? 'Fuzzing...' : 'Start Fuzzing'}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div style={styles.error}>{error}</div>
      )}

      {/* Results summary */}
      {results.length > 0 && (
        <>
          <div style={styles.summary}>
            <Crosshair size={14} style={{ color: 'var(--cyan)' }} />
            <span>
              <span style={styles.summaryCount}>{results.length}</span> of{' '}
              <span style={styles.summaryCount}>{tested}</span> requests produced interesting results
              {interestingCount > 0 && (
                <> &mdash; <span style={styles.summaryInteresting}>{interestingCount} reflected</span></>
              )}
            </span>
          </div>

          {/* Results table */}
          <div style={styles.tableWrap}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th
                    style={{ ...styles.th, ...(sortField === 'param' ? styles.thSorted : {}) }}
                    onClick={() => handleSort('param')}
                  >
                    Param{sortIndicator('param')}
                  </th>
                  <th
                    style={{ ...styles.th, ...(sortField === 'payload' ? styles.thSorted : {}) }}
                    onClick={() => handleSort('payload')}
                  >
                    Payload{sortIndicator('payload')}
                  </th>
                  <th
                    style={{ ...styles.th, ...(sortField === 'status_code' ? styles.thSorted : {}) }}
                    onClick={() => handleSort('status_code')}
                  >
                    Status{sortIndicator('status_code')}
                  </th>
                  <th
                    style={{ ...styles.th, ...(sortField === 'size' ? styles.thSorted : {}) }}
                    onClick={() => handleSort('size')}
                  >
                    Size{sortIndicator('size')}
                  </th>
                  <th
                    style={{ ...styles.th, ...(sortField === 'reflected' ? styles.thSorted : {}) }}
                    onClick={() => handleSort('reflected')}
                  >
                    Reflected{sortIndicator('reflected')}
                  </th>
                </tr>
              </thead>
              <tbody>
                {sortedResults.map((r, i) => (
                  <tr key={i} style={r.reflected ? styles.trInteresting : undefined}>
                    <td style={styles.td}>{r.param}</td>
                    <td style={{ ...styles.td, color: 'var(--text-h)' }}>{r.payload}</td>
                    <td style={styles.td}>{r.status_code}</td>
                    <td style={styles.td}>{r.size.toLocaleString()}</td>
                    <td style={styles.td}>
                      {r.reflected ? (
                        <span style={styles.badgeYes}>Yes</span>
                      ) : (
                        <span style={styles.badgeNo}>No</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
