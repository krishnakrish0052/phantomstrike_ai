// @ts-nocheck
import { useState } from 'react'
import { Send, Globe, Copy, ArrowRight } from 'lucide-react'
import { api } from '../api/endpoints'
import type { HttpFrameworkResponse } from '../api/types'
import { CollapsibleSection } from './CollapsibleSection'

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const

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
    color: 'var(--green)',
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
    background: 'var(--green-dim)',
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
    boxSizing: 'border-box' as const,
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
    background: 'var(--green)',
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
  loadingText: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '13px',
    color: 'var(--text-dim)',
  },
  responsePanel: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '12px',
  },
  statusRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  },
  statusCode: {
    fontWeight: 600,
    fontSize: '14px',
    padding: '4px 12px',
    borderRadius: 'var(--radius-sm)',
    fontFamily: 'var(--mono)',
  },
  statusOk: {
    background: 'var(--green-dim)',
    color: 'var(--green)',
    border: '1px solid var(--green)',
  },
  statusRedirect: {
    background: 'var(--cyan-dim)',
    color: 'var(--cyan)',
    border: '1px solid var(--cyan)',
  },
  statusClientErr: {
    background: 'var(--amber-dim)',
    color: 'var(--amber)',
    border: '1px solid var(--amber)',
  },
  statusServerErr: {
    background: 'var(--red-dim)',
    color: 'var(--red)',
    border: '1px solid var(--red)',
  },
  statusDefault: {
    background: 'var(--white-dim)',
    color: 'var(--text-dim)',
    border: '1px solid var(--border)',
  },
  metaText: {
    fontSize: '12px',
    color: 'var(--text-dim)',
  },
  responseSection: {
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    overflow: 'hidden',
  },
  responseBodyHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '6px 12px',
    background: 'var(--bg-card2)',
    borderBottom: '1px solid var(--border)',
  },
  responseBodyLabel: {
    fontSize: '11px',
    fontWeight: 600,
    color: 'var(--text-dim)',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
  },
  responsePre: {
    margin: 0,
    padding: '14px',
    fontSize: '12px',
    fontFamily: 'var(--mono)',
    color: 'var(--text-h)',
    whiteSpace: 'pre-wrap' as const,
    wordBreak: 'break-all' as const,
    lineHeight: 1.55,
    overflowX: 'auto' as const,
    maxHeight: '480px',
    overflowY: 'auto' as const,
    background: 'var(--bg)',
  },
  copyBtn: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
    background: 'transparent',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-xs)',
    color: 'var(--text-dim)',
    padding: '3px 8px',
    fontSize: '11px',
    fontFamily: 'var(--sans)',
    cursor: 'pointer',
    transition: 'color 0.15s, border-color 0.15s',
  },
  copyBtnSuccess: {
    color: 'var(--green)',
    borderColor: 'var(--green)',
  },
  headerTable: {
    width: '100%',
    borderCollapse: 'collapse' as const,
    fontSize: '12px',
    fontFamily: 'var(--mono)',
  },
  headerTh: {
    textAlign: 'left' as const,
    padding: '4px 12px',
    fontWeight: 600,
    color: 'var(--text-dim)',
    fontSize: '11px',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
  },
  headerTd: {
    padding: '3px 12px',
    color: 'var(--text-h)',
    borderTop: '1px solid var(--border)',
    wordBreak: 'break-all' as const,
  },
}

function statusBadgeStyle(code: number): React.CSSProperties {
  if (code >= 200 && code < 300) return { ...styles.statusCode, ...styles.statusOk }
  if (code >= 300 && code < 400) return { ...styles.statusCode, ...styles.statusRedirect }
  if (code >= 400 && code < 500) return { ...styles.statusCode, ...styles.statusClientErr }
  if (code >= 500) return { ...styles.statusCode, ...styles.statusServerErr }
  return { ...styles.statusCode, ...styles.statusDefault }
}

export function HTTPRepeater() {
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState<string>('GET')
  const [headers, setHeaders] = useState('')
  const [body, setBody] = useState('')
  const [response, setResponse] = useState<HttpFrameworkResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const handleSend = async () => {
    setError(null)
    setResponse(null)

    if (!url.trim()) {
      setError('URL is required')
      return
    }

    let parsedHeaders: Record<string, string> | undefined
    if (headers.trim()) {
      parsedHeaders = {}
      const lines = headers.split('\n').filter(Boolean)
      for (const line of lines) {
        const idx = line.indexOf(':')
        if (idx > 0) {
          const key = line.slice(0, idx).trim()
          const value = line.slice(idx + 1).trim()
          if (key) parsedHeaders[key] = value
        }
      }
    }

    setLoading(true)
    try {
      const res = await api.httpFramework.repeater({
        url: url.trim(),
        method: method || 'GET',
        headers: parsedHeaders,
        data: body.trim() || undefined,
      })
      setResponse(res)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Request failed'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = () => {
    if (!response?.response?.content) return
    navigator.clipboard.writeText(response.response.content).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const statusCode = response?.response?.status_code
  const responseHeaders = response?.response?.headers ?? {}
  const responseBody = response?.response?.content ?? ''
  const responseTime = response?.response?.time
  const responseSize = response?.response?.size

  return (
    <div style={styles.wrapper}>
      {/* Header */}
      <div style={styles.header}>
        <Globe size={18} style={styles.headerIcon} />
        <h2 style={styles.headerTitle}>HTTP Repeater</h2>
        <span style={styles.headerBadge}>Request Builder</span>
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
            {METHODS.map(m => (
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

      {/* Headers textarea */}
      <div>
        <div style={{ ...styles.label, marginBottom: 4 }}>Headers</div>
        <textarea
          style={styles.textarea}
          placeholder={'Content-Type: application/json\nAuthorization: Bearer token'}
          value={headers}
          onChange={e => setHeaders(e.target.value)}
        />
        <span style={styles.hint}>One header per line (Key: Value)</span>
      </div>

      {/* Body textarea (hidden for GET) */}
      {method !== 'GET' && (
        <div>
          <div style={{ ...styles.label, marginBottom: 4 }}>Request Body</div>
          <textarea
            style={{ ...styles.textarea, minHeight: '100px' }}
            placeholder='{"key": "value"}'
            value={body}
            onChange={e => setBody(e.target.value)}
          />
        </div>
      )}

      {/* Send button */}
      <div>
        <button
          style={{ ...styles.btn, ...(loading ? styles.btnDisabled : {}) }}
          onClick={handleSend}
          disabled={loading}
        >
          <Send size={14} />
          {loading ? 'Sending...' : 'Send Request'}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div style={styles.error}>{error}</div>
      )}

      {/* Response panel */}
      {response && statusCode && (
        <div style={styles.responsePanel}>
          {/* Status badge row */}
          <div style={styles.statusRow}>
            <span style={statusBadgeStyle(statusCode)}>
              {statusCode}
            </span>
            {responseTime !== undefined && (
              <span style={styles.metaText}>
                {responseTime.toFixed(2)}s
              </span>
            )}
            {responseSize !== undefined && (
              <span style={styles.metaText}>
                {responseSize.toLocaleString()} bytes
              </span>
            )}
          </div>

          {/* Response headers (collapsible) */}
          {Object.keys(responseHeaders).length > 0 && (
            <CollapsibleSection title="Response Headers" defaultOpen={false}>
              <table style={styles.headerTable}>
                <thead>
                  <tr>
                    <th style={styles.headerTh}>Header</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(responseHeaders).map(([key, value]) => (
                    <tr key={key}>
                      <td style={styles.headerTd}>
                        <strong>{key}</strong>: {value}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CollapsibleSection>
          )}

          {/* Response body */}
          {responseBody && (
            <div style={styles.responseSection}>
              <div style={styles.responseBodyHeader}>
                <span style={styles.responseBodyLabel}>
                  Response Body
                </span>
                <button
                  style={{
                    ...styles.copyBtn,
                    ...(copied ? styles.copyBtnSuccess : {}),
                  }}
                  onClick={handleCopy}
                  title="Copy response body"
                >
                  <Copy size={11} />
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre style={styles.responsePre}>{responseBody}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
