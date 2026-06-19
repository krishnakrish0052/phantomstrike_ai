// @ts-nocheck
// @ts-nocheck
import { useState } from 'react'
import { Globe, Send, Crosshair, Target, History } from 'lucide-react'
import { api } from '../../api'
import { HTTPRepeater } from '../../components/HTTPRepeater'
import { HTTPIntruder } from '../../components/HTTPIntruder'
import { ScopeEditor } from '../../components/ScopeEditor'

export default function HttpFrameworkPage() {
  const [tab, setTab] = useState<'repeater'|'intruder'|'spider'|'scope'|'history'>('repeater')
  const [spiderUrl, setSpiderUrl] = useState('')
  const [spiderDepth, setSpiderDepth] = useState(3)
  const [spiderPages, setSpiderPages] = useState(100)
  const [spiderResult, setSpiderResult] = useState<any>(null)
  const [spiderLoading, setSpiderLoading] = useState(false)
  const [history, setHistory] = useState<any>(null)
  const [historyLoading, setHistoryLoading] = useState(false)

  async function handleSpider() {
    if (!spiderUrl) return
    setSpiderLoading(true)
    try { const r = await api.httpFramework.spider(spiderUrl, spiderDepth, spiderPages); setSpiderResult(r) } catch {}
    setSpiderLoading(false)
  }

  async function loadHistory() {
    setHistoryLoading(true)
    try { const r = await api.httpFramework.history(); setHistory(r) } catch {}
    setHistoryLoading(false)
  }

  const tabs = [
    { id: 'repeater', label: 'Repeater', icon: <Send size={14} /> },
    { id: 'intruder', label: 'Intruder', icon: <Crosshair size={14} /> },
    { id: 'spider', label: 'Spider', icon: <Globe size={14} /> },
    { id: 'scope', label: 'Scope', icon: <Target size={14} /> },
    { id: 'history', label: 'History', icon: <History size={14} /> },
  ] as const

  return (
    <div className="page-content" style={{ padding: '24px 32px', maxWidth: 1000 }}>
      <div style={{ display: 'flex', gap: 24, marginBottom: 24 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => { setTab(t.id); if (t.id === 'history') loadHistory() }}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '6px 14px', border: 'none', borderRadius: 6,
              cursor: 'pointer', fontSize: 13, fontFamily: 'inherit',
              background: tab === t.id ? 'var(--accent)' : 'var(--bg-card2)',
              color: tab === t.id ? '#fff' : 'var(--text)' }}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {tab === 'repeater' && <HTTPRepeater />}
      {tab === 'intruder' && <HTTPIntruder />}
      {tab === 'scope' && <ScopeEditor onScopeChange={(host, inc) => api.httpFramework.setScope({ host, include_subdomains: inc })} />}

      {tab === 'spider' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 900 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'end' }}>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Base URL</label>
              <input type="text" value={spiderUrl} onChange={e => setSpiderUrl(e.target.value)}
                style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 13 }} placeholder="https://target.com" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Max Depth</label>
              <input type="number" value={spiderDepth} onChange={e => setSpiderDepth(+e.target.value)} min={1} max={10}
                style={{ width: 70, padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 13 }} />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Max Pages</label>
              <input type="number" value={spiderPages} onChange={e => setSpiderPages(+e.target.value)} min={10} max={500}
                style={{ width: 70, padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 13 }} />
            </div>
            <button onClick={handleSpider} disabled={spiderLoading || !spiderUrl}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 6, border: 'none',
                background: 'var(--accent)', color: '#fff', fontSize: 13, cursor: 'pointer', fontFamily: 'inherit', fontWeight: 600 }}>
              {spiderLoading ? '⟳' : <Globe size={14} />} Start Spider
            </button>
          </div>
          {spiderResult?.success && (
            <div>
              <div style={{ fontSize: 13, color: 'var(--green)', marginBottom: 8 }}>Found {spiderResult.total_pages} pages, {spiderResult.forms?.length || 0} forms</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {spiderResult.discovered_urls?.slice(0, 50).map((u: string, i: number) => (
                  <span key={i} style={{ fontSize: 11, background: 'var(--bg-card2)', padding: '2px 8px', borderRadius: 4, color: 'var(--text)', fontFamily: 'monospace', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{u}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'history' && (
        <div>
          <h3 style={{ fontSize: 15, color: 'var(--text-h)', margin: '0 0 16px' }}>Proxy History ({history?.total_requests || 0} requests)</h3>
          {history?.history?.slice(-50).reverse().map((entry: any, i: number) => (
            <div key={i} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px', marginBottom: 6, display: 'flex', gap: 12, alignItems: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent)', minWidth: 40 }}>{entry.request?.method}</span>
              <span style={{ fontSize: 12, color: 'var(--text)', flex: 1, fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entry.request?.url}</span>
              <span style={{ fontSize: 12, padding: '2px 8px', borderRadius: 4, background: entry.response?.status_code < 400 ? 'var(--green-dim)' : 'var(--red-dim)', color: entry.response?.status_code < 400 ? 'var(--green)' : 'var(--red)', fontWeight: 600 }}>{entry.response?.status_code}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
