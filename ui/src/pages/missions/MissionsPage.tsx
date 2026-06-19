// @ts-nocheck
import { useState, useEffect, useCallback } from 'react'
import { Target, Play, Pause, XCircle, FileText, Clock, CheckCircle, Loader } from 'lucide-react'
import { useToast } from '../../components/ToastProvider'

export default function MissionsPage() {
  const { pushToast } = useToast()
  const [missions, setMissions] = useState<any[]>([])
  const [prompt, setPrompt] = useState('')
  const [stealth, setStealth] = useState('maximum')
  const [loading, setLoading] = useState(false)

  const fetchMissions = useCallback(async () => {
    try {
      const r = await fetch('/api/orchestrator/missions', { headers: { 'Accept': 'application/json' } }).then(r => r.json())
      if (r.missions) setMissions(r.missions)
    } catch {}
  }, [])

  useEffect(() => { fetchMissions(); const i = setInterval(fetchMissions, 5000); return () => clearInterval(i) }, [fetchMissions])

  async function startMission() {
    if (!prompt) return
    setLoading(true)
    try {
      const r = await fetch('/api/orchestrator/mission', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ prompt, stealth }),
      }).then(r => r.json())
      if (r.mission_id) {
        pushToast({ content: `Mission started! ID: ${r.mission_id}`, type: 'success' })
        setPrompt(''); fetchMissions()
      }
    } catch {}
    setLoading(false)
  }

  async function abortMission(id: string) {
    try {
      await fetch(`/api/orchestrator/mission/${id}/abort`, { method: 'POST', headers: { 'Accept': 'application/json' } })
      pushToast({ content: 'Mission aborted', type: 'error' }); fetchMissions()
    } catch {}
  }

  const statusIcons: any = {
    pending: <Clock size={14} color="var(--text-dim)" />,
    running: <Loader size={14} color="var(--amber)" style={{ animation: 'spin 1s linear infinite' }} />,
    completed: <CheckCircle size={14} color="var(--green)" />,
    failed: <XCircle size={14} color="var(--red)" />,
    aborted: <XCircle size={14} color="var(--orange)" />,
  }

  return (
    <div className="page-content" style={{ padding: '24px 32px', maxWidth: 1000 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24 }}>
        <Target size={20} color="var(--accent)" />
        <h2 style={{ margin: 0, fontSize: 18, color: 'var(--text-h)' }}>Mission Console</h2>
      </div>

      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 24 }}>
        <div style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 12 }}>
          Enter a hacking objective. The AI orchestrator will decompose it, dispatch specialized agents,
          execute through the undetectable layer, and report back — all autonomously.
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input type="text" value={prompt} onChange={e => setPrompt(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && startMission()}
            placeholder="e.g. Hack this IMEI 123456789012345 || Scan target.com for all vulnerabilities || Get admin access to 10.0.0.5"
            style={{ flex: 1, padding: '12px 14px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 14, fontFamily: 'inherit' }} />
          <select value={stealth} onChange={e => setStealth(e.target.value)}
            style={{ padding: '12px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 13, cursor: 'pointer' }}>
            <option value="maximum">Maximum Stealth</option>
            <option value="high">High Stealth</option>
            <option value="medium">Medium Stealth</option>
            <option value="low">Low Stealth</option>
          </select>
          <button onClick={startMission} disabled={loading || !prompt}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '12px 24px', borderRadius: 6, border: 'none', background: 'var(--accent)', color: '#fff', fontSize: 14, cursor: 'pointer', fontFamily: 'inherit', fontWeight: 600, whiteSpace: 'nowrap' }}>
            {loading ? <Loader size={14} /> : <Play size={14} />}
            Start Mission
          </button>
        </div>
      </div>

      <h3 style={{ fontSize: 14, color: 'var(--text-h)', marginBottom: 12 }}>Active & Recent Missions ({missions.length})</h3>
      {missions.length === 0 ? (
        <div style={{ color: 'var(--text-dim)', fontSize: 13, padding: 24, textAlign: 'center' }}>
          No missions yet. Enter a hacking objective above to launch your first autonomous AI mission.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {missions.map((m: any) => (
            <div key={m.id} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 14, display: 'flex', gap: 12, alignItems: 'center' }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500, marginBottom: 4 }}>{m.prompt?.slice(0, 100)}{(m.prompt?.length > 100) ? '...' : ''}</div>
                <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-dim)' }}>
                  <span>ID: {m.id?.slice(0, 14)}</span>
                  <span>Stealth: {m.stealth_level || 'maximum'}</span>
                  <span>Phases: {m.phases_json ? (typeof m.phases_json === 'string' ? JSON.parse(m.phases_json).length : m.phases_json.length) : 0}</span>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {statusIcons[m.status] || <Clock size={14} />}
                <span style={{ fontSize: 12, fontWeight: 600, color: m.status === 'running' ? 'var(--amber)' : m.status === 'completed' ? 'var(--green)' : 'var(--text-dim)', textTransform: 'uppercase' }}>{m.status}</span>
              </div>
              {m.status === 'running' && (
                <button onClick={() => abortMission(m.id)}
                  style={{ padding: '5px 10px', borderRadius: 4, border: '1px solid var(--red)', background: 'transparent', color: 'var(--red)', cursor: 'pointer', fontSize: 11 }}>
                  ABORT
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
