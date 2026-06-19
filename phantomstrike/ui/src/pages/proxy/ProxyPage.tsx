// @ts-nocheck
import { useState, useEffect, useCallback } from 'react'
import { Shield, RotateCw, Activity, Wifi, WifiOff, Zap } from 'lucide-react'
import { api } from '../../api'
import { useToast } from '../../components/ToastProvider'

export default function ProxyPage() {
  const { pushToast } = useToast()
  const [status, setStatus] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const fetchStatus = useCallback(async () => {
    try {
      const r = await (fetch('/api/undetectable/proxy/status', { headers: { 'Accept': 'application/json' } }).then(r => r.json()))
      setStatus(r)
    } catch {}
  }, [])

  useEffect(() => { fetchStatus(); const i = setInterval(fetchStatus, 5000); return () => clearInterval(i) }, [fetchStatus])

  async function startProxy() {
    setLoading(true)
    try {
      const r = await (fetch('/api/undetectable/proxy/start', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: JSON.stringify({ stealth: 'maximum', strategy: 'per_request' }) }).then(r => r.json()))
      if (r.success) { pushToast({ content: 'Phantom Proxy started — all tools now undetectable', type: 'success' }); fetchStatus() }
      else pushToast({ content: r.error || 'Failed to start', type: 'error' })
    } catch {}
    setLoading(false)
  }

  async function stopProxy() {
    setLoading(true)
    try {
      await fetch('/api/undetectable/proxy/stop', { method: 'POST', headers: { 'Accept': 'application/json' } })
      pushToast({ content: 'Proxy stopped', type: 'info' }); fetchStatus()
    } catch {}
    setLoading(false)
  }

  async function rotateCircuit() {
    try {
      const r = await (fetch('/api/undetectable/circuit/rotate', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: '{}' }).then(r => r.json()))
      if (r.success) { pushToast({ content: `Circuit rotated! New exit IP: ${r.new_exit_ip}`, type: 'success' }); fetchStatus() }
    } catch {}
  }

  const running = status?.running

  return (
    <div className="page-content" style={{ padding: '24px 32px', maxWidth: 900 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24 }}>
        <Shield size={20} color="var(--accent)" />
        <h2 style={{ margin: 0, fontSize: 18, color: 'var(--text-h)' }}>Phantom Proxy Control</h2>
        <span style={{ fontSize: 11, padding: '3px 10px', borderRadius: 4, background: running ? 'var(--green-dim)' : 'var(--red-dim)', color: running ? 'var(--green)' : 'var(--red)', fontWeight: 600, marginLeft: 8 }}>
          {running ? <><Wifi size={10} /> RUNNING</> : <><WifiOff size={10} /> STOPPED</>}
        </span>
      </div>

      <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
        <button onClick={startProxy} disabled={running || loading}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '10px 20px', borderRadius: 6, border: 'none', background: 'var(--green)', color: '#000', fontSize: 14, cursor: 'pointer', fontFamily: 'inherit', fontWeight: 600, opacity: running ? .5 : 1 }}>
          <Zap size={14} /> Start Proxy
        </button>
        <button onClick={stopProxy} disabled={!running || loading}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '10px 20px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 14, cursor: 'pointer', fontFamily: 'inherit', opacity: !running ? .5 : 1 }}>
          <WifiOff size={14} /> Stop Proxy
        </button>
        <button onClick={rotateCircuit} disabled={!running}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '10px 20px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 14, cursor: 'pointer', fontFamily: 'inherit', opacity: !running ? .5 : 1 }}>
          <RotateCw size={14} /> Rotate Identity
        </button>
      </div>

      {status && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>EXIT IP</div>
            <div style={{ fontSize: 20, fontFamily: 'monospace', color: 'var(--accent)', fontWeight: 700 }}>{status.exit_ip || 'N/A'}</div>
            <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>This is what targets see</div>
          </div>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>STEALTH LEVEL</div>
            <div style={{ fontSize: 20, color: 'var(--amber)', fontWeight: 700, textTransform: 'uppercase' }}>{status.stealth_level || 'OFF'}</div>
            <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>Strategy: {status.rotation?.strategy || 'N/A'}</div>
          </div>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>CONNECTIONS ROUTED</div>
            <div style={{ fontSize: 20, color: 'var(--text-h)', fontWeight: 700 }}>{status.total_connections || 0}</div>
            <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>Active: {status.active_connections || 0}</div>
          </div>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>IDENTITIES</div>
            <div style={{ fontSize: 20, color: 'var(--text-h)', fontWeight: 700 }}>{status.rotation?.total_identities || 0}</div>
            <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>Tor: {status.rotation?.tor_available ? 'YES' : 'NO'} | Circuits: {status.rotation?.tor_circuits_rotated || 0}</div>
          </div>
        </div>
      )}

      {running && (
        <div style={{ marginTop: 16, padding: 12, background: 'var(--green-dim)', borderRadius: 6, fontSize: 12, color: 'var(--green)' }}>
          <Activity size={12} style={{ marginRight: 6 }} />
          All 153 tools are now routing through the Phantom Proxy. Your identity changes with every request.
          Set <code style={{ background: 'var(--bg-card)', padding: '1px 4px', borderRadius: 3 }}>ALL_PROXY=socks5://127.0.0.1:9051</code> for any external tool.
        </div>
      )}
    </div>
  )
}
