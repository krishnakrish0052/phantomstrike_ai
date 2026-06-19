// @ts-nocheck
import { useState, useEffect, useCallback } from 'react'
import { Shield, AlertTriangle, CheckCircle, XCircle, Eye, Zap } from 'lucide-react'
import { useToast } from '../../components/ToastProvider'

export default function DefensePage() {
  const { pushToast } = useToast()
  const [status, setStatus] = useState<any>(null)
  const [honeypots, setHoneypots] = useState<any>(null)

  const fetchStatus = useCallback(async () => {
    try {
      const [s, h] = await Promise.all([
        fetch('/api/defense/status', { headers: { 'Accept': 'application/json' } }).then(r => r.json()),
        fetch('/api/defense/honeypots', { headers: { 'Accept': 'application/json' } }).then(r => r.json()),
      ])
      setStatus(s); setHoneypots(h)
    } catch {}
  }, [])

  useEffect(() => { fetchStatus(); const i = setInterval(fetchStatus, 10000); return () => clearInterval(i) }, [fetchStatus])

  async function terminate() {
    try {
      await fetch('/api/defense/terminate', { method: 'POST', headers: { 'Accept': 'application/json' } })
      pushToast({ content: 'EMERGENCY TERMINATION TRIGGERED — all sessions killed, evidence wiped', type: 'error' })
      fetchStatus()
    } catch {}
  }

  const threatLevel = status?.threat_level || 0
  const threatColors = ['var(--green)', 'var(--amber)', 'var(--orange)', 'var(--red)']
  const threatLabels = ['NORMAL', 'ELEVATED', 'HIGH', 'CRITICAL']

  return (
    <div className="page-content" style={{ padding: '24px 32px', maxWidth: 900 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24 }}>
        <Eye size={20} color="var(--accent)" />
        <h2 style={{ margin: 0, fontSize: 18, color: 'var(--text-h)' }}>Defense Monitor</h2>
        <span style={{ fontSize: 12, padding: '4px 12px', borderRadius: 4, background: threatColors[threatLevel] + '20', color: threatColors[threatLevel], fontWeight: 700, marginLeft: 8 }}>
          THREAT: {threatLabels[threatLevel]}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 24 }}>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>HONEYPOT DETECTION</div>
          <div style={{ fontSize: 20, color: 'var(--green)', fontWeight: 700 }}>
            <Shield size={18} style={{ marginRight: 4 }} /> ACTIVE
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>
            {honeypots?.honeypots_count || 0} known honeypots blocked
          </div>
        </div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>COUNTER-SURVEILLANCE</div>
          <div style={{ fontSize: 20, color: status?.counter_surveillance_active ? 'var(--amber)' : 'var(--green)', fontWeight: 700 }}>
            {status?.counter_surveillance_active ? <AlertTriangle size={18} /> : <CheckCircle size={18} />}
            {' '}{status?.counter_surveillance_active ? 'THREAT DETECTED' : 'CLEAN'}
          </div>
        </div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>IP REPUTATION</div>
          <div style={{ fontSize: 20, color: 'var(--text-h)', fontWeight: 700 }}>
            {status?.ip_blacklist_checks || 0} checks
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>
            {status?.blacklisted_ips || 0} blacklisted
          </div>
        </div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>CANARY TOKENS</div>
          <div style={{ fontSize: 20, color: status?.canary_detected ? 'var(--red)' : 'var(--green)', fontWeight: 700 }}>
            {status?.canary_detected ? <XCircle size={18} /> : <CheckCircle size={18} />}
            {' '}{status?.canary_detected ? 'DETECTED' : 'NONE'}
          </div>
        </div>
      </div>

      <button onClick={terminate}
        style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '12px 24px', borderRadius: 6, border: 'none', background: 'var(--red)', color: '#fff', fontSize: 14, cursor: 'pointer', fontFamily: 'inherit', fontWeight: 700 }}>
        <Zap size={14} /> EMERGENCY TERMINATION
      </button>
      <span style={{ fontSize: 11, color: 'var(--text-dim)', marginLeft: 12 }}>Kills all sessions, rotates identities, wipes evidence</span>

      {status?.alerts?.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <h3 style={{ fontSize: 14, color: 'var(--text-h)', marginBottom: 8 }}>Recent Alerts</h3>
          {status.alerts.map((a: any, i: number) => (
            <div key={i} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px', marginBottom: 4, display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ color: a.threat_level >= 2 ? 'var(--red)' : 'var(--amber)', fontWeight: 600 }}>{a.type}</span>
              <span style={{ fontSize: 12, color: 'var(--text-dim)', flex: 1 }}>{a.target}</span>
              <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>{a.timestamp}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
