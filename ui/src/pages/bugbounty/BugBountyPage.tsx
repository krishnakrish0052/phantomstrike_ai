// @ts-nocheck
// @ts-nocheck
import React, { useState, useEffect } from 'react'
import { Bug, Shield, Target, Check } from 'lucide-react'
import { api } from '../../api'
import { useToast } from '../../components/ToastProvider'

const WORKFLOW_TYPES = [
  { id: 'recon', label: 'Reconnaissance' },
  { id: 'vuln_hunting', label: 'Vulnerability Hunting' },
  { id: 'business_logic', label: 'Business Logic' },
  { id: 'osint', label: 'OSINT' },
  { id: 'file_upload', label: 'File Upload Testing' },
  { id: 'comprehensive', label: 'Comprehensive Assessment' },
]

export default function BugBountyPage() {
  const { pushToast } = useToast()
  const [domain, setDomain] = useState('')
  const [scope, setScope] = useState('')
  const [outOfScope, setOutOfScope] = useState('')
  const [selectedWorkflows, setSelectedWorkflows] = useState<string[]>(['comprehensive'])
  const [sessionId, setSessionId] = useState('')
  const [loading, setLoading] = useState(false)
  const [assessments, setAssessments] = useState<any[]>([])
  const [result, setResult] = useState<any>(null)

  async function loadAssessments() {
    try { const r = await api.bugBounty.listAssessments(); if (r.success) setAssessments(r.assessments || []) } catch {}
  }

  useEffect(() => { loadAssessments() }, [])

  async function handleCreate() {
    if (!domain) return
    setLoading(true)
    try {
      const r = await api.bugBounty.createAssessment({} as any, {} as any, {
        session_id: sessionId || 'bb_' + Date.now(),
        domain,
        scope,
        out_of_scope: outOfScope,
        workflow_types: selectedWorkflows,
      })
      if (r.success) {
        setResult(r.assessment || r)
        loadAssessments()
        pushToast({ content: 'Assessment created', type: 'success' })
      }
    } catch {}
    setLoading(false)
  }

  function toggleWorkflow(id: string) {
    setSelectedWorkflows(prev => prev.includes(id) ? prev.filter(w => w !== id) : [...prev, id])
  }

  return (
    <div className="page-content" style={{ padding: '24px 32px', maxWidth: 900 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24 }}>
        <Bug size={18} color="var(--accent)" />
        <h2 style={{ margin: 0, fontSize: 16, color: 'var(--text-h)' }}>Bug Bounty Assessment</h2>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase' }}>Target Domain *</label>
            <input type="text" value={domain} onChange={e => setDomain(e.target.value)}
              style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 13 }}
              placeholder="example.com" />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Scope (newline-separated URLs)</label>
            <textarea value={scope} onChange={e => setScope(e.target.value)} rows={4}
              style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 12, resize: 'vertical', fontFamily: 'monospace' }}
              placeholder="https://example.com/api/*&#10;https://example.com/app/*" />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Out of Scope</label>
            <textarea value={outOfScope} onChange={e => setOutOfScope(e.target.value)} rows={2}
              style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 12, resize: 'vertical', fontFamily: 'monospace' }}
              placeholder="https://example.com/admin/*" />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Session ID</label>
            <input type="text" value={sessionId} onChange={e => setSessionId(e.target.value)}
              style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-card2)', color: 'var(--text)', fontSize: 13 }} placeholder="Optional" />
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <label style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase' }}>Workflow Types</label>
          {WORKFLOW_TYPES.map(w => (
            <label key={w.id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--text)', cursor: 'pointer', padding: '6px 10px', background: selectedWorkflows.includes(w.id) ? 'var(--accent)' + '18' : 'transparent', borderRadius: 4 }}>
              <input type="checkbox" checked={selectedWorkflows.includes(w.id)} onChange={() => toggleWorkflow(w.id)}
                style={{ accentColor: 'var(--accent)' }} />
              {w.label}
            </label>
          ))}
        </div>
      </div>

      <button onClick={handleCreate} disabled={loading || !domain}
        style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '10px 20px', borderRadius: 6, border: 'none',
          background: 'var(--accent)', color: '#fff', fontSize: 14, cursor: 'pointer', fontFamily: 'inherit', fontWeight: 600, marginTop: 20 }}>
        {loading ? '⟳ Creating...' : <><Shield size={14} /> Create Assessment</>}
      </button>

      {result && (
        <div style={{ marginTop: 24, padding: 16, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}>
          <div style={{ fontSize: 14, color: 'var(--green)', fontWeight: 600, marginBottom: 8 }}>
            <Check size={14} style={{ marginRight: 4 }} /> Assessment Created
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', fontFamily: 'monospace' }}>ID: {result.id || result.assessment?.id || '?'}</div>
        </div>
      )}

      {assessments.length > 0 && (
        <div style={{ marginTop: 32 }}>
          <h3 style={{ fontSize: 14, color: 'var(--text-h)', marginBottom: 12 }}>Recent Assessments ({assessments.length})</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {assessments.map((a: any) => (
              <div key={a.id} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500 }}>{a.domain}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{a.workflow_types} · {a.created_at?.slice(0, 16) || ''}</div>
                </div>
                <span style={{ fontSize: 11, padding: '3px 8px', borderRadius: 4, background: a.completed_at ? 'var(--green-dim)' : 'var(--amber-dim)', color: a.completed_at ? 'var(--green)' : 'var(--amber)' }}>
                  {a.completed_at ? 'COMPLETED' : 'PENDING'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
