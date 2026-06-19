// @ts-nocheck
// @ts-nocheck
import React, { useState, useEffect } from 'react'
import { Link, Target, List, Trash2, Play, Download } from 'lucide-react'
import { api, type AttackChain } from '../../api'
import { AttackChainViewer } from '../../components/AttackChainViewer'
import { useToast } from '../../components/ToastProvider'

export default function AttackChainsPage() {
  const { pushToast } = useToast()
  const [tab, setTab] = useState<'builder'|'saved'>('builder')
  const [chains, setChains] = useState<AttackChain[]>([])
  const [loading, setLoading] = useState(false)
  const [simulating, setSimulating] = useState<string | null>(null)
  const [simResults, setSimResults] = useState<Record<string, any>>({})

  async function loadChains() {
    setLoading(true)
    try { const r = await api.listAttackChains(); if (r.success) setChains(r.chains || []) } catch {}
    setLoading(false)
  }

  useEffect(() => { if (tab === 'saved') loadChains() }, [tab])

  async function handleSimulate(chainId: string) {
    setSimulating(chainId)
    try { const r = await api.simulateAttackChain({ chain_id: chainId }); if (r.success && r.simulation) setSimResults(prev => ({...prev, [chainId]: r.simulation})) } catch {}
    setSimulating(null)
  }

  async function handleDelete(chainId: string) {
    try { await api.deleteAttackChain(chainId); loadChains(); pushToast({ content: 'Chain deleted', type: 'info' }) } catch {}
  }

  return (
    <div className="page-content" style={{ padding: '24px 32px', maxWidth: 1000 }}>
      <div style={{ display: 'flex', gap: 24, marginBottom: 24 }}>
        {[
          { id: 'builder', label: 'Builder', icon: <Target size={14} /> },
          { id: 'saved', label: 'Saved Chains', icon: <List size={14} /> },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id as any)}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '6px 14px', border: 'none', borderRadius: 6,
              cursor: 'pointer', fontSize: 13, fontFamily: 'inherit',
              background: tab === t.id ? 'var(--accent)' : 'var(--bg-card2)', color: tab === t.id ? '#fff' : 'var(--text)' }}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {tab === 'builder' && <AttackChainViewer onBuildChain={async (software, env, depth) => {
        try { await api.buildAttackChain({ target_software: software, target_environment: env, max_depth: depth }) } catch {}
      }} />}

      {tab === 'saved' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {chains.map(chain => (
            <div key={(chain as any).chain_id} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                <div>
                  <div style={{ fontSize: 14, color: 'var(--text-h)', fontWeight: 600 }}>{chain.target_software}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>
                    {chain.stages?.length || 0} stages · {chain.complexity} · {chain.target_environment} · Prob: {(chain.overall_probability * 100).toFixed(1)}%
                  </div>
                  <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
                    {chain.stages?.map(s => (
                      <span key={s.stage} style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'var(--bg-card2)', color: 'var(--text-dim)' }}>{s.technique?.id}</span>
                    ))}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button onClick={() => handleSimulate((chain as any).chain_id)} disabled={simulating === (chain as any).chain_id}
                    style={{ padding: '6px 10px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-card2)', color: 'var(--text)', cursor: 'pointer' }}>
                    {simulating === (chain as any).chain_id ? '⟳' : <Play size={12} />}
                  </button>
                  <button onClick={() => handleDelete((chain as any).chain_id)}
                    style={{ padding: '6px 10px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-card2)', color: 'var(--red)', cursor: 'pointer' }}>
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
              {simResults[(chain as any).chain_id] && (
                <div style={{ marginTop: 12, padding: 12, background: 'var(--bg-card2)', borderRadius: 6 }}>
                  <div style={{ fontSize: 12, color: 'var(--green)', marginBottom: 4, fontWeight: 600 }}>
                    Simulation: {(simResults[(chain as any).chain_id].full_chain_probability * 100).toFixed(1)}% success
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{simResults[(chain as any).chain_id].recommendation}</div>
                </div>
              )}
            </div>
          ))}
          {chains.length === 0 && <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>No saved attack chains. Build one in the Builder tab.</div>}
        </div>
      )}
    </div>
  )
}
