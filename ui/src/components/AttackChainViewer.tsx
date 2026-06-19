// @ts-nocheck
import { useState } from 'react';
import { api } from '../api';
import type { AttackChain, SimulateChainResponse } from '../api/types';

// ── icon components ──────────────────────────────────────────────────────
function Link() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </svg>
  );
}

function Shield() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function ChevronRight() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="m9 18 6-6-6-6" />
    </svg>
  );
}

function Target() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="6" />
      <circle cx="12" cy="12" r="2" />
    </svg>
  );
}

function AlertTriangle() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

// ── helpers ──────────────────────────────────────────────────────────────
function complexityColor(c: AttackChain['complexity']): string {
  switch (c) {
    case 'LOW': return 'var(--green)';
    case 'MEDIUM': return 'var(--amber)';
    case 'HIGH': return 'var(--red)';
    default: return 'var(--fg)';
  }
}

function probColor(v: number): string {
  if (v >= 80) return 'var(--green)';
  if (v >= 50) return 'var(--amber)';
  return 'var(--red)';
}

// ── component ────────────────────────────────────────────────────────────
interface Props {
  chain?: AttackChain;
  onBuildChain?: (software: string, env: string, depth: number) => void;
}

export function AttackChainViewer({ chain, onBuildChain }: Props) {
  const [software, setSoftware] = useState('');
  const [environment, setEnvironment] = useState('linux');
  const [maxDepth, setMaxDepth] = useState(5);
  const [building, setBuilding] = useState(false);
  const [builtChain, setBuiltChain] = useState<AttackChain | null>(null);
  const [buildError, setBuildError] = useState('');
  const [simulating, setSimulating] = useState(false);
  const [simulation, setSimulation] = useState<SimulateChainResponse['simulation'] | null>(null);
  const [simError, setSimError] = useState('');

  const displayChain = chain ?? builtChain;

  async function handleBuild() {
    if (!software.trim()) return;
    setBuilding(true);
    setBuildError('');
    setSimulation(null);
    setSimError('');
    try {
      if (onBuildChain) {
        onBuildChain(software.trim(), environment, maxDepth);
      } else {
        const res = await api.buildAttackChain({
          target_software: software.trim(),
          target_environment: environment,
          max_depth: maxDepth,
        });
        if (res.success && res.chain) {
          setBuiltChain(res.chain);
        } else {
          setBuildError(res.error ?? 'Failed to build attack chain');
        }
      }
    } catch (e: any) {
      setBuildError(e?.message ?? String(e));
    } finally {
      setBuilding(false);
    }
  }

  async function handleSimulate() {
    if (!displayChain) return;
    setSimulating(true);
    setSimError('');
    setSimulation(null);
    try {
      const res = await api.simulateAttackChain({
        chain_id: displayChain.chain_id,
        iterations: 1000,
      });
      if (res.success && res.simulation) {
        setSimulation(res.simulation);
      } else {
        setSimError(res.error ?? 'Simulation failed');
      }
    } catch (e: any) {
      setSimError(e?.message ?? String(e));
    } finally {
      setSimulating(false);
    }
  }

  // ── styles ─────────────────────────────────────────────────────────────
  const container: React.CSSProperties = {
    maxWidth: 1000,
    margin: '0 auto',
    padding: '16px',
    fontFamily: 'var(--font-mono, monospace)',
    color: 'var(--fg)',
  };

  const card: React.CSSProperties = {
    background: 'var(--bg-card2, #1e1e2e)',
    border: '1px solid var(--border, #313244)',
    borderRadius: 8,
    padding: 16,
    marginBottom: 12,
  };

  const inputBase: React.CSSProperties = {
    background: 'var(--bg-input, #181825)',
    border: '1px solid var(--border, #313244)',
    borderRadius: 6,
    color: 'var(--fg)',
    padding: '8px 12px',
    fontSize: 14,
    fontFamily: 'var(--font-mono, monospace)',
    width: '100%',
    boxSizing: 'border-box',
  };

  const btn: React.CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    padding: '8px 16px',
    borderRadius: 6,
    border: '1px solid var(--border, #313244)',
    background: 'var(--blue-dim, #1e1e3e)',
    color: 'var(--fg)',
    fontSize: 14,
    fontFamily: 'var(--font-mono, monospace)',
    cursor: 'pointer',
  };

  const btnDisabled: React.CSSProperties = { ...btn, opacity: 0.5, cursor: 'not-allowed' };

  const stageCard: React.CSSProperties = {
    background: 'var(--bg-card2, #1e1e2e)',
    border: '1px solid var(--border, #313244)',
    borderRadius: 8,
    padding: '12px 14px',
    minWidth: 180,
    maxWidth: 220,
    flex: '0 0 auto',
  };

  const badge: React.CSSProperties = {
    display: 'inline-block',
    background: 'var(--blue-dim, #1e1e3e)',
    color: 'var(--blue, #89b4fa)',
    fontSize: 11,
    padding: '2px 8px',
    borderRadius: 4,
    fontWeight: 600,
  };

  const errStyle: React.CSSProperties = {
    background: 'var(--bg-card2, #1e1e2e)',
    border: '1px solid var(--red)',
    color: 'var(--red)',
    borderRadius: 6,
    padding: '10px 14px',
    fontSize: 13,
    marginBottom: 12,
  };

  return (
    <div style={container}>
      {/* ── Build Form ────────────────────────────────────────────────── */}
      <div style={card}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <Target /> <span style={{ fontWeight: 600, fontSize: 14 }}>Build Attack Chain</span>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'flex-end' }}>
          <div style={{ flex: '1 1 200px' }}>
            <label style={{ fontSize: 12, color: 'var(--fg-dim, #6c7086)', display: 'block', marginBottom: 4 }}>
              Target Software / Component
            </label>
            <input
              style={inputBase}
              value={software}
              onChange={e => setSoftware(e.target.value)}
              placeholder="e.g. Apache Struts 2.5, log4j, nginx 1.20"
              onKeyDown={e => e.key === 'Enter' && handleBuild()}
            />
          </div>

          <div style={{ minWidth: 140 }}>
            <label style={{ fontSize: 12, color: 'var(--fg-dim, #6c7086)', display: 'block', marginBottom: 4 }}>
              Environment
            </label>
            <select
              style={inputBase}
              value={environment}
              onChange={e => setEnvironment(e.target.value)}
            >
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
              <option value="cloud">Cloud</option>
            </select>
          </div>

          <div style={{ minWidth: 100 }}>
            <label style={{ fontSize: 12, color: 'var(--fg-dim, #6c7086)', display: 'block', marginBottom: 4 }}>
              Max Depth
            </label>
            <input
              type="number"
              style={{ ...inputBase, width: 80 }}
              value={maxDepth}
              min={1}
              max={12}
              onChange={e => setMaxDepth(Number(e.target.value))}
            />
          </div>

          <button
            style={building ? btnDisabled : btn}
            disabled={building || !software.trim()}
            onClick={handleBuild}
          >
            <Shield />
            {building ? 'Building…' : 'Build'}
          </button>
        </div>
      </div>

      {buildError && <div style={errStyle}><AlertTriangle /> {buildError}</div>}

      {/* ── Chain Visualization ────────────────────────────────────────── */}
      {displayChain && (
        <>
          <div style={card}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <Link />
              <span style={{ fontWeight: 600, fontSize: 14 }}>
                Attack Chain: {displayChain.target_software}
              </span>
              <span style={{
                fontSize: 11,
                color: 'var(--fg-dim, #6c7086)',
                marginLeft: 'auto',
              }}>
                {displayChain.target_environment}
              </span>
            </div>

            {/* horizontal stage flow */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 0,
              overflowX: 'auto',
              padding: '8px 0 12px',
            }}>
              {displayChain.stages.map((s, i) => (
                <div key={s.stage} style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
                  <div style={stageCard}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                      <span style={{
                        background: 'var(--blue-dim, #1e1e3e)',
                        color: 'var(--blue, #89b4fa)',
                        width: 22,
                        height: 22,
                        borderRadius: '50%',
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: 11,
                        fontWeight: 700,
                      }}>
                        {s.stage}
                      </span>
                      <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg)' }}>
                        {s.label}
                      </span>
                    </div>

                    <div style={{ fontSize: 12, color: 'var(--fg-dim, #a6adc8)', marginBottom: 6, lineHeight: 1.4 }}>
                      {s.objective}
                    </div>

                    <div style={{ marginBottom: 6 }}>
                      <span style={badge}>
                        {s.technique.id} — {s.technique.name}
                      </span>
                    </div>

                    {/* probability bar */}
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 2 }}>
                        <span style={{ color: 'var(--fg-dim, #6c7086)' }}>Success</span>
                        <span style={{ color: probColor(s.success_probability * 100), fontWeight: 600 }}>
                          {(s.success_probability * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div style={{
                        height: 4,
                        borderRadius: 2,
                        background: 'var(--bg-input, #181825)',
                        overflow: 'hidden',
                      }}>
                        <div style={{
                          height: '100%',
                          width: `${Math.min(100, s.success_probability * 100)}%`,
                          background: probColor(s.success_probability * 100),
                          borderRadius: 2,
                          transition: 'width 0.3s ease',
                        }} />
                      </div>
                    </div>

                    {s.suggested_tools.length > 0 && (
                      <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {s.suggested_tools.map(t => (
                          <span key={t} style={{
                            fontSize: 10,
                            padding: '1px 6px',
                            borderRadius: 3,
                            background: 'var(--bg-input, #181825)',
                            color: 'var(--fg-dim, #a6adc8)',
                          }}>
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* arrow connector between stages */}
                  {i < displayChain.stages.length - 1 && (
                    <div style={{ flexShrink: 0, padding: '0 4px', color: 'var(--fg-dim, #6c7086)' }}>
                      <ChevronRight />
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* overall probability */}
            <div style={{
              marginTop: 8,
              paddingTop: 10,
              borderTop: '1px solid var(--border, #313244)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 8,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 12, color: 'var(--fg-dim, #6c7086)' }}>Overall Probability</span>
                <span style={{
                  fontSize: 16,
                  fontWeight: 700,
                  color: probColor(displayChain.overall_probability * 100),
                }}>
                  {(displayChain.overall_probability * 100).toFixed(1)}%
                </span>
                <span style={{
                  fontSize: 11,
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: complexityColor(displayChain.complexity),
                  color: '#000',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                }}>
                  {displayChain.complexity}
                </span>
              </div>

              <button
                style={simulating ? btnDisabled : btn}
                disabled={simulating}
                onClick={handleSimulate}
              >
                <AlertTriangle />
                {simulating ? 'Simulating…' : 'Simulate (Monte Carlo)'}
              </button>
            </div>
          </div>

          {simError && <div style={errStyle}><AlertTriangle /> {simError}</div>}

          {/* ── Simulation Results ─────────────────────────────────────── */}
          {simulation && (
            <div style={card}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <AlertTriangle />
                <span style={{ fontWeight: 600, fontSize: 14 }}>
                  Monte Carlo Simulation ({simulation.iterations.toLocaleString()} runs)
                </span>
              </div>

              <div style={{ marginBottom: 12 }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  fontSize: 13,
                  marginBottom: 4,
                }}>
                  <span style={{ color: 'var(--fg-dim, #6c7086)' }}>
                    Full-chain success rate
                  </span>
                  <span style={{
                    fontWeight: 700,
                    color: probColor(simulation.full_chain_probability * 100),
                  }}>
                    {(simulation.full_chain_probability * 100).toFixed(1)}%
                    {' '}
                    <span style={{ fontWeight: 400, fontSize: 11, color: 'var(--fg-dim, #6c7086)' }}>
                      ({simulation.full_chain_successes}/{simulation.iterations})
                    </span>
                  </span>
                </div>
                <div style={{
                  height: 6,
                  borderRadius: 3,
                  background: 'var(--bg-input, #181825)',
                  overflow: 'hidden',
                }}>
                  <div style={{
                    height: '100%',
                    width: `${Math.min(100, simulation.full_chain_probability * 100)}%`,
                    background: probColor(simulation.full_chain_probability * 100),
                    borderRadius: 3,
                    transition: 'width 0.4s ease',
                  }} />
                </div>
              </div>

              {/* per-stage simulation */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {simulation.stage_probabilities.map(sp => {
                  const delta = sp.simulated_prob - sp.theoretical_prob;
                  const deltaColor = delta >= 0 ? 'var(--green)' : 'var(--red)';
                  return (
                    <div key={sp.stage} style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      fontSize: 12,
                      padding: '4px 0',
                      borderBottom: '1px solid var(--border, #313244)',
                    }}>
                      <span style={{
                        width: 22,
                        height: 22,
                        borderRadius: '50%',
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: 10,
                        fontWeight: 700,
                        background: simulation.bottleneck_stage === sp.stage
                          ? 'var(--red)'
                          : 'var(--blue-dim, #1e1e3e)',
                        color: simulation.bottleneck_stage === sp.stage ? '#fff' : 'var(--fg)',
                      }}>
                        {sp.stage}
                      </span>
                      <span style={{ flex: 1, color: 'var(--fg-dim, #a6adc8)' }}>
                        {sp.objective}
                      </span>
                      <span style={{ color: 'var(--fg-dim, #6c7086)', width: 50, textAlign: 'right' }}>
                        {(sp.theoretical_prob * 100).toFixed(0)}%
                      </span>
                      <span style={{ color: 'var(--fg)', width: 50, textAlign: 'right', fontWeight: 700 }}>
                        {(sp.simulated_prob * 100).toFixed(0)}%
                      </span>
                      <span style={{ color: deltaColor, width: 50, textAlign: 'right', fontSize: 11 }}>
                        {delta >= 0 ? '+' : ''}{(delta * 100).toFixed(1)}%
                      </span>
                    </div>
                  );
                })}
              </div>

              {simulation.recommendation && (
                <div style={{
                  marginTop: 10,
                  padding: '8px 12px',
                  borderRadius: 6,
                  background: 'var(--bg-input, #181825)',
                  fontSize: 12,
                  color: 'var(--fg-dim, #a6adc8)',
                  lineHeight: 1.5,
                }}>
                  <strong style={{ color: 'var(--fg)' }}>Recommendation:</strong>{' '}
                  {simulation.recommendation}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {!displayChain && !buildError && (
        <div style={{
          ...card,
          textAlign: 'center',
          color: 'var(--fg-dim, #6c7086)',
          fontSize: 13,
          padding: '32px 16px',
        }}>
          Enter a target software/component and environment, then click Build to generate an attack chain.
        </div>
      )}
    </div>
  );
}
