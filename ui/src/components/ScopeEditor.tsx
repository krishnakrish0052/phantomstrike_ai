// @ts-nocheck
import { useState } from 'react'
import { Target, Plus, Trash2, Globe } from 'lucide-react'
import { api } from '../api'

interface ScopeRule {
  pattern: string
  type: 'include' | 'exclude'
}

export function ScopeEditor({
  onScopeChange,
}: {
  onScopeChange?: (host: string, includeSubdomains: boolean) => void
}) {
  const [host, setHost] = useState('')
  const [includeSubdomains, setIncludeSubdomains] = useState(false)
  const [applying, setApplying] = useState(false)
  const [rules, setRules] = useState<ScopeRule[]>([])
  const [newRule, setNewRule] = useState({ pattern: '', type: 'include' as 'include' | 'exclude' })

  async function applyScope() {
    if (!host.trim()) return
    setApplying(true)
    try {
      const res = await api.httpFramework.setScope({
        host: host.trim(),
        include_subdomains: includeSubdomains,
      })
      if (res.success) {
        onScopeChange?.(host.trim(), includeSubdomains)
      }
    } finally {
      setApplying(false)
    }
  }

  function addRule() {
    const pattern = newRule.pattern.trim()
    if (!pattern) return
    setRules(prev => [...prev, { pattern, type: newRule.type }])
    setNewRule({ pattern: '', type: 'include' })
  }

  function removeRule(index: number) {
    setRules(prev => prev.filter((_, i) => i !== index))
  }

  return (
    <div style={styles.card}>
      {/* Header */}
      <div style={styles.header}>
        <Target size={18} color="var(--green)" />
        <span style={styles.title}>Target Scope</span>
      </div>

      {/* Host input row */}
      <div style={styles.row}>
        <div style={styles.inputWrapper}>
          <Globe size={14} color="var(--text-dim)" style={styles.inputIcon} />
          <input
            type="text"
            placeholder="example.com"
            value={host}
            onChange={e => setHost(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && applyScope()}
            style={styles.input}
          />
        </div>
      </div>

      {/* Include subdomains + Apply */}
      <div style={styles.row}>
        <label style={styles.checkLabel}>
          <input
            type="checkbox"
            checked={includeSubdomains}
            onChange={e => setIncludeSubdomains(e.target.checked)}
            style={styles.checkbox}
          />
          <span style={styles.checkText}>Include subdomains</span>
        </label>
        <button
          onClick={applyScope}
          disabled={applying || !host.trim()}
          style={{
            ...styles.btnApply,
            opacity: applying || !host.trim() ? 0.5 : 1,
          }}
        >
          <Target size={12} />
          <span>{applying ? 'Applying...' : 'Apply'}</span>
        </button>
      </div>

      {/* Divider */}
      <div style={styles.divider} />

      {/* Rules list */}
      <div style={styles.sectionHeader}>
        <span style={styles.sectionTitle}>Scope Rules</span>
        <span style={styles.ruleCount}>{rules.length}</span>
      </div>

      {rules.length === 0 ? (
        <div style={styles.empty}>No scope rules defined. Add patterns below.</div>
      ) : (
        <div style={styles.rulesList}>
          {rules.map((rule, i) => (
            <div key={i} style={styles.ruleItem}>
              <span
                style={{
                  ...styles.badge,
                  background: rule.type === 'include' ? 'var(--green-dim)' : 'var(--red-dim)',
                  color: rule.type === 'include' ? 'var(--green)' : 'var(--red)',
                }}
              >
                {rule.type}
              </span>
              <span style={styles.rulePattern}>{rule.pattern}</span>
              <button
                onClick={() => removeRule(i)}
                style={styles.btnIcon}
                title="Remove rule"
              >
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Add rule */}
      <div style={styles.addRuleRow}>
        <select
          value={newRule.type}
          onChange={e => setNewRule(prev => ({ ...prev, type: e.target.value as 'include' | 'exclude' }))}
          style={styles.select}
        >
          <option value="include">Include</option>
          <option value="exclude">Exclude</option>
        </select>
        <input
          type="text"
          placeholder="*.example.com"
          value={newRule.pattern}
          onChange={e => setNewRule(prev => ({ ...prev, pattern: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && addRule()}
          style={{ ...styles.input, flex: 1 }}
        />
        <button
          onClick={addRule}
          disabled={!newRule.pattern.trim()}
          style={{
            ...styles.btnAdd,
            opacity: !newRule.pattern.trim() ? 0.5 : 1,
          }}
        >
          <Plus size={14} />
        </button>
      </div>
    </div>
  )
}

const styles: Record<string, React.CSSProperties> = {
  card: {
    background: 'var(--bg-card)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    padding: 16,
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
    maxWidth: 420,
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
  },
  title: {
    fontSize: 14,
    fontWeight: 600,
    color: 'var(--text-h)',
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
  },
  inputWrapper: {
    position: 'relative',
    flex: 1,
  },
  inputIcon: {
    position: 'absolute',
    left: 10,
    top: '50%',
    transform: 'translateY(-50%)',
    pointerEvents: 'none',
  } as React.CSSProperties,
  input: {
    width: '100%',
    padding: '8px 10px 8px 30px',
    background: 'var(--bg-card2)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    color: 'var(--text-h)',
    fontSize: 13,
    fontFamily: 'inherit',
    outline: 'none',
  },
  checkLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    cursor: 'pointer',
  },
  checkbox: {
    accentColor: 'var(--green)',
    cursor: 'pointer',
  },
  checkText: {
    fontSize: 12,
    color: 'var(--text)',
    userSelect: 'none',
  } as React.CSSProperties,
  btnApply: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    padding: '8px 14px',
    background: 'var(--green-dim)',
    border: '1px solid var(--green)',
    borderRadius: 6,
    color: 'var(--green)',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'opacity 0.15s',
  },
  divider: {
    height: 1,
    background: 'var(--border)',
    margin: '4px 0',
  },
  sectionHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  sectionTitle: {
    fontSize: 12,
    fontWeight: 600,
    color: 'var(--text)',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  },
  ruleCount: {
    fontSize: 11,
    color: 'var(--text-dim)',
    background: 'var(--bg-card2)',
    padding: '1px 7px',
    borderRadius: 10,
  },
  empty: {
    fontSize: 12,
    color: 'var(--text-dim)',
    fontStyle: 'italic',
    padding: '8px 0',
  },
  rulesList: {
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
    maxHeight: 200,
    overflowY: 'auto',
  },
  ruleItem: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    padding: '6px 8px',
    background: 'var(--bg-card2)',
    borderRadius: 6,
    border: '1px solid var(--border)',
  },
  badge: {
    fontSize: 10,
    fontWeight: 600,
    textTransform: 'uppercase',
    padding: '2px 6px',
    borderRadius: 4,
    whiteSpace: 'nowrap',
    flexShrink: 0,
  },
  rulePattern: {
    flex: 1,
    fontSize: 12,
    color: 'var(--text)',
    fontFamily: 'var(--mono, monospace)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  btnIcon: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 4,
    background: 'none',
    border: 'none',
    color: 'var(--red)',
    cursor: 'pointer',
    borderRadius: 4,
    flexShrink: 0,
  },
  addRuleRow: {
    display: 'flex',
    gap: 6,
  },
  select: {
    padding: '8px 10px',
    background: 'var(--bg-card2)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    color: 'var(--text-h)',
    fontSize: 12,
    fontFamily: 'inherit',
    outline: 'none',
    cursor: 'pointer',
  },
  btnAdd: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '8px 10px',
    background: 'var(--blue-dim)',
    border: '1px solid var(--blue)',
    borderRadius: 6,
    color: 'var(--blue)',
    cursor: 'pointer',
    transition: 'opacity 0.15s',
  },
}
