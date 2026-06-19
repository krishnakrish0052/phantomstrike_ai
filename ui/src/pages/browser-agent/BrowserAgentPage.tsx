// @ts-nocheck
// @ts-nocheck
import React from 'react'
import { Globe, Camera, ExternalLink } from 'lucide-react'
import { BrowserInspector } from '../../components/BrowserInspector'

export default function BrowserAgentPage() {
  return (
    <div className="page-content" style={{ padding: '24px 32px', maxWidth: 1100 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
        <Globe size={18} color="var(--accent)" />
        <h2 style={{ margin: 0, fontSize: 16, color: 'var(--text-h)' }}>Browser Agent</h2>
      </div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        {['http://testphp.vulnweb.com', 'http://httpbin.org', 'https://example.com'].map(u => (
          <a key={u} href="#" onClick={e => { e.preventDefault(); /* Quick nav handled by BrowserInspector */ }}
            style={{ fontSize: 11, color: 'var(--blue)', textDecoration: 'none', padding: '4px 10px', background: 'var(--bg-card2)', borderRadius: 4, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <ExternalLink size={10} /> {u}
          </a>
        ))}
      </div>
      <BrowserInspector />
    </div>
  )
}
