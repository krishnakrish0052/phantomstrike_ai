import { usePersistentState } from './usePersistentState'
import type { Page } from '../app/routing'

/** Pages that cannot be disabled (always visible). */
export const ALWAYS_VISIBLE_PAGES: ReadonlySet<Page> = new Set(['dashboard', 'settings'])

export interface PageConfig {
  page: Exclude<Page, 'session-detail'>
  label: string
  description: string
}

/** All navigable pages with human-readable metadata. */
export const PAGE_CONFIGS: PageConfig[] = [
  { page: 'dashboard', label: 'Home', description: 'Overview dashboard with KPIs and live status' },
  { page: 'run',       label: 'Run',  description: 'Execute security tools interactively' },
  { page: 'logs',      label: 'Logs', description: 'Live server log stream' },
  { page: 'tasks',     label: 'Tasks', description: 'Background task queue and progress' },
  { page: 'tools',     label: 'Tools', description: 'Browse and inspect available tools' },
  { page: 'plugins',   label: 'Plugins', description: 'Manage skill and plugin extensions' },
  { page: 'reports',   label: 'Reports', description: 'Generated scan reports' },
  { page: 'sessions',  label: 'Sessions', description: 'Saved recon/engagement sessions' },
  { page: 'loot',      label: 'Loot', description: 'Captured credentials and artefacts' },
  { page: 'exploit', label: 'Exploit Generator', description: 'Generate and execute security exploits' },
  { page: 'http-framework', label: 'HTTP Framework', description: 'Burp Suite alternative — Repeater, Intruder, Spider' },
  { page: 'browser-agent', label: 'Browser Agent', description: 'Selenium-based web application security inspection' },
  { page: 'attack-chains', label: 'Attack Chains', description: 'Multi-stage attack chain builder with MITRE ATT&CK mapping' },
  { page: 'bugbounty', label: 'Bug Bounty', description: 'Bug bounty assessment workflow management' },
  { page: 'proxy',     label: 'Phantom Proxy', description: 'Undetectable IP rotation — control your identity layer' },
  { page: 'defense',   label: 'Defense Monitor', description: 'Real-time self-defense — honeypot detection, counter-surveillance' },
  { page: 'missions',  label: 'Mission Console', description: 'Autonomous AI hacking missions — one prompt, complete execution' },
  { page: 'help',      label: 'Help', description: 'Documentation and keyboard shortcuts' },
  { page: 'settings',  label: 'Settings', description: 'Application settings (always visible)' },
]

const STORAGE_KEY = 'phantomstrike_disabled_pages'

/**
 * Returns the set of disabled page keys and a toggle function.
 * Settings and Dashboard are always enabled and cannot be toggled off.
 */
export function usePageVisibility() {
  const [disabledPages, setDisabledPages] = usePersistentState<string[]>(STORAGE_KEY, [])

  function isPageEnabled(page: Page): boolean {
    if (ALWAYS_VISIBLE_PAGES.has(page)) return true
    return !disabledPages.includes(page)
  }

  function togglePage(page: Page) {
    if (ALWAYS_VISIBLE_PAGES.has(page)) return
    setDisabledPages(prev =>
      prev.includes(page) ? prev.filter(p => p !== page) : [...prev, page]
    )
  }

  return { disabledPages, isPageEnabled, togglePage }
}
