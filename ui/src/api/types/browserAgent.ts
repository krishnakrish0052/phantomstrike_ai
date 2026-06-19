export interface BrowserSession {
  id: string;
  session_id: string;
  target_url: string;
  screenshot_path: string;
  page_source: string;
  network_logs: string;
  console_errors: string;
  security_score: number;
  findings_json: string;
  created_at: string;
}

export interface PageInfo {
  title: string;
  url: string;
  cookies: Array<{ name: string; value: string; domain: string }>;
  local_storage: Record<string, string>;
  session_storage: Record<string, string>;
  forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string; value: string }> }>;
  links: Array<{ href: string; text: string }>;
  inputs: Array<{ name: string; type: string; id: string; placeholder: string }>;
  scripts: Array<{ type: 'external' | 'inline'; src?: string; content?: string }>;
  network_requests: Array<{ url: string; status: number; mimeType: string }>;
  console_errors: Array<{ level: string; message: string }>;
}

export interface SecurityAnalysis {
  total_issues: number;
  issues: Array<{
    type: string;
    severity: string;
    description: string;
    location?: string;
    form_action?: string;
    count?: number;
    header?: string;
  }>;
  security_score: number;
  passive_modules?: string[];
}

export interface ActiveTestFinding {
  type: string;
  severity: string;
  description: string;
  url: string;
}

export interface ActiveTests {
  active_findings: ActiveTestFinding[];
  tested_forms: number;
}

export interface BrowserAgentPayload {
  action: 'navigate' | 'screenshot' | 'close' | 'status';
  url?: string;
  headless?: boolean;
  wait_time?: number;
  proxy_port?: number;
  active_tests?: boolean;
}

export interface BrowserAgentResponse {
  success: boolean;
  page_info?: PageInfo;
  security_analysis?: SecurityAnalysis;
  screenshot?: string;
  active_tests?: ActiveTests;
  timestamp?: string;
  current_url?: string;
  browser_active?: boolean;
  screenshots_taken?: number;
  pages_visited?: number;
  error?: string;
}
