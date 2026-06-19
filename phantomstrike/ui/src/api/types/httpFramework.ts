export interface HttpProxyEntry {
  id: number;
  url: string;
  method: string;
  headers: Record<string, string>;
  data?: unknown;
  timestamp: string;
}

export interface HttpRepeaterPayload {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  data?: string;
  cookies?: Record<string, string>;
}

export interface HttpIntruderPayload {
  url: string;
  method?: string;
  location?: 'query' | 'body' | 'headers' | 'cookie';
  params?: string[];
  payloads?: string[];
  base_data?: Record<string, string>;
  max_requests?: number;
}

export interface HttpIntruderResult {
  param: string;
  payload: string;
  status_code: number;
  size: number;
  reflected: boolean;
}

export interface HttpIntruderResponse {
  success: boolean;
  tested: number;
  interesting: HttpIntruderResult[];
  error?: string;
}

export interface HttpScopePayload {
  host: string;
  include_subdomains?: boolean;
}

export interface HttpFrameworkResponse {
  success: boolean;
  request?: HttpProxyEntry;
  response?: {
    status_code: number;
    headers: Record<string, string>;
    content: string;
    size: number;
    time: number;
  };
  vulnerabilities?: Array<{
    type: string;
    severity: string;
    description: string;
    url?: string;
  }>;
  history?: Array<{ request: HttpProxyEntry; response: unknown }>;
  total_requests?: number;
  discovered_urls?: string[];
  forms?: unknown[];
  total_pages?: number;
  rules_set?: number;
  scope?: { host: string; include_subdomains: boolean };
  error?: string;
}
