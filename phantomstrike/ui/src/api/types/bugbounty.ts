export interface BugBountyAssessment {
  id: string;
  session_id: string;
  domain: string;
  scope: string;
  out_of_scope: string;
  workflow_types: string;
  findings_json: string;
  summary: string;
  created_at: string;
  completed_at: string | null;
}

export interface BugBountyCreatePayload {
  session_id: string;
  domain: string;
  scope?: string;
  out_of_scope?: string;
  workflow_types?: string[];
}

export interface BugBountyCreateResponse {
  success: boolean;
  assessment?: BugBountyAssessment;
  error?: string;
}

export interface BugBountyAssessmentResponse {
  success: boolean;
  assessment?: BugBountyAssessment;
  error?: string;
}

export interface BugBountyListResponse {
  success: boolean;
  assessments: BugBountyAssessment[];
  total: number;
}
