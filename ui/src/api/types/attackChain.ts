export interface AttackChainStage {
  stage: number;
  objective: string;
  label: string;
  technique: { id: string; name: string };
  alternate_techniques?: Array<{ id: string; name: string }>;
  success_probability: number;
  suggested_tools: string[];
  description: string;
}

export interface AttackChain {
  chain_id: string;
  target_software: string;
  target_environment: string;
  stages: AttackChainStage[];
  overall_probability: number;
  complexity: 'LOW' | 'MEDIUM' | 'HIGH';
  mitre_attack_mapping: Record<string, string>;
  created_at: string;
  session_id?: string;
}

export interface BuildChainPayload {
  target_software: string;
  target_environment?: string;
  max_depth?: number;
  session_id?: string;
}

export interface BuildChainResponse {
  success: boolean;
  chain?: AttackChain;
  error?: string;
}

export interface SimulateChainPayload {
  chain_id: string;
  iterations?: number;
}

export interface StageSimulation {
  stage: number;
  objective: string;
  theoretical_prob: number;
  simulated_prob: number;
}

export interface SimulateChainResponse {
  success: boolean;
  simulation?: {
    chain_id: string;
    iterations: number;
    full_chain_successes: number;
    full_chain_probability: number;
    stage_probabilities: StageSimulation[];
    bottleneck_stage: number | null;
    recommendation: string;
  };
  error?: string;
}

export interface ChainsListResponse {
  success: boolean;
  chains: AttackChain[];
  total: number;
}
