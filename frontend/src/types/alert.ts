export type RiskLevel = "low" | "medium" | "high" | "critical";
export type AnalysisMode = "fast" | "enriched" | "deep";
export type AlertStatus =
  | "auto_triaged"
  | "needs_review"
  | "investigating"
  | "resolved"
  | "false_positive";
export type AutomationDecision =
  | "observe_only"
  | "auto_close"
  | "notify_owner"
  | "block_ip_recommended"
  | "human_review_required";

export interface MitreTechnique {
  technique_id: string;
  name: string;
}

export interface RiskScoreItem {
  name: string;
  score: number;
  reason: string;
  source: string;
}

export interface RiskScoreBreakdown {
  base_score: number;
  items: RiskScoreItem[];
  total_score: number;
  risk_level: RiskLevel;
  confidence: number;
}

export interface AnalysisMetadata {
  analysis_mode: AnalysisMode;
  enabled_modules: string[];
  skipped_modules: string[];
  latency_ms: number;
  rag_used: boolean;
  threat_intel_used: boolean;
  memory_used: boolean;
}

export interface SecurityAlert {
  alert_id: string;
  event_id: string;
  attack_type: string;
  risk_score: number;
  risk_level: RiskLevel;
  source_ip: string;
  target: string;
  confidence: number;
  evidence: string[];
  mitre_attack: MitreTechnique[];
  recommendations: string[];
  report_markdown?: string | null;
  analysis_mode: AnalysisMode;
  score_breakdown?: RiskScoreBreakdown | null;
  analysis_metadata?: AnalysisMetadata | null;
  status: AlertStatus;
  automation_decision: AutomationDecision;
  triage_reason: string;
  requires_human_review: boolean;
  business_owner?: string | null;
  asset_name?: string | null;
  asset_criticality?: string | null;
  context_references: string[];
  analyst_note?: string | null;
  handled_by?: string | null;
  handled_at?: string | null;
}
