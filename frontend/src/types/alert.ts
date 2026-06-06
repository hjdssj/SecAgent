export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface MitreTechnique {
  technique_id: string;
  name: string;
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
}
