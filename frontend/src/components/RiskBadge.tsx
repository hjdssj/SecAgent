import type { RiskLevel } from "../types/alert";

interface RiskBadgeProps {
  level: RiskLevel;
}

const LABELS: Record<RiskLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export function RiskBadge({ level }: RiskBadgeProps) {
  return <span className={`risk-badge risk-badge--${level}`}>{LABELS[level]}</span>;
}
