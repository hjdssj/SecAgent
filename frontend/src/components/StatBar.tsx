import { Activity, AlertTriangle, Radar, ShieldCheck } from "lucide-react";
import type { SecurityAlert } from "../types/alert";

interface StatBarProps {
  alerts: SecurityAlert[];
  lastUpdated: Date | null;
}

export function StatBar({ alerts, lastUpdated }: StatBarProps) {
  const critical = alerts.filter((alert) => alert.risk_level === "critical").length;
  const high = alerts.filter((alert) => alert.risk_level === "high").length;
  const review = alerts.filter((alert) => alert.requires_human_review).length;
  const sources = new Set(alerts.map((alert) => alert.source_ip)).size;

  return (
    <section className="statbar" aria-label="alert statistics">
      <div className="stat">
        <Activity size={18} aria-hidden="true" />
        <div>
          <span className="stat__label">Total</span>
          <strong>{alerts.length}</strong>
        </div>
      </div>
      <div className="stat">
        <AlertTriangle size={18} aria-hidden="true" />
        <div>
          <span className="stat__label">Critical</span>
          <strong>{critical}</strong>
        </div>
      </div>
      <div className="stat">
        <Radar size={18} aria-hidden="true" />
        <div>
          <span className="stat__label">High</span>
          <strong>{high}</strong>
        </div>
      </div>
      <div className="stat">
        <ShieldCheck size={18} aria-hidden="true" />
        <div>
          <span className="stat__label">Review</span>
          <strong>{review}</strong>
        </div>
      </div>
      <div className="stat">
        <Radar size={18} aria-hidden="true" />
        <div>
          <span className="stat__label">Sources</span>
          <strong>{sources}</strong>
        </div>
      </div>
      <div className="stat stat--wide">
        <span className="stat__label">Updated</span>
        <strong>{lastUpdated ? lastUpdated.toLocaleTimeString() : "--:--:--"}</strong>
      </div>
    </section>
  );
}
