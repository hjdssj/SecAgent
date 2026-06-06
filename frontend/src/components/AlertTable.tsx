import { ChevronRight } from "lucide-react";
import type { SecurityAlert } from "../types/alert";
import { RiskBadge } from "./RiskBadge";

interface AlertTableProps {
  alerts: SecurityAlert[];
  selectedAlertId: string | null;
  onSelect: (alert: SecurityAlert) => void;
}

export function AlertTable({ alerts, selectedAlertId, onSelect }: AlertTableProps) {
  return (
    <section className="alert-list" aria-label="alerts">
      <div className="panel-heading">
        <h2>Alerts</h2>
        <span>{alerts.length}</span>
      </div>
      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Risk</th>
              <th>Attack</th>
              <th>Source</th>
              <th>Target</th>
              <th>Confidence</th>
              <th aria-label="select" />
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr
                key={alert.alert_id}
                className={alert.alert_id === selectedAlertId ? "is-selected" : ""}
                onClick={() => onSelect(alert)}
              >
                <td>
                  <RiskBadge level={alert.risk_level} />
                </td>
                <td>
                  <strong>{alert.attack_type}</strong>
                  <span className="muted mono">{alert.alert_id}</span>
                </td>
                <td className="mono">{alert.source_ip}</td>
                <td className="target-cell">{alert.target}</td>
                <td>{Math.round(alert.confidence * 100)}%</td>
                <td>
                  <button
                    className="icon-button icon-button--quiet"
                    type="button"
                    title="Open alert"
                    onClick={(event) => {
                      event.stopPropagation();
                      onSelect(alert);
                    }}
                  >
                    <ChevronRight size={16} aria-hidden="true" />
                  </button>
                </td>
              </tr>
            ))}
            {alerts.length === 0 ? (
              <tr>
                <td className="empty-row" colSpan={6}>
                  No alerts
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
