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
              <th>Time</th>
              <th>Attack</th>
              <th>Status</th>
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
                  <span className="mono">{formatTimestamp(alert.event_timestamp)}</span>
                </td>
                <td>
                  <strong>{alert.attack_type}</strong>
                  {alert.event_count > 1 ? (
                    <span className="aggregate-count">x{alert.event_count}</span>
                  ) : null}
                  <span className="muted mono">{alert.alert_id}</span>
                </td>
                <td>
                  <span className="status-pill">{alert.status}</span>
                  {alert.requires_human_review ? <span className="muted">review</span> : null}
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
                <td className="empty-row" colSpan={8}>
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

function formatTimestamp(value?: string | null): string {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}
