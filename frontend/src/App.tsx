import { BookOpen, RefreshCw, Shield } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchRecentAlerts, updateAlertStatus } from "./api/alerts";
import { AlertDetail } from "./components/AlertDetail";
import { AlertTable } from "./components/AlertTable";
import { KnowledgePage } from "./components/KnowledgePage";
import { StatBar } from "./components/StatBar";
import type { AlertStatus, RiskLevel, SecurityAlert } from "./types/alert";

type StatusFilter = AlertStatus | "all";
type RiskFilter = RiskLevel | "all";
type WorkspaceView = "alerts" | "knowledge";

const STATUS_OPTIONS: Array<{ label: string; value: StatusFilter }> = [
  { label: "All", value: "all" },
  { label: "Auto Triaged", value: "auto_triaged" },
  { label: "Needs Review", value: "needs_review" },
  { label: "Investigating", value: "investigating" },
  { label: "Resolved", value: "resolved" },
  { label: "False Positive", value: "false_positive" },
];

const RISK_OPTIONS: Array<{ label: string; value: RiskFilter }> = [
  { label: "All", value: "all" },
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
];

export default function App() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isUpdating, setIsUpdating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [reviewOnly, setReviewOnly] = useState(false);
  const [view, setView] = useState<WorkspaceView>("alerts");

  const selectedAlert = useMemo(
    () => alerts.find((alert) => alert.alert_id === selectedAlertId) ?? alerts[0] ?? null,
    [alerts, selectedAlertId],
  );

  const loadAlerts = useCallback(async () => {
    setIsLoading(true);
    try {
      const nextAlerts = await fetchRecentAlerts({
        count: 50,
        status: statusFilter === "all" ? undefined : statusFilter,
        riskLevel: riskFilter === "all" ? undefined : riskFilter,
        requiresHumanReview: reviewOnly ? true : undefined,
      });
      setAlerts(nextAlerts);
      setError(null);
      setLastUpdated(new Date());
      setSelectedAlertId((current) => {
        if (current && nextAlerts.some((alert) => alert.alert_id === current)) {
          return current;
        }

        return nextAlerts[0]?.alert_id ?? null;
      });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to fetch alerts");
    } finally {
      setIsLoading(false);
    }
  }, [reviewOnly, riskFilter, statusFilter]);

  const handleStatusUpdate = useCallback(
    async (alertId: string, update: { status: AlertStatus; analyst_note?: string; handled_by?: string }) => {
      setIsUpdating(true);
      try {
        const updatedAlert = await updateAlertStatus(alertId, update);
        setAlerts((current) =>
          current.map((alert) => (alert.alert_id === updatedAlert.alert_id ? updatedAlert : alert)),
        );
        setError(null);
        setLastUpdated(new Date());
        await loadAlerts();
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : "Failed to update alert status");
      } finally {
        setIsUpdating(false);
      }
    },
    [loadAlerts],
  );

  useEffect(() => {
    void loadAlerts();
    const timer = window.setInterval(() => void loadAlerts(), 5000);

    return () => window.clearInterval(timer);
  }, [loadAlerts]);

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true">
            <Shield size={22} />
          </span>
          <div>
            <span className="eyebrow">SecRAG Agent</span>
            <h1>SOC Console</h1>
          </div>
        </div>
        <div className="topbar__actions">
          {error ? <span className="status status--error">{error}</span> : null}
          {view === "alerts" ? (
            <button
              className="icon-button"
              type="button"
              title="Refresh alerts"
              onClick={() => void loadAlerts()}
              disabled={isLoading}
            >
              <RefreshCw size={18} className={isLoading ? "is-spinning" : ""} aria-hidden="true" />
            </button>
          ) : null}
        </div>
      </header>

      <section className="view-tabs" aria-label="workspace views">
        <button
          className={view === "alerts" ? "view-tab is-active" : "view-tab"}
          type="button"
          onClick={() => setView("alerts")}
        >
          <Shield size={16} aria-hidden="true" />
          SOC Console
        </button>
        <button
          className={view === "knowledge" ? "view-tab is-active" : "view-tab"}
          type="button"
          onClick={() => setView("knowledge")}
        >
          <BookOpen size={16} aria-hidden="true" />
          Knowledge
        </button>
      </section>

      {view === "alerts" ? (
        <>
          <StatBar alerts={alerts} lastUpdated={lastUpdated} />

          <section className="filterbar" aria-label="alert filters">
            <label>
              <span>Status</span>
              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value as StatusFilter)}
              >
                {STATUS_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Risk</span>
              <select
                value={riskFilter}
                onChange={(event) => setRiskFilter(event.target.value as RiskFilter)}
              >
                {RISK_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="checkbox-control">
              <input
                type="checkbox"
                checked={reviewOnly}
                onChange={(event) => setReviewOnly(event.target.checked)}
              />
              <span>Needs human review</span>
            </label>
          </section>

          <div className="workspace">
            <AlertTable
              alerts={alerts}
              selectedAlertId={selectedAlert?.alert_id ?? null}
              onSelect={(alert) => setSelectedAlertId(alert.alert_id)}
            />
            <AlertDetail alert={selectedAlert} isUpdating={isUpdating} onStatusUpdate={handleStatusUpdate} />
          </div>
        </>
      ) : (
        <KnowledgePage />
      )}
    </main>
  );
}
