import { RefreshCw, Shield } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchRecentAlerts } from "./api/alerts";
import { AlertDetail } from "./components/AlertDetail";
import { AlertTable } from "./components/AlertTable";
import { StatBar } from "./components/StatBar";
import type { SecurityAlert } from "./types/alert";

export default function App() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const selectedAlert = useMemo(
    () => alerts.find((alert) => alert.alert_id === selectedAlertId) ?? alerts[0] ?? null,
    [alerts, selectedAlertId],
  );

  const loadAlerts = useCallback(async () => {
    setIsLoading(true);
    try {
      const nextAlerts = await fetchRecentAlerts(50);
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
  }, []);

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
          <button
            className="icon-button"
            type="button"
            title="Refresh alerts"
            onClick={() => void loadAlerts()}
            disabled={isLoading}
          >
            <RefreshCw size={18} className={isLoading ? "is-spinning" : ""} aria-hidden="true" />
          </button>
        </div>
      </header>

      <StatBar alerts={alerts} lastUpdated={lastUpdated} />

      <div className="workspace">
        <AlertTable
          alerts={alerts}
          selectedAlertId={selectedAlert?.alert_id ?? null}
          onSelect={(alert) => setSelectedAlertId(alert.alert_id)}
        />
        <AlertDetail alert={selectedAlert} />
      </div>
    </main>
  );
}
