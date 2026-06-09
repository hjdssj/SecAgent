import {
  Brain,
  Crosshair,
  FileText,
  Gauge,
  ListChecks,
  MessageSquareText,
  Network,
  Save,
  Server,
  ShieldCheck,
  Timer,
  CalendarClock,
  UserCheck,
} from "lucide-react";
import { useEffect, useState } from "react";
import type { AlertStatus, SecurityAlert } from "../types/alert";
import { FollowupChat } from "./FollowupChat";
import { RiskBadge } from "./RiskBadge";
import { ReportPanel } from "./ReportPanel";

interface AlertDetailProps {
  alert: SecurityAlert | null;
  isUpdating: boolean;
  onStatusUpdate: (
    alertId: string,
    update: { status: AlertStatus; analyst_note?: string; handled_by?: string },
  ) => Promise<void>;
}

const STATUS_OPTIONS: Array<{ label: string; value: AlertStatus }> = [
  { label: "Auto Triaged", value: "auto_triaged" },
  { label: "Needs Review", value: "needs_review" },
  { label: "Investigating", value: "investigating" },
  { label: "Resolved", value: "resolved" },
  { label: "False Positive", value: "false_positive" },
];

export function AlertDetail({ alert, isUpdating, onStatusUpdate }: AlertDetailProps) {
  const [status, setStatus] = useState<AlertStatus>("auto_triaged");
  const [analystNote, setAnalystNote] = useState("");
  const [handledBy, setHandledBy] = useState("analyst");

  useEffect(() => {
    setStatus(alert?.status ?? "auto_triaged");
    setAnalystNote(alert?.analyst_note ?? "");
    setHandledBy(alert?.handled_by ?? "analyst");
  }, [alert]);

  if (!alert) {
    return (
      <section className="detail-empty">
        <FileText size={24} aria-hidden="true" />
        <span>No alert selected</span>
      </section>
    );
  }

  return (
    <section className="detail-layout" aria-label="alert detail">
      <div className="detail-header">
        <div>
          <span className="eyebrow mono">{alert.alert_id}</span>
          <h1>{alert.attack_type}</h1>
        </div>
        <RiskBadge level={alert.risk_level} />
      </div>

      <div className="detail-grid">
        <Metric icon={<Server size={17} />} label="Source" value={alert.source_ip} mono />
        <Metric icon={<Crosshair size={17} />} label="Target" value={alert.target} />
        <Metric icon={<Brain size={17} />} label="Score" value={String(alert.risk_score)} />
        <Metric icon={<ListChecks size={17} />} label="Events" value={String(alert.event_count ?? 1)} />
        <Metric
          icon={<CalendarClock size={17} />}
          label="Attack Time"
          value={formatTimestamp(alert.event_timestamp)}
        />
        <Metric
          icon={<CalendarClock size={17} />}
          label="First Seen"
          value={formatTimestamp(alert.first_seen)}
        />
        <Metric
          icon={<CalendarClock size={17} />}
          label="Last Seen"
          value={formatTimestamp(alert.last_seen)}
        />
        <Metric
          icon={<Network size={17} />}
          label="Confidence"
          value={`${Math.round(alert.confidence * 100)}%`}
        />
        <Metric icon={<Gauge size={17} />} label="Mode" value={alert.analysis_mode ?? "fast"} />
        <Metric
          icon={<Timer size={17} />}
          label="Latency"
          value={`${alert.analysis_metadata?.latency_ms ?? 0}ms`}
        />
        <Metric icon={<ShieldCheck size={17} />} label="Status" value={alert.status ?? "auto_triaged"} />
        <Metric
          icon={<UserCheck size={17} />}
          label="Review"
          value={alert.requires_human_review ? "Required" : "Not required"}
        />
      </div>

      <section className="analysis-panel">
        <div className="panel-heading">
          <h2>
            <span aria-hidden="true">
              <Gauge size={17} />
            </span>
            Analysis
          </h2>
          <span>{alert.analysis_mode ?? "fast"}</span>
        </div>
        <div className="analysis-grid">
          <AnalysisGroup title="Enabled" items={alert.analysis_metadata?.enabled_modules ?? []} />
          <AnalysisGroup title="Skipped" items={alert.analysis_metadata?.skipped_modules ?? []} />
        </div>
      </section>

      <FollowupChat sessionId={alert.session_id} />

      <section className="llm-panel">
        <div className="panel-heading">
          <h2>
            <span aria-hidden="true">
              <MessageSquareText size={17} />
            </span>
            LLM Report
          </h2>
          <span>{alert.llm_used ? "Generated" : "Skipped"}</span>
        </div>
        <div className="llm-grid">
          <TriageItem label="Used" value={alert.llm_used ? "Yes" : "No"} />
          <TriageItem label="Provider" value={alert.llm_provider ?? "None"} />
          <TriageItem label="Model" value={alert.llm_model ?? "None"} />
          <TriageItem label="Latency" value={`${alert.llm_latency_ms ?? 0}ms`} />
          <TriageItem label="Tokens" value={String(alert.llm_total_tokens ?? 0)} />
          <TriageItem label="Skip/Error" value={alert.llm_error ?? alert.llm_skipped_reason ?? "None"} />
        </div>
        {alert.llm_summary ? (
          <div className="llm-summary">
            <span className="metric__label">Analyst Summary</span>
            <p>{alert.llm_summary}</p>
          </div>
        ) : null}
      </section>

      <section className="score-panel">
        <div className="panel-heading">
          <h2>
            <span aria-hidden="true">
              <Brain size={17} />
            </span>
            Score Breakdown
          </h2>
          <span>{alert.score_breakdown?.total_score ?? alert.risk_score}</span>
        </div>
        <ul className="score-list">
          {alert.score_breakdown?.items?.length ? (
            alert.score_breakdown.items.map((item, index) => (
              <li key={`${item.name}-${index}`}>
                <div>
                  <strong>{item.name}</strong>
                  <span>{item.reason}</span>
                </div>
                <span className="score-delta">{item.score >= 0 ? `+${item.score}` : item.score}</span>
              </li>
            ))
          ) : (
            <li>
              <div>
                <strong>Base score</strong>
                <span>No detailed score breakdown</span>
              </div>
              <span className="score-delta">+{alert.risk_score}</span>
            </li>
          )}
        </ul>
      </section>

      <section className="triage-panel">
        <div className="panel-heading">
          <h2>
            <span aria-hidden="true">
              <ShieldCheck size={17} />
            </span>
            Auto Triage
          </h2>
          <span>{alert.automation_decision ?? "observe_only"}</span>
        </div>
        <div className="triage-grid">
          <TriageItem label="Status" value={alert.status ?? "auto_triaged"} />
          <TriageItem label="Decision" value={alert.automation_decision ?? "observe_only"} />
          <TriageItem label="Owner" value={alert.business_owner ?? "Unknown"} />
          <TriageItem label="Asset" value={alert.asset_name ?? "Unknown"} />
          <TriageItem label="Criticality" value={alert.asset_criticality ?? "Unknown"} />
          <TriageItem label="Human Review" value={alert.requires_human_review ? "Required" : "Not required"} />
        </div>
        <div className="triage-reason">
          <span className="metric__label">Reason</span>
          <p>{alert.triage_reason || "No auto triage reason"}</p>
        </div>
        <form
          className="status-form"
          onSubmit={(event) => {
            event.preventDefault();
            void onStatusUpdate(alert.alert_id, {
              status,
              analyst_note: analystNote.trim() || undefined,
              handled_by: handledBy.trim() || "analyst",
            });
          }}
        >
          <label>
            <span className="metric__label">Update Status</span>
            <select value={status} onChange={(event) => setStatus(event.target.value as AlertStatus)}>
              {STATUS_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="metric__label">Handled By</span>
            <input value={handledBy} onChange={(event) => setHandledBy(event.target.value)} />
          </label>
          <label className="status-form__note">
            <span className="metric__label">Analyst Note</span>
            <textarea
              value={analystNote}
              onChange={(event) => setAnalystNote(event.target.value)}
              rows={3}
            />
          </label>
          <button className="primary-button" type="submit" disabled={isUpdating}>
            <Save size={16} aria-hidden="true" />
            {isUpdating ? "Saving" : "Save"}
          </button>
        </form>
        <div className="context-ref-list">
          <span className="metric__label">Context References</span>
          {alert.context_references.length > 0 ? (
            <ul>
              {alert.context_references.map((item, index) => (
                <li key={`context-${index}`}>{item}</li>
              ))}
            </ul>
          ) : (
            <p className="muted">No context references</p>
          )}
        </div>
      </section>

      <div className="detail-columns">
        <InfoBlock title="Evidence" icon={<FileText size={17} />} items={alert.evidence} />
        <InfoBlock
          title="Recommendations"
          icon={<ListChecks size={17} />}
          items={alert.recommendations}
          ordered
        />
      </div>

      <section className="mitre-panel">
        <div className="panel-heading">
          <h2>ATT&CK</h2>
        </div>
        <div className="chip-row">
          {alert.mitre_attack.length > 0 ? (
            alert.mitre_attack.map((item) => (
              <span className="chip" key={`${item.technique_id}-${item.name}`}>
                <strong>{item.technique_id}</strong>
                {item.name}
              </span>
            ))
          ) : (
            <span className="muted">No mapping</span>
          )}
        </div>
      </section>

      <ReportPanel markdown={alert.report_markdown} />
    </section>
  );
}

interface TriageItemProps {
  label: string;
  value: string;
}

function TriageItem({ label, value }: TriageItemProps) {
  return (
    <div className="triage-item">
      <span className="metric__label">{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

interface AnalysisGroupProps {
  title: string;
  items: string[];
}

function AnalysisGroup({ title, items }: AnalysisGroupProps) {
  return (
    <div className="analysis-group">
      <span className="metric__label">{title}</span>
      <div className="chip-row chip-row--compact">
        {items.length > 0 ? (
          items.map((item) => (
            <span className="chip" key={`${title}-${item}`}>
              {item}
            </span>
          ))
        ) : (
          <span className="muted">None</span>
        )}
      </div>
    </div>
  );
}

interface MetricProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  mono?: boolean;
}

function Metric({ icon, label, value, mono }: MetricProps) {
  return (
    <div className="metric">
      <span className="metric__icon" aria-hidden="true">
        {icon}
      </span>
      <div>
        <span className="metric__label">{label}</span>
        <strong className={mono ? "mono" : undefined}>{value}</strong>
      </div>
    </div>
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
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

interface InfoBlockProps {
  title: string;
  icon: React.ReactNode;
  items: string[];
  ordered?: boolean;
}

function InfoBlock({ title, icon, items, ordered }: InfoBlockProps) {
  const ListTag = ordered ? "ol" : "ul";

  return (
    <section className="info-block">
      <div className="panel-heading">
        <h2>
          <span aria-hidden="true">{icon}</span>
          {title}
        </h2>
        <span>{items.length}</span>
      </div>
      {items.length > 0 ? (
        <ListTag>
          {items.map((item, index) => (
            <li key={`${title}-${index}`}>{item}</li>
          ))}
        </ListTag>
      ) : (
        <p className="muted">No items</p>
      )}
    </section>
  );
}
