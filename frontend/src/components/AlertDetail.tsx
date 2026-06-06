import { Brain, Crosshair, FileText, ListChecks, Network, Server } from "lucide-react";
import type { SecurityAlert } from "../types/alert";
import { RiskBadge } from "./RiskBadge";
import { ReportPanel } from "./ReportPanel";

interface AlertDetailProps {
  alert: SecurityAlert | null;
}

export function AlertDetail({ alert }: AlertDetailProps) {
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
        <Metric
          icon={<Network size={17} />}
          label="Confidence"
          value={`${Math.round(alert.confidence * 100)}%`}
        />
      </div>

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
