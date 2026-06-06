import ReactMarkdown from "react-markdown";

interface ReportPanelProps {
  markdown?: string | null;
}

export function ReportPanel({ markdown }: ReportPanelProps) {
  return (
    <section className="report-panel" aria-label="markdown report">
      <div className="panel-heading">
        <h2>Report</h2>
      </div>
      <div className="markdown-body">
        {markdown ? <ReactMarkdown>{markdown}</ReactMarkdown> : <p>No report</p>}
      </div>
    </section>
  );
}
