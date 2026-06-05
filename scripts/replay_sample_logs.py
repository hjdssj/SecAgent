import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
SAMPLE_LOG_DIR = ROOT_DIR / "data" / "sample_logs"
REPORT_DIR = ROOT_DIR / "reports"

sys.path.append(str(BACKEND_DIR))

from app.agents.orchestrator import SecurityAnalysisOrchestrator
from app.collector.modsecurity_parser import ModSecurityParser
from app.models.alert import SecurityAlert


def load_log_lines() -> list[str]:
    """
    Load all non-empty log lines from the sample log directory.

    Parameters:
     None

    Returns:
     A list of sample log lines

    Raises:
     None
    """

    lines: list[str] = []

    if not SAMPLE_LOG_DIR.exists():
        return lines

    for log_file in SAMPLE_LOG_DIR.glob("*.log"):
        for line in log_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()

            if not line:
                continue

            lines.append(line)

    return lines


def write_report(alert: SecurityAlert) -> None:
    """
    Write the Markdown report from a security alert into the reports directory.

    Parameters:
     alert - generated security alert object

    Returns:
     None

    Raises:
     None
    """

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if not alert.report_markdown:
        return

    report_path = REPORT_DIR / f"{alert.alert_id}.md"
    report_path.write_text(alert.report_markdown, encoding="utf-8")


def main() -> None:
    """
    Replay sample logs and generate security alerts.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    parser = ModSecurityParser()
    orchestrator = SecurityAnalysisOrchestrator()
    lines = load_log_lines()

    if not lines:
        print("No sample logs found.")
        return

    for line in lines:
        event = parser.parse_line(line)
        alert = orchestrator.analyze(event)
        write_report(alert)

        print(
            f"[{alert.attack_type}] "
            f"{alert.risk_level} "
            f"{alert.source_ip} -> {alert.target} "
            f"score={alert.risk_score} "
            f"report={alert.alert_id}.md"
        )


if __name__ == "__main__":
    main()
