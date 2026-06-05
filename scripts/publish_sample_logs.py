import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
SAMPLE_LOG_DIR = ROOT_DIR / "data" / "sample_logs"

sys.path.append(str(BACKEND_DIR))

from app.collector.modsecurity_parser import ModSecurityParser
from app.storage.redis_client import publish_event


def load_log_lines() -> list[str]:
    """
    读取样例日志目录中的所有非空日志行。

    Parameters:
     None

    Returns:
     样例日志行列表

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


def main() -> None:
    """
    将样例日志发布到 Redis Stream。

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    parser = ModSecurityParser()
    lines = load_log_lines()

    if not lines:
        print("No sample logs found.")
        return

    for line in lines:
        event = parser.parse_line(line)
        message_id = publish_event(event)

        print(
            f"published event {message_id}: "
            f"{event.source_ip} -> {event.path}"
        )


if __name__ == "__main__":
    main()
