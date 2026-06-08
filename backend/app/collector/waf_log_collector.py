import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote, urlsplit

from app.collector.modsecurity_parser import ModSecurityParser
from app.core.config import PROJECT_ROOT, get_csv_env, get_path_env
from app.models.event import SecurityEvent
from app.storage.redis_client import publish_event

DEFAULT_AUDIT_LOG_PATH = (
    PROJECT_ROOT / "data" / "waf_logs" / "modsecurity" / "audit" / "audit.log"
)
DEFAULT_OFFSET_PATH = PROJECT_ROOT / "data" / "waf_logs" / ".collector.offset"
DEFAULT_IGNORED_PATHS = ["/__waf_health"]


class WafLogCollector:
    """
    Collect WAF audit logs and publish normalized security events to Redis.

    Parameters:
     log_path - local path of the WAF audit log file
     offset_path - local path used to remember the last read file offset

    Returns:
     A collector instance that can read WAF logs and publish SecurityEvent objects

    Raises:
     None
    """

    def __init__(
        self,
        log_path: Path | None = None,
        offset_path: Path | None = None,
    ) -> None:
        """
        Initialize the WAF log collector.

        Parameters:
         log_path - local path of the WAF audit log file
         offset_path - local path used to remember the last read file offset

        Returns:
         None

        Raises:
         None
        """

        self.log_path = log_path or get_path_env("WAF_AUDIT_LOG_PATH", DEFAULT_AUDIT_LOG_PATH)
        self.offset_path = offset_path or get_path_env("WAF_COLLECTOR_OFFSET_PATH", DEFAULT_OFFSET_PATH)
        self.ignored_paths = set(
            get_csv_env("WAF_COLLECTOR_IGNORED_PATHS", DEFAULT_IGNORED_PATHS)
        )
        self.parser = ModSecurityParser()

    def collect_once(self, from_start: bool = False) -> int:
        """
        Read new WAF audit log entries once and publish them to Redis.

        Parameters:
         from_start - whether to ignore the saved offset and read the log from the beginning

        Returns:
         Number of security events successfully published to Redis

        Raises:
         None
        """

        if not self.log_path.exists():
            return 0

        start_offset = 0 if from_start else self._load_offset()
        current_size = self.log_path.stat().st_size

        if start_offset > current_size:
            start_offset = 0

        with self.log_path.open("r", encoding="utf-8", errors="ignore") as file:
            file.seek(start_offset)
            content = file.read()
            end_offset = file.tell()

        if not content.strip():
            self._save_offset(end_offset)
            return 0

        published = 0

        for entry in self._extract_entries(content):
            event = self._entry_to_event(entry)

            if event is None:
                continue

            if self._should_ignore_event(event):
                continue

            publish_event(event)
            published += 1

        self._save_offset(end_offset)
        return published

    def collect_forever(self, interval_seconds: float = 2.0) -> None:
        """
        Continuously collect new WAF audit log entries and publish them to Redis.

        Parameters:
         interval_seconds - sleep interval between two collection attempts

        Returns:
         None

        Raises:
         None
        """

        while True:
            published = self.collect_once()

            if published:
                print(f"published waf events: {published}")

            time.sleep(interval_seconds)

    def _extract_entries(self, content: str) -> list[dict[str, Any] | str]:
        """
        Extract JSON audit entries or simplified log lines from raw log text.

        Parameters:
         content - newly read WAF audit log text

        Returns:
         A list of parsed JSON dictionaries or simplified key=value log lines

        Raises:
         None
        """

        entries: list[dict[str, Any] | str] = []
        decoder = json.JSONDecoder()
        index = 0

        while index < len(content):
            while index < len(content) and content[index].isspace():
                index += 1

            if index >= len(content):
                break

            if content[index] == "{":
                try:
                    item, next_index = decoder.raw_decode(content, index)
                except json.JSONDecodeError:
                    break

                if isinstance(item, dict):
                    entries.append(item)

                index = next_index
                continue

            next_line = content.find("\n", index)

            if next_line == -1:
                line = content[index:].strip()
                index = len(content)
            else:
                line = content[index:next_line].strip()
                index = next_line + 1

            if line:
                entries.append(line)

        return entries

    def _entry_to_event(self, entry: dict[str, Any] | str) -> Optional[SecurityEvent]:
        """
        Convert one audit log entry into a normalized security event.

        Parameters:
         entry - parsed ModSecurity JSON entry or simplified key=value log line

        Returns:
         A normalized security event, or None when the entry cannot be converted

        Raises:
         None
        """

        if isinstance(entry, str):
            return self.parser.parse_line(entry)

        transaction = entry.get("transaction")

        if not isinstance(transaction, dict):
            return None

        request = transaction.get("request")
        response = transaction.get("response")
        messages = transaction.get("messages")

        if not isinstance(request, dict):
            request = {}

        if not isinstance(response, dict):
            response = {}

        if not isinstance(messages, list):
            messages = []

        uri = str(request.get("uri") or "")
        decoded_uri = unquote(uri)
        path, query = self._split_url(decoded_uri)
        first_message = self._first_message(messages)

        return SecurityEvent(
            event_id=str(transaction.get("unique_id") or "") or None,
            timestamp=self._parse_timestamp(transaction.get("time_stamp")),
            source_ip=str(transaction.get("client_ip") or "unknown"),
            method=str(request.get("method") or "GET"),
            url=decoded_uri,
            path=path,
            query=query,
            status=self._parse_status(response.get("http_code")),
            user_agent=self._get_header(request, "User-Agent"),
            waf_rule_id=first_message.get("rule_id"),
            waf_message=first_message.get("message"),
            raw_log=json.dumps(entry, ensure_ascii=False),
        )

    def _should_ignore_event(self, event: SecurityEvent) -> bool:
        """
        Decide whether a normalized event should be ignored by the collector.

        Parameters:
         event - normalized security event parsed from WAF logs

        Returns:
         True when the event path is configured as collector noise, otherwise False

        Raises:
         None
        """

        return event.path in self.ignored_paths

    def _first_message(self, messages: list[Any]) -> dict[str, Optional[str]]:
        """
        Extract the first ModSecurity rule message from an audit log entry.

        Parameters:
         messages - list of ModSecurity message objects

        Returns:
         A dictionary containing rule_id and message values

        Raises:
         None
        """

        for item in messages:
            if not isinstance(item, dict):
                continue

            details = item.get("details")

            if not isinstance(details, dict):
                details = {}

            return {
                "rule_id": self._optional_string(
                    details.get("ruleId") or details.get("rule_id")
                ),
                "message": self._optional_string(item.get("message")),
            }

        return {"rule_id": None, "message": None}

    def _get_header(self, request: dict[str, Any], name: str) -> str:
        """
        Read a request header from a ModSecurity request object.

        Parameters:
         request - ModSecurity request dictionary
         name - target HTTP header name

        Returns:
         Header value when present, otherwise an empty string

        Raises:
         None
        """

        headers = request.get("headers")

        if not isinstance(headers, dict):
            return ""

        for key, value in headers.items():
            if key.lower() == name.lower():
                return str(value)

        return ""

    def _split_url(self, url: str) -> tuple[str, str]:
        """
        Split a request URI into path and query string.

        Parameters:
         url - original request URI

        Returns:
         A tuple containing request path and query string

        Raises:
         None
        """

        parsed = urlsplit(url)
        return parsed.path, parsed.query

    def _parse_timestamp(self, value: Any) -> Optional[datetime]:
        """
        Parse a ModSecurity timestamp into a datetime object when possible.

        Parameters:
         value - timestamp value from the audit log

        Returns:
         Parsed datetime object, or None when parsing fails

        Raises:
         None
        """

        if not value:
            return None

        text = str(value).strip()

        for fmt in (
            "%a %b %d %H:%M:%S %Y",
            "%d/%b/%Y:%H:%M:%S %z",
            "%Y-%m-%dT%H:%M:%S%z",
        ):
            try:
                parsed = datetime.strptime(text, fmt)
            except ValueError:
                continue

            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=UTC)

            return parsed.astimezone(UTC)

        return None

    def _parse_status(self, value: Any) -> Optional[int]:
        """
        Parse an HTTP status value into an integer.

        Parameters:
         value - raw status value from the audit log

        Returns:
         Parsed integer status, or None when parsing fails

        Raises:
         None
        """

        if value is None:
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _optional_string(self, value: Any) -> Optional[str]:
        """
        Convert a value into a non-empty string when possible.

        Parameters:
         value - source value to convert

        Returns:
         Non-empty string value, or None when the value is empty

        Raises:
         None
        """

        if value is None:
            return None

        text = str(value)
        return text or None

    def _load_offset(self) -> int:
        """
        Load the last processed log file offset.

        Parameters:
         None

        Returns:
         Last processed byte offset, or zero when no offset exists

        Raises:
         None
        """

        if not self.offset_path.exists():
            return 0

        try:
            return int(self.offset_path.read_text(encoding="utf-8").strip())
        except ValueError:
            return 0

    def _save_offset(self, offset: int) -> None:
        """
        Save the last processed log file offset.

        Parameters:
         offset - byte offset after the latest successful read

        Returns:
         None

        Raises:
         None
        """

        self.offset_path.parent.mkdir(parents=True, exist_ok=True)
        self.offset_path.write_text(str(offset), encoding="utf-8")


def collect_once(
    log_path: Path = DEFAULT_AUDIT_LOG_PATH,
    from_start: bool = False,
) -> int:
    """
    Collect WAF audit logs once using the default collector.

    Parameters:
     log_path - local path of the WAF audit log file
     from_start - whether to read the log from the beginning

    Returns:
     Number of security events successfully published to Redis

    Raises:
     None
    """

    return WafLogCollector(log_path=log_path).collect_once(from_start=from_start)


def main() -> None:
    """
    Run the WAF log collector from the command line.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    cli = argparse.ArgumentParser(description="Collect WAF logs into Redis.")
    cli.add_argument("--log-path", type=Path, default=None)
    cli.add_argument("--from-start", action="store_true")
    cli.add_argument("--follow", action="store_true")
    cli.add_argument("--interval", type=float, default=2.0)
    args = cli.parse_args()

    collector = WafLogCollector(log_path=args.log_path)

    if args.follow:
        collector.collect_forever(interval_seconds=args.interval)
        return

    published = collector.collect_once(from_start=args.from_start)
    print(f"published waf events: {published}")


if __name__ == "__main__":
    main()
