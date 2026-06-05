import re
from urllib.parse import urlsplit

from app.models.event import SecurityEvent


class ModSecurityParser:
    """
    Parse simplified ModSecurity log lines into normalized security events.

    Parameters:
     None

    Returns:
     A parser instance used to convert WAF log text into SecurityEvent objects

    Raises:
     None
    """

    def parse_line(self, line: str) -> SecurityEvent:
        """
        Parse a single WAF log line into a normalized security event.

        Parameters:
         line - single WAF log line in key=value format

        Returns:
         A normalized security event object

        Raises:
         None
        """

        fields = self._extract_fields(line)

        url = fields.get("url", "")
        path, query = self._split_url(url)

        status_text = fields.get("status")
        status = int(status_text) if status_text else None

        return SecurityEvent(
            source_ip=fields.get("client_ip", "unknown"),
            method=fields.get("method", "GET"),
            url=url,
            path=path,
            query=query,
            status=status,
            user_agent=fields.get("user_agent", ""),
            waf_rule_id=fields.get("rule_id") or None,
            waf_message=fields.get("message"),
            raw_log=line,
        )

    def _extract_fields(self, line: str) -> dict[str, str]:
        """
        Extract key=value fields from a single log line.

        Parameters:
         line - single WAF log line in key=value format

        Returns:
         A mapping from field names to field values

        Raises:
         None
        """

        pattern = r'(\w+)=("[^"]*"|\S*)'
        fields: dict[str, str] = {}

        for key, value in re.findall(pattern, line):
            fields[key] = value.strip('"')

        return fields

    def _split_url(self, url: str) -> tuple[str, str]:
        """
        Split a URL into request path and query string.

        Parameters:
         url - original request URL

        Returns:
         A tuple containing request path and query string

        Raises:
         None
        """

        parsed = urlsplit(url)
        return parsed.path, parsed.query
