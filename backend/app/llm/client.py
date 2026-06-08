import json
import time
from collections.abc import Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.llm.schemas import (
    LLMAttackClassificationResult,
    LLMConfig,
    LLMFollowupResult,
    LLMReportResult,
)


class OpenAICompatibleLLMClient:
    """
    Call an OpenAI-compatible chat completions endpoint.

    Parameters:
     config - LLM provider configuration

    Returns:
     Client capable of generating LLM report results

    Raises:
     None
    """

    def __init__(self, config: LLMConfig) -> None:
        """
        Initialize the client.

        Parameters:
         config - LLM provider configuration

        Returns:
         None

        Raises:
         None
        """

        self.config = config

    def generate_report(self, messages: list[dict[str, str]]) -> LLMReportResult:
        """
        Generate one report using chat completions.

        Parameters:
         messages - OpenAI-compatible chat messages

        Returns:
         LLM report result containing generated content or error information

        Raises:
         None
        """

        started = time.perf_counter()
        url = self._chat_completions_url()
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        request = Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                data = json.loads(raw)
        except HTTPError as error:
            return self._error_result(started, f"HTTP_{error.code}")
        except URLError as error:
            return self._error_result(started, f"URL_ERROR:{error.reason}")
        except TimeoutError:
            return self._error_result(started, "TIMEOUT")
        except json.JSONDecodeError:
            return self._error_result(started, "INVALID_PROVIDER_JSON")

        content = self._extract_content(data)
        parsed = self._parse_content(content)
        usage = data.get("usage", {})

        return LLMReportResult(
            used=True,
            summary=parsed.get("summary") or content[:300],
            report_markdown=parsed.get("report_markdown") or content,
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            total_tokens=usage.get("total_tokens"),
        )

    def classify_attack(
        self,
        messages: list[dict[str, str]],
    ) -> LLMAttackClassificationResult:
        """
        Classify one rule-unknown security event using chat completions.

        Parameters:
         messages - OpenAI-compatible chat messages

        Returns:
         LLM attack classification result containing parsed JSON or error information

        Raises:
         None
        """

        started = time.perf_counter()
        url = self._chat_completions_url()
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": self.config.unknown_classifier_max_tokens,
            "response_format": {"type": "json_object"},
        }

        request = Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                data = json.loads(raw)
        except HTTPError as error:
            return self._classification_error_result(started, f"HTTP_{error.code}")
        except URLError as error:
            return self._classification_error_result(started, f"URL_ERROR:{error.reason}")
        except TimeoutError:
            return self._classification_error_result(started, "TIMEOUT")
        except json.JSONDecodeError:
            return self._classification_error_result(started, "INVALID_PROVIDER_JSON")

        content = self._extract_content(data)
        parsed = self._parse_classification_content(content)
        usage = data.get("usage", {})

        return LLMAttackClassificationResult(
            used=True,
            attack_suspected=parsed.get("attack_suspected", False),
            attack_type=parsed.get("attack_type"),
            confidence=parsed.get("confidence", 0.0),
            reason=parsed.get("reason"),
            matched_indicators=parsed.get("matched_indicators", []),
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            total_tokens=usage.get("total_tokens"),
        )

    def answer_followup(
        self,
        messages: list[dict[str, str]],
    ) -> LLMFollowupResult:
        """
        Answer one follow-up question using chat completions.

        Parameters:
         messages - OpenAI-compatible chat messages

        Returns:
         LLM follow-up result containing Markdown answer or error information

        Raises:
         None
        """

        started = time.perf_counter()
        url = self._chat_completions_url()
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        request = Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                data = json.loads(raw)
        except HTTPError as error:
            return self._followup_error_result(started, f"HTTP_{error.code}")
        except URLError as error:
            return self._followup_error_result(started, f"URL_ERROR:{error.reason}")
        except TimeoutError:
            return self._followup_error_result(started, "TIMEOUT")
        except json.JSONDecodeError:
            return self._followup_error_result(started, "INVALID_PROVIDER_JSON")

        content = self._extract_content(data)
        usage = data.get("usage", {})

        return LLMFollowupResult(
            used=True,
            answer_markdown=content,
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            total_tokens=usage.get("total_tokens"),
        )

    def stream_followup(
        self,
        messages: list[dict[str, str]],
    ) -> Iterator[str]:
        """
        Stream one follow-up answer using OpenAI-compatible chat completions.

        Parameters:
         messages - OpenAI-compatible chat messages

        Returns:
         Iterator of assistant content chunks

        Raises:
         RuntimeError - raised when the provider request fails
        """

        url = self._chat_completions_url()
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": True,
        }

        request = Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                for raw_line in response:
                    line = raw_line.decode("utf-8").strip()

                    if not line.startswith("data:"):
                        continue

                    data = line.removeprefix("data:").strip()

                    if data == "[DONE]":
                        break

                    chunk = self._extract_stream_delta(data)

                    if chunk:
                        yield chunk
        except HTTPError as error:
            raise RuntimeError(f"HTTP_{error.code}") from error
        except URLError as error:
            raise RuntimeError(f"URL_ERROR:{error.reason}") from error
        except TimeoutError as error:
            raise RuntimeError("TIMEOUT") from error

    def _extract_stream_delta(self, data: str) -> str:
        """
        Extract assistant delta content from one streaming JSON line.

        Parameters:
         data - raw JSON payload from an SSE data line

        Returns:
         Assistant content delta or empty string

        Raises:
         None
        """

        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            return ""

        choices = parsed.get("choices") or []

        if not choices:
            return ""

        delta = choices[0].get("delta") or {}
        return str(delta.get("content") or "")

    def _chat_completions_url(self) -> str:
        """
        Build the chat completions URL.

        Parameters:
         None

        Returns:
         Full chat completions URL

        Raises:
         None
        """

        base_url = self.config.base_url.rstrip("/")

        if base_url.endswith("/chat/completions"):
            return base_url

        return f"{base_url}/chat/completions"

    def _extract_content(self, data: dict) -> str:
        """
        Extract assistant content from provider response.

        Parameters:
         data - provider JSON response

        Returns:
         Assistant message content

        Raises:
         None
        """

        choices = data.get("choices") or []

        if not choices:
            return ""

        message = choices[0].get("message") or {}
        return str(message.get("content") or "")

    def _parse_content(self, content: str) -> dict[str, str]:
        """
        Parse model content as JSON when possible.

        Parameters:
         content - raw model output

        Returns:
         Parsed output dictionary or empty dictionary

        Raises:
         None
        """

        cleaned = content.strip()

        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.removeprefix("json").strip()

        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            return {}

        if not isinstance(parsed, dict):
            return {}

        return {
            "summary": str(parsed.get("summary") or ""),
            "report_markdown": str(parsed.get("report_markdown") or ""),
        }

    def _parse_classification_content(self, content: str) -> dict:
        """
        Parse model content as an attack classification JSON object.

        Parameters:
         content - raw model output

        Returns:
         Parsed and normalized classification dictionary

        Raises:
         None
        """

        cleaned = content.strip()

        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.removeprefix("json").strip()

        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            return {}

        if not isinstance(parsed, dict):
            return {}

        indicators = parsed.get("matched_indicators") or []

        if not isinstance(indicators, list):
            indicators = [str(indicators)]

        return {
            "attack_suspected": bool(parsed.get("attack_suspected", False)),
            "attack_type": str(parsed.get("attack_type") or "") or None,
            "confidence": self._bounded_float(parsed.get("confidence"), 0.0, 1.0),
            "reason": str(parsed.get("reason") or "") or None,
            "matched_indicators": [str(item) for item in indicators[:10]],
        }

    def _error_result(self, started: float, error: str) -> LLMReportResult:
        """
        Build a failed LLM result without raising.

        Parameters:
         started - perf counter timestamp captured before the request
         error - failure reason

        Returns:
         LLM report result containing error metadata

        Raises:
         None
        """

        return LLMReportResult(
            used=False,
            error=error,
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    def _classification_error_result(
        self,
        started: float,
        error: str,
    ) -> LLMAttackClassificationResult:
        """
        Build a failed classification result without raising.

        Parameters:
         started - perf counter timestamp captured before the request
         error - failure reason

        Returns:
         LLM classification result containing error metadata

        Raises:
         None
        """

        return LLMAttackClassificationResult(
            used=False,
            error=error,
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    def _followup_error_result(
        self,
        started: float,
        error: str,
    ) -> LLMFollowupResult:
        """
        Build a failed follow-up result without raising.

        Parameters:
         started - perf counter timestamp captured before the request
         error - failure reason

        Returns:
         LLM follow-up result containing error metadata

        Raises:
         None
        """

        return LLMFollowupResult(
            used=False,
            error=error,
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    def _bounded_float(self, value: object, minimum: float, maximum: float) -> float:
        """
        Convert a value to a bounded float.

        Parameters:
         value - source value to convert
         minimum - lower bound
         maximum - upper bound

        Returns:
         Bounded float value

        Raises:
         None
        """

        try:
            number = float(value)
        except (TypeError, ValueError):
            number = minimum

        return min(max(number, minimum), maximum)
