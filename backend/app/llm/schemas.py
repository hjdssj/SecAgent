from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    """
    Store runtime configuration for optional LLM report enhancement.

    Parameters:
     enabled - whether LLM enhancement is enabled
     provider - provider name used for metadata
     base_url - OpenAI-compatible base URL
     api_key - API key used by the provider
     model - chat completion model name
     timeout_seconds - HTTP timeout in seconds
     max_tokens - maximum generated tokens
     temperature - sampling temperature
     only_for_review - whether to call LLM only for alerts requiring human review
     min_risk_level - minimum risk level allowed to trigger LLM
     unknown_classifier_enabled - whether LLM can classify rule-unknown attacks
     unknown_classifier_max_tokens - maximum tokens for unknown attack classification
     unknown_classifier_min_confidence - minimum confidence required to accept classification

    Returns:
     LLM configuration used by the report enhancer

    Raises:
     None
    """

    enabled: bool = False
    provider: str = "openai_compatible"
    base_url: str = ""
    api_key: str = ""
    model: str = "qwen3-max"
    timeout_seconds: float = 30.0
    max_tokens: int = 1200
    temperature: float = 0.2
    only_for_review: bool = True
    min_risk_level: str = "high"
    unknown_classifier_enabled: bool = False
    unknown_classifier_max_tokens: int = 500
    unknown_classifier_min_confidence: float = 0.7


class LLMReportResult(BaseModel):
    """
    Represent the result of one LLM report enhancement attempt.

    Parameters:
     used - whether a real LLM call produced content
     skipped_reason - reason why the LLM call was skipped
     summary - concise LLM-generated analyst summary
     report_markdown - LLM-generated Markdown report section
     model - model used for generation
     provider - provider used for generation
     latency_ms - LLM call latency in milliseconds
     prompt_tokens - prompt token count returned by provider when available
     completion_tokens - completion token count returned by provider when available
     total_tokens - total token count returned by provider when available
     error - failure reason when the LLM call failed

    Returns:
     Structured LLM enhancement result

    Raises:
     None
    """

    used: bool = False
    skipped_reason: str | None = None
    summary: str | None = None
    report_markdown: str | None = None
    model: str | None = None
    provider: str | None = None
    latency_ms: float = 0.0
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    error: str | None = None


class LLMAttackClassificationResult(BaseModel):
    """
    Represent an LLM-assisted attack classification result.

    Parameters:
     used - whether a real LLM call was made
     skipped_reason - reason why classification was skipped
     attack_suspected - whether the model suspects an attack
     attack_type - normalized attack type suggested by the model
     confidence - model confidence from 0.0 to 1.0
     reason - concise reason for the classification
     matched_indicators - indicators cited by the model
     model - model used for classification
     provider - provider used for classification
     latency_ms - LLM call latency in milliseconds
     prompt_tokens - prompt tokens returned by provider when available
     completion_tokens - completion tokens returned by provider when available
     total_tokens - total tokens returned by provider when available
     error - failure reason when classification failed

    Returns:
     Structured LLM attack classification result

    Raises:
     None
    """

    used: bool = False
    skipped_reason: str | None = None
    attack_suspected: bool = False
    attack_type: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str | None = None
    matched_indicators: list[str] = Field(default_factory=list)
    model: str | None = None
    provider: str | None = None
    latency_ms: float = 0.0
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    error: str | None = None


class LLMFollowupResult(BaseModel):
    """
    Represent the result of one analysis follow-up question.

    Parameters:
     used - whether a real LLM call produced an answer
     answer_markdown - Markdown answer generated from saved analysis context
     model - model used for the answer
     provider - provider used for the answer
     latency_ms - LLM call latency in milliseconds
     prompt_tokens - prompt tokens returned by provider when available
     completion_tokens - completion tokens returned by provider when available
     total_tokens - total tokens returned by provider when available
     error - failure reason when the LLM call failed or was skipped

    Returns:
     Structured follow-up answer result

    Raises:
     None
    """

    used: bool = False
    answer_markdown: str = ""
    model: str | None = None
    provider: str | None = None
    latency_ms: float = 0.0
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    error: str | None = None


class LLMChatMessage(BaseModel):
    """
    Represent one OpenAI-compatible chat message.

    Parameters:
     role - chat message role
     content - chat message content

    Returns:
     Chat message object for provider requests

    Raises:
     None
    """

    role: str
    content: str


class LLMChatRequest(BaseModel):
    """
    Represent one LLM chat completion request.

    Parameters:
     model - chat completion model name
     messages - ordered chat messages
     temperature - sampling temperature
     max_tokens - maximum generated tokens

    Returns:
     Request object for OpenAI-compatible chat completions

    Raises:
     None
    """

    model: str
    messages: list[LLMChatMessage] = Field(default_factory=list)
    temperature: float = 0.2
    max_tokens: int = 1200
