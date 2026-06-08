from app.core.config import get_bool_env, get_env, get_float_env, get_int_env
from app.llm.schemas import LLMConfig


def load_llm_config() -> LLMConfig:
    """
    Load LLM configuration from environment variables.

    Parameters:
     None

    Returns:
     LLM configuration with safe defaults

    Raises:
     None
    """

    api_key = get_env("LLM_API_KEY") or get_env("DASHSCOPE_API_KEY")
    base_url = get_env("LLM_BASE_URL") or get_env("DASHSCOPE_BASE_URL")
    model = get_env("LLM_MODEL") or get_env("OPENAI_MODEL", "qwen3-max")

    return LLMConfig(
        enabled=get_bool_env("LLM_ENABLED", False),
        provider=get_env("LLM_PROVIDER", "openai_compatible"),
        base_url=base_url,
        api_key=api_key,
        model=model,
        timeout_seconds=get_float_env("LLM_TIMEOUT_SECONDS", 30.0),
        max_tokens=get_int_env("LLM_MAX_TOKENS", 1200),
        temperature=get_float_env("LLM_TEMPERATURE", 0.2),
        only_for_review=get_bool_env("LLM_ONLY_FOR_REVIEW", True),
        min_risk_level=get_env("LLM_MIN_RISK_LEVEL", "high"),
        unknown_classifier_enabled=get_bool_env("LLM_UNKNOWN_CLASSIFIER_ENABLED", False),
        unknown_classifier_max_tokens=get_int_env("LLM_UNKNOWN_CLASSIFIER_MAX_TOKENS", 500),
        unknown_classifier_min_confidence=get_float_env(
            "LLM_UNKNOWN_CLASSIFIER_MIN_CONFIDENCE",
            0.7,
        ),
    )
