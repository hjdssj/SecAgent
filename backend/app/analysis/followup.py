from typing import Literal

from pydantic import BaseModel, Field


class AnalysisFollowupMessage(BaseModel):
    """
    Represent one prior follow-up conversation message.

    Parameters:
     role - message role in the follow-up conversation
     content - message text shown to or written by the analyst

    Returns:
     Follow-up conversation message

    Raises:
     None
    """

    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


class AnalysisFollowupRequest(BaseModel):
    """
    Represent one follow-up question for a saved analysis session.

    Parameters:
     question - analyst question about the saved analysis context
     history - previous follow-up messages in the current frontend conversation

    Returns:
     Follow-up request body

    Raises:
     None
    """

    question: str = Field(min_length=1, max_length=2000)
    history: list[AnalysisFollowupMessage] = Field(default_factory=list, max_length=12)


class AnalysisFollowupResponse(BaseModel):
    """
    Represent one follow-up answer generated from saved analysis context.

    Parameters:
     session_id - analysis session identifier
     question - original analyst question
     answer_markdown - Markdown answer based only on saved session context
     llm_used - whether a real LLM call produced the answer
     llm_model - model used for the answer
     llm_provider - provider used for the answer
     llm_latency_ms - LLM call latency in milliseconds
     llm_prompt_tokens - prompt tokens returned by provider when available
     llm_completion_tokens - completion tokens returned by provider when available
     llm_total_tokens - total tokens returned by provider when available
     llm_error - failure reason when the LLM call failed or was skipped

    Returns:
     Follow-up answer response

    Raises:
     None
    """

    session_id: str
    question: str
    answer_markdown: str
    llm_used: bool = False
    llm_model: str | None = None
    llm_provider: str | None = None
    llm_latency_ms: float = 0.0
    llm_prompt_tokens: int | None = None
    llm_completion_tokens: int | None = None
    llm_total_tokens: int | None = None
    llm_error: str | None = None
