import json
import time
from collections.abc import Iterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.analysis.followup import AnalysisFollowupRequest, AnalysisFollowupResponse
from app.analysis.state import AnalysisState
from app.llm.followup_answerer import AnalysisFollowupAnswerer
from app.memory.session_memory import SessionMemoryStore

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


@router.get("/{session_id}/result", response_model=AnalysisState)
def get_analysis_result(session_id: str) -> AnalysisState:
    """
    Return saved analysis session context for follow-up questions.

    Parameters:
     session_id - analysis session identifier returned on a security alert

    Returns:
     Saved analysis state used as follow-up question context

    Raises:
     HTTPException - returned when the session result does not exist
    """

    state = SessionMemoryStore().load_state(session_id)

    if state is None:
        raise HTTPException(status_code=404, detail="Analysis session not found")

    return state


@router.post("/{session_id}/ask", response_model=AnalysisFollowupResponse)
def ask_analysis_followup(
    session_id: str,
    request: AnalysisFollowupRequest,
) -> AnalysisFollowupResponse:
    """
    Answer a follow-up question from saved analysis context.

    Parameters:
     session_id - analysis session identifier returned on a security alert
     request - follow-up question request body

    Returns:
     Markdown answer generated only from saved analysis context

    Raises:
     HTTPException - returned when the session result does not exist
    """

    state = SessionMemoryStore().load_state(session_id)

    if state is None:
        raise HTTPException(status_code=404, detail="Analysis session not found")

    return AnalysisFollowupAnswerer().answer(state, request.question, request.history)


@router.post("/{session_id}/ask/stream")
def stream_analysis_followup(
    session_id: str,
    request: AnalysisFollowupRequest,
) -> StreamingResponse:
    """
    Stream a follow-up answer from saved analysis context as SSE chunks.

    Parameters:
     session_id - analysis session identifier returned on a security alert
     request - follow-up question request body

    Returns:
     Server-sent event stream containing answer chunks and final metadata

    Raises:
     HTTPException - returned when the session result does not exist
    """

    state = SessionMemoryStore().load_state(session_id)

    if state is None:
        raise HTTPException(status_code=404, detail="Analysis session not found")

    answerer = AnalysisFollowupAnswerer()

    return StreamingResponse(
        _sse_followup_stream(answerer, state, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def _sse_followup_stream(
    answerer: AnalysisFollowupAnswerer,
    state: AnalysisState,
    request: AnalysisFollowupRequest,
) -> Iterator[str]:
    """
    Stream a follow-up answer from the LLM provider when available.

    Parameters:
     answerer - follow-up answerer containing runtime LLM configuration
     state - saved analysis state used as answer context
     request - follow-up request containing question and history

    Returns:
     Iterator of server-sent event frames

    Raises:
     None
    """

    if (
        not hasattr(answerer, "config")
        or not hasattr(answerer, "client")
        or not hasattr(answerer, "prompt_builder")
        or not answerer.config.enabled
        or not answerer.config.api_key
        or not answerer.config.base_url
    ):
        response = answerer.answer(state, request.question, request.history)
        yield from _sse_followup_response(response)
        return

    started = time.perf_counter()
    answer_parts: list[str] = []
    metadata = AnalysisFollowupResponse(
        session_id=state.session_id,
        question=request.question,
        answer_markdown="",
        llm_used=True,
        llm_model=answerer.config.model,
        llm_provider=answerer.config.provider,
    )
    yield _sse_event("meta", metadata.model_dump(mode="json"))

    try:
        messages = answerer.prompt_builder.build_messages(
            state,
            request.question,
            request.history,
        )

        for chunk in answerer.client.stream_followup(messages):
            answer_parts.append(chunk)
            yield _sse_event("chunk", {"content": chunk})
    except RuntimeError as error:
        message = f"无法生成追问回答：{error}"
        answer_parts = [message]
        yield _sse_event("chunk", {"content": message})
        metadata.llm_used = False
        metadata.llm_error = str(error)

    completed = metadata.model_copy(
        update={
            "answer_markdown": "".join(answer_parts),
            "llm_latency_ms": round((time.perf_counter() - started) * 1000, 2),
        }
    )
    yield _sse_event("done", completed.model_dump(mode="json"))


def _sse_followup_response(response: AnalysisFollowupResponse) -> Iterator[str]:
    """
    Convert one follow-up response into server-sent event chunks.

    Parameters:
     response - completed follow-up answer response

    Returns:
     Iterator of server-sent event frames

    Raises:
     None
    """

    metadata = response.model_copy(update={"answer_markdown": ""}).model_dump(mode="json")
    yield _sse_event("meta", metadata)

    for chunk in _chunk_text(response.answer_markdown):
        yield _sse_event("chunk", {"content": chunk})

    yield _sse_event("done", response.model_dump(mode="json"))


def _chunk_text(text: str, size: int = 24) -> Iterator[str]:
    """
    Split text into bounded chunks for incremental frontend rendering.

    Parameters:
     text - source answer text
     size - maximum characters in one chunk

    Returns:
     Iterator of text chunks

    Raises:
     None
    """

    if not text:
        return

    for index in range(0, len(text), size):
        yield text[index : index + size]


def _sse_event(event: str, data: dict) -> str:
    """
    Format one server-sent event frame.

    Parameters:
     event - event name
     data - JSON-serializable event payload

    Returns:
     SSE frame text

    Raises:
     None
    """

    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {payload}\n\n"
