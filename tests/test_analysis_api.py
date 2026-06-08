import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.api.analysis as analysis_api
from app.analysis.followup import AnalysisFollowupMessage
from app.analysis.state import AnalysisState
from app.analysis.followup import AnalysisFollowupResponse
from app.models.event import SecurityEvent


class FakeSessionMemoryStore:
    """
    Return deterministic analysis state for API tests.

    Parameters:
     state - analysis state returned from load_state

    Returns:
     Fake session memory store

    Raises:
     None
    """

    def __init__(self, state: AnalysisState | None = None) -> None:
        """
        Initialize fake store.

        Parameters:
         state - analysis state returned from load_state

        Returns:
         None

        Raises:
         None
        """

        self.state = state

    def load_state(self, session_id: str) -> AnalysisState | None:
        """
        Return the configured analysis state.

        Parameters:
         session_id - analysis session identifier

        Returns:
         Analysis state or None

        Raises:
         None
        """

        return self.state


def build_client(state: AnalysisState | None, monkeypatch) -> TestClient:
    """
    Build an isolated FastAPI client for analysis API tests.

    Parameters:
     state - analysis state returned by the fake store
     monkeypatch - pytest monkeypatch fixture

    Returns:
     Test client with analysis router installed

    Raises:
     None
    """

    app = FastAPI()
    app.include_router(analysis_api.router)
    monkeypatch.setattr(
        analysis_api,
        "SessionMemoryStore",
        lambda: FakeSessionMemoryStore(state),
    )
    monkeypatch.setattr(
        analysis_api,
        "AnalysisFollowupAnswerer",
        lambda: FakeFollowupAnswerer(),
    )
    return TestClient(app)


class FakeFollowupAnswerer:
    """
    Return deterministic follow-up API answers.

    Parameters:
     None

    Returns:
     Fake follow-up answerer

    Raises:
     None
    """

    def answer(
        self,
        state: AnalysisState,
        question: str,
        history: list[AnalysisFollowupMessage] | None = None,
    ) -> AnalysisFollowupResponse:
        """
        Return a deterministic follow-up response.

        Parameters:
         state - saved analysis state
         question - analyst follow-up question
         history - previous follow-up messages in the current conversation

        Returns:
         Deterministic follow-up response

        Raises:
         None
        """

        return AnalysisFollowupResponse(
            session_id=state.session_id,
            question=question,
            answer_markdown="fake follow-up answer",
            llm_used=True,
            llm_model="fake-model",
            llm_provider="fake-provider",
        )


def test_analysis_result_api_returns_saved_state(monkeypatch) -> None:
    """
    Verify analysis result API returns saved session context.

    Parameters:
     monkeypatch - pytest monkeypatch fixture

    Returns:
     None

    Raises:
     None
    """

    state = AnalysisState(
        session_id="session-api-test",
        event=SecurityEvent(source_ip="1.1.1.1", path="/login", url="/login"),
    )
    client = build_client(state, monkeypatch)

    response = client.get("/api/analysis/session-api-test/result")

    assert response.status_code == 200
    assert response.json()["session_id"] == "session-api-test"


def test_analysis_result_api_returns_404_when_missing(monkeypatch) -> None:
    """
    Verify analysis result API returns 404 for missing session context.

    Parameters:
     monkeypatch - pytest monkeypatch fixture

    Returns:
     None

    Raises:
     None
    """

    client = build_client(None, monkeypatch)

    response = client.get("/api/analysis/session-missing/result")

    assert response.status_code == 404


def test_analysis_followup_api_answers_from_saved_state(monkeypatch) -> None:
    """
    Verify follow-up API answers questions from saved session context.

    Parameters:
     monkeypatch - pytest monkeypatch fixture

    Returns:
     None

    Raises:
     None
    """

    state = AnalysisState(
        session_id="session-api-test",
        event=SecurityEvent(source_ip="1.1.1.1", path="/login", url="/login"),
    )
    client = build_client(state, monkeypatch)

    response = client.post(
        "/api/analysis/session-api-test/ask",
        json={
            "question": "为什么是高危？",
            "history": [
                {"role": "user", "content": "先解释证据"},
                {"role": "assistant", "content": "命中了 WAF 规则"},
            ],
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == "session-api-test"
    assert data["question"] == "为什么是高危？"
    assert data["answer_markdown"] == "fake follow-up answer"


def test_analysis_followup_stream_api_returns_sse_chunks(monkeypatch) -> None:
    """
    Verify follow-up stream API returns answer chunks as server-sent events.

    Parameters:
     monkeypatch - pytest monkeypatch fixture

    Returns:
     None

    Raises:
     None
    """

    state = AnalysisState(
        session_id="session-api-test",
        event=SecurityEvent(source_ip="1.1.1.1", path="/login", url="/login"),
    )
    client = build_client(state, monkeypatch)

    response = client.post(
        "/api/analysis/session-api-test/ask/stream",
        json={
            "question": "为什么是高危？",
            "history": [
                {"role": "user", "content": "先解释证据"},
            ],
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "event: meta" in response.text
    assert "event: chunk" in response.text
    assert "fake follow-up answer" in response.text
    assert "event: done" in response.text


def test_analysis_followup_api_returns_404_when_missing(monkeypatch) -> None:
    """
    Verify follow-up API returns 404 for missing session context.

    Parameters:
     monkeypatch - pytest monkeypatch fixture

    Returns:
     None

    Raises:
     None
    """

    client = build_client(None, monkeypatch)

    response = client.post(
        "/api/analysis/session-missing/ask",
        json={"question": "为什么是高危？"},
    )

    assert response.status_code == 404
