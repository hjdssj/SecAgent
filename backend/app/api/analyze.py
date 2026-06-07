from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.agents.orchestrator import SecurityAnalysisOrchestrator
from app.db.dependencies import get_db_session
from app.models.alert import SecurityAlert
from app.models.event import SecurityEvent
from app.repositories.alert_repository import AlertRepository

router = APIRouter(prefix="/api", tags=["analyze"])
orchestrator = SecurityAnalysisOrchestrator()


@router.post("/analyze", response_model=SecurityAlert)
def analyze_event(
    event: SecurityEvent,
    session: Session = Depends(get_db_session),
) -> SecurityAlert:
    """
    Analyze one normalized security event and persist the generated alert.

    Parameters:
     event - normalized security event submitted by API, replay script, or collector
     session - database session

    Returns:
     Structured security alert generated from the event

    Raises:
     None
    """

    alert = orchestrator.analyze(event)
    AlertRepository(session).save(alert)
    return alert
