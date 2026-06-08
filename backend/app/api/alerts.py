from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.dependencies import get_db_session
from app.models.alert import RiskLevel, SecurityAlert
from app.models.alert_update import AlertStatusUpdate
from app.repositories.alert_repository import AlertRepository
from app.triage.schemas import AlertStatus

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/recent", response_model=list[SecurityAlert])
def get_recent_alerts(
    count: int = Query(default=20, ge=1, le=100),
    status: Optional[AlertStatus] = Query(default=None),
    risk_level: Optional[RiskLevel] = Query(default=None),
    requires_human_review: Optional[bool] = Query(default=None),
    session: Session = Depends(get_db_session),
) -> list[SecurityAlert]:
    """
    Query recent persisted security alerts with optional workflow filters.

    Parameters:
     count - maximum number of alerts to return
     status - optional workflow status filter
     risk_level - optional risk level filter
     requires_human_review - optional human review filter
     session - database session

    Returns:
     Recent security alerts ordered from newest to oldest

    Raises:
     None
    """

    return AlertRepository(session).list_recent(
        count=count,
        status=status,
        risk_level=risk_level,
        requires_human_review=requires_human_review,
    )


@router.patch("/{alert_id}/status", response_model=SecurityAlert)
def update_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    session: Session = Depends(get_db_session),
) -> SecurityAlert:
    """
    Update alert workflow status and analyst fields.

    Parameters:
     alert_id - alert identifier to update
     update - status update request body
     session - database session

    Returns:
     Updated security alert

    Raises:
     HTTPException - returned when the alert does not exist
    """

    alert = AlertRepository(session).update_status(alert_id, update)

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert
