from typing import Optional

from pydantic import BaseModel

from app.triage.schemas import AlertStatus


class AlertStatusUpdate(BaseModel):
    """
    Represent a request to update alert workflow status.

    Parameters:
     status - target alert workflow status
     analyst_note - optional analyst note recorded with the status change
     handled_by - optional analyst identifier recorded with the status change

    Returns:
     A validated alert status update request

    Raises:
     None
    """

    status: AlertStatus
    analyst_note: Optional[str] = None
    handled_by: Optional[str] = None
