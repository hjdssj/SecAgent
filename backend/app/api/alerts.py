from fastapi import APIRouter, Query

from app.models.alert import SecurityAlert
from app.storage.redis_client import read_recent_alerts

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/recent", response_model=list[SecurityAlert])
def get_recent_alerts(count: int = Query(default=20, ge=1, le=100)) -> list[SecurityAlert]:
    """
    查询最近生成的安全告警。

    Parameters:
     count - 返回的最大告警数量

    Returns:
     最近生成的安全告警列表

    Raises:
     None
    """

    return read_recent_alerts(count=count)
