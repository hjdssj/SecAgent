from fastapi import FastAPI

from app.api.alerts import router as alerts_router
from app.api.analyze import router as analyze_router

app = FastAPI(
    title="SecRAG Agent Backend",
    version="0.1.0",
)


@app.get("/api/health")
def health() -> dict[str, str]:
    """
    检查后端服务是否正常运行。

    Parameters:
     None

    Returns:
     后端服务健康状态

    Raises:
     None
    """

    return {
        "status": "ok",
        "message": "SecRAG-agent-backend",
    }


app.include_router(analyze_router)
app.include_router(alerts_router)
