from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.alerts import router as alerts_router
from app.api.analyze import router as analyze_router
from app.core.config import get_csv_env
from app.db.init_db import init_db

app = FastAPI(
    title="SecRAG Agent Backend",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_csv_env(
        "BACKEND_CORS_ORIGINS",
        ["http://127.0.0.1:5173", "http://localhost:5173"],
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    """
    Initialize application resources when the backend starts.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    init_db()


@app.get("/api/health")
def health() -> dict[str, str]:
    """
    Check whether the backend service is healthy.

    Parameters:
     None

    Returns:
     Backend service health status

    Raises:
     None
    """

    return {
        "status": "ok",
        "message": "SecRAG-agent-backend",
    }


app.include_router(analyze_router)
app.include_router(alerts_router)
