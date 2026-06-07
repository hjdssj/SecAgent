from typing import Any

from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

app = FastAPI(
    title="SecAgent Business Demo",
    version="0.1.0",
)


class OrderRequest(BaseModel):
    """
    Represent a demo order request body.

    Parameters:
     sku - demo product identifier
     quantity - requested quantity
     comment - optional free-form user comment

    Returns:
     Validated demo order request

    Raises:
     None
    """

    sku: str = Field(default="demo")
    quantity: int = Field(default=1, ge=1)
    comment: str = Field(default="")


@app.get("/")
def health() -> dict[str, str]:
    """
    Return business demo health information.

    Parameters:
     None

    Returns:
     Health response used to verify WAF upstream proxying

    Raises:
     None
    """

    return {
        "service": "business-demo",
        "status": "ok",
    }


@app.get("/login")
def login(id: str = Query(default="")) -> dict[str, str]:
    """
    Return a demo login response that echoes the provided ID.

    Parameters:
     id - demo user identifier from query string

    Returns:
     Demo login response

    Raises:
     None
    """

    return {
        "page": "login",
        "id": id,
    }


@app.get("/search")
def search(q: str = Query(default="")) -> dict[str, str]:
    """
    Return a demo search response that echoes the search query.

    Parameters:
     q - demo search query from query string

    Returns:
     Demo search response

    Raises:
     None
    """

    return {
        "page": "search",
        "q": q,
    }


@app.get("/download")
def download(file: str = Query(default="readme.txt")) -> dict[str, str]:
    """
    Return a demo download response that echoes the requested file name.

    Parameters:
     file - demo file name from query string

    Returns:
     Demo download response

    Raises:
     None
    """

    return {
        "page": "download",
        "file": file,
    }


@app.post("/api/order")
def create_order(order: OrderRequest) -> dict[str, Any]:
    """
    Return a demo order response that echoes the request body.

    Parameters:
     order - demo order request body

    Returns:
     Demo order response

    Raises:
     None
    """

    return {
        "page": "order",
        "accepted": True,
        "order": order.model_dump(),
    }
