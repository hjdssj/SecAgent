import importlib.util
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parents[1]
BUSINESS_DEMO_PATH = ROOT_DIR / "infra" / "business-demo" / "main.py"


def load_business_demo_app():
    """
    Load the business-demo FastAPI app from its file path.

    Parameters:
     None

    Returns:
     FastAPI app object from business-demo

    Raises:
     RuntimeError - raised when the module cannot be loaded
    """

    spec = importlib.util.spec_from_file_location("business_demo_main", BUSINESS_DEMO_PATH)

    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load business-demo module")

    module = importlib.util.module_from_spec(spec)
    sys.modules["business_demo_main"] = module
    spec.loader.exec_module(module)
    return module.app


def test_business_demo_health() -> None:
    """
    Verify business-demo health endpoint.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    client = TestClient(load_business_demo_app())

    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["service"] == "business-demo"


def test_business_demo_attack_surface_endpoints() -> None:
    """
    Verify business-demo exposes stable WAF testing endpoints.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    client = TestClient(load_business_demo_app())

    login = client.get("/login?id=1%27%20OR%20%271%27%3D%271")
    search = client.get("/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
    download = client.get("/download?file=../../etc/passwd")
    order = client.post(
        "/api/order",
        json={
            "sku": "demo",
            "quantity": 1,
            "comment": "<script>alert(1)</script>",
        },
    )

    assert login.status_code == 200
    assert login.json()["page"] == "login"
    assert search.status_code == 200
    assert search.json()["page"] == "search"
    assert download.status_code == 200
    assert download.json()["page"] == "download"
    assert order.status_code == 200
    assert order.json()["accepted"] is True
