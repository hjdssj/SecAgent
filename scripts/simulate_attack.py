import argparse
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT_DIR = Path(__file__).resolve().parents[1]


def load_env_file() -> None:
    """
    Load project dotenv values for standalone demo scripts.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    env_path = ROOT_DIR / ".env"

    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file()

BASE_URL = os.getenv("WAF_BASE_URL", "http://127.0.0.1:8080")

ATTACKS = {
    "normal": {
        "path": "/",
        "user_agent": "Mozilla/5.0",
    },
    "sqli": {
        "path": "/login?id=" + quote("1' OR '1'='1"),
        "user_agent": "sqlmap/1.7",
    },
    "xss": {
        "path": "/search?q=" + quote("<script>alert(1)</script>"),
        "user_agent": "Mozilla/5.0",
    },
    "path_traversal": {
        "path": "/download?file=../../etc/passwd",
        "user_agent": "Mozilla/5.0",
    },
    "order_json": {
        "path": "/api/order",
        "user_agent": "Mozilla/5.0",
        "method": "POST",
        "json": {
            "sku": "demo",
            "quantity": 1,
            "comment": "<script>alert(1)</script>",
        },
    },
}


def send_request(name: str) -> None:
    """
    Send one demo request to the local WAF service.

    Parameters:
     name - demo request name defined in ATTACKS

    Returns:
     None

    Raises:
     None
    """

    item = ATTACKS[name]
    url = BASE_URL + item["path"]
    data = None
    headers = {"User-Agent": item["user_agent"]}

    if "json" in item:
        data = json.dumps(item["json"]).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = Request(
        url,
        data=data,
        headers=headers,
        method=item.get("method", "GET"),
    )

    try:
        with urlopen(request, timeout=5) as response:
            print(f"{name}: HTTP {response.status}")
    except HTTPError as error:
        print(f"{name}: HTTP {error.code}")
    except URLError as error:
        print(f"{name}: request failed: {error.reason}")


def main() -> None:
    """
    Send demo attack traffic to the local WAF service.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    parser = argparse.ArgumentParser(description="Send demo traffic to SecRAG WAF.")
    parser.add_argument(
        "case",
        choices=["all", *ATTACKS.keys()],
        default="all",
        nargs="?",
    )
    args = parser.parse_args()

    names = ATTACKS.keys() if args.case == "all" else [args.case]

    for name in names:
        send_request(name)


if __name__ == "__main__":
    main()
