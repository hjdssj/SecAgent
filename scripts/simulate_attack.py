import argparse
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

BASE_URL = "http://127.0.0.1:8080"

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
    request = Request(url, headers={"User-Agent": item["user_agent"]})

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
