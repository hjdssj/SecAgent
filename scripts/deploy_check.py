import argparse
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.append(str(BACKEND_DIR))

from app.core.config import get_env, get_int_env, get_path_env
from app.storage.redis_client import get_redis_client


def check_http(name: str, url: str, timeout: float = 5.0) -> bool:
    """
    Check whether one HTTP endpoint is reachable.

    Parameters:
     name - human-readable service name
     url - HTTP URL to check
     timeout - request timeout in seconds

    Returns:
     True when the endpoint returns a 2xx or 3xx status, otherwise False

    Raises:
     None
    """

    try:
        with urlopen(url, timeout=timeout) as response:
            ok = 200 <= response.status < 400
            print(f"{name}: {'ok' if ok else 'failed'} status={response.status}")
            return ok
    except HTTPError as error:
        print(f"{name}: failed status={error.code}")
    except URLError as error:
        print(f"{name}: failed error={error.reason}")
    except TimeoutError:
        print(f"{name}: failed error=timeout")

    return False


def check_redis() -> bool:
    """
    Check whether Redis is reachable using configured environment values.

    Parameters:
     None

    Returns:
     True when Redis responds to ping, otherwise False

    Raises:
     None
    """

    try:
        client = get_redis_client()
        ok = bool(client.ping())
        print(f"Redis: {'ok' if ok else 'failed'}")
        return ok
    except Exception as error:
        print(f"Redis: failed error={type(error).__name__}")
        return False


def check_audit_log() -> bool:
    """
    Check whether the configured WAF audit log path exists.

    Parameters:
     None

    Returns:
     True when the audit log path exists, otherwise False

    Raises:
     None
    """

    path = get_path_env(
        "WAF_AUDIT_LOG_PATH",
        ROOT_DIR / "data" / "waf_logs" / "modsecurity" / "audit" / "audit.log",
    )
    ok = path.exists()
    print(f"WAF audit log: {'ok' if ok else 'missing'} path={path}")
    return ok


def check_business_proxy() -> bool:
    """
    Check whether business-demo is reachable directly and through WAF.

    Parameters:
     None

    Returns:
     True when both direct and WAF-proxied business checks pass

    Raises:
     None
    """

    business_url = get_env(
        "DEPLOY_CHECK_BUSINESS_URL",
        f"http://127.0.0.1:{get_int_env('BUSINESS_DEMO_PORT', 3000)}/",
    )
    waf_proxy_url = get_env(
        "DEPLOY_CHECK_WAF_PROXY_URL",
        f"{get_env('WAF_BASE_URL', 'http://127.0.0.1:8080')}/",
    )

    return all(
        [
            check_http("Business demo", business_url),
            check_http("WAF proxy", waf_proxy_url),
        ]
    )


def main() -> None:
    """
    Run deployment readiness checks for the single-server setup.

    Parameters:
     None

    Returns:
     None

    Raises:
     SystemExit - exits with non-zero code when required checks fail
    """

    parser = argparse.ArgumentParser(description="Check SecAgent deployment health.")
    parser.add_argument("--skip-audit-log", action="store_true")
    parser.add_argument("--skip-business", action="store_true")
    args = parser.parse_args()

    backend_url = get_env(
        "DEPLOY_CHECK_BACKEND_URL",
        f"http://{get_env('BACKEND_HOST', '127.0.0.1')}:{get_int_env('BACKEND_PORT', 8000)}/api/health",
    )
    frontend_url = get_env(
        "DEPLOY_CHECK_FRONTEND_URL",
        f"http://{get_env('FRONTEND_HOST', '127.0.0.1')}:{get_int_env('FRONTEND_PORT', 5173)}/health",
    )
    waf_url = get_env(
        "DEPLOY_CHECK_WAF_URL",
        f"{get_env('WAF_BASE_URL', 'http://127.0.0.1:8080')}/__waf_health",
    )

    checks = [
        check_redis(),
        check_http("Backend", backend_url),
        check_http("Frontend", frontend_url),
        check_http("WAF", waf_url),
    ]

    if not args.skip_audit_log:
        checks.append(check_audit_log())

    if not args.skip_business:
        checks.append(check_business_proxy())

    if not all(checks):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
