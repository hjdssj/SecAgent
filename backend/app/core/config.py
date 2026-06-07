import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ENV_PATH = PROJECT_ROOT / ".env"


def load_env_file(env_path: Path = DEFAULT_ENV_PATH, override: bool = False) -> None:
    """
    Load simple KEY=VALUE pairs from a dotenv file into process environment.

    Parameters:
     env_path - dotenv file path to load
     override - whether file values should replace existing process environment values

    Returns:
     None

    Raises:
     None
    """

    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if not key:
            continue

        if override or key not in os.environ:
            os.environ[key] = value


def get_env(name: str, default: str = "") -> str:
    """
    Read a string environment value.

    Parameters:
     name - environment variable name
     default - fallback value used when the variable is empty

    Returns:
     Environment value or fallback

    Raises:
     None
    """

    value = os.getenv(name)
    return value if value not in (None, "") else default


def get_int_env(name: str, default: int) -> int:
    """
    Read an integer environment value.

    Parameters:
     name - environment variable name
     default - fallback value used when parsing fails

    Returns:
     Parsed integer value or fallback

    Raises:
     None
    """

    try:
        return int(get_env(name, str(default)))
    except ValueError:
        return default


def get_float_env(name: str, default: float) -> float:
    """
    Read a floating point environment value.

    Parameters:
     name - environment variable name
     default - fallback value used when parsing fails

    Returns:
     Parsed float value or fallback

    Raises:
     None
    """

    try:
        return float(get_env(name, str(default)))
    except ValueError:
        return default


def get_bool_env(name: str, default: bool = False) -> bool:
    """
    Read a boolean environment value.

    Parameters:
     name - environment variable name
     default - fallback value used when the variable is empty

    Returns:
     Parsed boolean value or fallback

    Raises:
     None
    """

    value = get_env(name)

    if not value:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_csv_env(name: str, default: list[str] | None = None) -> list[str]:
    """
    Read a comma-separated environment value.

    Parameters:
     name - environment variable name
     default - fallback list used when the variable is empty

    Returns:
     List of non-empty comma-separated values

    Raises:
     None
    """

    raw = get_env(name)

    if not raw:
        return default or []

    return [item.strip() for item in raw.split(",") if item.strip()]


def get_path_env(name: str, default: Path) -> Path:
    """
    Read a path environment value relative to the project root when needed.

    Parameters:
     name - environment variable name
     default - fallback path used when the variable is empty

    Returns:
     Absolute or project-root-relative path

    Raises:
     None
    """

    raw = get_env(name)

    if not raw:
        return default

    path = Path(raw)

    if path.is_absolute():
        return path

    return PROJECT_ROOT / path


load_env_file()
