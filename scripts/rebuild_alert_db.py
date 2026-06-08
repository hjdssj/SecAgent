import argparse
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_DB = ROOT_DIR / "data" / "secagent.db"
DEFAULT_OUTPUT_DB = ROOT_DIR / "data" / "secagent.rebuilt.db"
DEFAULT_IGNORED_TARGETS = ["/__waf_health"]


def parse_targets(raw_targets: str) -> list[str]:
    """
    Parse comma-separated alert target paths.

    Parameters:
     raw_targets - comma-separated target paths

    Returns:
     List of target paths

    Raises:
     None
    """

    return [item.strip() for item in raw_targets.split(",") if item.strip()]


def rebuild_database(
    source_db: Path,
    output_db: Path,
    ignored_targets: list[str],
) -> tuple[int, int]:
    """
    Rebuild a SQLite alert database while dropping ignored target alerts.

    Parameters:
     source_db - existing SQLite database path
     output_db - rebuilt SQLite database path
     ignored_targets - alert target paths that should not be copied

    Returns:
     Tuple containing copied row count and skipped row count

    Raises:
     RuntimeError - raised when rebuilt database fails integrity check
    """

    if output_db.exists():
        output_db.unlink()

    output_db.parent.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect(source_db)
    target = sqlite3.connect(output_db)

    try:
        source.text_factory = bytes
        source.row_factory = sqlite3.Row
        create_sql = get_alert_table_sql(source)
        index_sql = get_alert_index_sql(source)
        target.execute(create_sql)

        columns = get_alert_columns(source)
        target_index = columns.index("target")
        placeholders = ", ".join(["?"] * len(columns))
        column_list = ", ".join(columns)
        insert_sql = f"INSERT INTO alerts ({column_list}) VALUES ({placeholders})"

        copied = 0
        skipped = 0

        for row in source.execute("SELECT * FROM alerts ORDER BY id"):
            values = [decode_sqlite_value(row[column]) for column in columns]

            if values[target_index] in ignored_targets:
                skipped += 1
                continue

            target.execute(insert_sql, values)
            copied += 1

        for sql in index_sql:
            target.execute(sql)

        target.commit()
        check_result = target.execute("PRAGMA integrity_check").fetchone()[0]

        if check_result != "ok":
            raise RuntimeError(f"rebuilt database failed integrity_check: {check_result}")

        return copied, skipped
    finally:
        source.close()
        target.close()


def get_alert_table_sql(connection: sqlite3.Connection) -> str:
    """
    Read alerts table creation SQL from a SQLite database.

    Parameters:
     connection - SQLite connection

    Returns:
     CREATE TABLE statement for alerts

    Raises:
     RuntimeError - raised when alerts table is missing
    """

    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='alerts'"
    ).fetchone()

    if row is None:
        raise RuntimeError("alerts table not found")

    return decode_sqlite_text(row[0])


def get_alert_index_sql(connection: sqlite3.Connection) -> list[str]:
    """
    Read alerts index creation SQL from a SQLite database.

    Parameters:
     connection - SQLite connection

    Returns:
     CREATE INDEX statements for alerts

    Raises:
     None
    """

    rows = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='alerts' AND sql IS NOT NULL"
    ).fetchall()
    return [decode_sqlite_text(row[0]) for row in rows]


def get_alert_columns(connection: sqlite3.Connection) -> list[str]:
    """
    Read alerts table column names from SQLite.

    Parameters:
     connection - SQLite connection

    Returns:
     Ordered alerts table column names

    Raises:
     None
    """

    rows = connection.execute("PRAGMA table_info(alerts)").fetchall()
    return [decode_sqlite_text(row[1]) for row in rows]


def decode_sqlite_value(value):
    """
    Decode SQLite values that may contain malformed text bytes.

    Parameters:
     value - SQLite value read from the source database

    Returns:
     Decoded text for bytes, otherwise the original value

    Raises:
     None
    """

    if isinstance(value, bytes):
        return decode_sqlite_text(value)

    return value


def decode_sqlite_text(value) -> str:
    """
    Decode SQLite text with replacement for malformed bytes.

    Parameters:
     value - SQLite text value or raw bytes

    Returns:
     Decoded text

    Raises:
     None
    """

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return str(value)


def backup_database(source_db: Path) -> Path:
    """
    Copy the source database to a timestamped backup file.

    Parameters:
     source_db - source SQLite database path

    Returns:
     Backup database path

    Raises:
     None
    """

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = source_db.with_name(f"{source_db.stem}.corrupt-{timestamp}{source_db.suffix}")
    shutil.copy2(source_db, backup_path)
    return backup_path


def replace_database(source_db: Path, rebuilt_db: Path) -> Path:
    """
    Backup the source database and replace it with the rebuilt database.

    Parameters:
     source_db - source SQLite database path
     rebuilt_db - rebuilt SQLite database path

    Returns:
     Backup database path

    Raises:
     None
    """

    backup_path = backup_database(source_db)
    shutil.copy2(rebuilt_db, source_db)
    return backup_path


def main() -> None:
    """
    Run alert database rebuild from the command line.

    Parameters:
     None

    Returns:
     None

    Raises:
     None
    """

    parser = argparse.ArgumentParser(
        description="Rebuild a malformed SecAgent SQLite alert database."
    )
    parser.add_argument("--source-db", type=Path, default=DEFAULT_SOURCE_DB)
    parser.add_argument("--output-db", type=Path, default=DEFAULT_OUTPUT_DB)
    parser.add_argument(
        "--ignored-targets",
        default=",".join(DEFAULT_IGNORED_TARGETS),
        help="Comma-separated alert targets to drop while rebuilding.",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Replace source database after rebuilding and backing it up.",
    )
    args = parser.parse_args()

    targets = parse_targets(args.ignored_targets)
    copied, skipped = rebuild_database(args.source_db, args.output_db, targets)

    print(f"source db: {args.source_db}")
    print(f"rebuilt db: {args.output_db}")
    print(f"copied alerts: {copied}")
    print(f"skipped alerts: {skipped}")
    print("integrity_check: ok")

    if not args.replace:
        print("source database was not replaced. add --replace to swap it after backup.")
        return

    backup_path = replace_database(args.source_db, args.output_db)
    print(f"backup db: {backup_path}")
    print("source database replaced.")


if __name__ == "__main__":
    main()
