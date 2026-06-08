import sqlite3
from pathlib import Path

import scripts.rebuild_alert_db as rebuild


def create_source_db(path: Path) -> None:
    """
    Create a small source alert database for rebuild tests.

    Parameters:
     path - SQLite database path

    Returns:
     None

    Raises:
     None
    """

    connection = sqlite3.connect(path)

    try:
        connection.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY,
                alert_id TEXT NOT NULL,
                target TEXT NOT NULL,
                attack_type TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE UNIQUE INDEX ix_alerts_alert_id ON alerts (alert_id)")
        connection.execute(
            "INSERT INTO alerts (id, alert_id, target, attack_type) VALUES (1, 'health', '/__waf_health', 'Unknown')"
        )
        connection.execute(
            "INSERT INTO alerts (id, alert_id, target, attack_type) VALUES (2, 'login', '/login', 'SQL Injection')"
        )
        connection.commit()
    finally:
        connection.close()


def test_rebuild_database_drops_ignored_target(tmp_path: Path) -> None:
    """
    Verify rebuild copies useful alerts and drops ignored targets.

    Parameters:
     tmp_path - pytest temporary directory

    Returns:
     None

    Raises:
     None
    """

    source_db = tmp_path / "source.db"
    output_db = tmp_path / "rebuilt.db"
    create_source_db(source_db)

    copied, skipped = rebuild.rebuild_database(
        source_db,
        output_db,
        ["/__waf_health"],
    )

    connection = sqlite3.connect(output_db)

    try:
        rows = connection.execute(
            "SELECT alert_id, target FROM alerts ORDER BY id"
        ).fetchall()
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        connection.close()

    assert copied == 1
    assert skipped == 1
    assert rows == [("login", "/login")]
    assert integrity == "ok"


def test_replace_database_creates_backup(tmp_path: Path) -> None:
    """
    Verify replacing a database creates a backup copy.

    Parameters:
     tmp_path - pytest temporary directory

    Returns:
     None

    Raises:
     None
    """

    source_db = tmp_path / "source.db"
    rebuilt_db = tmp_path / "rebuilt.db"
    create_source_db(source_db)
    create_source_db(rebuilt_db)

    backup_path = rebuild.replace_database(source_db, rebuilt_db)

    assert source_db.exists()
    assert backup_path.exists()
    assert backup_path.name.startswith("source.corrupt-")
