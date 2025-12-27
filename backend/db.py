import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from pathlib import Path

import psycopg
from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


# Ensure backend/.env is loaded even if the app entrypoint doesn't load it.
_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_env_path, override=True)


def get_database_url() -> Optional[str]:
    # Reload backend/.env at call time so changes take effect without restart.
    load_dotenv(dotenv_path=_env_path, override=True)
    url = os.getenv("DATABASE_URL")
    if url:
        return url

    host = os.getenv("PGHOST")
    port = os.getenv("PGPORT")
    user = os.getenv("PGUSER")
    password = os.getenv("PGPASSWORD")
    dbname = os.getenv("PGDATABASE")

    if not (host and port and user and password and dbname):
        return None

    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


def connect() -> Connection[Any]:
    url = get_database_url()
    if not url:
        raise RuntimeError(
            "Database is not configured. Set DATABASE_URL or PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE"
        )

    conn = psycopg.connect(url, autocommit=True, row_factory=dict_row)
    ensure_schema(conn)
    return conn


def ensure_schema(conn: Connection[Any]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS process_snapshots (
              id BIGSERIAL PRIMARY KEY,
              collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
              hostname TEXT,
              summary JSONB NOT NULL,
              processes JSONB NOT NULL
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS eventlog_batches (
              id BIGSERIAL PRIMARY KEY,
              collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
              hostname TEXT,
              log_name TEXT NOT NULL,
              since_hours INTEGER NOT NULL,
              max_events INTEGER NOT NULL,
              summary JSONB NOT NULL,
              events JSONB NOT NULL
            );
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS app_usage_samples (
              id BIGSERIAL PRIMARY KEY,
              collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
              hostname TEXT,
              sample JSONB NOT NULL
            );
            """
        )


def db_health() -> Dict[str, Any]:
    url = get_database_url()
    if not url:
        return {"ok": False, "configured": False, "message": "DATABASE_URL not set"}

    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 AS ok")
                row = cur.fetchone()
        return {"ok": True, "configured": True, "result": row}
    except Exception as e:
        return {"ok": False, "configured": True, "error": str(e)}


def insert_process_snapshot(*, hostname: str, summary: Dict[str, Any], processes: Any) -> int:
    collected_at = datetime.now(timezone.utc)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO process_snapshots (collected_at, hostname, summary, processes)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (collected_at, hostname, Jsonb(summary), Jsonb(processes)),
            )
            row = cur.fetchone()
            return int(row["id"]) if row and "id" in row else -1


def insert_eventlog_batch(
    *,
    hostname: str,
    log_name: str,
    since_hours: int,
    max_events: int,
    summary: Dict[str, Any],
    events: Any,
) -> int:
    collected_at = datetime.now(timezone.utc)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO eventlog_batches (
                  collected_at, hostname, log_name, since_hours, max_events, summary, events
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    collected_at,
                    hostname,
                    log_name,
                    int(since_hours),
                    int(max_events),
                    Jsonb(summary),
                    Jsonb(events),
                ),
            )
            row = cur.fetchone()
            return int(row["id"]) if row and "id" in row else -1


def insert_app_usage_sample(*, hostname: str, sample: Any) -> int:
    collected_at = datetime.now(timezone.utc)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO app_usage_samples (collected_at, hostname, sample)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (collected_at, hostname, Jsonb(sample)),
            )
            row = cur.fetchone()
            return int(row["id"]) if row and "id" in row else -1


def fetch_app_usage_samples_since(*, hostname: Optional[str], since_hours: int, limit: int = 200) -> List[Dict[str, Any]]:
    """指定期間のサンプルを古い順で取得（履歴計算用）。"""
    since_hours_i = max(1, min(24 * 365, int(since_hours)))
    limit_i = max(2, min(2000, int(limit)))

    where = "WHERE collected_at >= (NOW() - (%s * INTERVAL '1 hour'))"
    params: List[Any] = [since_hours_i]
    if hostname:
        where += " AND hostname = %s"
        params.append(hostname)

    sql = f"""
        SELECT id, collected_at, hostname, sample
        FROM app_usage_samples
        {where}
        ORDER BY collected_at ASC
        LIMIT %s
    """
    params.append(limit_i)

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall() or []
            return [dict(r) for r in rows]
