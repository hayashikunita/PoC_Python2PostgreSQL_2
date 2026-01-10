from __future__ import annotations

from dotenv import load_dotenv
import os
import psycopg
from urllib.parse import urlsplit, urlunsplit


def _mask_database_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        if not parts.username and not parts.password:
            return url

        netloc = parts.hostname or ""
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        if parts.username:
            netloc = f"{parts.username}:***@{netloc}"

        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        # Fallback: don't risk printing secrets
        return "(masked)"


def main() -> None:
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)
    url = os.getenv("DATABASE_URL")
    if url:
        print("DATABASE_URL=", _mask_database_url(url))
    if not url:
        raise SystemExit("DATABASE_URL not set")

    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute("select current_user, inet_server_addr(), inet_server_port(), version()")
            row = cur.fetchone()
            print("connected:", row)


if __name__ == "__main__":
    main()
