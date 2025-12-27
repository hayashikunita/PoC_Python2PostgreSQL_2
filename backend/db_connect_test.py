from __future__ import annotations

from dotenv import load_dotenv
import os
import psycopg


def main() -> None:
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=True)
    url = os.getenv("DATABASE_URL")
    print("DATABASE_URL=", url)
    if not url:
        raise SystemExit("DATABASE_URL not set")

    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute("select current_user, inet_server_addr(), inet_server_port(), version()")
            row = cur.fetchone()
            print("connected:", row)


if __name__ == "__main__":
    main()
