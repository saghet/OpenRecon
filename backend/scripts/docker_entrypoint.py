"""
Idempotent Docker entrypoint for OpenRecon API:
Safely reconciles Alembic migration state with existing PostgreSQL tables
before starting uvicorn, preventing DuplicateObject errors on pre-initialized DBs.
"""

import os
import subprocess
import sys

from sqlalchemy import create_engine, inspect

from app.core.database import database_url


def main() -> None:
    engine = create_engine(database_url)
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    engine.dispose()

    if "alembic_version" not in tables:
        if "discovered_endpoints" in tables:
            subprocess.run(["alembic", "stamp", "head"], check=True)
        elif "organizations" in tables:
            subprocess.run(["alembic", "stamp", "ff505bdc538b"], check=True)
            subprocess.run(["alembic", "upgrade", "head"], check=True)
        else:
            subprocess.run(["alembic", "upgrade", "head"], check=True)
    else:
        subprocess.run(["alembic", "upgrade", "head"], check=True)

    os.execvp(
        "uvicorn",
        ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"],
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Entrypoint failed: {exc}", file=sys.stderr)
        sys.exit(1)
