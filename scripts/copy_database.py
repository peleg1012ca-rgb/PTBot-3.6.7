"""Copy a consistent SQLite snapshot without modifying or replacing either file."""

from contextlib import closing
from pathlib import Path
import os
import sqlite3
import sys


def copy_database(source, destination):
    source = Path(source).resolve()
    destination = Path(destination).resolve()
    if not source.is_file() or source == destination:
        raise ValueError("Choose an existing source and a new destination")
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as old:
        if old.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Source integrity check failed")
        # Exclusive creation prevents accidentally overwriting an existing DB.
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(destination)) as new:
                old.backup(new)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    print("Snapshot created:", destination)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python scripts/copy_database.py OLD_DB NEW_DB")
    copy_database(*sys.argv[1:])
