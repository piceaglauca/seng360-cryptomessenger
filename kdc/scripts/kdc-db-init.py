# Accepts .sql filename as command line argument.
# Creates kdc db from schema in .sql file.
# Overwrites existing kdc db.
# Reference: https://docs.python.org/3/library/sqlite3.html

import logging
import os
import sqlite3
import sys

# `logging` module has constants for each log level. Get them based on env var
LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
LOG_FORMAT = "[%(asctime)s] %(module)s %(levelname)s: %(message)s"

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
LOGGER = logging.getLogger(__name__)


def main():
    # Read command line argument sys.argv[1] as .sql filename.
    # Obtain schema from .sql file.
    try:
        kdc_schema_path = sys.argv[1]
        with open(kdc_schema_path) as kdc_schema_file:
            kdc_schema = kdc_schema_file.read()
    except FileNotFoundError:
        LOGGER.error('Failed to read schema from file.')
        sys.exit(1)

    # Delete db if exists.
    try:
        os.remove('/var/lib/kdc.db')
    except FileNotFoundError:
        pass

    # Create db and establish db connection.
    con = sqlite3.connect('/var/lib/kdc.db') # Create .db file.
    # con = sqlite3.connect(':memory:') # Create in memory.

    # Initialize kdc db from obtained schema.
    cur = con.cursor()
    cur.executescript(kdc_schema)

    # Save changes to db and close connection.
    con.commit()
    con.close()


if __name__ == "__main__":
    main()
