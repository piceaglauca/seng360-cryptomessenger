# Accepts .sql filename as command line argument.
# Creates client db from schema in .sql file.
# Overwrites existing client db.
# Reference: https://docs.python.org/3/library/sqlite3.html

import logging
import os
import sqlite3
import sys

# `logging` module has constants for each log level. Get them based on env var
LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
LOG_FORMAT = "[%(asctime)s] %(module)s:%(funcName)s %(levelname)s: %(message)s"

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)
LOGGER = logging.getLogger(__name__)


def main():
    # Read command line argument sys.argv[1] as .sql filename.
    # Obtain schema from .sql file.
    try:
        client_schema_path = sys.argv[1]
        with open(client_schema_path) as client_schema_file:
            client_schema = client_schema_file.read()
    except FileNotFoundError:
        LOGGER.error('Failed to read schema from file.')
        sys.exit(1)

    # Delete db if exists.
    try:
        os.remove('/var/lib/client.db')
    except FileNotFoundError:
        pass

    # Create db and establish db connection.
    con = sqlite3.connect('/var/lib/client.db') # Create .db file.
    # con = sqlite3.connect(':memory:') # Create in memory.

    # Initialize client db from obtained schema.
    cur = con.cursor()
    cur.executescript(client_schema)

    # Save changes to db and close connection.
    con.commit()
    con.close()


if __name__ == "__main__":
    main()
