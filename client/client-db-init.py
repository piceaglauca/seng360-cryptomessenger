# Accepts .sql filename as command line argument.
# Creates client db from schema in .sql file.
# Overwrites existing client db.
# Reference: https://docs.python.org/3/library/sqlite3.html

import sqlite3
import os
import sys

# Read command line argument sys.argv[1] as .sql filename.
# Obtain schema from .sql file.
client_schema = None
try:
    client_schema_path = sys.argv[1]
    with open(client_schema_path) as client_schema_file:
        client_schema = client_schema_file.read()
except:
    sys.exit('Failed to read schema from file.')

# Delete db if exists.
try:
    os.remove('/var/lib/client.db')
except:
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

