# Accepts .sql filename as command line argument.
# Creates kdc db from schema in .sql file.
# Overwrites existing kdc db.
# Reference: https://docs.python.org/3/library/sqlite3.html

import sqlite3
import os
import sys

# Read command line argument sys.argv[1] as .sql filename.
# Obtain schema from .sql file.
kdc_schema = None
try:
    kdc_schema_path = sys.argv[1]
    with open(kdc_schema_path) as kdc_schema_file:
        kdc_schema = kdc_schema_file.read()
except:
    sys.exit('Failed to read schema from file.')

# Delete db if exists.
try:
    os.remove('/var/lib/kdc.db')
except:
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

