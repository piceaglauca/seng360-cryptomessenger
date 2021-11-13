# Initializes kdc database.
# Creates tables.
# Reference: https://docs.python.org/3/library/sqlite3.html

import sqlite3

# Establish db connection. Creates db if does not exist.
con = sqlite3.connect('kdc.db') # Create .db file on disk.
# con = sqlite3.connect(':memory:') # Create in memory.

# Initialize db cursor.
cur = con.cursor()

# Create example users table.
cur.execute(
    "CREATE TABLE user("
    "user_id PRIMARY KEY,"
    "id_key,"
    "signed_key,"
    "onetime_key"
    ");"
)

# Save changes to db.
con.commit()

# Close db connection.
con.close()