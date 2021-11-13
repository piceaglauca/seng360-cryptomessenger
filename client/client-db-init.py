# Initializes client database.
# Creates tables.
# Reference: https://docs.python.org/3/library/sqlite3.html

import sqlite3

# Establish db connection. Creates db if does not exist.
con = sqlite3.connect('client.db') # Create .db file on disk.
# con = sqlite3.connect(':memory:') # Create in memory.

# Initialize db cursor.
cur = con.cursor()

# Create example messages table.
cur.execute(
    "CREATE TABLE message("
    "msg_id PRIMARY KEY,"
    "body"
    ");"
)

# Save changes to db.
con.commit()

# Close db connection.
con.close()

