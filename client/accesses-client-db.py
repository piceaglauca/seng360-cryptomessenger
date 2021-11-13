# Example python app that accesses database initialized by client-db-init.py.
# Reference: https://docs.python.org/3/library/sqlite3.html

import sqlite3
import cryptography

# Establish db connection. 
# Db is initialized by client-db-init.py when container image is created.
con = sqlite3.connect('client.db')

# Initialize db cursor.
cur = con.cursor()

# Populate example messages table.
cur.execute(
    "INSERT INTO message VALUES"
    "(1, 'message 1 body'),"
    "(2, 'message 2 body'),"
    "(3, 'message 3 body');"
)

# Obtain and print rows:
for row in cur.execute("SELECT * FROM message;"):
    print(row)

# Save changes to db.
con.commit()

# Close db connection.
con.close()