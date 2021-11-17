# Example python app that accesses database initialized by client-db-init.py.
# Reference: https://docs.python.org/3/library/sqlite3.html

import sqlite3
import cryptography

# Establish db connection. 
# Db is initialized by client-db-init.py when container image is created.
con = sqlite3.connect('/var/lib/client.db')

# Initialize db cursor.
cur = con.cursor()

# Query db.
cur.execute(
    "SELECT * FROM message;"
)

# Obtain and print rows:
for row in cur.execute("SELECT * FROM message;"):
    print(row)

# Save changes to db and close connection.
con.commit()
con.close()
