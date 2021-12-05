import os

from crypto import KeyBundle
from dblib import KDCDBCursor

DB_DIR = '../data'
DB_PATH = f'{DB_DIR}/kdc.db'
SCRIPT_DIR = '../scripts'


class Server:
    """Key Distribution Center.

    Stores key bundles of users, and provides them to users looking to begin
    a secret conversation with a user."""

    def __init__(self):
        if not os.path.exists(DB_PATH):
            os.system(f'python3 {SCRIPT_DIR}/kdc-db-init.py {DB_DIR}/kdc-schema.sql')
        self.kdc_db = KDCDBCursor(DB_PATH)

    def register(self, keybundle: str) -> str:
        """Register a key bundle (json) with the server.

        Returns a user ID."""

        kb = KeyBundle.unpackage(keybundle)
        uuid = self.kdc_db.addUser(kb.username, kb.package())

        return uuid

    def getKeyBundle(self, username: str) -> str: # -> json
        """Get a key bundle (json) to initiate X3DH protocol."""

        # Get KeyBundle from db, and verify user exists
        full_kb = KeyBundle.unpackage(self.kdc_db.getKeyBundle(username))
        if full_kb is None:
            return None

        kb_for_user = KeyBundle()
        kb_for_user.id = full_kb.id
        kb_for_user.username = full_kb.username
        kb_for_user.ipk = full_kb.ipk
        kb_for_user.spk = full_kb.spk
        kb_for_user.opk = full_kb.opk.pop(0) # forget the sent OPK

        # Write the keybundle back to the db, without the sent OPK
        self.kdc_db.updateKeyBundle(username, full_kb.package())

        return kb_for_user.package()
