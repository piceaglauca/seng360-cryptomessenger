# Library of functions for interacting with client and server databases.
# References:
# https://docs.python.org/3/library/uuid.html

import uuid
import logging
import os
import sqlite3
import sys
import json
from crypto import KeyBundle


class KDCDBCursor:

    def __init__(self, path = 'kdc.db'):
        self.path = path
        self.con = sqlite3.connect(self.path)
        self.cur = self.con.cursor()

    def __del__(self):
        self.con.close()

    def addUser(self, username, key_bundle):
        key_bundle = KeyBundle.unpackage(key_bundle)
        key_bundle.id = str(uuid.uuid4()) # Create random UUID.
        self.cur.execute(
            'INSERT INTO registry VALUES (?, ?)', (username, KeyBundle.package(key_bundle))
        )
        self.con.commit()
        return key_bundle.id

    def getUsers(self):
        self.cur.execute(
            'SELECT username FROM registry'
        )
        self.con.commit()
        return [result[0] for result in self.cur.fetchall()]

    def getKeyBundle(self, username):
        if username not in self.getUsers():
            return None

        # Get key bundle from db (contains all OPKs).
        self.cur.execute(
            'SELECT * FROM registry WHERE username = ?', [username]
        )
        #key_bundle = KeyBundle.unpackage(self.cur.fetchall()[0][1])
        key_bundle = self.cur.fetchall()[0][1]
        return key_bundle
        
        # Consume one OPK.
        #key_bundle_one_opk = key_bundle.consumeOPK()

    def updateKeyBundle(self, username, key_bundle):
        # Put key bundle back in db.
        self.cur.execute(
            'UPDATE registry SET key_bundle = ? WHERE  username = ?', (key_bundle, username)
        )
        self.con.commit()
        #return KeyBundle.package(key_bundle_one_opk)
