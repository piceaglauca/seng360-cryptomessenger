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


class ClientDBCursor:

    def __init__(self, path = 'client.db'):
        self.path = path
        self.con = sqlite3.connect(self.path)
        self.cur = self.con.cursor()

    def __del__(self):
        self.con.close()

    def addConversation(self, peer):
        id = str(uuid.uuid4()) # Create random UUID.
        self.cur.execute(
            'INSERT INTO conversation VALUES (?, ?)', (id, peer)
        )
        self.con.commit()

    def getMessageHistory(self, peer):
        self.cur.execute(
            'SELECT message.body, message.tag, message.timestamp FROM conversation JOIN message ON conversation.id = message.conversation_id WHERE conversation.peer = ?', [peer]
        )
        self.con.commit()
        return self.cur.fetchall()

    def deleteMessageHistory(self, peer):
        # Get conversation id for specified peer.
        conversation_id = None
        try:
            conversation_id = self.__getConversationId(peer)
        except Exception as e:
            print(e)
            return
        self.cur.execute(
            'DELETE FROM message WHERE conversation_id = ?', [conversation_id]
        )
        self.cur.execute(
            'DELETE FROM conversation WHERE id = ?', [conversation_id]
        )
        self.con.commit()

    def getPeers(self):
        self.cur.execute(
            'SELECT peer FROM conversation'
        )
        self.con.commit()
        return self.cur.fetchall()        

    def addMessage(self, message, tag, peer):
        # Get conversation id for specified peer.
        conversation_id = None
        try:
            conversation_id = self.__getConversationId(peer)
        except Exception as e:
            print(e)
            return
            
        id = str(uuid.uuid4()) # Create random UUID.
        self.cur.execute(
            'INSERT INTO message VALUES (?, ?, ?, ?, DATETIME(\'now\'))', (id, conversation_id, message, tag)
        )
        self.con.commit()

    def __getConversationId(self, peer):
         # Get conversation id for specified peer.
        self.cur.execute(
            'SELECT id FROM conversation WHERE conversation.peer = ?', [peer]
        )
        self.con.commit()
        return str(self.cur.fetchall()[0][0])
