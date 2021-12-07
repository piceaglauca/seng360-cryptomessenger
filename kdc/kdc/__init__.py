"""crypticmessenger KDC server"""

# Standard lib
import logging
import os
import sys
import json

# Deps
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect

# Internal modules
from kdc.server import Server

LOG_FILE = "/var/log/server.log"
# `logging` module has constants for each log level. Get them based on env var
LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
LOG_FORMAT = "[%(asctime)s] %(module)s:%(funcName)s %(levelname)s: %(message)s"
logging.basicConfig(filename=LOG_FILE, format=LOG_FORMAT, level=LOG_LEVEL)
LOGGER = logging.getLogger(__name__)

# Init web server
APP = FastAPI()

# For storing connected users
USERS = {}


@APP.websocket("/{username}/{friend_username}")
async def chat(user: WebSocket, username: str, friend_username: str):
    """WebSocket endpoint for handling chat messages"""

    # Wait for user to accept connection
    await user.accept()
    
    try:    
        # Add user to set of connected users
        USERS[username] = user

        friend = await connect_users(user, friend_username)

        while True:
            # Wait for a message from this user
            #message = await user.receive_json()
            message = await user.receive()

            # Send a JSON string of tuple of sender and received message..
            await friend.send_json((username, message))
    
    except WebSocketDisconnect:
        del USERS[username]


@APP.post("/register")
async def register(request: Request):
    uuid = Server().register(await request.body())
    return uuid


@APP.get("/key-bundle/{username}")
async def key_bundle(username: str):
    key_bundle = Server().getKeyBundle(username)
    return key_bundle


async def connect_users(user, friend_username: str):
    # I.e., second member of chat connected
    if friend_username in USERS:
        # Tell client to start handshake
        await user.send_json(("start_handshake", None))
        print("sent start hs req")
        # Client starts handshake, and sends keys back to server
        #handshake_keys = await user.receive_json()
        handshake_keys = await user.receive()
        friend = USERS[friend_username]
        # Send keys to friend and instruct to finish handshake
        await friend.send_json(("finish_handshake", handshake_keys))
        # Inform waiting user
        await friend.send_json((
            "INFO", f"'{friend_username}' has joined the chat."))

    # # I.e., first member of chat connected
    else:
        # Inform just logged on user that their friend has not yet logged on
        await user.send_json((
            "INFO", f"'{friend_username}' is not yet online."))
        # Wait for handshake to finish
        #handshake_done = await user.receive_json()
        handshake_done = await user.receive()
        # If handshake failed
        if not handshake_done:
            sys.exit(1)
    
    return friend
