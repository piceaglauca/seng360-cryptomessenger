"""crypticmessenger KDC server"""

# Standard lib
import logging
import os
from typing import Any

# Deps
from fastapi import FastAPI, Request, WebSocket

# Internal modules
from kdc.server import Server

# `logging` module has constants for each log level. Get them based on env var
LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
LOG_FORMAT = "[%(asctime)s] %(module)s:%(funcName)s %(levelname)s: %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL)
LOGGER = logging.getLogger(__name__)

# Init web server
APP = FastAPI()

# For storing connected users
USERS = {}


@APP.websocket("/{me}/{friend}")
async def chat(connection: WebSocket, me: str, friend: str):
    """WebSocket endpoint for handling chat messages"""

    # Wait for user to accept connection
    await connection.accept()
    
    # Add user to set of connected users
    USERS[me] = connection

    if friend in USERS:
        await USERS[friend].send_text(f"INFO: {me} has joined the chat.")

    else:
        await USERS[me].send_text(f"INFO: {friend} not yet online.")

    while True:
        # Wait for a message from this user
        message = await USERS[me].receive_text()

        # Send a JSON string of tuple of sender and received message..
        await USERS[friend].send_text(f"{me}: {message}")


@APP.post("/register")
def register(request: Request):
    server = Server()
    uuid = server.register(request.body())
    return uuid