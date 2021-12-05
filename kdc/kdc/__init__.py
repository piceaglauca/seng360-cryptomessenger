"""crypticmessenger KDC server"""

# Standard lib
import logging
import os

# Deps
from fastapi import FastAPI, WebSocket

# `logging` module has constants for each log level. Get them based on env var
LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
LOG_FORMAT = "[%(asctime)s] %(module)s:%(funcName)s %(levelname)s: %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL)
LOGGER = logging.getLogger(__name__)

# Init web server
APP = FastAPI()

# For storing connected users
USERS = set()


@APP.websocket("/{username}")
async def chat(user: WebSocket, username: str):
    """WebSocket endpoint for handling chat messages"""

    # Wait for user to accept connection
    await user.accept()
    # Add user to set of connected users
    USERS.add(user)

    while True:
        # Wait for a message from this user
        message = await user.receive_text()

        # Once received, for every connected user (as `recipient`)...
        for recipient in USERS:
            # Send a JSON string of tuple of sender and received message..
            await recipient.send_json((username, message))
