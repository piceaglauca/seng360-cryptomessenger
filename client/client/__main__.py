"""Main entrypoint for crypticmessenger client"""

# Standard lib
import asyncio
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass
import json
import logging
import os
import sys
import time

# Deps
import websockets

LOG_FILE = "/var/log/client.log"
# `logging` module has constants for each log level. Get them based on env var
LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
LOG_FORMAT = "[%(asctime)s] %(module)s:%(funcName)s %(levelname)s: %(message)s"
logging.basicConfig(filename=LOG_FILE, format=LOG_FORMAT, level=LOG_LEVEL)
LOGGER = logging.getLogger(__name__)

# Chat endpoint
URL = "ws://kdc:8000"


def main():
    # DEBUG:
    username = login()
    friend = input("Who do you want to talk to? ")
    asyncio.run(chat(username, friend))
    
    return 0


def login():
    """Handles logging in to server
    
    This includes account creation and authenticate.
    """

    new_account = False

    while True:
        try:
            username = input("Username: ")

            if not username:
                print("Please enter a username.")
                continue
            
            # TODO: Replace `True` with user check
            if not True:
                print("User does not exist.")
                new_account = input(
                    "Would you like to create it? (Y/n): ").lower() in ("y", "")
                
            while True:
                password = getpass("New password: " if new_account else "Password: ")

                if not password:
                    print("Please enter a password.")
                    continue

                break

            if new_account:
                # Create account
                print("Account created.")
                time.sleep(1)
            
            # TODO: Replace `True` with auth request
            if not True:
                print("Invalid credentials")
                continue

            return username
        
        except KeyboardInterrupt:
            print()
            sys.exit(0)


async def chat(username: str, friend: str) -> None:
    """Connects to server and starts the chat
    
    Connects via WebSocket, loops forever.
    """

    async with websockets.connect(f"{URL}/{username}/{friend}") as server:
        print(f"Connected as '{username}'. Chatting to {friend}")
        
        # Set up task for listening to server for incoming messages
        server_task = asyncio.ensure_future(
            server_handler(server))

        # Set up task for handling input from user
        input_task = asyncio.ensure_future(
            input_handler(server))

        # Wait for both tasks to finish (note: both tasks run forever)
        _, pending = await asyncio.wait(
            [server_task, input_task],
            return_when=asyncio.FIRST_COMPLETED)

        # Cancel any remaining tasks
        for task in pending:
            task.cancel()


async def server_handler(server) -> None:
    """Handles incoming messages from server"""

    # For each new message received from server
    async for message in server:
        print(message)


async def input_handler(server) -> None:
    """Waits for user input and sends messages to server"""

    while True:
        # Prompt user for message
        message = await async_input()
        # Send message to server
        await server.send(message)


async def async_input(prompt: str = "") -> str:
    """Accepts input from user, asynchronously
    
    Taken from: https://gist.github.com/delivrance/675a4295ce7dc70f0ce0b164fcdbd798
    """

    with ThreadPoolExecutor(1, "AsyncInput") as executor:
        return await asyncio.get_event_loop().run_in_executor(
            executor, input, prompt)


if __name__ == "__main__":
    main()
    