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
import requests
import websockets

# Internal
from crypto import KeyBundle, User

LOG_FILE = "/var/log/client.log"
# `logging` module has constants for each log level. Get them based on env var
LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
LOG_FORMAT = "[%(asctime)s] %(module)s:%(funcName)s %(levelname)s: %(message)s"
logging.basicConfig(filename=LOG_FILE, format=LOG_FORMAT, level=LOG_LEVEL)
LOGGER = logging.getLogger(__name__)

# Chat endpoint
HOST = "kdc"
PORT = 8000


class Registerer:
    @staticmethod
    def register(json_str):
        r = requests.post(
            f"http://{HOST}:{PORT}/register",
            data=json_str)

        return r.text


def main():
    user = login()
    friend = input("Who do you want to talk to? ")

    asyncio.run(chat(user, friend))
    
    return 0


def login() -> User:
    """Handles logging in to server
    
    This includes account creation and authenticate.
    """

    new_account = False

    while True:
        username = input("Username: ")

        if not username:
            print("Please enter a username.")
            continue
        
        try:
            user = User.login(username)
        
        except Exception:
            print("User doesn't exist.")
            create_user = input("Create it? [y/N] ").lower() == "y"

            if create_user:
                user = User.new(username)

            else:
                continue

            user.register(Registerer)

        return user
        

async def chat(user: User, friend: str) -> None:
    """Connects to server and starts the chat
    
    Connects via WebSocket, loops forever.
    """

    async with websockets.connect(f"ws://{HOST}:{PORT}/{user.username}/{friend}") as server:
        print(f"Connected as '{user.username}'. Chatting to '{friend}'")
        
        # Set up task for listening to server for incoming messages
        server_task = asyncio.ensure_future(
            server_handler(server, user, friend))

        # Set up task for handling input from user
        input_task = asyncio.ensure_future(
            input_handler(server, user, friend))

        # Wait for both tasks to finish (note: both tasks run forever)
        _, pending = await asyncio.wait(
            [server_task, input_task],
            return_when=asyncio.FIRST_COMPLETED)

        # Cancel any remaining tasks
        for task in pending:
            task.cancel()


async def server_handler(server, user: User, friend: str) -> None:
    """Handles incoming messages from server"""

    # decryptor = user.cipher.decryptor()

    # For each new message received from server
    async for data in server:
        sender, message = json.loads(data)

        if sender == "start_handshake":
            handshake_keys = start_handshake(user, friend)
            #await server.send_json(handshake_keys)
            await server.send(json.dumps(handshake_keys))

        elif sender == "finish_handshake":
            user.finishHandshake(json.loads(message['text']))
            #await server.send_json(True)
            await server.send("True")

        elif sender == "INFO":
            print(f"{sender}: {message}")
        else:
            plaintext = user.decrypt(friend, message)
            #print(f"{sender}: {message}")
            print(f"{sender}: {plaintext}")


def start_handshake(user: User, friend: str):
    r = requests.get(f"http://{HOST}:{PORT}/key-bundle/{friend}")
    return user.startHandshake(r.json())


async def input_handler(server, user: User, friend: str) -> None:
    """Waits for user input and sends messages to server"""

    # encryptor = user.cipher.encryptor()

    while True:
        # Prompt user for message
        message = await async_input()
        # encoded_message = message.encode()
        # encrypted_message = enc_kb = encryptor.update(encoded_message) + encryptor.finalize()
        # Send message to server
        #await server.send_json(message)
        encrypted_message = user.encrypt(friend, message)
        await server.send(encrypted_message)


async def async_input(prompt: str = "") -> str:
    """Accepts input from user, asynchronously
    
    Taken from: https://gist.github.com/delivrance/675a4295ce7dc70f0ce0b164fcdbd798
    """

    with ThreadPoolExecutor(1, "AsyncInput") as executor:
        return await asyncio.get_event_loop().run_in_executor(
            executor, input, prompt)


if __name__ == "__main__":
    main()
