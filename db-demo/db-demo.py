# Example usage of dblib with crypto library.

from crypto import *
from dblib import *
import os

os.system('kdc-db-init.py kdc-schema.sql')
os.system('bob-db-init.py client-schema.sql')
os.system('alice-db-init.py client-schema.sql')

kdc_db = KDCDBCursor('kdc.db')
bob_db = ClientDBCursor('bobdb.db')
alice_db = ClientDBCursor('alicedb.db')


########
# Messaging demo w/ dbs:

print('Creating two new users, alice and bob')
alice = User.new()
bob = User.new()

print('Alice registers with the server.')
alice_kb = KeyBundle.from_user(alice).package()
alice.id = kdc_db.addUser('Alice', alice_kb) # Server would return alice.id to Alice.
print(f"Alice's user id is now {alice.id}")

print('Bob registers with the server.')
bob_kb = KeyBundle.from_user(bob).package()
bob.id = kdc_db.addUser('Bob', bob_kb) # Server would return bob.id to Bob.
print(f"Bob's user id is now {bob.id}")

print("Bob wants to communicate with Alice, so he asks the server for her keybundle.")
alice_kb = kdc_db.getKeyBundle('Alice')

print("Bob will receive Alice's key bundle and derive the shared secret.")
handshake_keys = bob.startHandshake(alice_kb)

print('Bob sends an initial message to Alice, including the required public keys for her to generate the shared secret.')
alice.finishHandshake(handshake_keys)

print(f'Did alice derive the same secret key as bob? {alice.ratchets[bob.id].root_key == bob.ratchets[alice.id].root_key}')

plaintext='attack at dawn'
print(f'Bob sends Alice a message: {plaintext}')
cryptext=bob.ratchets[alice.id].encrypt(plaintext)
print(f'cryptext is: {cryptext}')
print(f'Alice sees: {alice.ratchets[bob.id].decrypt(cryptext)}')

print('Bob stores the message')
bob_db.addConversation('Alice')
bob_db.addMessage(plaintext, 'Alice')
print('Alice stores the message')
alice_db.addConversation('Bob')
alice_db.addMessage(plaintext, 'Bob')

plaintext='affirmative'
print(f'Alice responds to Bob: {plaintext}')
cryptext=alice.ratchets[bob.id].encrypt(plaintext)
print(f'cryptext is: {cryptext}')
print(f'Bob sees: {bob.ratchets[alice.id].decrypt(cryptext)}')

print(f'Alice and Bob reset their ratchets')
alice.ratchets[bob.id].updateRootKey()
bob.ratchets[alice.id].updateRootKey()

print('Bob stores the message')
bob_db.addMessage(plaintext, 'Alice')
print('Alice stores the message')
alice_db.addMessage(plaintext, 'Bob')

plaintext='attack at dawn'
print(f'Bob sends Alice a message: {plaintext}')
cryptext=bob.ratchets[alice.id].encrypt(plaintext)
print(f'cryptext is: {cryptext}')
print(f'Alice sees: {alice.ratchets[bob.id].decrypt(cryptext)}')

print('Bob stores the message')
bob_db.addMessage(plaintext, 'Alice')
print('Alice stores the message')
alice_db.addMessage(plaintext, 'Bob')

plaintext='affirmative'
print(f'Alice responds to Bob: {plaintext}')
cryptext=alice.ratchets[bob.id].encrypt(plaintext)
print(f'cryptext is: {cryptext}')
print(f'Bob sees: {bob.ratchets[alice.id].decrypt(cryptext)}')

print('Bob stores the message')
bob_db.addMessage(plaintext, 'Alice')
print('Alice stores the message')
alice_db.addMessage(plaintext, 'Bob')


########
# contents of dbs:

print('\nInfo:\n')

print('Registered users:')
for user in kdc_db.getUsers():
    print(user)
print()

print('Bob\'s peers:')
print(bob_db.getPeers())
print()

print('Alice\'s peers:')
print(alice_db.getPeers())
print()

#print('Delete Bob\s message history with Alice')
#bob_db.deleteMessageHistory('Alice')
#print('Delete Alice\'s message history with Bob')
#alice_db.deleteMessageHistory('Bob')

print('Bob\'s message history with Alice:')
bob_alice_history = bob_db.getMessageHistory('Alice')
for message in bob_alice_history:
    print(message)
print()

print('Alice\'s message history with Bob:')
alice_bob_history = alice_db.getMessageHistory('Bob')
for message in alice_bob_history:
    print(message)
print()

