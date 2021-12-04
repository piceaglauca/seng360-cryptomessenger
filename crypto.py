# Use Cases:
# 1. Create a new user - generate prekey bundle, create User() object
# 2. Login a user - create User() object with stored keys
# 3. Rotate keys - User() object already created, need to refresh existing keys
# 4. Encrypt a message/operate ratchet
# 5. Decrypt a message/operate ratchet


# Key generation libraries
from cryptography.hazmat.primitives.asymmetric.ed25519 import *
from cryptography.hazmat.primitives.asymmetric.x25519 import *

# Key translation to/from bytes
from cryptography.hazmat.primitives import serialization
import json

# Key translation from ed25519 to x25519
import nacl.signing

# Key Derivation Function
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Message encryption/decryption
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes

# Password-based encryption
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os # for nonces
import getpass

# Exceptions from invalid keys/signatures
from cryptography.exceptions import *


def diffieHellman(ipk_private = None, ipk_public = None, \
                  epk_private = None, epk_public = None, \
                  spk_private = None, spk_public = None, \
                  opk_private = None, opk_public = None):
    """Perform a Diffie-Hellman 4-way exchange with the given keys.

    If Bob is seeking a shared secret with Alice, Bob will call this function
    first with the following keys:
    - ipk_private (Bob's)
    - epk_private (Bob's)
    - ipk_public  (Alice's)
    - spk_public  (Alice's)
    - opk_public  (Alice's)

    Alice will call this function subsequently with the following keys:
    - ipk_private (Alice's)
    - spk_private (Alice's)
    - opk_private (Alice's)
    - ipk_public  (Bob's)
    - epk_public  (Bob's)"""

    # startHandshake
    if epk_private is not None:
        DH1 = ipk_private.exchange(spk_public)
        DH2 = epk_private.exchange(ipk_public)
        DH3 = epk_private.exchange(spk_public)
        DH4 = epk_private.exchange(opk_public)

    # finishHandshake
    else:
        DH1 = spk_private.exchange(ipk_public)
        DH2 = ipk_private.exchange(epk_public)
        DH3 = spk_private.exchange(epk_public)
        DH4 = opk_private.exchange(epk_public)

    return DH1 + DH2 + DH3 + DH4


def kdf(key):
    """Derive a hashed key of 32-byte length from a shared secret input."""

    kdf = HKDF(\
            algorithm=hashes.SHA256(), \
            length = 32, \
            salt=bytes(256), \
            info=b'cryptomessenger')
    return kdf.derive(key)


class Server:
    """Key Distribution Center.

    Stores key bundles of users, and provides them to users looking to begin
    a secret conversation with a user."""

    def __init__(self):
        self.users = {}
        self.nextUserID = 0

    def register(self, keybundle: dict) -> int:
        """Register a key bundle with the server.

        Returns a user ID."""

        kb = KeyBundle.unpackage(keybundle)
        kb.id = self.nextUserID
        self.users[self.nextUserID] = kb
        self.nextUserID += 1
        return self.nextUserID - 1

    def getKeyBundle(self, user_id: int): # -> KeyBundle
        """Get a key bundle to initiate X3DH protocol."""

        if user_id in self.users.keys():
            kb = KeyBundle()
            kb.id = self.users[user_id].id
            kb.ipk = self.users[user_id].ipk
            kb.spk = self.users[user_id].spk
            kb.opk = self.users[user_id].opk.pop(0) # forget the sent OPK

            return kb # TODO: should return a JSON or something
        else:
            return None # TODO: handle a 'user not found' error


class User:
    """A User of the cryptomessenger.

    A User contains the prekey bundle. If not supplied, the prekey bundle will
    be generated fresh.

    Important attributes:
    ipk -- the identity prekey, type IPK
    spk -- the signed prekey, type SPK
    opk -- the one-time use prekey, type list of OPK
    """

    def __init__(self):
        self.id = None # received from server when key bundle is registered
        self.ipk = None
        self.spk = None
        self.opk = None
        self.nonce = None
        self.ratchets = {}

    @staticmethod
    def new(): # -> User
        """Create a new user with prekeys.

        Note: the User ID is not created at this stage, as it will be provided
        by the server when the keybundle is registered."""

        user = User()
        user.ipk = IPK.generate()
        user.spk = SPK.generate(user.ipk)
        user.opk = OPK.generateMany()

        # Get password from user, and create cipher object for encrypting
        # and decrypting at-rest data.
        password = kdf(getpass.getpass('Enter a new password: ').encode())
        if password == kdf(getpass.getpass('Confirm password: ').encode()):
            user.nonce = os.urandom(32)
            user.cipher = Cipher(algorithms.AES(kdf(user.nonce + password)),
                                 modes.GCM(user.nonce))
        else:
            raise Exception('invalid password')
        
        return user

    @staticmethod
    def login(): # -> User
        pass

    def register(self, server):
        """Register my key bundle with the server."""

        self.id = server.register(KeyBundle.from_user(self).package())

    def startHandshake(self, peer_keybundle: str):
        """Calculate the shared secret from a users prekey bundle."""

        kb = KeyBundle.unpackage(peer_keybundle)
        epk = KeyPair.generate()

        if self.id is None:
            raise Exception('Register with Server first.')

        self.ratchets[kb.id] = DoubleRatchet(
            my_id = self.id,
            peer_id = kb.id,
            associated_data = self.ipk.public_bytes() + kb.ipk.public_bytes(),
            root_key = diffieHellman(
                ipk_private = self.ipk,
                epk_private = epk,
                ipk_public = kb.ipk,
                spk_public = kb.spk,
                opk_public = kb.opk))
        epk.private = None

        return {'id': self.id, \
                'ipk': self.ipk.public_bytes(), \
                'epk': epk.public_bytes(), \
                'opk': kb.opk.public_bytes()}

    def finishHandshake(self, peer_keybundle: str):
        """Calculate the matching shared secret from a users prekey bundle."""

        peer_id = peer_keybundle['id']
        peer_ipk = IPK.from_public_bytes(peer_keybundle['ipk'])
        peer_epk = KeyPair.from_public_bytes(peer_keybundle['epk'])
        used_opk = OPK.from_public_bytes(peer_keybundle['opk'])

        opk = None
        for i in range(len(self.opk)):
            if self.opk[i].public_bytes() == used_opk.public_bytes():
                opk = self.opk.pop(i)
                break

        self.ratchets[peer_id] = DoubleRatchet(
            my_id = self.id,
            peer_id = peer_id,
            associated_data = peer_ipk.public_bytes() + self.ipk.public_bytes(),
            root_key = diffieHellman(
                ipk_public = peer_ipk,
                epk_public = peer_epk,
                ipk_private = self.ipk,
                spk_private = self.spk,
                opk_private = opk))


class DoubleRatchet:
    """Double ratchet encryption

    Creates three ratchet: the first is the root key, seeded with the shared
    secret derived during the diffie-hellman key exchange with the prekey
    bundles. The other two are the sending and receiving ratchets, which will
    be turned everytime a message is encrypted or decrypted. Periodically,
    they will be reset by ratching the root key."""

    def __init__(self, root_key, my_id, peer_id, associated_data):
        self.root_key = kdf(root_key)
        self.my_id = my_id
        self.peer_id = peer_id
        self.associated_data = associated_data
        self.recv_key = self.root_key
        self.send_key = self.root_key

        self.updateEncryptor()
        self.updateDecryptor()

    def updateRootKey(self):
        """Ratchet the root key, and update the send and receive ratchets.

        Provides perfect forward secrecy."""

        self.root_key = kdf(self.root_key)
        self.recv_key = self.root_key
        self.send_key = self.root_key

        self.updateEncryptor()
        self.updateDecryptor()

    def updateEncryptor(self):
        """Refresh the encryptor with the ratcheted send key."""

        self.send_key = kdf(self.send_key + str(self.my_id).encode())
        self.encryptor = Cipher(
            algorithms.AES(self.send_key),
            modes.GCM(self.associated_data) # IV
        ).encryptor()
        self.encryptor.authenticate_additional_data(self.associated_data)

    def updateDecryptor(self):
        """Refresh the decryptor with the ratcheted receive key."""

        self.recv_key = kdf(self.recv_key + str(self.peer_id).encode())
        self.decryptor = Cipher(
            algorithms.AES(self.recv_key),
            modes.GCM(self.associated_data) # IV
        ).decryptor()
        self.decryptor.authenticate_additional_data(self.associated_data)

    def encrypt(self, message):
        """Encrypt a message and ratchet the send key."""

        self.updateEncryptor()

        return (self.encryptor.update(message.encode()) + self.encryptor.finalize(), self.encryptor.tag)

    def decrypt(self, tagged_message):
        """Decrypt a message and ratchet the receive key."""

        message = tagged_message[0]
        tag = tagged_message[1]

        self.updateDecryptor()

        text = self.decryptor.update(message) + self.decryptor.finalize_with_tag(tag)
        return text.decode()


class KeyBundle:
    """A KeyBundle for deriving shared secrets using X3DH."""

    def __init__(self):
        self.id = None
        self.ipk = None
        self.spk = None
        self.opk = None

    def validateSignature(self) -> None:
        """Validate the signed SPK."""

        self.ipk.verify(self.spk.signature, self.spk.public_bytes())

    def package(self) -> str:
        """Convert prekey bundle to json for transmission."""

        # Most cases will only have a single OPK in the key bundle.
        if isinstance(self.opk, OPK):
            packagedOPK = self.opk.public_bytes().hex()

        # When registering with the server, there will be a list of OPKs
        elif isinstance(self.opk, list):
            packagedOPK = []
            for opk in self.opk:
                packagedOPK.append(opk.public_bytes().hex())

        pkg =  {'ID'       : self.id, \
                'IPK'      : self.ipk.public_bytes().hex(), \
                'SPK'      : self.spk.public_bytes().hex(), \
                'signature': self.spk.signature.hex(), \
                'OPK'      : packagedOPK}

        return json.dumps(pkg)

    @staticmethod
    def unpackage(bundle_json: str): # -> KeyBundle, throws TypeError
        """Create a KeyBundle object from keys packaged in a json."""

        bundle = json.loads(bundle_json)
        bundle['IPK'] = bytes.fromhex(bundle['IPK'])
        bundle['SPK'] = bytes.fromhex(bundle['SPK'])
        bundle['signature'] = bytes.fromhex(bundle['signature'])

        if isinstance(bundle, dict) and \
                'ID' in bundle.keys() and \
                'IPK' in bundle.keys() and \
                'SPK' in bundle.keys() and \
                'signature' in bundle.keys() and \
                'OPK' in bundle.keys():

            # Most cases will only have a single OPK in the key bundle.
            if isinstance(bundle['OPK'], str):
                unpackagedOPK = OPK.from_public_bytes(bytes.fromhex(bundle['OPK']))

            # When registering with the server, there will be a list of OPKs
            elif isinstance(bundle['OPK'], list):
                unpackagedOPK = []
                for opk in bundle['OPK']:
                    unpackagedOPK.append(OPK.from_public_bytes(bytes.fromhex(opk)))

            return KeyBundle.from_keys(\
                        bundle['ID'], \
                        IPK.from_public_bytes(bundle['IPK']), \
                        SPK.from_public_bytes(bundle['SPK'], \
                                              bundle['signature']), \
                        unpackagedOPK)

        elif isinstance(bundle, dict):
            raise TypeError(f"Invalid key bundle. Expected keys: ['ID','IPK','SPK','signature','OPK']. Got: {bundle.keys()}")
        else:
            raise TypeError(f'invalid key bundle. Expected dictionary, got {type(bundle)}')

    @staticmethod
    def from_keys(id: int, ipk, spk, opk): # -> KeyBundle
        """Generate a KeyBundle from key objects."""

        kb = KeyBundle()
        kb.id = id
        kb.ipk = ipk
        kb.spk = spk
        kb.opk = opk

        kb.validateSignature()

        return kb

    @staticmethod
    def from_user(user): # -> KeyBundle
        """Generate a KeyBundle from a User object."""

        kb = KeyBundle()
        kb.id = user.id
        kb.ipk = user.ipk
        kb.spk = user.spk
        kb.opk = user.opk

        kb.validateSignature()
        
        return kb


class KeyPair:
    """A generic private/public key pair. 

    May contain X25519 or Ed25519 keys. This class is extended by
    IPK/SPK/OPK, but is used directly for ephemeral keys.

    Important attributes:
    private -- The private key object.
    public  -- The public key object."""

    private = None
    public = None

    @staticmethod
    def generate():
        """Generate a new X25519 KeyPair."""

        kp = KeyPair()
        kp.private = X25519PrivateKey.generate()
        kp.public = kp.private.public_key()

        return kp

    def exchange(self, public_key) -> bytes:
        """Perform a Diffie-Hellman derivation."""

        if isinstance(public_key, IPK):
            peer_public_key = public_key.to_x25519_public()
        else:
            peer_public_key = public_key.public

        return self.private.exchange(peer_public_key)

    def public_bytes(self, \
                    encoding = serialization.Encoding.Raw, \
                    format = serialization.PublicFormat.Raw):
        """Get the public key as bytes.

        Keyword arguments:
        encoding -- The serialization encoding to use (default Raw)
        format -- The serialization format to use (default Raw)

        Note if using encoding/format other than the default, either none or
        both must be Raw. For details, see the python cryptography doc:
        https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
        """

        return self.public.public_bytes(encoding, format)

    def private_bytes(self, \
                    encoding = serialization.Encoding.Raw, \
                    format = serialization.PrivateFormat.Raw, \
                    encryption_algorithm = serialization.NoEncryption()):
        """Get the private key as bytes.

        Keyword arguments:
        encoding -- The serialization encoding to use (default Raw)
        format -- The serialization format to use (default Raw)
        encryption_algorithm -- The encrypt algo to use (default None)

        Note if using encoding/format/encryption_algorithm other than the
        default, either encoding/format is Raw and encrypt_algorithm is None,
        or none of them are Raw/None. For details, see the cryptography doc:
        https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
        """

        return self.private.private_bytes(encoding, \
                                            format, \
                                            encryption_algorithm)

    @staticmethod
    def from_private_bytes(key: bytes, type: str ='x25519'): # -> (PrivateKey, PublicKey)
        """Create Private and Public Key objects from a private key of 
        specified type."""

        kp = KeyPair()
        if type == 'x25519':
            kp.private = X25519PrivateKey.from_private_bytes(key)
        elif type == 'ed25519':
            kp.private = Ed25519PrivateKey.from_private_bytes(key)

        kp.public = kp.private.public_key()

        return kp

    @staticmethod
    def from_public_bytes(key: bytes, type: str = 'x25519'): # -> PublicKey
        """Create a Public Key object from a public key of specified type."""

        kp = KeyPair()
        if type == 'x25519':
            kp.public = X25519PublicKey.from_public_bytes(key)
        elif type == 'ed25519':
            kp.public = Ed25519PublicKey.from_public_bytes(key)

        return kp


class IPK(KeyPair):
    """An ed25519 pre-keypair.

    An IPK should be instantiated indirectly through the generate()
    function, or derived from bytes using from_public_bytes() or
    from_private_bytes()."""

    def sign(self, message: bytes) -> bytes:
        """Sign the given message with the associated ed25519 private key."""

        return self.private.sign(message)

    def verify(self, signature: bytes, message: bytes) -> None:
        """Verify the validity of a signed message."""

        # Ed25519.verify() does not return a value. Instead, it throws
        # InvalidSignature if the signature is invalid.
        try:
            self.public.verify(signature, message)
        except InvalidSignature:
            raise # TODO: should we handle the invalid signature somehow?

    def exchange(self, public_key) -> bytes:
        """Perform a Diffie-Hellman derivation."""

        return self.to_x25519_private().exchange(public_key.public)

    def to_x25519_private(self) -> X25519PrivateKey:
        """Convert the ed25519 private key to a birationally equivalent
        x25519 key.

        Credit to Spencer Davis."""

        ed_private_pynacl = nacl.signing.SigningKey(self.private_bytes())
        x_private_pynacl = ed_private_pynacl.to_curve25519_private_key()
        return X25519PrivateKey.from_private_bytes(x_private_pynacl.encode())

    def to_x25519_public(self) -> X25519PublicKey:
        """Convert the ed25519 public key to a birationally equivalent
        x25519 key.

        Credit to Spencer Davis."""

        ed_public_pynacl = nacl.signing.VerifyKey(self.public_bytes())
        x_public_pynacl = ed_public_pynacl.to_curve25519_public_key()
        return X25519PublicKey.from_public_bytes(x_public_pynacl.encode())

    @staticmethod
    def generate(): # -> IPK
        """Generate an ed25519 pre-keypair."""

        ipk = IPK()
        ipk.private = Ed25519PrivateKey.generate()
        ipk.public = ipk.private.public_key()

        return ipk

    @staticmethod
    def from_public_bytes(public_bytes: bytes): # -> IPK
        """Create an IPK object from public key bytes representation."""

        ipk = IPK()
        kp = KeyPair.from_public_bytes(public_bytes, 'ed25519')
        ipk.public = kp.public

        return ipk

    @staticmethod
    def from_private_bytes(private_bytes: bytes): # -> IPK
        """Create an IPK object from private key bytes representation."""

        ipk = IPK()
        kp = KeyPair.from_private_bytes(private_bytes, 'ed25519')
        ipk.private, ipk.public = kp.private, kp.public

        return ipk


class SPK(KeyPair):
    """An x25519 pre-keypair.

    An SPK should be instantiated indirectly through the generate() 
    function, or derived from bytes using from_public_bytes() or 
    from_private_bytes()."""

    @staticmethod
    def generate(signing_key): # -> SPK
        """Generate an x25519 pre-keypair, and sign with the ed25519 key."""

        spk = SPK()
        spk.private = X25519PrivateKey.generate()
        spk.public = spk.private.public_key()
        spk.signature = signing_key.sign(spk.public_bytes())

        return spk

    @staticmethod
    def from_public_bytes(public_bytes: bytes, signature: bytes): # -> SPK
        """Create an SPK object from public key bytes representation."""

        spk = SPK()
        kp = KeyPair.from_public_bytes(public_bytes)
        spk.public = kp.public
        spk.signature = signature

        return spk

    @staticmethod
    def from_private_bytes(private_bytes: bytes, signature: bytes): # -> SPK
        """Create an SPK object from private key bytes representation."""

        spk = SPK()
        kp = KeyPair.from_private_bytes(private_bytes)
        spk.private, spk.public = kp.private, kp.public
        spk.signature = signature

        return spk


class OPK(KeyPair):
    """An x25519 pre-keypair.

    An OPK should be instantiated indirectly through the generate() 
    function, or derived from bytes using from_public_bytes() or 
    from_private_bytes()."""

    @staticmethod
    def generate(): # -> OPK
        """Generate an x25519 pre-keypair."""

        opk = OPK()
        opk.private = X25519PrivateKey.generate()
        opk.public = opk.private.public_key()

        return opk

    @staticmethod
    def generateMany(nKeys: int = 100) -> list: # list of OPK
        """Generate several x25519 pre-keypairs."""

        return [OPK.generate() for i in range(nKeys)]

    @staticmethod
    def from_public_bytes(public_bytes: bytes): # -> OPK
        """Create an OPK object from public key bytes representation."""

        opk = OPK()
        kp = KeyPair.from_public_bytes(public_bytes)
        opk.public = kp.public

        return opk

    @staticmethod
    def from_private_bytes(private_bytes: bytes): # -> OPK
        """Create an OPK object from public key bytes representation."""

        opk = OPK()
        kp = KeyPair.from_private_bytes(private_bytes)
        opk.private, opk.public = kp.private, kp.public

        return opk


## Testing/demo
if __name__ == '__main__':
    print('Creating user for Alice.')
    alice = User.new()
    print('Creating user for Bob.')
    bob = User.new()

    print('Creating the server connection (just an object instantiation for now)')
    server = Server()

    print('Alice registers with the server.')
    alice.register(server)
    print(f"Alice's user id is now {alice.id}")

    print('Bob registers with the server.')
    bob.register(server)
    print(f"Bob's user id is now {bob.id}")

    print("Bob wants to communicate with Alice, so he asks the server for her keybundle.")
    alice_kb = server.getKeyBundle(alice.id).package()

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

    plaintext='affirmative'
    print(f'Alice responds to Bob: {plaintext}')
    cryptext=alice.ratchets[bob.id].encrypt(plaintext)
    print(f'cryptext is: {cryptext}')
    print(f'Bob sees: {bob.ratchets[alice.id].decrypt(cryptext)}')

    print(f'Alice and Bob reset their ratchets')
    alice.ratchets[bob.id].updateRootKey()
    bob.ratchets[alice.id].updateRootKey()

    plaintext='attack at dawn'
    print(f'Bob sends Alice a message: {plaintext}')
    cryptext=bob.ratchets[alice.id].encrypt(plaintext)
    print(f'cryptext is: {cryptext}')
    print(f'Alice sees: {alice.ratchets[bob.id].decrypt(cryptext)}')

    plaintext='affirmative'
    print(f'Alice responds to Bob: {plaintext}')
    cryptext=alice.ratchets[bob.id].encrypt(plaintext)
    print(f'cryptext is: {cryptext}')
    print(f'Bob sees: {bob.ratchets[alice.id].decrypt(cryptext)}')
