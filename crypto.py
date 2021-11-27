# Use Cases:
# 1. Create a new user - generate prekey bundle, create User() object
# 2. Login a user - create User() object with stored keys
# 3. Rotate keys - User() object already created, need to refresh existing keys
# 4. Encrypt a message/operate ratchet
# 5. Decrypt a message/operate ratchet

from cryptography.hazmat.primitives.asymmetric.ed25519 import *
from cryptography.hazmat.primitives.asymmetric.x25519 import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import *


class Server:
    def __init__(self):
        self.users = {}
        self.nextUserID = 0

    def register(self, keybundle: dict) -> int:
        """Register a key bundle with the server.

        Returns a user ID."""

        kb = KeyBundle.unpackage(keybundle)
        kb.peer_id = self.nextUserID
        self.users[self.nextUserID] = kb
        self.nextUserID += 1
        return self.nextUserID - 1

    def getKeyBundle(self, user_id: int): # -> KeyBundle
        """Get a key bundle to initiate X3DH protocol."""

        if user_id in self.users.keys():
            kb = KeyBundle()
            kb.peer_id = self.users[user_id].peer_id
            kb.edpk = self.users[user_id].edpk
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
    edpk -- the ed25519 prekey, type EDPK
    ipk -- the identity prekey, type IPK
    spk -- the signed prekey, type SPK
    opk -- the one-time use prekey, type list of OPK
    """

    def __init__(self):
        self.id = None # received from server when key bundle is registered
        self.edpk = None
        self.ipk = None
        self.spk = None
        self.opk = None
        self.shared_keys = {}

    @staticmethod
    def new(): # -> User
        """Create a new user with prekeys.

        Note: the User ID is not created at this stage, as it will be provided
        by the server when the keybundle is registered."""

        user = User()
        user.edpk = EDPK.generate()
        user.ipk = IPK.generate()
        user.spk = SPK.generate(user.edpk)
        user.opk = OPK.generateMany()
        
        return user

    def register(self, server):
        """Register my key bundle with the server."""

        self.id = server.register(KeyBundle.from_user(self).package())

    def initializeCommunication(self, keybundle_pkg: dict): # -> tuple
        """Derive a shared secret from a KeyBundle.

        Returns a tuple of (ipk, epk, keybundle) to be sent to peer so the
        shared secret can be generated independently."""

        keybundle = KeyBundle.unpackage(keybundle_pkg)
        epk = KeyPair.generate()

        # TODO: improve this. The key is stored in plaintext in memory.
        # Instead of storing keys, we should store Encryptor objects
        # from cryptography.hazmat.primitives.ciphers.Cipher
        # Left as is for rough initial proof of concept
        self.shared_keys[keybundle.peer_id] = (
                self.diffieHellman(self.ipk, epk, keybundle), 
                self.ipk.public_bytes(), 
                epk.public_bytes())
        epk.private = None

        return (self.ipk.public_bytes(), epk.public_bytes(), keybundle.package())

        # TODO: replace the above with something like this:
        #associated_data = self.ipk.public_bytes() + keybundle.ipk.public_bytes()
        #encryptor = Cipher(
        #        algorithms.AES(kdf.derive(DH1 + DH2 + DH3 + DH4)),
        #        modes.GCM(b'U\xa4\xdb\xee\x96A\xb4\xf4\xa0\x98\xbf\xe1') # IV
        #    ).encryptor()
        #encryptor.authenticate_additional_data(associated_data)
        #self.encryptors[keybundle.peer_id] = (encryptor, associated_data)

    # TODO: finish this
    def encrypt(self, user: int, message: str) -> bytes:
        """Encrypt a message to a user with a shared key."""

        if user in self.encryptors.keys():
            encryptor, associated_data = self.encryptors[id]
            ciphertext = encryptor.update(message) + encryptor.finalize()
            return (ciphertext, encryptor.tag)
        else:
            raise Exception # user not found

    # TODO: finish this
    def decrypt(key, associated_data, ciphertext, tag):
        pass

    def diffieHellman(self, ipk, epk, keybundle):
        """Derive the shared secret from keys."""

        # Initial diffie hellman
        if isinstance(ipk.private, X25519PrivateKey):
            DH1 = ipk.exchange(keybundle.spk)
            DH2 = epk.exchange(keybundle.ipk)
            DH3 = epk.exchange(keybundle.spk)
            DH4 = epk.exchange(keybundle.opk)

        # Peer has generated shared secret, so generate the same.
        else:
            matchingOPK = None
            for opk in self.opk:
                if opk.public_bytes() == keybundle.opk.public_bytes():
                    matchingOPK = opk
            if matchingOPK is None:
                raise Exception # couldn't find matching OPK

            DH1 = self.spk.exchange(ipk)
            DH2 = self.ipk.exchange(epk)
            DH3 = self.spk.exchange(epk)
            DH4 = matchingOPK.exchange(epk)

        # Derive shared secret from above diffie-hellmans
        kdf = HKDF(\
                algorithm=hashes.SHA256(), \
                length = 32, \
                salt=bytes(256), \
                info=b'cryptomessenger')
        return kdf.derive(DH1 + DH2 + DH3 + DH4)


class KeyBundle:
    """A KeyBundle for deriving shared secrets using X3DH."""

    def __init__(self):
        self.peer_id = None
        self.edpk = None
        self.ipk = None
        self.spk = None
        self.opk = None

    def validateSignature(self) -> None:
        """Validate the signed SPK."""

        self.edpk.verify(self.spk.signature, self.spk.public_bytes())

    def package(self) -> dict:
        """Convert prekey bundle to dictionary for transmission."""

        # Most cases will only have a single OPK in the key bundle.
        if isinstance(self.opk, OPK):
            packagedOPK = self.opk.public_bytes()

        # When registering with the server, there will be a list of OPKs
        elif isinstance(self.opk, list):
            packagedOPK = []
            for opk in self.opk:
                packagedOPK.append(opk.public_bytes())

        return {'ID'       : self.peer_id, \
                'EDPK'     : self.edpk.public_bytes(), \
                'IPK'      : self.ipk.public_bytes(), \
                'SPK'      : self.spk.public_bytes(), \
                'signature': self.spk.signature, \
                'OPK'      : packagedOPK}

    @staticmethod
    def unpackage(bundle: dict): # -> KeyBundle, throws TypeError
        """Create a KeyBundle object from keys packaged in a dictionary."""

        if isinstance(bundle, dict) and \
                'ID' in bundle.keys() and \
                'EDPK' in bundle.keys() and \
                'IPK' in bundle.keys() and \
                'SPK' in bundle.keys() and \
                'signature' in bundle.keys() and \
                'OPK' in bundle.keys():

            # Most cases will only have a single OPK in the key bundle.
            if isinstance(bundle['OPK'], bytes):
                unpackagedOPK = OPK.from_public_bytes(bundle['OPK'])

            # When registering with the server, there will be a list of OPKs
            elif isinstance(bundle['OPK'], list):
                unpackagedOPK = []
                for opk in bundle['OPK']:
                    unpackagedOPK.append(OPK.from_public_bytes(opk))

            return KeyBundle.from_keys(\
                        bundle['ID'], \
                        EDPK.from_public_bytes(bundle['EDPK']), \
                        IPK.from_public_bytes(bundle['IPK']), \
                        SPK.from_public_bytes(bundle['SPK'], \
                                              bundle['signature']), \
                        unpackagedOPK)

        elif isinstance(bundle, dict):
            raise TypeError(f"Invalid key bundle. Expected keys: ['ID','EDPK','IPK','SPK','signature','OPK']. Got: {bundle.keys()}")
        else:
            raise TypeError(f'invalid key bundle. Expected dictionary, got {type(bundle)}')

    @staticmethod
    def from_keys(peer_id: int, edpk, ipk, spk, opk): # -> KeyBundle
        """Generate a KeyBundle from key objects."""

        kb = KeyBundle()
        kb.peer_id = peer_id
        kb.edpk = edpk
        kb.ipk = ipk
        kb.spk = spk
        kb.opk = opk

        kb.validateSignature()

        return kb

    @staticmethod
    def from_user(user): # -> KeyBundle
        """Generate a KeyBundle from a User object."""

        kb = KeyBundle()
        kb.peer_id = user.id
        kb.edpk = user.edpk
        kb.ipk = user.ipk
        kb.spk = user.spk
        kb.opk = user.opk

        kb.validateSignature()
        
        return kb


class KeyPair:
    """A generic private/public key pair. 

    May contain X25519 or Ed25519 keys. This class is extended by
    IPK/SPK/OPK/EDPK, but is used directly for ephemeral keys.

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

        return self.private.exchange(public_key.public)

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


class EDPK(KeyPair):
    """An ed25519 pre-keypair.

    An EDPK should be instantiated indirectly through the generate() 
    function, or derived from bytes using from_public_bytes() or 
    from_private_bytes()."""

    def sign(self, message: bytes) -> bytes:
        """Sign the given message with the associated ed25519 private key."""

        return self.private.sign(message)

    def verify(self, signature: bytes, message: bytes) -> None:
        """Verify the validity of a signed message."""

        # Ed25519.verify() does not return a value. Instead, it throws 
        # InvalidSignature if the signature cannot be verified.
        try:
            self.public.verify(signature, message)
        except InvalidSignature:
            raise # TODO: should we handle the invalid signature somehow?

    @staticmethod
    def generate(): # -> EDPK
        """Generate an ed25519 pre-keypair."""

        edpk = EDPK()
        edpk.private = Ed25519PrivateKey.generate()
        edpk.public = edpk.private.public_key()

        return edpk

    @staticmethod
    def from_public_bytes(public_bytes: bytes): # -> EDPK
        """Create an EDPK object from public key bytes representation."""

        edpk = EDPK()
        kp = KeyPair.from_public_bytes(public_bytes, 'ed25519')
        edpk.public = kp.public

        return edpk

    @staticmethod
    def from_private_bytes(private_bytes: bytes): # -> EDPK
        """Create an EDPK object from private key bytes representation."""

        edpk = EDPK()
        kp = KeyPair.from_private_bytes(private_bytes, 'ed25519')
        edpk.private, edpk.public = kp.private, kp.public

        return edpk


class IPK(KeyPair):
    """An x25519 pre-keypair.

    An IPK should be instantiated indirectly through the generate() 
    function, or derived from bytes using from_public_bytes() or 
    from_private_bytes()."""

    @staticmethod
    def generate(): # -> IPK
        """Generate an x25519 pre-keypair."""

        ipk = IPK()
        ipk.private = X25519PrivateKey.generate()
        ipk.public = ipk.private.public_key()

        return ipk

    @staticmethod
    def from_public_bytes(public_bytes: bytes): # -> IPK
        """Create an IPK object from public key bytes representation."""

        ipk = IPK()
        kp = KeyPair.from_public_bytes(public_bytes)
        ipk.public = kp.public

        return ipk

    @staticmethod
    def from_private_bytes(private_bytes: bytes): # -> IPK
        """Create an IPK object from private key bytes representation."""

        ipk = IPK()
        kp = KeyPair.from_private_bytes(private_bytes)
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
    def from_private_bytes(private_bytes: bytes): # -> SPK
        """Create an SPK object from private key bytes representation."""

        spk = SPK()
        kp = KeyPair.from_private_bytes(private_bytes)
        spk.private, spk.public = kp.private, kp.public
        # TODO what about signature?

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
    print('Creating two new users, alice and bob')
    alice = User.new()
    bob = User.new()

    print('Creating the server connection (just an object instantiation for now)')
    server = Server()

    print('Alice registers with the server.')
    alice.register(server)
    print("Alice's user id is now {alice.id}")

    print("Bob wants to communicate with Alice, so he asks the server for her keybundle.")
    alice_kb = server.getKeyBundle(alice.id)

    print("Bob will receive Alice's key bundle and derive the shared secret.")
    keys_for_alice = bob.initializeCommunication(alice_kb.package())

    print('Bob sends an initial message to Alice, including the required public keys for her to generate the shared secret.')
    key=alice.diffieHellman(
        IPK.from_public_bytes(keys_for_alice[0]),
        KeyPair.from_public_bytes(keys_for_alice[1]), 
        KeyBundle.unpackage(keys_for_alice[2])
        )

    print(f'Did alice derive the same secret key as bob? {key == bob.shared_keys[0][0]}')
