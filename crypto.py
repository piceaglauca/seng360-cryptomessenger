# Use Cases:
# 1. Create a new user - generate prekey bundle, create User() object
# 2. Login a user - create User() object with stored keys
# 3. Rotate keys - User() object already created, need to refresh existing keys
# 4. Encrypt a message/operate ratchet
# 5. Decrypt a message/operate ratchet

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


class User:
    """A User of the cryptomessenger.

    A User contains the prekey bundle. If not supplied, the prekey bundle will
    be generated fresh.

    Constructor keyword arguments:
    ipk -- the identity prekey, type IPK (default None)
    spk -- the signed prekey, type SPK (default None)
    opk -- the one-time use prekey, type list of OPK (default None)

    TODO: allow User instantiation with existing prekey bundle.
    """

    def __init__(self, ipk=None, spk=None, opk=None):
        if ipk is None:
            self.ipk = IPK.generate(ipk)
        if spk is None:
            self.spk = SPK.generate(self.ipk, spk)
        if opk is None:
            self.opk = OPK.generate(opk)


class KeyPair:
    """A basic key pair consisting of a private and public x25519 key.

    A KeyPair should be instantiated indirectly through the generate()
    function."""

    def __init__(self, private_key):
        self.private = private_key
        self.public = self.private.public_key()

    def generate(private_key = None):
        """Instantiate a KeyPair object containing a private and public key.

        Keyword argument:
        private_key -- the x25519 private key. If not provided,
                        one will be generated."""

        if private_key is None:
            return KeyPair(X25519PrivateKey.generate())
        elif isinstance(private_key, X25519PrivateKey):
            return private_key
        else:
            raise Exception(f'invalid argument type: {type(private_key)}')

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

    def toEd25519(self):
        """Convert the x25519 private key to ed25519 private key."""

        return Ed25519PrivateKey.from_private_bytes(self.private_bytes())


class IPK:
    """An identity x25519 pre-keypair.

    An IPK should be instantiated indirectly through the generate()
    function."""

    def __init__(self, private_key = None):
        if isinstance(private_key, IPK):
            self.keyPair = private_key.keyPair
        elif isinstance(private_key, KeyPair):
            self.keyPair = private_key

    def generate(private_key = None):
        """Generate an identity x25519 pre-keypair.

        Keywork arguments:
        private_key -- an existing IPK object to clone (default None)"""

        if isinstance(private_key, IPK):
            return IPK(private_key)
        else:
            return IPK(KeyPair.generate(private_key))


class SPK:
    """A signed x25519 pre-keypair.

    An SPK should be instantiated indirectly through the generate()
    function."""

    def __init__(self, ipk, private_key = None):
        self.signature = None
        self.keyPair = None

        if isinstance(private_key, SPK):
            self.keyPair = private_key.keyPair
            self.signature = private_key.signature
        elif isinstance(private_key, KeyPair):
            self.keyPair = private_key

        if self.signature is None:
            self.signature = self.sign(ipk, self.keyPair.public_bytes())

    def sign(self, ipk, message):
        """Use the prekey to sign a message.

        Keyword arguments:
        ipk -- The identity key to use for signing.
        message -- The message to sign."""

        return ipk.keyPair.toEd25519().sign(message)

    def generate(ipk, private_key = None):
        """Generate a signed x25519 pre-keypair.

        Keywork arguments:
        ipk -- an identity keypair to use in signing this SPK (required)
        private_key -- an existing SPK object to clone (default None)"""

        if not isinstance(ipk, IPK):
            raise Exception(f'invalid IPK type: {type(ipk)}')

        if isinstance(private_key, SPK):
            return SPK(ipk, private_key)
        else:
            return SPK(ipk, KeyPair.generate(private_key))


class OPK:
    """A one-time use x25519 pre-keypair.

    An OPK should be instantiated indirectly through the generate()
    function."""

    def __init__(self):
        self.keyPair = KeyPair.generate()

    def generate(private_key = None):
        """Generate a list of 100 x25519 one-time use pre-keypairs.

        Keywork arguments:
        private_key -- an existing OPK object (or list of) to include (default None)
        """

        keyList = []
        if isinstance(private_key, OPK):
            keyList.append(private_key)
        elif isinstance(private_key, list):
            for key in private_key:
                if isinstance(key, OPK):
                    keyList.append(key)

        for i in range(100-len(keyList)):
            keyList.append(OPK())

        return keyList
