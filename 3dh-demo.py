# demo of triple diffie hellman using x25519 key exchange, and ed25519 signatures.
# uses PyNaCl module to generate Ed25519 keys and perform signing.
# uses crypto.py and Cryptography module to generate X25519 keys and do key exchanges.
# alice and bob each generate the shared secret and print it out.


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization
import nacl.signing
import nacl.bindings
from crypto import *
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


#########
## util:

# Takes Ed25510 public key (PyNaCl).
# Converts to X25519 public key (Cryptography).
def convertToX25519PublicKey(public_key_bytes):
    public_key_ed25519 = nacl.signing.VerifyKey(public_key_bytes)
    public_key_x22519 = public_key_ed25519.to_curve25519_public_key()
    return X25519PublicKey.from_public_bytes(public_key_x22519._public_key) # Converts from PyNaCl to Cryptography.

# Takes Ed25510 private key (PyNaCl).
# Converts to X25519 private key (Cryptography).
def convertToX25519PrivateKey(private_key):
    private_key_x22519 = private_key.to_curve25519_private_key()
    return X25519PrivateKey.from_private_bytes(private_key_x22519._private_key) # Converts from PyNaCl to Cryptography.


########
## prerequisites:

# alice generates keys on her machine:
a_ik = nacl.signing.SigningKey.generate()   # Alice IK
a_sk = KeyPair.generate()                   # Alice SK
a_ok = KeyPair.generate()                   # Alice OK
a_sig = a_ik.sign(a_sk.public_bytes())      # Alice signature

# bob generates keys on his machine:
b_ik = nacl.signing.SigningKey.generate()   # Bob IK
b_sk = KeyPair.generate()                   # Bob SK
b_ok = KeyPair.generate()                   # Bob OK
b_sig = b_ik.sign(b_sk.public_bytes())      # Bob signature

# alice sends key bundle to server:
a_ik_pub_bytes = a_ik.verify_key.encode()
a_sk_pub_bytes = a_sk.public_bytes()
a_ok_pub_bytes = a_ok.public_bytes()
a_sig_bytes = a_sig._signature

# bob sends key bundle to server:
b_ik_pub_bytes = b_ik.verify_key.encode()
b_sk_pub_bytes = b_sk.public_bytes()
b_ok_pub_bytes = b_ok.public_bytes()
b_sig_bytes = b_sig._signature


########
## alice wants to message bob.
## she obtains bob's key bundle.

# alice verifies bob's signature:
verifier = nacl.signing.VerifyKey(b_ik_pub_bytes)
try:
    verifier.verify(b_sk_pub_bytes, b_sig_bytes)
    print('signature verified')
except:
    print('could not verify signature')
    sys.exit()

# alice generates an ephemeral key:
a_ek = KeyPair.generate()
a_ek_pub_bytes = a_ek.public_bytes()

# alice prepares keys for exchange:
a_ik_priv = convertToX25519PrivateKey(a_ik)                     # Alice private IK converted to X25519.
a_ek_priv = a_ek.private
b_ik_pub = convertToX25519PublicKey(b_ik_pub_bytes)             # Bob public IK converted to X25519.
b_sk_pub = X25519PublicKey.from_public_bytes(b_sk_pub_bytes)
b_ok_pub = X25519PublicKey.from_public_bytes(b_ok_pub_bytes)

# alice performs 3DH:
a_dh1 = a_ik_priv.exchange(b_sk_pub)
a_dh2 = a_ek_priv.exchange(b_ik_pub)
a_dh3 = a_ek_priv.exchange(b_sk_pub)
a_dh4 = a_ek_priv.exchange(b_ok_pub)

# alice generates shared secret:
def a_generate_secret():
    hkdf = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = None,
        info = b"crypticmessenger",
    )

    a_secret = hkdf.derive(a_dh1 + a_dh2 + a_dh3 + a_dh4)
    print('alice\'s secret:')
    print(a_secret)

a_generate_secret()

# alice encrypts message and sends to bob.


########
## bob receives a message from alice.
## he obtains alice's key bundle.

# bob verifies alice's signature:
verifier = nacl.signing.VerifyKey(a_ik_pub_bytes)
try:
    verifier.verify(a_sk_pub_bytes, a_sig_bytes)
    print('signature verified')
except:
    print('could not verify signature')
    sys.exit()

# bob prepares keys for exchange:
a_ik_pub = convertToX25519PublicKey(a_ik_pub_bytes)             # Alice public IK converted to X25519.
a_ek_pub = X25519PublicKey.from_public_bytes(a_ek_pub_bytes)
b_ik_priv = convertToX25519PrivateKey(b_ik)                     # Bob private IK converted to X25519.
b_sk_priv = b_sk.private
b_ok_priv = b_ok.private

# bob peforms 3DH:
b_dh1 = b_sk_priv.exchange(a_ik_pub)
b_dh2 = b_ik_priv.exchange(a_ek_pub)
b_dh3 = b_sk_priv.exchange(a_ek_pub)
b_dh4 = b_ok_priv.exchange(a_ek_pub)

# bob generates shared secret:
def b_generate_secret():
    hkdf = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = None,
        info = b"crypticmessenger",
    )
    
    b_secret = hkdf.derive(b_dh1 + b_dh2 + b_dh3 + b_dh4)
    print('bob\'s secret:')
    print(b_secret)

b_generate_secret()






