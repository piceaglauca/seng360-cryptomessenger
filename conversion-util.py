from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization
import nacl.signing


# Takes PyCa Ed25519 private key.
# Converts to PyCa X25519 private key via PyNaCl.
def convertToX25519PrivateKey(ed_private_pyca):
    # Get PyCa Ed25519 private key bytes:
    ed_private_pyca_bytes = ed_private_pyca.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert PyCa Ed25519 private key to PyNaCl Ed25519 private key:
    ed_private_pynacl = nacl.signing.SigningKey(ed_private_pyca_bytes)

    # Convert PyNaCl Ed25519 private key to PyNaCl X25519 private key:
    x_private_pynacl = ed_private_pynacl.to_curve25519_private_key()

    # Convert PyNaCl X25519 private key to PyCa X25519 private key:
    x_private_pyca = X25519PrivateKey.from_private_bytes(x_private_pynacl.encode())

    return x_private_pyca


# Takes PyCa Ed25519 public key.
# Converts to PyCa X25519 public  key via PyNaCl.
def convertToX25519PublicKey(ed_public_pyca):
    # Get PyCa Ed25519 public key bytes:
    ed_public_pyca_bytes = ed_public_pyca.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Convert PyCa Ed25519 public key to PyNaCl Ed25519 public key:
    ed_public_pynacl = nacl.signing.VerifyKey(ed_public_pyca_bytes)

    # Convert PyNaCl Ed25519 public key to PyNaCl X25519 public key:
    x_public_pynacl = ed_public_pynacl.to_curve25519_public_key()

    # Convert PyNaCl X25519 public key to PyCa X25519 public key:
    x_public_pyca = X25519PublicKey.from_public_bytes(x_public_pynacl.encode())

    return x_public_pyca


########
# example:

# generate PyCa Ed25519 private key.
# convert to PyCa X25519 private key via PyNaCl.
alice_ik_priv_ed = Ed25519PrivateKey.generate()
alice_ik_priv_x = convertToX25519PrivateKey(alice_ik_priv_ed)

# generate PyCa Ed25519 public key.
# convert to PyCa X25519 public key via PyNaCl.
alice_ik_pub_ed = Ed25519PrivateKey.generate().public_key()
alice_ik_pub_x = convertToX25519PublicKey(alice_ik_pub_ed)

# print converted keys:
alice_ik_priv_x_bytes = alice_ik_priv_ed.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

alice_ik_pub_x_bytes = alice_ik_pub_x.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print(alice_ik_priv_x_bytes)
print(alice_ik_pub_x_bytes)


