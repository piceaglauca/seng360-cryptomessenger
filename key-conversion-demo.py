# Signing X25519 key with Ed25519 key.
# Converting Ed25519 keys to X25519.
# Using pynacl module for Ed25519 and conversions to X25519.
# Using cryptography module for X25519.
# References:
# https://github.com/pyca/cryptography/issues/5557
# https://github.com/pyca/pynacl/blob/main/docs/signing.rst 
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/ 



from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization
import nacl.signing
import nacl.bindings



# Signing using Ed25519:

# Generate alice IK (Ed25519).
alice_ik = nacl.signing.SigningKey.generate()

# Generate alice SK (X25519).
alice_sk = X25519PrivateKey.generate()
alice_sk_pub_bytes = alice_sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

# Sign alice SK public with alice IK private.
alice_sk_pub_sig_bytes = alice_ik.sign(alice_sk_pub_bytes)._signature

# Send bob the bytes:
# alice_sk_pub_bytes
# alice_sk_pub_sig_bytes
alice_ik_pub_bytes = alice_ik.verify_key.encode()

# Bob receives bytes.
# Bob creates verifier using alice_ik_pub.
verifier = nacl.signing.VerifyKey(alice_ik_pub_bytes)

# Ruin signature so verifier fails:
#alice_sk_pub_sig_bytes = 'ruinedsignature'

# Bob verifies signature.
try:
    verifier.verify(alice_sk_pub_bytes, alice_sk_pub_sig_bytes)
    print('signature verified')
except:
    print('could not verify signature')



# Converting from Ed25519 to X25519.
# If Alice wants to message Bob,
# she converts her IK private,
# and converts Bob's IK public,
# so she can do X25519 key exchange.

# Bob's IK.
bob_ik = nacl.signing.SigningKey.generate()
bob_ik_pub_bytes = bob_ik.verify_key.encode()

# Alice generates shared secret:

# Alice converts her IK private to X25519.
alice_ik_priv_x_nacl = alice_ik.to_curve25519_private_key()
alice_ik_priv_x = X25519PrivateKey.from_private_bytes(alice_ik_priv_x_nacl._private_key)

# Alice converts Bob's IK public to X25519
bob_ik_pub_x_nacl = bob_ik.verify_key.to_curve25519_public_key()
bob_ik_pub_x = X25519PublicKey.from_public_bytes(bob_ik_pub_x_nacl._public_key)

# Alice generates shared secret using converted keys.
alice_shared_secret = alice_ik_priv_x.exchange(bob_ik_pub_x)
print('alice generated shared secret:')
print(alice_shared_secret)


