from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend

# Key Generation
private_key = dsa.generate_private_key(
    key_size=1024,
    backend=default_backend()
)
public_key = private_key.public_key()

# Message
message = b"Hello, world!"

# Signature Generation
hash_algorithm = hashes.SHA256()
signature = private_key.sign(
    message,
    algorithm=hash_algorithm
)

# Signature Verification
try:
    public_key.verify(
        signature,
        message,
        algorithm=hash_algorithm
    )
    print("Signature is valid.")
except:
    print("Signature is invalid.")
