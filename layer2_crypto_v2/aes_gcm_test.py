
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate a secure 256-bit key
key = AESGCM.generate_key(bit_length=256)

aesgcm = AESGCM(key)

# Generate a unique nonce
nonce = os.urandom(12)

# UAV command
message = b"TAKEOFF ALTITUDE 10"

# Encrypt the message
encrypted_message = aesgcm.encrypt(
    nonce,
    message,
    None
)

print("AES-GCM Encryption Test")
print("-----------------------")
print("Original Message:", message)
print("Encrypted Message:", encrypted_message)

# Decrypt the message
decrypted_message = aesgcm.decrypt(
    nonce,
    encrypted_message,
    None
)

print("Decrypted Message:", decrypted_message)

if decrypted_message == message:
    print("Encryption test successful!")