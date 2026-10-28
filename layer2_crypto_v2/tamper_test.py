
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os

print("AES-GCM Tamper Detection Test")
print("-----------------------------")

# Generate a secure encryption key
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

# Encrypt a UAV command
nonce = os.urandom(12)
command = b"TAKEOFF ALTITUDE 10"

encrypted_command = aesgcm.encrypt(
    nonce,
    command,
    None
)

# Modify one byte of the encrypted command
tampered_command = bytearray(encrypted_command)
tampered_command[0] ^= 1
tampered_command = bytes(tampered_command)

# Try to decrypt the modified command
try:
    decrypted_command = aesgcm.decrypt(
        nonce,
        tampered_command,
        None
    )

    print("Warning: Tampered command was accepted!")

except InvalidTag:
    print("Tampered command rejected successfully!")
    print("AES-GCM integrity protection is working!")