
import oqs
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


print("ML-KEM + AES-GCM Integration Test")
print("----------------------------------")


# 1. UAV generates an ML-KEM key pair
uav = oqs.KeyEncapsulation("ML-KEM-768")

public_key = uav.generate_keypair()


# 2. Ground Station encapsulates a shared secret
ground_station = oqs.KeyEncapsulation("ML-KEM-768")

ciphertext, sender_secret = ground_station.encap_secret(
    public_key
)


# 3. UAV decapsulates the ciphertext
receiver_secret = uav.decap_secret(ciphertext)


# 4. Check shared secrets
if sender_secret != receiver_secret:
    print("Error: Shared secrets do not match!")
    raise SystemExit

print("ML-KEM shared secret established successfully!")


# 5. Derive an AES-256 key using HKDF
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"UAV-C2-AES-GCM"
).derive(sender_secret)


# 6. Encrypt a UAV command
aesgcm = AESGCM(aes_key)

nonce = os.urandom(12)

command = b"TAKEOFF ALTITUDE 10"

encrypted_command = aesgcm.encrypt(
    nonce,
    command,
    None
)


# 7. Decrypt the command
decrypted_command = aesgcm.decrypt(
    nonce,
    encrypted_command,
    None
)


print("Original Command:", command)
print("Encrypted Command:", encrypted_command)
print("Decrypted Command:", decrypted_command)


if decrypted_command == command:
    print("ML-KEM + AES-GCM test successful!")
else:
    print("Decryption failed!")
