import oqs

print("ML-DSA Digital Signature Test")
print("--------------------------------")

# Create ML-DSA signer
signer = oqs.Signature("ML-DSA-65")

# Generate public and secret keys
public_key = signer.generate_keypair()
secret_key = signer.export_secret_key()

# Message to authenticate
message = b"TAKEOFF ALTITUDE 10"

# Generate digital signature
signature = signer.sign(message)

print("Message:", message)
print("Public Key Size:", len(public_key))
print("Signature Size:", len(signature))

# Verify signature
verifier = oqs.Signature("ML-DSA-65")

is_valid = verifier.verify(
    message,
    signature,
    public_key
)

if is_valid:
    print("Signature verification successful!")
else:
    print("Signature verification failed!")

# Test tampered message
tampered_message = b"TAKEOFF ALTITUDE 100"

is_valid_tampered = verifier.verify(
    tampered_message,
    signature,
    public_key
)

if not is_valid_tampered:
    print("Tampered message rejected successfully!")
else:
    print("Warning: Tampered message accepted!")