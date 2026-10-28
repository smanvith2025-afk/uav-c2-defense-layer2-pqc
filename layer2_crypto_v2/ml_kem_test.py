
import oqs

print("ML-KEM Test")
print("------------")

kem = oqs.KeyEncapsulation("ML-KEM-768")

public_key = kem.generate_keypair()

ciphertext, shared_secret_sender = kem.encap_secret(public_key)

shared_secret_receiver = kem.decap_secret(ciphertext)

print("Public Key Size:", len(public_key))
print("Ciphertext Size:", len(ciphertext))
print("Shared Secret Size:", len(shared_secret_sender))

if shared_secret_sender == shared_secret_receiver:
    print("ML-KEM test successful!")
else:
    print("Shared secrets do not match!")
