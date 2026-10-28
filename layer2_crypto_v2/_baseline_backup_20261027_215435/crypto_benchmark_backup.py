
import oqs
import os
import time
import statistics

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

print("Cryptographic Performance Benchmark")
print("------------------------------------")

NUM_RUNS = 30

# -----------------------------
# ML-KEM-768 Benchmark
# -----------------------------

keygen_times = []
encap_times = []
decap_times = []

for _ in range(NUM_RUNS):

    kem = oqs.KeyEncapsulation("ML-KEM-768")

    start = time.perf_counter()
    public_key = kem.generate_keypair()
    keygen_times.append(time.perf_counter() - start)

    start = time.perf_counter()
    ciphertext, sender_secret = kem.encap_secret(public_key)
    encap_times.append(time.perf_counter() - start)

    start = time.perf_counter()
    receiver_secret = kem.decap_secret(ciphertext)
    decap_times.append(time.perf_counter() - start)

    if sender_secret != receiver_secret:
        print("Error: Shared secrets do not match!")
        break


# -----------------------------
# AES-GCM Benchmark
# -----------------------------

aes_key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(aes_key)

message = b"TAKEOFF ALTITUDE 10"

encryption_times = []
decryption_times = []

for _ in range(NUM_RUNS):

    nonce = os.urandom(12)

    start = time.perf_counter()
    encrypted = aesgcm.encrypt(
        nonce,
        message,
        None
    )
    encryption_times.append(time.perf_counter() - start)

    start = time.perf_counter()
    decrypted = aesgcm.decrypt(
        nonce,
        encrypted,
        None
    )
    decryption_times.append(time.perf_counter() - start)


def average_ms(times):
    return statistics.mean(times) * 1000


print("\nML-KEM-768 Results")
print("------------------")
print("Key Generation Average:",
      round(average_ms(keygen_times), 3), "ms")

print("Encapsulation Average:",
      round(average_ms(encap_times), 3), "ms")

print("Decapsulation Average:",
      round(average_ms(decap_times), 3), "ms")


print("\nAES-GCM Results")
print("----------------")
print("Encryption Average:",
      round(average_ms(encryption_times), 3), "ms")

print("Decryption Average:",
      round(average_ms(decryption_times), 3), "ms")

print("\nBenchmark completed successfully!")