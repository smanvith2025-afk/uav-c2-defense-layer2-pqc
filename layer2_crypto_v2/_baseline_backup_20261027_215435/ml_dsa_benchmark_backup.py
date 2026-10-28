import oqs
import time
import statistics

print("ML-DSA Performance Benchmark")
print("-----------------------------")

algorithm = "ML-DSA-65"
message = b"TAKEOFF ALTITUDE 10"
iterations = 100

signer = oqs.Signature(algorithm)
public_key = signer.generate_keypair()

# Generate signatures
signatures = []
sign_times = []

for _ in range(iterations):
    start = time.perf_counter()
    signature = signer.sign(message)
    end = time.perf_counter()

    signatures.append(signature)
    sign_times.append((end - start) * 1000)

# Verify signatures
verifier = oqs.Signature(algorithm)
verify_times = []

for signature in signatures:
    start = time.perf_counter()
    valid = verifier.verify(message, signature, public_key)
    end = time.perf_counter()

    verify_times.append((end - start) * 1000)

    if not valid:
        print("Signature verification failed!")

print(f"Algorithm: {algorithm}")
print(f"Iterations: {iterations}")
print(f"Public Key Size: {len(public_key)} bytes")
print(f"Signature Size: {len(signatures[0])} bytes")

print(f"Average Signing Time: "
      f"{statistics.mean(sign_times):.4f} ms")

print(f"Average Verification Time: "
      f"{statistics.mean(verify_times):.4f} ms")

print("ML-DSA benchmark completed successfully!")