import matplotlib.pyplot as plt

operations = [
    "ML-KEM\nKeygen",
    "ML-KEM\nEncap",
    "ML-KEM\nDecap",
    "ML-DSA\nSign",
    "ML-DSA\nVerify",
    "AES-GCM\nEncrypt",
    "AES-GCM\nDecrypt"
]

times = [
    0.164,
    0.191,
    0.225,
    1.7543,
    0.4838,
    0.001,
    0.001
]

plt.figure(figsize=(11, 6))
plt.bar(operations, times)

plt.title("Layer 2: Combined Cryptographic Performance")
plt.xlabel("Cryptographic Operation")
plt.ylabel("Average Time (ms)")
plt.grid(axis="y")
plt.tight_layout()

plt.savefig("layer2_combined_performance.png", dpi=300)
plt.show()
