import csv
import os
import statistics
import time
from pathlib import Path

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent
OUTPUT = BASE_DIR / "crypto_benchmark_results.csv"

KEM_ALGORITHM = "ML-KEM-768"
AES_ALGORITHM = "AES-256-GCM"

RUNS = 100
WARMUPS = 10

CSV_FIELDS = [
    "algorithm",
    "operation",
    "iterations",
    "mean_ms",
    "median_ms",
    "stdev_ms",
    "min_ms",
    "max_ms",
    "ci95_low_ms",
    "ci95_high_ms",
    "sizes_bytes",
]


def measure(operation, runs=RUNS, warmups=WARMUPS):
    for _ in range(warmups):
        operation()

    samples = []

    for _ in range(runs):
        start = time.perf_counter_ns()
        operation()
        elapsed = time.perf_counter_ns() - start
        samples.append(elapsed / 1_000_000)

    return samples


def summarize(algorithm, operation, samples, sizes=""):
    mean = statistics.mean(samples)
    sd = statistics.stdev(samples) if len(samples) > 1 else 0.0
    half_width = 1.96 * sd / (len(samples) ** 0.5)

    return {
        "algorithm": algorithm,
        "operation": operation,
        "iterations": len(samples),
        "mean_ms": mean,
        "median_ms": statistics.median(samples),
        "stdev_ms": sd,
        "min_ms": min(samples),
        "max_ms": max(samples),
        "ci95_low_ms": max(0.0, mean - half_width),
        "ci95_high_ms": mean + half_width,
        "sizes_bytes": sizes,
    }


def run_kem():
    keygen_samples = []
    encap_samples = []
    decap_samples = []

    public_key = None
    ciphertext = None
    shared_secret = None

    for run in range(WARMUPS + RUNS):
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as receiver:
            start = time.perf_counter_ns()
            public_key = receiver.generate_keypair()
            keygen_ms = (
                time.perf_counter_ns() - start
            ) / 1_000_000

            with oqs.KeyEncapsulation(KEM_ALGORITHM) as sender:
                start = time.perf_counter_ns()
                ciphertext, sender_secret = sender.encap_secret(
                    public_key
                )
                encap_ms = (
                    time.perf_counter_ns() - start
                ) / 1_000_000

            start = time.perf_counter_ns()
            receiver_secret = receiver.decap_secret(ciphertext)
            decap_ms = (
                time.perf_counter_ns() - start
            ) / 1_000_000

            if sender_secret != receiver_secret:
                raise RuntimeError(
                    "ML-KEM shared-secret mismatch"
                )

        if run >= WARMUPS:
            keygen_samples.append(keygen_ms)
            encap_samples.append(encap_ms)
            decap_samples.append(decap_ms)

        shared_secret = sender_secret

    sizes = (
        f"public_key={len(public_key)};"
        f"ciphertext={len(ciphertext)};"
        f"shared_secret={len(shared_secret)}"
    )

    return [
        summarize(
            KEM_ALGORITHM, "key_generation",
            keygen_samples, sizes
        ),
        summarize(
            KEM_ALGORITHM, "encapsulation",
            encap_samples, sizes
        ),
        summarize(
            KEM_ALGORITHM, "decapsulation",
            decap_samples, sizes
        ),
    ]


def run_aes_gcm():
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)

    # This benchmark represents a short 19-byte UAV command.
    message = b"TAKEOFF ALTITUDE 10"
    latest = {"nonce": None, "ciphertext": None}

    def encrypt_once():
        # A fresh 96-bit nonce is used for every encryption.
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, message, None)
        latest["nonce"] = nonce
        latest["ciphertext"] = ciphertext

    def decrypt_once():
        if latest["ciphertext"] is None:
            encrypt_once()

        plaintext = aes.decrypt(
            latest["nonce"],
            latest["ciphertext"],
            None,
        )

        if plaintext != message:
            raise RuntimeError("AES-GCM plaintext mismatch")

    encryption_samples = measure(encrypt_once)
    decryption_samples = measure(decrypt_once)

    sizes = (
        f"message={len(message)};"
        f"key=32;nonce=12"
    )

    return [
        summarize(
            AES_ALGORITHM, "encryption",
            encryption_samples, sizes
        ),
        summarize(
            AES_ALGORITHM, "decryption",
            decryption_samples, sizes
        ),
    ]


def main():
    print("Layer 2 Cryptographic Benchmark")
    print(f"ML-KEM algorithm: {KEM_ALGORITHM}")
    print(f"AES algorithm: {AES_ALGORITHM}")
    print(f"Measured runs: {RUNS}; warm-ups: {WARMUPS}")
    print("Timer: time.perf_counter_ns()")

    rows = run_kem() + run_aes_gcm()

    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    for row in rows:
        print(
            f"\n{row['algorithm']} / {row['operation']}"
        )
        print(f"  Mean:   {row['mean_ms']:.6f} ms")
        print(f"  Median: {row['median_ms']:.6f} ms")
        print(f"  SD:     {row['stdev_ms']:.6f} ms")
        print(f"  Min:    {row['min_ms']:.6f} ms")
        print(f"  Max:    {row['max_ms']:.6f} ms")
        print(
            f"  Approx. 95% CI: "
            f"[{row['ci95_low_ms']:.6f}, "
            f"{row['ci95_high_ms']:.6f}] ms"
        )

    print(f"\nCSV saved to: {OUTPUT}")
    print("All ML-KEM shared-secret checks passed.")
    print("All AES-GCM plaintext checks passed.")


if __name__ == "__main__":
    main()