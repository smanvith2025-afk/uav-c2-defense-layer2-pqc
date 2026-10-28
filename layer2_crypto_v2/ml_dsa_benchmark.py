import csv
import statistics
import time
from pathlib import Path

import oqs

ALGORITHM = "ML-DSA-65"
RUNS = 100
WARMUPS = 10
OUTPUT = Path(__file__).resolve().parent / "ml_dsa_benchmark_results.csv"


def measure(operation):
    """Measure an operation after warm-up and return samples and last result."""
    for _ in range(WARMUPS):
        operation()

    samples = []
    last_result = None

    for _ in range(RUNS):
        start = time.perf_counter_ns()
        last_result = operation()
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        samples.append(elapsed_ms)

    return samples, last_result


def summarize(operation, samples, sizes):
    ordered = sorted(samples)
    mean = statistics.mean(samples)
    sd = statistics.stdev(samples)
    half_width = 1.96 * sd / (len(samples) ** 0.5)

    # Approximate percentile indices for 100 measured samples.
    p95 = ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]

    return {
        "algorithm": ALGORITHM,
        "operation": operation,
        "iterations": len(samples),
        "mean_ms": mean,
        "median_ms": statistics.median(samples),
        "stdev_ms": sd,
        "p95_ms": p95,
        "min_ms": min(samples),
        "max_ms": max(samples),
        "ci95_low_ms": max(0.0, mean - half_width),
        "ci95_high_ms": mean + half_width,
        "sizes_bytes": sizes,
    }


def main():
    print("Layer 2 ML-DSA Benchmark")
    print(f"Algorithm: {ALGORITHM}")
    print(f"Measured runs: {RUNS}; warm-ups: {WARMUPS}")

    message = b"TAKEOFF ALTITUDE 10"

    with oqs.Signature(ALGORITHM) as signer:
        public_key = signer.generate_keypair()

        signing_samples, signature = measure(
            lambda: signer.sign(message)
        )

    with oqs.Signature(ALGORITHM) as verifier:

        def verify_once():
            if not verifier.verify(message, signature, public_key):
                raise RuntimeError("ML-DSA signature verification failed")
            return True

        verification_samples, _ = measure(verify_once)

    sizes = f"public_key={len(public_key)};signature={len(signature)}"

    rows = [
        summarize("signing", signing_samples, sizes),
        summarize("verification", verification_samples, sizes),
    ]

    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    for row in rows:
        print(f"\nOperation: {row['operation']}")
        print(f"  Mean:   {row['mean_ms']:.6f} ms")
        print(f"  Median: {row['median_ms']:.6f} ms")
        print(f"  Std dev:{row['stdev_ms']:.6f} ms")
        print(f"  P95:    {row['p95_ms']:.6f} ms")
        print(f"  Min:    {row['min_ms']:.6f} ms")
        print(f"  Max:    {row['max_ms']:.6f} ms")
        print(
            f"  Approx. 95% CI for mean: "
            f"[{row['ci95_low_ms']:.6f}, "
            f"{row['ci95_high_ms']:.6f}] ms"
        )

    print(f"\nPublic key size: {len(public_key)} bytes")
    print(f"Signature size: {len(signature)} bytes")
    print(f"CSV saved to: {OUTPUT}")
    print("All measured signatures verified successfully.")


if __name__ == "__main__":
    main()