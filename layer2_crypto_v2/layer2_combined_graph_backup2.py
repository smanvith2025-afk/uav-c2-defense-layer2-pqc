
import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent
CRYPTO_CSV = BASE / "crypto_benchmark_results.csv"
MLDSA_CSV = BASE / "ml_dsa_benchmark_results.csv"
OUTPUT = BASE / "layer2_combined_performance.png"


def read_rows(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Missing {path.name}. Run the corresponding benchmark first."
        )
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    rows = read_rows(CRYPTO_CSV) + read_rows(MLDSA_CSV)

    labels = []
    values = []

    display_names = {
        "key_generation": "ML-KEM Keygen",
        "encapsulation": "ML-KEM Encap",
        "decapsulation": "ML-KEM Decap",
        "signing": "ML-DSA Sign",
        "verification": "ML-DSA Verify",
        "encryption": "AES-GCM Encrypt",
        "decryption": "AES-GCM Decrypt",
    }

    for row in rows:
        operation = row["operation"]
        labels.append(display_names.get(operation, operation))
        values.append(float(row["mean_ms"]))

    if any(value <= 0 for value in values):
        raise ValueError("All measured times must be positive for log-scale plotting.")

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(labels, values)

    ax.set_yscale("log")
    ax.set_title("Layer 2 Cryptographic Performance")
    ax.set_xlabel("Cryptographic operation")
    ax.set_ylabel("Mean execution time (ms, logarithmic scale)")
    ax.tick_params(axis="x", rotation=25)
    ax.grid(axis="y", which="both", linestyle="--", alpha=0.4)

    for bar, value in zip(bars, values):
        ax.annotate(
            f"{value:.4g}",
            (bar.get_x() + bar.get_width() / 2, value),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center",
            fontsize=8,
        )

    fig.tight_layout()
    fig.savefig(OUTPUT, dpi=300)
    plt.close(fig)

    print(f"Graph saved to: {OUTPUT}")
    print("Times were read from the benchmark CSV files.")


if __name__ == "__main__":
    main()
