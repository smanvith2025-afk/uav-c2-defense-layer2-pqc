
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

    with path.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def main():
    rows = read_rows(CRYPTO_CSV) + read_rows(MLDSA_CSV)

    display_names = {
        "key_generation": "ML-KEM Keygen",
        "encapsulation": "ML-KEM Encap",
        "decapsulation": "ML-KEM Decap",
        "signing": "ML-DSA Sign",
        "verification": "ML-DSA Verify",
        "encryption": "AES-GCM Encrypt",
        "decryption": "AES-GCM Decrypt",
    }

    labels = []
    means = []
    lower_errors = []
    upper_errors = []

    for row in rows:
        operation = row["operation"]
        mean = float(row["mean_ms"])
        sd = float(row["stdev_ms"])

        if mean <= 0 or sd < 0:
            raise ValueError(
                f"Invalid timing data for operation: {operation}"
            )

        labels.append(display_names.get(operation, operation))
        means.append(mean)

        # Keep the lower error bar positive for the logarithmic axis.
        lower_bound = max(mean - sd, mean * 0.05)
        upper_bound = mean + sd

        lower_errors.append(mean - lower_bound)
        upper_errors.append(upper_bound - mean)

    if not rows:
        raise ValueError("No benchmark results were found in the CSV files.")

    fig, ax = plt.subplots(figsize=(12, 7))

    positions = list(range(len(labels)))
    ax.bar(
        positions,
        means,
        yerr=[lower_errors, upper_errors],
        capsize=4,
        error_kw={"elinewidth": 1.2},
    )

    ax.set_yscale("log")
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.set_title("Layer 2 Cryptographic Performance")
    ax.set_xlabel("Cryptographic operation")
    ax.set_ylabel("Mean execution time (ms, logarithmic scale)")
    ax.grid(axis="y", which="both", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)

    for position, mean in zip(positions, means):
        ax.annotate(
            f"{mean:.4g} ms",
            (position, mean),
            xytext=(0, 8),
            textcoords="offset points",
            ha="center",
            fontsize=8,
        )

    fig.text(
        0.5,
        0.015,
        "Bars show mean latency; error bars show ±1 standard deviation.",
        ha="center",
        fontsize=9,
    )

    fig.tight_layout(rect=(0, 0.045, 1, 1))
    fig.savefig(OUTPUT, dpi=300, bbox_inches="tight")
    plt.close(fig)

    print(f"Graph saved to: {OUTPUT}")
    print("Source: crypto_benchmark_results.csv and ml_dsa_benchmark_results.csv")
    print("Bars: mean execution time; error bars: +/- 1 standard deviation.")


if __name__ == "__main__":
    main()
