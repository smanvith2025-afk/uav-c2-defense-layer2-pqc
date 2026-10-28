"""Comprehensive Layer 2 Protocol & Cryptographic Benchmark Suite (v2).

Preserves original primitive CSV files (crypto_benchmark_results.csv and
ml_dsa_benchmark_results.csv) while generating comprehensive protocol-level,
serialization-level, and primitive-level measurements in:
  - results/<timestamp>/raw_benchmark_samples.csv
  - results/<timestamp>/benchmark_environment.json
  - results/<timestamp>/layer2_protocol_benchmark_results.csv
  - results/<timestamp>/layer2_message_overhead_results.csv
  - results/<timestamp>/layer2_protocol_e2e_benchmark.png
and synchronizing the top-level v2 summary artifacts:
  - layer2_protocol_benchmark_results.csv
  - layer2_message_overhead_results.csv
  - layer2_protocol_e2e_benchmark.png

Statistical methodology:
  - High-resolution timer: time.perf_counter_ns()
  - Warm-up iterations: 10 (excluded from statistics)
  - Measured iterations: 100 per operation
  - Reports mean, median, sample standard deviation, interquartile range (IQR),
    P95, P99, min, max, normal-approximation 95% CI, and non-parametric
    bootstrap 95% CI (2,000 resamples, seed=42) to avoid misleading normal
    approximations on right-skewed latency distributions (such as rejection-
    sampling loops in ML-DSA-65 signing).
  - Measures JSON serialization and binary header framing directly rather than
    inferring serialization latency by subtracting primitive means from E2E means.
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import oqs
import cryptography

from protocol import PROTOCOL_VERSION, __version__
from protocol.constants import (
    AES_NONCE_BYTES,
    AES_TAG_BYTES,
    HEADER_SIZE,
    KEM_ALGORITHM,
    MSG_TYPE_COMMAND,
    MSG_TYPE_HANDSHAKE_INIT,
    ROLE_GROUND_STATION,
    ROLE_UAV,
    SIG_ALGORITHM,
)
from protocol.crypto_core import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    kem_decapsulate,
    kem_encapsulate,
    kem_generate_keypair,
    sig_generate_keypair,
    sig_sign,
    sig_verify,
)
from protocol.identity import TrustStore
from protocol.messages import CommandPayload, HandshakePayload, MessageHeader
from protocol.receiver import Receiver
from protocol.sender import Sender
from protocol.session import SessionKeys, derive_epoch_root_secret
from protocol.transport import LocalTransport

BASE_DIR = Path(__file__).resolve().parent
RESULTS_ROOT = BASE_DIR / "results"
BENCHMARK_CSV = BASE_DIR / "layer2_protocol_benchmark_results.csv"
OVERHEAD_CSV = BASE_DIR / "layer2_message_overhead_results.csv"
E2E_GRAPH_PNG = BASE_DIR / "layer2_protocol_e2e_benchmark.png"

RUNS = 100
WARMUPS = 10
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 42

CSV_FIELDS = [
    "category",
    "algorithm",
    "operation",
    "iterations",
    "mean_ms",
    "median_ms",
    "stdev_ms",
    "iqr_ms",
    "p95_ms",
    "p99_ms",
    "min_ms",
    "max_ms",
    "ci95_norm_low_ms",
    "ci95_norm_high_ms",
    "ci95_boot_low_ms",
    "ci95_boot_high_ms",
    "sizes_bytes",
]

RAW_CSV_FIELDS = [
    "category",
    "algorithm",
    "operation",
    "iteration",
    "latency_ms",
]


def bootstrap_ci95_mean(samples: list[float], rng: random.Random) -> tuple[float, float]:
    """Compute non-parametric percentile bootstrap 95% CI for the mean."""
    n = len(samples)
    boot_means = sorted(
        sum(rng.choices(samples, k=n)) / n for _ in range(BOOTSTRAP_RESAMPLES)
    )
    low_idx = int(0.025 * BOOTSTRAP_RESAMPLES)
    high_idx = int(0.975 * BOOTSTRAP_RESAMPLES)
    return boot_means[low_idx], boot_means[high_idx]


def summarize(
    category: str,
    algorithm: str,
    operation: str,
    samples: list[float],
    raw_rows: list[dict],
    sizes: str = "",
) -> dict:
    """Record raw samples and compute parametric and non-parametric summary statistics."""
    for idx, val in enumerate(samples, start=1):
        raw_rows.append(
            {
                "category": category,
                "algorithm": algorithm,
                "operation": operation,
                "iteration": idx,
                "latency_ms": val,
            }
        )

    ordered = sorted(samples)
    n = len(ordered)
    mean = statistics.mean(ordered)
    median = statistics.median(ordered)
    sd = statistics.stdev(ordered) if n > 1 else 0.0
    q25 = ordered[int(0.25 * n)]
    q75 = ordered[int(0.75 * n)]
    iqr = q75 - q25
    p95 = ordered[min(n - 1, int(0.95 * n))]
    p99 = ordered[min(n - 1, int(0.99 * n))]

    half_width = 1.96 * sd / (n ** 0.5)
    rng = random.Random(BOOTSTRAP_SEED)
    boot_low, boot_high = bootstrap_ci95_mean(ordered, rng)

    return {
        "category": category,
        "algorithm": algorithm,
        "operation": operation,
        "iterations": n,
        "mean_ms": mean,
        "median_ms": median,
        "stdev_ms": sd,
        "iqr_ms": iqr,
        "p95_ms": p95,
        "p99_ms": p99,
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
        "ci95_norm_low_ms": max(0.0, mean - half_width),
        "ci95_norm_high_ms": mean + half_width,
        "ci95_boot_low_ms": boot_low,
        "ci95_boot_high_ms": boot_high,
        "sizes_bytes": sizes,
    }


def benchmark_primitives(raw_rows: list[dict]) -> list[dict]:
    """Benchmark individual cryptographic primitives and direct serialization/framing."""
    rows: list[dict] = []

    # 1. ML-KEM-768 keygen, encap, decap
    kem_keygen, kem_encap, kem_decap = [], [], []
    pk_len = ct_len = ss_len = 0
    for i in range(WARMUPS + RUNS):
        t0 = time.perf_counter_ns()
        kp = kem_generate_keypair()
        t1 = time.perf_counter_ns()
        enc = kem_encapsulate(kp.public_key)
        t2 = time.perf_counter_ns()
        ss = kem_decapsulate(enc.ciphertext, kp.secret_key)
        t3 = time.perf_counter_ns()
        if ss != enc.shared_secret:
            raise RuntimeError("ML-KEM shared secret mismatch")
        if i >= WARMUPS:
            kem_keygen.append((t1 - t0) / 1_000_000)
            kem_encap.append((t2 - t1) / 1_000_000)
            kem_decap.append((t3 - t2) / 1_000_000)
        pk_len, ct_len, ss_len = len(kp.public_key), len(enc.ciphertext), len(ss)

    kem_sizes = f"public_key={pk_len};ciphertext={ct_len};shared_secret={ss_len}"
    rows.append(summarize("Primitive", KEM_ALGORITHM, "kem_key_generation", kem_keygen, raw_rows, kem_sizes))
    rows.append(summarize("Primitive", KEM_ALGORITHM, "kem_encapsulation", kem_encap, raw_rows, kem_sizes))
    rows.append(summarize("Primitive", KEM_ALGORITHM, "kem_decapsulation", kem_decap, raw_rows, kem_sizes))

    # 2. ML-DSA-65 keygen, sign, verify
    dsa_keygen, dsa_sign, dsa_verify = [], [], []
    msg = b"TAKEOFF ALTITUDE 10"
    dsa_pk_len = dsa_sig_len = 0
    for i in range(WARMUPS + RUNS):
        t0 = time.perf_counter_ns()
        skp = sig_generate_keypair()
        t1 = time.perf_counter_ns()
        sig = sig_sign(msg, skp.secret_key)
        t2 = time.perf_counter_ns()
        ok = sig_verify(msg, sig, skp.public_key)
        t3 = time.perf_counter_ns()
        if not ok:
            raise RuntimeError("ML-DSA signature verification failed")
        if i >= WARMUPS:
            dsa_keygen.append((t1 - t0) / 1_000_000)
            dsa_sign.append((t2 - t1) / 1_000_000)
            dsa_verify.append((t3 - t2) / 1_000_000)
        dsa_pk_len, dsa_sig_len = len(skp.public_key), len(sig)

    dsa_sizes = f"public_key={dsa_pk_len};signature={dsa_sig_len};message={len(msg)}"
    rows.append(summarize("Primitive", SIG_ALGORITHM, "dsa_key_generation", dsa_keygen, raw_rows, dsa_sizes))
    rows.append(summarize("Primitive", SIG_ALGORITHM, "dsa_signing", dsa_sign, raw_rows, dsa_sizes))
    rows.append(summarize("Primitive", SIG_ALGORITHM, "dsa_verification", dsa_verify, raw_rows, dsa_sizes))

    # 3. Two-stage HKDF-SHA-256 v2 session key schedule (root secret + directional keys & nonce prefixes)
    hkdf_samples = []
    dummy_secret = os.urandom(32)
    dummy_sid = os.urandom(16)
    dummy_transcript_hash = hashlib.sha256(os.urandom(64)).digest()
    for i in range(WARMUPS + RUNS):
        t0 = time.perf_counter_ns()
        root, _ = derive_epoch_root_secret(
            kem_shared_secret=dummy_secret,
            session_id=dummy_sid,
            epoch=0,
            transcript_hash=dummy_transcript_hash,
            initiator_id="gs1",
            responder_id="uav1",
        )
        _ = SessionKeys.from_root_secret(
            root_secret=root,
            session_id=dummy_sid,
            epoch=0,
            transcript_hash=dummy_transcript_hash,
            initiator_id="gs1",
            responder_id="uav1",
        )
        t1 = time.perf_counter_ns()
        if i >= WARMUPS:
            hkdf_samples.append((t1 - t0) / 1_000_000)
    rows.append(
        summarize(
            "Primitive",
            "HKDF-SHA-256",
            "session_key_derivation",
            hkdf_samples,
            raw_rows,
            "ikm=32;stage1=32B_root+32B_confirm;stage2=2x32B_keys+2x4B_prefixes",
        )
    )

    # 4. AES-256-GCM encryption & decryption (19B command and signed CommandPayload)
    aes_key = os.urandom(32)
    aad = os.urandom(HEADER_SIZE)
    sample_cmd_payload = CommandPayload(
        sender_id="gs1",
        recipient_id="uav1",
        command="TAKEOFF",
        params="ALTITUDE 10",
        timestamp=1700000000.123456,
        signature=os.urandom(3309),
    ).to_json_bytes()
    for label, payload_bytes in [
        ("aes_encrypt_19B", b"TAKEOFF ALTITUDE 10"),
        ("aes_encrypt_signed_payload", sample_cmd_payload),
    ]:
        enc_samples, dec_samples = [], []
        for i in range(WARMUPS + RUNS):
            nonce = os.urandom(AES_NONCE_BYTES)
            t0 = time.perf_counter_ns()
            _, ct = aes_gcm_encrypt(aes_key, payload_bytes, aad, nonce=nonce)
            t1 = time.perf_counter_ns()
            pt = aes_gcm_decrypt(aes_key, nonce, ct, aad)
            t2 = time.perf_counter_ns()
            if pt != payload_bytes:
                raise RuntimeError("AES-GCM mismatch")
            if i >= WARMUPS:
                enc_samples.append((t1 - t0) / 1_000_000)
                dec_samples.append((t2 - t1) / 1_000_000)
        sz = f"plaintext={len(payload_bytes)};aad={HEADER_SIZE};nonce=12;tag=16"
        dec_label = label.replace("encrypt", "decrypt")
        rows.append(summarize("Primitive", "AES-256-GCM", label, enc_samples, raw_rows, sz))
        rows.append(summarize("Primitive", "AES-256-GCM", dec_label, dec_samples, raw_rows, sz))

    # 5. Direct measurement of JSON serialization + binary header framing (Command & Handshake)
    cmd_ser_samples, cmd_deser_samples = [], []
    dummy_sig = os.urandom(3309)
    dummy_sid = os.urandom(16)
    cmd_wire_len = 0
    for i in range(WARMUPS + RUNS):
        t0 = time.perf_counter_ns()
        cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="TAKEOFF",
            params="ALTITUDE 10",
            timestamp=1700000000.123456,
            signature=dummy_sig,
        )
        _ = cp.canonical_bytes_for_signing(dummy_sid, i + 1)
        cp_bytes = cp.to_json_bytes()
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=dummy_sid,
            sequence=i + 1,
        )
        hdr_bytes = hdr.to_bytes()
        t1 = time.perf_counter_ns()
        parsed_hdr = MessageHeader.from_bytes(hdr_bytes)
        parsed_cp = CommandPayload.from_json_bytes(cp_bytes)
        _ = parsed_cp.canonical_bytes_for_signing(parsed_hdr.session_id, parsed_hdr.sequence)
        t2 = time.perf_counter_ns()
        if parsed_hdr.sequence != i + 1 or parsed_cp.command != "TAKEOFF":
            raise RuntimeError("Command serialization validation failed")
        if i >= WARMUPS:
            cmd_ser_samples.append((t1 - t0) / 1_000_000)
            cmd_deser_samples.append((t2 - t1) / 1_000_000)
        cmd_wire_len = len(hdr_bytes) + len(cp_bytes)

    rows.append(
        summarize(
            "Serialization",
            "JSON+Struct",
            "command_serialize_and_frame",
            cmd_ser_samples,
            raw_rows,
            f"header={HEADER_SIZE};json_payload={cmd_wire_len - HEADER_SIZE}",
        )
    )
    rows.append(
        summarize(
            "Serialization",
            "JSON+Struct",
            "command_parse_and_unframe",
            cmd_deser_samples,
            raw_rows,
            f"header={HEADER_SIZE};json_payload={cmd_wire_len - HEADER_SIZE}",
        )
    )

    hs_ser_samples = []
    dummy_pk = os.urandom(1952)
    dummy_kem_pk = os.urandom(1184)
    dummy_hs_nonce = os.urandom(16)
    hs_wire_len = 0
    for i in range(WARMUPS + RUNS):
        t0 = time.perf_counter_ns()
        hp = HandshakePayload(
            sender_id="gs1",
            sender_role=ROLE_GROUND_STATION,
            sender_signing_key=dummy_pk,
            sender_kem_key=dummy_kem_pk,
            kem_ciphertext=b"",
            signature=dummy_sig,
            recipient_id="uav1",
            timestamp=1700000000.123456,
            handshake_nonce=dummy_hs_nonce,
        )
        _ = hp.canonical_bytes_for_signing(dummy_sid)
        hp_bytes = hp.to_json_bytes()
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_HANDSHAKE_INIT,
            session_id=dummy_sid,
            sequence=0,
        )
        hdr_bytes = hdr.to_bytes()
        _ = MessageHeader.from_bytes(hdr_bytes)
        parsed_hp = HandshakePayload.from_json_bytes(hp_bytes)
        _ = parsed_hp.canonical_bytes_for_signing(dummy_sid)
        t1 = time.perf_counter_ns()
        if i >= WARMUPS:
            hs_ser_samples.append((t1 - t0) / 1_000_000)
        hs_wire_len = len(hdr_bytes) + len(hp_bytes)

    rows.append(
        summarize(
            "Serialization",
            "JSON+Struct",
            "handshake_serialize_and_parse",
            hs_ser_samples,
            raw_rows,
            f"header={HEADER_SIZE};json_payload={hs_wire_len - HEADER_SIZE}",
        )
    )

    return rows


def benchmark_protocol_e2e(raw_rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Benchmark end-to-end Layer 2 v2 protocol operations and record byte overheads."""
    rows: list[dict] = []
    overhead_rows: list[dict] = []

    gs_keys = sig_generate_keypair()
    uav_keys = sig_generate_keypair()
    trust = TrustStore()
    trust.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
    trust.register_peer("uav1", ROLE_UAV, uav_keys.public_key)

    # 1. Full 3-message authenticated handshake
    hs_samples = []
    init_len = resp_len = conf_len = 0
    for i in range(WARMUPS + RUNS):
        tx_gs, tx_uav = LocalTransport.create_pair()
        sender = Sender("gs1", gs_keys, trust, tx_gs)
        receiver = Receiver("uav1", uav_keys, trust, tx_uav)

        t0 = time.perf_counter_ns()
        init_pkt = sender.initiate_handshake("uav1")
        resp_pkt = receiver.process_handshake_init(tx_uav.receive())
        sender.process_handshake_response(tx_gs.receive())
        conf_pkt = tx_uav.receive()
        receiver.process_handshake_confirm(conf_pkt)
        t1 = time.perf_counter_ns()

        if i >= WARMUPS:
            hs_samples.append((t1 - t0) / 1_000_000)
        init_len, resp_len, conf_len = len(init_pkt), len(resp_pkt), len(conf_pkt)

    hs_total_len = init_len + resp_len + conf_len
    hs_sizes = f"init={init_len};response={resp_len};confirm={conf_len};total={hs_total_len}"
    rows.append(
        summarize(
            "Protocol_E2E",
            "Layer2-Handshake",
            "full_authenticated_handshake",
            hs_samples,
            raw_rows,
            hs_sizes,
        )
    )

    # Establish one session for command and rekey benchmarks
    tx_gs, tx_uav = LocalTransport.create_pair()
    sender = Sender("gs1", gs_keys, trust, tx_gs)
    receiver = Receiver("uav1", uav_keys, trust, tx_uav)
    sender.initiate_handshake("uav1")
    receiver.process_handshake_init(tx_uav.receive())
    sender.process_handshake_response(tx_gs.receive())
    receiver.process_handshake_confirm(tx_uav.receive())

    # 2. Protected command send, receive, and full round-trip
    send_samples, recv_samples, rt_samples = [], [], []
    cmd_pkt_len = 0
    for i in range(WARMUPS + RUNS):
        t0 = time.perf_counter_ns()
        pkt = sender.send_command("TAKEOFF", "ALTITUDE 10")
        t1 = time.perf_counter_ns()
        raw_pkt = tx_uav.receive()
        ok, res = receiver.receive_packet(raw_pkt)
        t2 = time.perf_counter_ns()
        if not ok:
            raise RuntimeError(f"Command rejected during benchmark: {res}")
        if i >= WARMUPS:
            send_samples.append((t1 - t0) / 1_000_000)
            recv_samples.append((t2 - t1) / 1_000_000)
            rt_samples.append((t2 - t0) / 1_000_000)
        cmd_pkt_len = len(pkt)

    cmd_sizes = f"packet={cmd_pkt_len};header={HEADER_SIZE};nonce={AES_NONCE_BYTES};tag={AES_TAG_BYTES}"
    rows.append(summarize("Protocol_E2E", "Layer2-Command", "command_send_protect", send_samples, raw_rows, cmd_sizes))
    rows.append(summarize("Protocol_E2E", "Layer2-Command", "command_recv_validate", recv_samples, raw_rows, cmd_sizes))
    rows.append(summarize("Protocol_E2E", "Layer2-Command", "command_e2e_roundtrip", rt_samples, raw_rows, cmd_sizes))

    # 3. Session rekey latency (v2 ML-DSA-65 authenticated + root-secret chained + key-confirmed)
    rekey_samples = []
    rekey_req_len = rekey_resp_len = 0
    for i in range(WARMUPS + RUNS):
        t0 = time.perf_counter_ns()
        rk_pkt = sender.initiate_rekey()
        ok, res = receiver.receive_packet(tx_uav.receive())
        if not ok:
            raise RuntimeError(f"Rekey failed on receiver: {res}")
        rk_resp = tx_gs.receive()
        sender.complete_rekey(rk_resp)
        t1 = time.perf_counter_ns()
        if i >= WARMUPS:
            rekey_samples.append((t1 - t0) / 1_000_000)
        rekey_req_len, rekey_resp_len = len(rk_pkt), len(rk_resp)

    rk_sizes = f"rekey_init={rekey_req_len};rekey_resp={rekey_resp_len};total={rekey_req_len+rekey_resp_len}"
    rows.append(summarize("Protocol_E2E", "Layer2-Rekey", "session_rekey_e2e", rekey_samples, raw_rows, rk_sizes))

    # Measure terminate packet size
    term_pkt = sender.terminate_session()
    term_len = len(term_pkt) if term_pkt else 0

    overhead_rows = [
        {
            "message_type": "HANDSHAKE_INIT",
            "plaintext_command_bytes": 0,
            "header_bytes": HEADER_SIZE,
            "nonce_bytes": 0,
            "gcm_tag_bytes": 0,
            "crypto_payload_bytes": init_len - HEADER_SIZE,
            "total_wire_bytes": init_len,
            "description": "v2 header + JSON(v2 suite, sender_id, recipient_id, role, timestamp, 16B nonce, ML-DSA-65 pk [1952B hex], ML-KEM-768 pk [1184B hex], ML-DSA-65 sig [3309B hex])",
        },
        {
            "message_type": "HANDSHAKE_RESPONSE",
            "plaintext_command_bytes": 0,
            "header_bytes": HEADER_SIZE,
            "nonce_bytes": 0,
            "gcm_tag_bytes": 0,
            "crypto_payload_bytes": resp_len - HEADER_SIZE,
            "total_wire_bytes": resp_len,
            "description": "v2 header + JSON(v2 suite, sender_id, recipient_id, role, timestamp, 16B nonce, ML-DSA-65 pk [1952B hex], echoed ML-KEM-768 pk [1184B hex], ML-KEM-768 ct [1088B hex], ML-DSA-65 sig [3309B hex])",
        },
        {
            "message_type": "HANDSHAKE_CONFIRM",
            "plaintext_command_bytes": 0,
            "header_bytes": HEADER_SIZE,
            "nonce_bytes": AES_NONCE_BYTES,
            "gcm_tag_bytes": AES_TAG_BYTES,
            "crypto_payload_bytes": conf_len - HEADER_SIZE - AES_NONCE_BYTES - AES_TAG_BYTES,
            "total_wire_bytes": conf_len,
            "description": "v2 header (AAD) + 12B nonce + AES-256-GCM(length-framed transcript ML-DSA-65 sig [3309B]) + 16B tag",
        },
        {
            "message_type": "FULL_HANDSHAKE_3_MSG_TOTAL",
            "plaintext_command_bytes": 0,
            "header_bytes": HEADER_SIZE * 3,
            "nonce_bytes": AES_NONCE_BYTES,
            "gcm_tag_bytes": AES_TAG_BYTES,
            "crypto_payload_bytes": hs_total_len - (HEADER_SIZE * 3) - AES_NONCE_BYTES - AES_TAG_BYTES,
            "total_wire_bytes": hs_total_len,
            "description": "Aggregate wire bytes across HANDSHAKE_INIT + HANDSHAKE_RESPONSE + HANDSHAKE_CONFIRM",
        },
        {
            "message_type": "COMMAND (TAKEOFF ALTITUDE 10)",
            "plaintext_command_bytes": len(b"TAKEOFF ALTITUDE 10"),
            "header_bytes": HEADER_SIZE,
            "nonce_bytes": AES_NONCE_BYTES,
            "gcm_tag_bytes": AES_TAG_BYTES,
            "crypto_payload_bytes": cmd_pkt_len - HEADER_SIZE - AES_NONCE_BYTES - AES_TAG_BYTES,
            "total_wire_bytes": cmd_pkt_len,
            "description": "v2 header (AAD) + 12B nonce + AES-256-GCM(JSON whitelisted command + metadata + ML-DSA-65 sig [3309B hex]) + 16B tag",
        },
        {
            "message_type": "REKEY_INIT",
            "plaintext_command_bytes": 0,
            "header_bytes": HEADER_SIZE,
            "nonce_bytes": AES_NONCE_BYTES,
            "gcm_tag_bytes": AES_TAG_BYTES,
            "crypto_payload_bytes": rekey_req_len - HEADER_SIZE - AES_NONCE_BYTES - AES_TAG_BYTES,
            "total_wire_bytes": rekey_req_len,
            "description": "v2 header (AAD) + 12B nonce + AES-256-GCM(JSON RekeyPayload: epochs, 16B nonce, ML-KEM-768 pk [1184B hex], ML-DSA-65 sig [3309B hex]) + 16B tag",
        },
        {
            "message_type": "REKEY_RESPONSE",
            "plaintext_command_bytes": 0,
            "header_bytes": HEADER_SIZE,
            "nonce_bytes": AES_NONCE_BYTES,
            "gcm_tag_bytes": AES_TAG_BYTES,
            "crypto_payload_bytes": rekey_resp_len - HEADER_SIZE - AES_NONCE_BYTES - AES_TAG_BYTES,
            "total_wire_bytes": rekey_resp_len,
            "description": "v2 header (AAD) + 12B nonce + AES-256-GCM(JSON RekeyPayload: epochs, echoed ML-KEM-768 pk, ML-KEM-768 ct [1088B hex], 32B HMAC confirm tag, ML-DSA-65 sig [3309B hex]) + 16B tag",
        },
        {
            "message_type": "TERMINATE",
            "plaintext_command_bytes": len(b"TERMINATE"),
            "header_bytes": HEADER_SIZE,
            "nonce_bytes": AES_NONCE_BYTES,
            "gcm_tag_bytes": AES_TAG_BYTES,
            "crypto_payload_bytes": term_len - HEADER_SIZE - AES_NONCE_BYTES - AES_TAG_BYTES,
            "total_wire_bytes": term_len,
            "description": "v2 header (AAD) + 12B nonce + AES-256-GCM(JSON TerminatePayload: sender_id, epoch, timestamp, reason, ML-DSA-65 sig [3309B hex]) + 16B tag",
        },
    ]

    return rows, overhead_rows


def plot_e2e_benchmark(rows: list[dict], overhead_rows: list[dict], out_png: Path) -> None:
    """Generate a two-panel publication-quality figure from validated CSV data."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15.5, 6.8))

    # Panel A: Latency comparison (log scale)
    display_map = {
        "kem_key_generation": "ML-KEM-768\nKeygen",
        "kem_encapsulation": "ML-KEM-768\nEncap",
        "kem_decapsulation": "ML-KEM-768\nDecap",
        "dsa_key_generation": "ML-DSA-65\nKeygen",
        "dsa_signing": "ML-DSA-65\nSign",
        "dsa_verification": "ML-DSA-65\nVerify",
        "session_key_derivation": "HKDF-SHA256\n2-Stage KDF",
        "aes_encrypt_signed_payload": "AES-256-GCM\nEnc (6.7KB)",
        "aes_decrypt_signed_payload": "AES-256-GCM\nDec (6.7KB)",
        "command_serialize_and_frame": "Command\nSerialize+Frame",
        "command_parse_and_unframe": "Command\nParse+Unframe",
        "full_authenticated_handshake": "Full 3-Msg\nHandshake",
        "command_send_protect": "Command\nSend (Sign+Enc)",
        "command_recv_validate": "Command\nRecv (Dec+Ver)",
        "command_e2e_roundtrip": "Command\nFull Roundtrip",
        "session_rekey_e2e": "Session\nRekey E2E (v2)",
    }

    selected = [r for r in rows if r["operation"] in display_map]
    labels = [display_map[r["operation"]] for r in selected]
    means = [float(r["mean_ms"]) for r in selected]
    medians = [float(r["median_ms"]) for r in selected]
    sds = [float(r["stdev_ms"]) for r in selected]

    color_map = {
        "Primitive": "#2b5c8f",
        "Serialization": "#2a9d8f",
        "Protocol_E2E": "#b84a39",
    }
    colors = [color_map.get(r["category"], "#2b5c8f") for r in selected]

    lower_err = [m - max(m - s, m * 0.08) for m, s in zip(means, sds)]
    upper_err = sds

    x = list(range(len(labels)))
    ax1.bar(
        x,
        means,
        yerr=[lower_err, upper_err],
        capsize=3.5,
        color=colors,
        alpha=0.88,
        error_kw={"elinewidth": 1.1, "ecolor": "#222222"},
    )
    ax1.scatter(x, medians, color="#ffd166", edgecolor="black", zorder=5, s=36, label="Median latency")
    ax1.set_yscale("log")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=40, ha="right", fontsize=8.0)
    ax1.set_ylabel("Execution Time (ms, logarithmic scale)", fontsize=10)
    ax1.set_title("(a) Primitive, Serialization & Protocol Latency (n = 100)", fontsize=11, fontweight="bold")
    ax1.grid(axis="y", which="both", linestyle="--", alpha=0.4)
    ax1.set_axisbelow(True)

    for pos, mean_val in zip(x, means):
        ax1.annotate(
            f"{mean_val:.3g}",
            (pos, mean_val),
            xytext=(0, 7),
            textcoords="offset points",
            ha="center",
            fontsize=7.2,
        )

    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    legend_items = [
        Patch(facecolor="#2b5c8f", alpha=0.88, label="Cryptographic Primitive"),
        Patch(facecolor="#2a9d8f", alpha=0.88, label="Direct Serialization / Framing"),
        Patch(facecolor="#b84a39", alpha=0.88, label="End-to-End Protocol Operation"),
        Line2D([0], [0], marker="o", color="w", label="Median Latency", markerfacecolor="#ffd166", markeredgecolor="black", markersize=7),
    ]
    ax1.legend(handles=legend_items, loc="upper left", fontsize=8.0)

    # Panel B: Wire size breakdown by message type
    msg_labels = [
        r["message_type"]
        .replace(" (TAKEOFF ALTITUDE 10)", "\n(TAKEOFF)")
        .replace("FULL_HANDSHAKE_3_MSG_TOTAL", "FULL HANDSHAKE\n(3-Msg Total)")
        for r in overhead_rows
    ]
    total_bytes = [int(r["total_wire_bytes"]) for r in overhead_rows]
    y_pos = list(range(len(msg_labels)))

    bar_colors = [
        "#1d3557" if r["message_type"] == "FULL_HANDSHAKE_3_MSG_TOTAL" else "#3a7ca5"
        for r in overhead_rows
    ]
    ax2.barh(y_pos, total_bytes, color=bar_colors, alpha=0.88, edgecolor="#1d3557")
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(msg_labels, fontsize=8.5)
    ax2.invert_yaxis()
    ax2.set_xlabel("Total Wire Packet Size (bytes)", fontsize=10)
    ax2.set_title("(b) Protocol v2 Wire Overhead by Message Type", fontsize=11, fontweight="bold")
    ax2.grid(axis="x", linestyle="--", alpha=0.4)
    ax2.set_axisbelow(True)

    max_b = max(total_bytes)
    ax2.set_xlim(0, max_b * 1.18)
    for idx, b_val in enumerate(total_bytes):
        ax2.annotate(
            f"{b_val:,} B",
            (b_val, idx),
            xytext=(5, 0),
            textcoords="offset points",
            va="center",
            fontsize=8.5,
            fontweight="bold",
        )

    fig.suptitle(
        f"UAV-C2-PQ-L2 v{__version__} Post-Quantum Command Security Protocol (ML-KEM-768 + ML-DSA-65 + AES-256-GCM)",
        fontsize=12.0,
        fontweight="bold",
        y=0.98,
    )
    fig.text(
        0.5,
        0.01,
        f"Environment: Python {sys.version.split()[0]}, liboqs {oqs.oqs_version()}, cryptography {cryptography.__version__}, {platform.system()}-{platform.release()} ({os.cpu_count()} logical CPUs). Bars show mean ± 1 SD; yellow dots show median.",
        ha="center",
        fontsize=8.5,
    )
    fig.tight_layout(rect=(0, 0.035, 1, 0.94))
    fig.savefig(out_png, dpi=300, bbox_inches="tight")
    plt.close(fig)


def compute_source_hashes() -> dict[str, str]:
    """Compute SHA-256 hashes of all protocol source files and benchmark script."""
    hashes: dict[str, str] = {}
    files = sorted((BASE_DIR / "protocol").glob("*.py")) + [
        BASE_DIR / "test_protocol.py",
        BASE_DIR / "layer2_protocol_benchmark.py",
    ]
    for path in files:
        if path.exists():
            rel = path.relative_to(BASE_DIR).as_posix()
            hashes[rel] = hashlib.sha256(path.read_bytes()).hexdigest().upper()
    return hashes


def main() -> None:
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    timestamp_label = now_utc.strftime("%Y-%m-%dT%H%M%SZ")
    run_dir = RESULTS_ROOT / timestamp_label
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"Layer 2 v{__version__} Comprehensive Protocol & Primitive Benchmark")
    print("=" * 64)
    print(f"Timestamp:    {timestamp_label}")
    print(f"Output dir:   {run_dir}")
    print(f"Python:       {sys.version.split()[0]}")
    print(f"Platform:     {platform.platform()}")
    print(f"Processor:    {platform.processor()} ({os.cpu_count()} logical CPUs)")
    print(f"liboqs:       {oqs.oqs_version()}")
    print(f"cryptography: {cryptography.__version__}")
    print(f"Runs:         {RUNS} measured, {WARMUPS} warm-ups (bootstrap resamples={BOOTSTRAP_RESAMPLES}, seed={BOOTSTRAP_SEED})")
    print()

    raw_rows: list[dict] = []
    prim_rows = benchmark_primitives(raw_rows)
    e2e_rows, overhead_rows = benchmark_protocol_e2e(raw_rows)
    all_rows = prim_rows + e2e_rows

    run_bench_csv = run_dir / "layer2_protocol_benchmark_results.csv"
    run_overhead_csv = run_dir / "layer2_message_overhead_results.csv"
    run_raw_csv = run_dir / "raw_benchmark_samples.csv"
    run_env_json = run_dir / "benchmark_environment.json"
    run_png = run_dir / "layer2_protocol_e2e_benchmark.png"

    with run_bench_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(all_rows)

    with run_overhead_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(overhead_rows[0].keys()))
        writer.writeheader()
        writer.writerows(overhead_rows)

    with run_raw_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=RAW_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(raw_rows)

    env_metadata = {
        "protocol_version": PROTOCOL_VERSION,
        "package_version": __version__,
        "timestamp_utc": now_utc.isoformat(),
        "timestamp_dir": timestamp_label,
        "command": f"{sys.executable} {Path(__file__).name}",
        "python_version": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "liboqs_version": oqs.oqs_version(),
        "cryptography_version": cryptography.__version__,
        "timer": "time.perf_counter_ns()",
        "warmups": WARMUPS,
        "measured_iterations": RUNS,
        "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "source_sha256": compute_source_hashes(),
    }
    run_env_json.write_text(json.dumps(env_metadata, indent=2), encoding="utf-8")

    plot_e2e_benchmark(all_rows, overhead_rows, run_png)

    # Copy exact artifacts from this timestamped run to the top-level v2 workspace
    shutil.copy2(run_bench_csv, BENCHMARK_CSV)
    shutil.copy2(run_overhead_csv, OVERHEAD_CSV)
    shutil.copy2(run_png, E2E_GRAPH_PNG)

    for row in all_rows:
        print(
            f"[{row['category']}] {row['algorithm']} / {row['operation']}: "
            f"mean={row['mean_ms']:.4f} ms, median={row['median_ms']:.4f} ms, "
            f"sd={row['stdev_ms']:.4f} ms, iqr={row['iqr_ms']:.4f} ms, "
            f"p95={row['p95_ms']:.4f} ms, p99={row['p99_ms']:.4f} ms, "
            f"boot95=[{row['ci95_boot_low_ms']:.4f}, {row['ci95_boot_high_ms']:.4f}] ms"
        )

    print()
    print(f"Saved timestamped run directory: {run_dir}")
    print(f"Saved raw samples CSV:           {run_raw_csv}")
    print(f"Saved environment JSON:          {run_env_json}")
    print(f"Saved benchmark CSV:             {BENCHMARK_CSV}")
    print(f"Saved overhead CSV:              {OVERHEAD_CSV}")
    print(f"Saved E2E figure:                {E2E_GRAPH_PNG}")


if __name__ == "__main__":
    main()
