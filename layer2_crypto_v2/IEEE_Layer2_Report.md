# Design, Implementation, and Empirical Evaluation of a Layer 2 Post-Quantum Cryptographic Protocol for UAV Command-and-Control Security

**Abstract**—Unmanned Aerial Vehicle (UAV) command-and-control (C2) links require low-latency message authentication, confidentiality, and replay resistance against active adversaries. While classical public-key schemes such as RSA and Elliptic Curve Cryptography (ECDH/ECDSA) are vulnerable to Shor's algorithm on future Cryptographically Relevant Quantum Computers (CRQCs), transitioning to NIST-standardized post-quantum cryptography introduces larger public keys, ciphertexts, and signatures alongside rejection-sampling latency variance. In this work, we design, implement, and empirically evaluate a complete Layer 2 post-quantum UAV command security protocol (`UAV-C2-PQ-L2 v1`) combining Module-Lattice-Based Key-Encapsulation (`ML-KEM-768`, FIPS 203), Module-Lattice-Based Digital Signatures (`ML-DSA-65`, FIPS 204), context-bound key derivation (`HKDF-SHA-256`, RFC 5869), and authenticated encryption with associated data (`AES-256-GCM`, NIST SP 800-38D). Our protocol prevents public-key substitution via an explicit trust store, binds handshake transcripts and per-command signatures to session and sequence contexts, enforces deterministic 96-bit nonces with explicit reuse detection, and implements a fail-closed 8-stage receiver validation pipeline. Across 120 automated positive, negative, and fuzz security tests and 100-iteration high-resolution benchmarks on an x86-64 Windows 11 testbed, the full 3-message authenticated handshake completes in a mean of `9.5152 ms` (median `8.9811 ms`), and end-to-end protected command processing (`Sign + Encrypt + Decrypt + Verify + Replay Check`) requires a mean of `2.4774 ms` (median `1.9909 ms`, P95 `5.3621 ms`). We analyze protocol wire overhead, latency skewness from `ML-DSA-65` rejection sampling using non-parametric bootstrap confidence intervals, and practical deployment constraints for bandwidth-limited UAV links.

---

## I. Introduction & Research Contribution

### A. Motivation
Unmanned Aerial Vehicles (UAVs) rely on wireless command-and-control (C2) links to receive safety-critical flight directives (`TAKEOFF`, `WAYPOINT`, `RTL`, `LAND`, `EMERGENCY_STOP`). Compromising the authenticity or integrity of C2 messages allows an adversary to hijack flight paths, replay stale commands, or force premature termination. Furthermore, adversaries operating under a *Store-Now-Decrypt-Later* (SNDL) paradigm can record encrypted C2 sessions today and decrypt them once Cryptographically Relevant Quantum Computers (CRQCs) become available, or use quantum algorithms to forge classical digital signatures in real time once CRQCs mature.

In August 2024, the U.S. National Institute of Standards and Technology (NIST) published the first finalized Post-Quantum Cryptography (PQC) standards: **FIPS 203** (`ML-KEM`, derived from CRYSTALS-Kyber) [1] for key establishment and **FIPS 204** (`ML-DSA`, derived from CRYSTALS-Dilithium) [2] for digital signatures. However, isolated primitive benchmarks do not establish a secure C2 protocol: `ML-KEM` alone provides no peer authentication, naive `AES-GCM` usage risks catastrophic nonce reuse, and decoupled signature verification can permit cross-session or intra-session command replay.

### B. Scope & Contributions
This work focuses strictly on **Layer 2 (Cryptographic Session & Command Security)** of a multi-layered UAV security architecture. Layer 1 (physical/RF networking) and Layer 3 (behavioral/AI intent analysis) are isolated via clean software interfaces. Specifically, this project makes four concrete contributions:
1. **Complete Layer 2 Protocol Architecture (`UAV-C2-PQ-L2 v1`):** We transition from isolated single-process primitive scripts to a modular, multi-component protocol (`protocol/`) featuring distinct `Sender` (Ground Station) and `Receiver` (UAV) roles, an explicit `TrustStore` supporting identity registration, key rotation, and peer revocation, a 3-message mutually authenticated handshake, in-session ephemeral `ML-KEM-768` rekeying, and authenticated session termination.
2. **Defense-in-Depth Command Protection:** Each UAV command is protected by both an inner contextual `ML-DSA-65` signature (binding protocol version, sender ID, recipient ID, 128-bit session ID, 32-bit monotonic sequence number, command verb, parameters, and timestamp) and outer `AES-256-GCM` authenticated encryption whose Associated Authenticated Data (AAD) binds the 22-byte binary wire header.
3. **Comprehensive Automated Security Verification:** We implement a 120-test automated verification suite (`test_protocol.py`) covering 25 security categories—including bit-flipped ciphertexts, forged headers, key substitution, mid-session peer revocation, duplicate/replayed packets, out-of-order policies, nonce reuse, counter exhaustion, cross-session injection, and parser fuzzing—proving that rejected packets never reach the UAV command handler.
4. **Rigorous Statistical & Wire-Overhead Evaluation:** We benchmark both individual primitives and end-to-end protocol workflows over 100 measured iterations (following 10 warm-up iterations) using `time.perf_counter_ns()`, reporting parametric and non-parametric (percentile bootstrap) 95% confidence intervals alongside exact byte-level wire overhead breakdowns.

---

## II. Threat Model & Trust Assumptions

We assume a Dolev-Yao adversary ($\mathcal{A}$) with complete control over the communication channel between the Ground Station (`gs1`) and the UAV (`uav1`):
- **Capabilities:** $\mathcal{A}$ can eavesdrop on all packets, drop or reorder frames, replay previously captured packets within the same session or across sessions, modify arbitrary bits in headers, nonces, ciphertexts, or tags, and initiate rogue handshakes using self-generated `ML-KEM-768` and `ML-DSA-65` keypairs.
- **Trust Assumptions:**
  1. Endpoint memory on the Ground Station and UAV is not compromised during mission execution.
  2. Each peer's `TrustStore` is pre-provisioned before flight with the legitimate peer's `1,952`-byte `ML-DSA-65` public key bound to its canonical `peer_id` and role (`ground_station` or `uav`).
  3. The underlying platform provides high-entropy randomness (`os.urandom`) for 128-bit session identifiers and lattice key generation.

---

## III. Protocol Architecture & Cryptographic Design

### A. Cryptographic Algorithms & NIST Security Level
The protocol selects **NIST Security Category 3** parameters (comparable to or exceeding AES-192 / SHA-384 against classical and quantum attacks) for asymmetric primitives, paired with 256-bit symmetric cryptography:
- **Key Establishment:** `ML-KEM-768` (FIPS 203) [1] — Public key: `1,184 B`; Ciphertext: `1,088 B`; Shared secret: `32 B`.
- **Digital Signatures:** `ML-DSA-65` (FIPS 204) [2] — Public key: `1,952 B`; Signature: `3,309 B`.
- **Key Derivation:** `HKDF-SHA-256` (RFC 5869) [3] — Derives directional 256-bit encryption keys and 32-bit deterministic nonce prefixes.
- **Authenticated Encryption:** `AES-256-GCM` (NIST SP 800-38D) [4] — 256-bit key (`32 B`), 96-bit nonce (`12 B`), 128-bit tag (`16 B`), and 22-byte binary header as AAD.

### B. Three-Message Mutually Authenticated Handshake
To prevent active public-key substitution and unauthenticated session establishment, session setup proceeds in three steps:
1. **`HANDSHAKE_INIT` (`MsgType = 1`, `13,041 B`):** The Ground Station (`gs1`) generates a random 16-byte `session_id` and a fresh ephemeral `ML-KEM-768` keypair $(\mathit{ek}_{\text{pk}}, \mathit{ek}_{\text{sk}})$. It constructs a canonical JSON signing context binding `(protocol_version, sender_id, sender_role, recipient_id, session_id, sender_signing_key, sender_kem_key)` and signs it with its long-term `ML-DSA-65` secret key.
2. **`HANDSHAKE_RESPONSE` (`MsgType = 2`, `12,839 B`):** The UAV (`uav1`) verifies `gs1` in its `TrustStore` (rejecting unknown or revoked identities or substituted signing keys) and verifies the `ML-DSA-65` signature on `HANDSHAKE_INIT`. Only after signature verification succeeds does `uav1` encapsulate a 32-byte shared secret $(c_{\text{kem}}, ss) \leftarrow \text{ML-KEM-768.Encap}(\mathit{ek}_{\text{pk}})$, derive session keys via `HKDF-SHA-256`, and sign its canonical response containing $c_{\text{kem}}$.
3. **`HANDSHAKE_CONFIRM` (`MsgType = 3`, `3,359 B`):** Upon verifying `uav1`'s response signature against the `TrustStore`, `gs1` decapsulates $ss \leftarrow \text{ML-KEM-768.Decap}(c_{\text{kem}}, \mathit{ek}_{\text{sk}})$, erases $\mathit{ek}_{\text{sk}}$, derives the directional session keys, signs the concatenated handshake transcript $(\text{Init} \parallel \text{Response})$, and sends the signature encrypted under `sender_enc_key` with the 22-byte header as AAD.

### C. Context-Bound Key Schedule & Deterministic Nonces
Using `salt = session_id (16B) || rekey_epoch (4B big-endian)`, `HKDF-SHA-256` derives four domain-separated values from the 32-byte `ML-KEM-768` shared secret:
- `sender_enc_key` (`32 B`, `info = "UAV-C2-PQ-L2-v1-sender-enc"`)
- `receiver_enc_key` (`32 B`, `info = "UAV-C2-PQ-L2-v1-receiver-enc"`)
- `sender_nonce_prefix` (`4 B`, `info = "UAV-C2-PQ-L2-v1-sender-auth"`)
- `receiver_nonce_prefix` (`4 B`, `info = "UAV-C2-PQ-L2-v1-receiver-auth"`)

Following NIST SP 800-38D §8.2.1 [4], each 96-bit `AES-256-GCM` nonce is constructed deterministically as:

$$\text{Nonce}_{96} = \text{Prefix}_{32} \parallel \text{Counter}_{64}$$

where $\text{Counter}_{64}$ increments strictly monotonically per message (`1, 2, ...`). Both endpoints enforce a hard limit of `SESSION_MAX_MESSAGES = 2^20` (`1,048,576`) invocations per key epoch and maintain explicit `_emitted_nonces` and `_received_nonces` sets, raising `NonceError` if a duplicate nonce is ever encountered.

### D. Protected Command Format & Fail-Closed Receiver Pipeline
Every `MSG_TYPE_COMMAND` (`MsgType = 4`) packet carries a 22-byte binary header (`version=1`, `msg_type=4`, `session_id`, `sequence`), a 12-byte deterministic nonce, and the `AES-256-GCM` ciphertext + 16-byte tag of a JSON `CommandPayload`. Inside the encrypted payload, an `ML-DSA-65` signature covers the canonical encoding of `(protocol_version, sender_id, recipient_id, session_id, sequence, command, params, timestamp)`.

The UAV `Receiver.receive_packet` method enforces an 8-stage fail-closed pipeline:
1. Packet length (`50..65,536 B`) and binary framing check.
2. Header parsing, protocol version (`== 1`), and message type check.
3. Session liveness, expiration (`<= 1,800 s`), message cap (`< 2^20`), and `session_id` match.
4. `AES-256-GCM` authentication tag verification (including 22-byte header AAD) and decryption.
5. Plaintext size (`<= 16,384 B`), JSON schema, strict field-type validation (rejecting Python `bool` masquerading as `int`), and `sender_id`/`recipient_id` verification.
6. `TrustStore` peer lookup (checking mid-session revocation) and `ML-DSA-65` signature verification over the reconstructed canonical command context.
7. Sequence number validation (`validate_recv_sequence`: strictly positive, non-duplicate, within `MAX_SEQUENCE_GAP = 100`) and 96-bit nonce uniqueness verification (`validate_and_record_nonce`).
8. Atomic sequence commit (`accept_recv_sequence`) and dispatch to the command handler.

---

## IV. Experimental Methodology & Testbed Environment

### A. Hardware and Software Environment
All experiments were executed on the following verified workstation environment:
- **Operating System:** Windows 11 (`Windows-11-10.0.26200-SP0`, `AMD64`)
- **Processor:** `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel` (`16` logical CPUs)
- **Python Runtime:** Python `3.14.5` (`C:\Python314\python.exe`)
- **Cryptographic & Plotting Libraries:** `liboqs-python==0.16.0.1` (wrapping native `liboqs`), `cryptography==50.0.1` (OpenSSL backend), `matplotlib==3.11.2`, and `pytest==9.1.1`.

### B. Statistical Measurement Protocol
Each benchmark operation in `layer2_protocol_benchmark.py` executes `10` unmeasured warm-up iterations (to populate instruction caches and initialize library contexts) followed by `n = 100` measured iterations timed via `time.perf_counter_ns()`.

**Confidence Interval Methodology:** Lattice signature schemes based on Fiat-Shamir with Aborts (`ML-DSA-65`) exhibit right-skewed latency distributions because the signing loop repeats polynomial rejection sampling until norm bounds are satisfied [2]. For skewed distributions, standard normal approximations ($\bar{x} \pm 1.96 s/\sqrt{n}$) can be sensitive to tail outliers. Therefore, we report **both** the normal-approximation 95% CI and a **non-parametric percentile bootstrap 95% CI** (`2,000` bootstrap resamples with fixed seed `42`), alongside the median, interquartile range (IQR), P95, and P99 latencies.

---

## V. Empirical Results & Evaluation

### A. Baseline Verification vs. Full Protocol Benchmarks
Table I preserves the original baseline microbenchmarks recorded in `crypto_benchmark_results.csv` and `ml_dsa_benchmark_results.csv`, which measured raw primitives in isolation. Table II presents the comprehensive primitive and end-to-end protocol measurements from `layer2_protocol_benchmark_results.csv`.

#### Table I: Preserved Baseline Primitive Measurements (`n = 100`, `10` Warm-ups)
*(Source: `crypto_benchmark_results.csv` and `ml_dsa_benchmark_results.csv`)*

| Algorithm | Operation | Mean (ms) | Median (ms) | Std Dev (ms) | P95 (ms) | Min (ms) | Max (ms) | Approx. 95% CI (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| `ML-KEM-768` | Key Generation | 0.1606 | 0.1568 | 0.0190 | — | 0.1510 | 0.2734 | `[0.1569, 0.1643]` |
| `ML-KEM-768` | Encapsulation | 0.1879 | 0.1852 | 0.0134 | — | 0.1794 | 0.2883 | `[0.1852, 0.1905]` |
| `ML-KEM-768` | Decapsulation | 0.2223 | 0.2187 | 0.0098 | — | 0.2122 | 0.2695 | `[0.2204, 0.2242]` |
| `AES-256-GCM` | Encryption (19 B) | 0.000814 | 0.000800 | 0.000074 | — | 0.000700 | 0.001100 | `[0.000800, 0.000828]` |
| `AES-256-GCM` | Decryption (19 B) | 0.000749 | 0.000700 | 0.000052 | — | 0.000700 | 0.000900 | `[0.000739, 0.000759]` |
| `ML-DSA-65` | Signing (19 B) | 1.7782 | 1.4809 | 1.0958 | 4.0986 | 0.6963 | 5.5819 | `[1.5634, 1.9929]` |
| `ML-DSA-65` | Verification (19 B) | 0.4761 | 0.4730 | 0.0082 | 0.4959 | 0.4649 | 0.5030 | `[0.4745, 0.4777]` |

#### Table II: Comprehensive Layer 2 Primitive & End-to-End Protocol Latency (`n = 100`, `10` Warm-ups)
*(Source: `layer2_protocol_benchmark_results.csv`)*

| Category | Algorithm / Workflow | Operation | Mean (ms) | Median (ms) | Std Dev (ms) | IQR (ms) | P95 (ms) | P99 (ms) | Bootstrap 95% CI (ms) |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| Primitive | `ML-KEM-768` | `kem_key_generation` | 0.1723 | 0.1644 | 0.0275 | 0.0079 | 0.2087 | 0.3752 | `[0.1677, 0.1785]` |
| Primitive | `ML-KEM-768` | `kem_encapsulation` | 0.1971 | 0.1911 | 0.0190 | 0.0076 | 0.2610 | 0.2908 | `[0.1937, 0.2012]` |
| Primitive | `ML-KEM-768` | `kem_decapsulation` | 0.2374 | 0.2261 | 0.0384 | 0.0103 | 0.3065 | 0.4776 | `[0.2308, 0.2459]` |
| Primitive | `ML-DSA-65` | `dsa_key_generation` | 0.4669 | 0.4508 | 0.0600 | 0.0200 | 0.5178 | 0.9320 | `[0.4571, 0.4804]` |
| Primitive | `ML-DSA-65` | `dsa_signing` | 1.9556 | 1.6296 | 1.1503 | 1.2388 | 4.6008 | 6.0349 | `[1.7348, 2.1907]` |
| Primitive | `ML-DSA-65` | `dsa_verification` | 0.5141 | 0.4892 | 0.0741 | 0.0343 | 0.6288 | 0.9601 | `[0.5011, 0.5307]` |
| Primitive | `HKDF-SHA-256` | `session_key_derivation` | 0.0183 | 0.0146 | 0.0253 | 0.0004 | 0.0191 | 0.2508 | `[0.0148, 0.0244]` |
| Primitive | `AES-256-GCM` | `aes_encrypt_19B` | 0.0019 | 0.0019 | 0.0001 | 0.0001 | 0.0020 | 0.0032 | `[0.0019, 0.0020]` |
| Primitive | `AES-256-GCM` | `aes_decrypt_19B` | 0.0019 | 0.0019 | 0.0004 | 0.0001 | 0.0020 | 0.0063 | `[0.0019, 0.0020]` |
| Primitive | `AES-256-GCM` | `aes_encrypt_signed_payload` (`6,742 B`) | 0.0031 | 0.0031 | 0.0001 | 0.0001 | 0.0032 | 0.0033 | `[0.0031, 0.0031]` |
| Primitive | `AES-256-GCM` | `aes_decrypt_signed_payload` (`6,742 B`) | 0.0030 | 0.0030 | 0.0000 | 0.0000 | 0.0031 | 0.0032 | `[0.0030, 0.0030]` |
| Protocol E2E | `Layer2-Handshake` | `full_authenticated_handshake` | 9.5152 | 8.9811 | 2.4456 | 2.9185 | 14.6201 | 19.3801 | `[9.0475, 10.0158]` |
| Protocol E2E | `Layer2-Command` | `command_send_protect` | 1.9084 | 1.4211 | 1.3389 | 1.0866 | 4.7798 | 7.0472 | `[1.6549, 2.1861]` |
| Protocol E2E | `Layer2-Command` | `command_recv_validate` | 0.5691 | 0.5388 | 0.0911 | 0.0575 | 0.7977 | 1.0235 | `[0.5524, 0.5888]` |
| Protocol E2E | `Layer2-Command` | `command_e2e_roundtrip` | 2.4774 | 1.9909 | 1.3522 | 1.1196 | 5.3621 | 7.6604 | `[2.2231, 2.7570]` |
| Protocol E2E | `Layer2-Rekey` | `session_rekey_e2e` | 0.6923 | 0.6571 | 0.0870 | 0.0573 | 0.9196 | 1.1115 | `[0.6758, 0.7104]` |

**Key Observations:**
1. **Asymmetric Signing Dominates Command Latency:** On the sender side (`command_send_protect`, mean `1.9084 ms`), `ML-DSA-65` signing (`1.9556 ms` mean) accounts for `>98%` of execution time, whereas `AES-256-GCM` encryption of the 6,742-byte signed JSON payload takes only `0.0031 ms` (`3.1 µs`).
2. **Fast, Deterministic UAV Receiver Validation:** Crucially for resource-constrained UAVs, `ML-DSA-65` verification (`0.5141 ms` mean, `0.0741 ms` SD) does *not* involve rejection-sampling loops. Consequently, total UAV receiver validation (`command_recv_validate`) completes in a tight distribution around `0.5691 ms` (median `0.5388 ms`, P95 `0.7977 ms`).
3. **Lightweight In-Session Rekeying:** Because in-session rekeying (`session_rekey_e2e`) uses `ML-KEM-768` over the already-authenticated session channel without requiring new `ML-DSA-65` signatures, a complete rekey round-trip completes in `0.6923 ms` (`~13.7x` faster than the initial `9.5152 ms` 3-way handshake).

### B. Message & Protocol Wire Overhead Analysis
Table III details the byte-level breakdown of each protocol message from `layer2_message_overhead_results.csv`.

#### Table III: Layer 2 Protocol Wire Overhead Breakdown
*(Source: `layer2_message_overhead_results.csv`)*

| Message Type | Plaintext Command (B) | Binary Header (B) | Nonce (B) | GCM Tag (B) | Crypto Payload (B) | Total Wire Size (B) |
|---|---:|---:|---:|---:|---:|---:|
| `HANDSHAKE_INIT` | 0 | 22 | 0 | 0 | 13,019 | **13,041** |
| `HANDSHAKE_RESPONSE` | 0 | 22 | 0 | 0 | 12,817 | **12,839** |
| `HANDSHAKE_CONFIRM` | 0 | 22 | 12 | 16 | 3,309 | **3,359** |
| `COMMAND (TAKEOFF ALTITUDE 10)` | 19 | 22 | 12 | 16 | 6,748 | **6,798** |
| `REKEY_INIT` | 0 | 22 | 12 | 16 | 1,184 | **1,234** |
| `REKEY_RESPONSE` | 0 | 22 | 12 | 16 | 1,088 | **1,138** |
| `TERMINATE` | 9 | 22 | 12 | 16 | 9 | **59** |

Because `HANDSHAKE_INIT`, `HANDSHAKE_RESPONSE`, and `COMMAND` encode binary keys and signatures as hexadecimal strings inside JSON payloads (`3,309 B` `ML-DSA-65` signature = `6,618` hex chars), a 19-byte command incurs `6,779 bytes` of framing and cryptographic overhead (`6,798 B` total). Replacing hex-JSON serialization with compact binary struct packing in future iterations will halve command packet size to `~3,420 B` without altering any cryptographic primitive.

### C. Automated Security Test Suite Results
All 25 required security test categories (120 total test cases in `test_protocol.py`) passed (`120 passed, 0 failed in 1.04s`):
- **Positive Verification (Categories 1–3, 20):** Handshake completion, directional key agreement, sequential command acceptance, in-session rekey key rotation, and clean session termination.
- **Cryptographic Integrity & Authenticity (Categories 4–10, 18, 23–24):** Forged/zeroed `ML-DSA-65` signatures, flipped ciphertext bits, truncated tags, modified header AAD fields (`version`, `session_id`, `sequence`), wrong `AES-256-GCM` keys, unknown/revoked peers (including mid-session revocation), public-key substitution attacks, and corrupted handshake transcripts all fail closed with `0` commands reaching `CommandRecord.accepted`.
- **Replay, Ordering, & Nonce Lifecycle (Categories 11–14, 19, 21–22):** Immediate and delayed replays, forged packets reusing sequence numbers, out-of-order packets (tested under both strict monotonic rejection and sliding-window mode), expired sessions, reused 96-bit nonces, nonce counter exhaustion, post-restart cross-session replays, and concurrent multi-session cross-injection are deterministically rejected.
- **Framing, Bounds, & Parser Fuzzing (Categories 15–17, 25):** Empty packets, 1-byte packets, header-only packets, truncated nonces, oversized packets (`> 65,536 B`), invalid versions/types, and 47 parameterized random fuzz inputs execute cleanly without unhandled exceptions.

---

## VI. Limitations & Future Work

1. **Workstation Benchmarks vs. Embedded Avionics:** The reported sub-3 ms command latencies were measured on an Intel64 desktop processor using an in-memory transport (`LocalTransport`). Real-time UAV deployment suitability cannot be claimed from desktop microbenchmarks alone; future work must profile `ML-KEM-768` and `ML-DSA-65` on embedded flight companion computers (e.g., ARM Cortex-A72 / Cortex-M7) over real RF/serial links with packet loss and fragmentation.
2. **Binary Serialization & Link Fragmentation:** Transitioning from hex-encoded JSON payloads to binary `struct`/CBOR encoding will reduce the 3-way handshake transcript from `29,239 B` to `~13,200 B` and per-command packets from `6,798 B` to `~3,420 B`.
3. **Formal Verification & Hardware Key Protection:** Future work includes modeling the `UAV-C2-PQ-L2` handshake and rekey state machine in Tamarin or ProVerif and integrating hardware-backed key storage (TPM/HSM) to eliminate Python garbage-collection key remnants.

---

## References

[1] National Institute of Standards and Technology (NIST), *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, Federal Information Processing Standards Publication (FIPS) 203, Aug. 2024. https://doi.org/10.6028/NIST.FIPS.203

[2] National Institute of Standards and Technology (NIST), *Module-Lattice-Based Digital Signature Standard*, Federal Information Processing Standards Publication (FIPS) 204, Aug. 2024. https://doi.org/10.6028/NIST.FIPS.204

[3] H. Krawczyk and P. Eronen, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*, IETF RFC 5869, May 2010. https://doi.org/10.17487/RFC5869

[4] M. Dworkin, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, NIST Special Publication 800-38D, Nov. 2007. https://doi.org/10.6028/NIST.SP.800-38D
