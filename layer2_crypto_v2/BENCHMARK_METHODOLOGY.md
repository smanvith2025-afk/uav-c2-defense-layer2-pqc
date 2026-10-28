# UAV-C2-PQ-L2 v2 — Benchmark Methodology & Result Integrity

**Benchmark Script:** [`layer2_protocol_benchmark.py`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/layer2_protocol_benchmark.py)
**Timestamped Run Directory:** [`results/2026-10-28T153951Z/`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/results/2026-10-28T153951Z)
**Top-Level Synchronized Outputs:**
- [`layer2_protocol_benchmark_results.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/layer2_protocol_benchmark_results.csv)
- [`layer2_message_overhead_results.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/layer2_message_overhead_results.csv)
- [`layer2_protocol_e2e_benchmark.png`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/layer2_protocol_e2e_benchmark.png)

---

## 1. Execution Environment & Reproducibility Metadata

Recorded in [`results/2026-10-28T153951Z/benchmark_environment.json`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/results/2026-10-28T153951Z/benchmark_environment.json):
- **OS / Platform:** `Windows-11-10.0.26200-SP0` (64-bit)
- **Processor:** `Intel64 Family 6 Model 183 Stepping 1, GenuineIntel` (`16` logical CPUs)
- **Python Runtime:** `3.14.5 (tags/v3.14.5:5607950, May 10 2026, 10:43:50) [MSC v.1944 64 bit (AMD64)]`
- **Cryptographic Libraries:** `liboqs 0.16.0` (`liboqs-python 0.16.0.1`), `cryptography 50.0.1`
- **Timer:** `time.perf_counter_ns()` (nanosecond resolution, converted to milliseconds via `/ 1_000_000`)
- **Warm-up Iterations:** `10` per operation (executed before timing collection and excluded from statistics)
- **Measured Iterations:** `100` per operation (`1,900` total raw samples saved in [`raw_benchmark_samples.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/results/2026-10-28T153951Z/raw_benchmark_samples.csv))
- **Confidence Intervals:** Both normal-approximation 95% CI ($\bar{x} \pm 1.96 s / \sqrt{n}$) and non-parametric percentile bootstrap 95% CI (`2,000` resamples, deterministic `random.Random(42)`)

---

## 2. Direct Measurement vs. Subtraction & Operation Definitions

In `v2`, JSON serialization and binary struct framing are **measured directly** as dedicated benchmark operations (`category = "Serialization"`) rather than estimated by subtracting primitive means from end-to-end means:

1. **`command_serialize_and_frame` (`0.0200 ms` mean, `0.0197 ms` median):**
   Directly times `CommandPayload` instantiation, `canonical_bytes_for_signing()`, `to_json_bytes()` (`6,747 B`), and `MessageHeader.to_bytes()` (`22 B`).
2. **`command_parse_and_unframe` (`0.0219 ms` mean, `0.0212 ms` median):**
   Directly times `MessageHeader.from_bytes()`, `CommandPayload.from_json_bytes()` (including strict JSON parsing, whitelist check, and hex decoding of the `3,309 B` signature), and `canonical_bytes_for_signing()`.
3. **`handshake_serialize_and_parse` (`0.0898 ms` mean, `0.0894 ms` median):**
   Directly times `HandshakePayload.canonical_bytes_for_signing()`, `to_json_bytes()` (`13,264 B`), `MessageHeader.to_bytes()`, `MessageHeader.from_bytes()`, `HandshakePayload.from_json_bytes()`, and `canonical_bytes_for_signing()`.

### Why `full_authenticated_handshake` (`9.3599 ms` mean, `sd = 2.2486 ms`) Has Higher Variance
A full 3-message `v2` handshake executes:
- `1× ML-KEM-768` keygen (`~0.176 ms`) + `1×` encapsulation (`~0.199 ms`) + `1×` decapsulation (`~0.239 ms`)
- `3× ML-DSA-65` signings (`HANDSHAKE_INIT`, `HANDSHAKE_RESPONSE`, `HANDSHAKE_CONFIRM`: $3 \times 1.574\text{ ms} \approx 4.72\text{ ms}$)
- `3× ML-DSA-65` verifications ($3 \times 0.511\text{ ms} \approx 1.53\text{ ms}$)
- `2×` two-stage `HKDF-SHA-256` derivations (`initiator` + `responder`: $2 \times 0.029\text{ ms} \approx 0.058\text{ ms}$)
- `1× AES-256-GCM` encryption + `1×` decryption of `HANDSHAKE_CONFIRM` (`3,309 B`)
- JSON/hex serialization and parsing of two large handshake payloads (`13.3 KB` and `15.5 KB`)

Because `ML-DSA-65` signing uses Fiat–Shamir with Aborts (rejection sampling over lattice vectors), individual signing calls exhibit a right-skewed latency distribution (`min = 0.72 ms`, `median = 1.26 ms`, `mean = 1.57 ms`, `p95 = 3.54 ms`, `max = 6.33 ms`). Summing three independent `ML-DSA-65` signings per handshake produces the observed `9.36 ms` mean (`9.03 ms` median, `2.25 ms` SD).

### Why `session_rekey_e2e` Increased from `0.66 ms` (`v1`) to `6.1461 ms` (`v2`)
In `v1`, `session_rekey_e2e` (`0.66 ms`) only performed `ML-KEM-768` keygen + encap + decap + `AES-256-GCM` without any `ML-DSA-65` signatures (`F-12`). In `v2`, `REKEY_INIT` and `REKEY_RESPONSE` are both signed and verified with `ML-DSA-65` (`2×` signings + `2×` verifications $\approx 4.17\text{ ms}$), plus `ML-KEM-768` (`~0.61 ms`), two-stage chained `HKDF-SHA-256`, `HMAC-SHA-256` key confirmation, and JSON/hex serialization, yielding `6.1461 ms` mean (`5.6427 ms` median).

---

## 3. Complete Benchmark Results Summary (`n = 100`, `warmups = 10`)

Every value below is taken verbatim from [`layer2_protocol_benchmark_results.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/layer2_protocol_benchmark_results.csv):

| Category | Algorithm | Operation | Mean (ms) | Median (ms) | SD (ms) | IQR (ms) | P95 (ms) | P99 (ms) | Min (ms) | Max (ms) | Bootstrap 95% CI (ms) |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| Primitive | `ML-KEM-768` | `kem_key_generation` | `0.1761` | `0.1710` | `0.0164` | `0.0139` | `0.2172` | `0.2435` | `0.1610` | `0.2435` | `[0.1730, 0.1795]` |
| Primitive | `ML-KEM-768` | `kem_encapsulation` | `0.1990` | `0.1955` | `0.0102` | `0.0109` | `0.2198` | `0.2465` | `0.1871` | `0.2465` | `[0.1971, 0.2012]` |
| Primitive | `ML-KEM-768` | `kem_decapsulation` | `0.2386` | `0.2323` | `0.0178` | `0.0154` | `0.2748` | `0.3251` | `0.2202` | `0.3251` | `[0.2353, 0.2422]` |
| Primitive | `ML-DSA-65` | `dsa_key_generation` | `0.4727` | `0.4653` | `0.0257` | `0.0226` | `0.5435` | `0.5730` | `0.4419` | `0.5730` | `[0.4678, 0.4781]` |
| Primitive | `ML-DSA-65` | `dsa_signing` | `1.5739` | `1.2601` | `0.9968` | `0.8255` | `3.5357` | `6.3309` | `0.7197` | `6.3309` | `[1.3852, 1.7801]` |
| Primitive | `ML-DSA-65` | `dsa_verification` | `0.5113` | `0.5051` | `0.0264` | `0.0252` | `0.5642` | `0.6324` | `0.4797` | `0.6324` | `[0.5064, 0.5167]` |
| Primitive | `HKDF-SHA-256` | `session_key_derivation` | `0.0289` | `0.0281` | `0.0020` | `0.0011` | `0.0341` | `0.0391` | `0.0274` | `0.0391` | `[0.0285, 0.0293]` |
| Primitive | `AES-256-GCM` | `aes_encrypt_19B` | `0.0036` | `0.0026` | `0.0081` | `0.0001` | `0.0047` | `0.0829` | `0.0025` | `0.0829` | `[0.0027, 0.0058]` |
| Primitive | `AES-256-GCM` | `aes_decrypt_19B` | `0.0027` | `0.0026` | `0.0005` | `0.0001` | `0.0038` | `0.0054` | `0.0024` | `0.0054` | `[0.0026, 0.0028]` |
| Primitive | `AES-256-GCM` | `aes_encrypt_signed_payload` | `0.0038` | `0.0037` | `0.0001` | `0.0001` | `0.0040` | `0.0049` | `0.0036` | `0.0049` | `[0.0037, 0.0038]` |
| Primitive | `AES-256-GCM` | `aes_decrypt_signed_payload` | `0.0037` | `0.0037` | `0.0001` | `0.0000` | `0.0038` | `0.0039` | `0.0035` | `0.0039` | `[0.0037, 0.0037]` |
| Serialization | `JSON+Struct` | `command_serialize_and_frame` | `0.0200` | `0.0197` | `0.0009` | `0.0007` | `0.0219` | `0.0249` | `0.0189` | `0.0249` | `[0.0198, 0.0202]` |
| Serialization | `JSON+Struct` | `command_parse_and_unframe` | `0.0219` | `0.0212` | `0.0029` | `0.0021` | `0.0244` | `0.0467` | `0.0196` | `0.0467` | `[0.0214, 0.0226]` |
| Serialization | `JSON+Struct` | `handshake_serialize_and_parse` | `0.0898` | `0.0894` | `0.0031` | `0.0035` | `0.0946` | `0.1009` | `0.0842` | `0.1009` | `[0.0892, 0.0904]` |
| Protocol_E2E | `Layer2-Handshake` | `full_authenticated_handshake` | `9.3599` | `9.0252` | `2.2486` | `2.5493` | `14.4036` | `16.5967` | `6.0827` | `16.5967` | `[8.9284, 9.8106]` |
| Protocol_E2E | `Layer2-Command` | `command_send_protect` | `2.0475` | `1.5718` | `1.7093` | `1.3415` | `4.6199` | `14.1657` | `0.7631` | `14.1657` | `[1.7394, 2.4192]` |
| Protocol_E2E | `Layer2-Command` | `command_recv_validate` | `0.5785` | `0.5570` | `0.0560` | `0.0511` | `0.6924` | `0.8187` | `0.5223` | `0.8187` | `[0.5680, 0.5902]` |
| Protocol_E2E | `Layer2-Command` | `command_e2e_roundtrip` | `2.6260` | `2.1382` | `1.7135` | `1.3502` | `5.1789` | `14.7693` | `1.2947` | `14.7693` | `[2.3194, 2.9971]` |
| Protocol_E2E | `Layer2-Rekey` | `session_rekey_e2e` | `6.1461` | `5.6427` | `1.8937` | `2.4027` | `9.4626` | `15.8109` | `3.8247` | `15.8109` | `[5.7887, 6.5302]` |

---

## 4. Wire-Size Accounting & Analytical 57.6 kbps Link Transmission Estimate

Values from [`layer2_message_overhead_results.csv`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/layer2_message_overhead_results.csv), paired with an **analytical** serial/telemetry link serialization estimate at `57,600 bps` (`7,200 B/s`, 8N1 framing ignored, zero propagation/MAC delay):

| Message Type | Plaintext (B) | Header (B) | Nonce (B) | GCM Tag (B) | Crypto Payload (B) | Total Wire Bytes (B) | Analytical Air Time @ 57.6 kbps (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `HANDSHAKE_INIT` | `0` | `22` | `0` | `0` | `13,265` | `13,287` | `1,845.4 ms` |
| `HANDSHAKE_RESPONSE` | `0` | `22` | `0` | `0` | `15,429` | `15,451` | `2,146.0 ms` |
| `HANDSHAKE_CONFIRM` | `0` | `22` | `12` | `16` | `3,309` | `3,359` | `466.5 ms` |
| **`FULL_HANDSHAKE_3_MSG_TOTAL`** | **`0`** | **`66`** | **`12`** | **`16`** | **`32,003`** | **`32,097`** | **`4,457.9 ms`** |
| `COMMAND (TAKEOFF ALTITUDE 10)` | `19` | `22` | `12` | `16` | `6,748` | `6,798` | `944.2 ms` |
| `REKEY_INIT` | `0` | `22` | `12` | `16` | `9,189` | `9,239` | `1,283.2 ms` |
| `REKEY_RESPONSE` | `0` | `22` | `12` | `16` | `11,429` | `11,479` | `1,594.3 ms` |
| `TERMINATE` | `9` | `22` | `12` | `16` | `6,738` | `6,788` | `942.8 ms` |

> **Important Note on Hex-in-JSON Wire Encoding:** Because `v2` preserves `v1`'s UTF-8 JSON payload encoding with hexadecimal strings for binary keys, ciphertexts, and `ML-DSA-65` signatures (`3,309 B` $\to$ `6,618` hex chars), a protected command packet is `6,798 B` on the wire (`~3,420 B` if binary-packed). Replacing hex-in-JSON with binary CBOR/struct encoding would halve wire overhead on narrowband links without changing any cryptographic primitive.
