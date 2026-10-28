# UAV-C2-PQ-L2 v2 — Layer 2 Post-Quantum UAV Command-and-Control Security Protocol

**Protocol Version:** `2` (`__version__ = "2.0.0"`, `PROTOCOL_VERSION = 2`)
**Workspace:** `C:\Users\smanv\UAV_Security_Project\layer2_crypto_v2`
**Cryptographic Suite:** `ML-KEM-768` (FIPS 203) + `ML-DSA-65` (FIPS 204) + `HKDF-SHA-256` (RFC 5869) + `AES-256-GCM` (NIST SP 800-38D)
**Test Suite Status:** `157 passed in 2.02s` (`test_protocol.py`)

---

## 1. Overview & Security Architecture (`v2`)

`UAV-C2-PQ-L2 v2` is the hardened, security-remediated Layer 2 cryptographic command-and-control protocol for Ground Station (`ground_station`) to UAV (`uav`) communications. It remediates all 17 findings (`F-01` through `F-17`) identified in the `v1` security audit:

- **Isolated Pending Handshake & Explicit Key Confirmation (`F-01`, `F-02`, `F-03`, `F-04`):** Responder sessions stage in `SessionState.AWAITING_CONFIRM` inside an isolated `_pending_session` slot until the initiator's encrypted and `ML-DSA-65`-signed `HANDSHAKE_CONFIRM` is verified over a 4-byte length-prefixed, domain-separated transcript (`TRANSCRIPT_CONFIRM_LABEL`). Unauthenticated, malformed, stale, or replayed `HANDSHAKE_INIT` packets never disrupt an established session.
- **End-to-End Role Enforcement (`F-15`):** `TrustStore.verify_peer_role()`, `Sender`, and `Receiver` enforce that only a trusted `ground_station` peer can initiate handshakes, send commands, rekey, or terminate a session, and only a trusted `uav` peer can respond to handshakes and execute commands.
- **Two-Stage `HKDF-SHA-256` Key Schedule & Identity-Signed Chained Rekeying (`F-06`, `F-12`, `F-13`):** Stage 1 derives an epoch `root_secret` (and 32-byte `rekey_confirm_key`) bound to `session_id`, `epoch`, `SHA256(transcript)`, `initiator_id`, and `responder_id`. On rekey (`epoch >= 1`), `REKEY_INIT` and `REKEY_RESPONSE` carry `ML-DSA-65` signatures over the epoch transition and chain `prev_root_secret || kem_shared_secret`, with atomic rollback (`abort_rekey()`) if `complete_rekey()` fails.
- **Strict Pre-Parse Input Validation & Command Whitelisting (`F-05`, `F-09`, `F-10`):** Enforces exact FIPS 203/204 byte lengths before `liboqs` C FFI calls, enforces `VALID_COMMANDS` (`TAKEOFF`, `LAND`, `HOVER`, `RTL`, `WAYPOINT`, `SET_ALTITUDE`, `SET_SPEED`, `EMERGENCY_STOP`, `ABORT`), rejects `NaN`/`Infinity` JSON constants, and enforces $\pm 60\text{ s}$ timestamp freshness.
- **Bounded `O(1)` Replay Window & Sequence-Before-Signature Ordering (`F-07`, `F-08`, `F-11`, `F-14`):** Validates sequence numbers before `ML-DSA-65` signature verification, tracks nonces across all encrypted message types (`CONFIRM`, `COMMAND`, `REKEY`, `TERMINATE`) within a bounded `200`-entry window (`NONCE_WINDOW_SIZE = 200`), and uses `time.monotonic()` for session lifetime tracking.

---

## 2. Repository Structure & Key Deliverables

```text
layer2_crypto_v2/
├── protocol/
│   ├── __init__.py                 # Package exports (__version__ = "2.0.0", PROTOCOL_VERSION = 2)
│   ├── constants.py                # FIPS 203/204 sizes, v2 HKDF labels, bounds, VALID_COMMANDS
│   ├── crypto_core.py              # ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256
│   ├── errors.py                   # Fail-closed protocol exception hierarchy
│   ├── identity.py                 # PeerIdentity & TrustStore with verify_peer_role() & compare_digest()
│   ├── messages.py                 # MessageHeader, CommandPayload, HandshakePayload, RekeyPayload, TerminatePayload
│   ├── session.py                  # SessionState (with AWAITING_CONFIRM), 2-stage KDF, atomic rekey, O(1) nonce window
│   ├── sender.py                   # Ground Station initiator & command/rekey/terminate sender
│   ├── receiver.py                 # UAV responder with isolated _pending_session & strict role/sequence checks
│   └── transport.py                # Abstract Transport & deterministic in-memory LocalTransport
├── results/
│   └── 2026-10-28T153951Z/         # Timestamped v2 benchmark run directory (raw samples, env JSON, CSVs, PNG)
├── test_protocol.py                # 157 unit, regression, and adversarial tests (F-01 through F-17)
├── layer2_protocol_benchmark.py    # Reproducible primitive, serialization, and E2E benchmark suite
├── layer2_protocol_benchmark_results.csv
├── layer2_message_overhead_results.csv
├── layer2_protocol_e2e_benchmark.png
├── SECURITY_REMEDIATION_REPORT.md  # Detailed finding-by-finding disposition (F-01 to F-17)
├── SECURITY_TRACEABILITY.csv       # Traceability matrix (Finding -> v1 -> v2 -> Test -> Result)
├── PROTOCOL_V2_SPEC.md             # Formal v2 wire format, state machine, and key schedule specification
├── BENCHMARK_METHODOLOGY.md        # Statistical methodology, direct serialization timing, and wire accounting
├── CHANGELOG_V2.md                 # Complete v1 -> v2 changelog and wire-compatibility notes
├── NOT_REVIEWED_AND_LIMITATIONS.md # Explicit scope boundaries and unassessed areas
└── FINAL_VALIDATION_REPORT.md      # Final verification evidence, v1/v2 SHA-256 manifest, and pass/fail status
```

---

## 3. Environment Setup & Exact Reproduction Commands

### 3.1 Tested Environment
- **OS:** Windows 11 (`Windows-11-10.0.26200-SP0`)
- **Python:** `3.14.5` (64-bit)
- **Dependencies:** `liboqs-python 0.16.0.1` (`liboqs 0.16.0`), `cryptography 50.0.1`, `pytest 9.1.1`, `matplotlib`

### 3.2 Run Full Test Suite (`157` Tests)

**Windows PowerShell:**
```powershell
Set-Location "C:\Users\smanv\UAV_Security_Project\layer2_crypto_v2"
python -m pytest test_protocol.py -v
```

**Windows Command Prompt (`cmd.exe`):**
```cmd
cd /d C:\Users\smanv\UAV_Security_Project\layer2_crypto_v2
python -m pytest test_protocol.py -v
```

### 3.3 Run Protocol & Primitive Benchmark Suite
Running `layer2_protocol_benchmark.py` creates a new timestamped subfolder under `results/<timestamp>/` containing `raw_benchmark_samples.csv`, `benchmark_environment.json`, `layer2_protocol_benchmark_results.csv`, `layer2_message_overhead_results.csv`, and `layer2_protocol_e2e_benchmark.png`, and synchronizes the top-level CSVs and PNG:

**Windows PowerShell:**
```powershell
Set-Location "C:\Users\smanv\UAV_Security_Project\layer2_crypto_v2"
python layer2_protocol_benchmark.py
```

---

## 4. Validated `v2` Benchmark Metrics (`results/2026-10-28T153951Z/`)

### 4.1 Primitive, Direct Serialization & End-to-End Protocol Latency (`n = 100`, `warmups = 10`)

| Category | Algorithm | Operation | Mean (ms) | Median (ms) | SD (ms) | P95 (ms) | Bootstrap 95% CI (ms) |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| Primitive | `ML-KEM-768` | `kem_key_generation` | `0.1761` | `0.1710` | `0.0164` | `0.2172` | `[0.1730, 0.1795]` |
| Primitive | `ML-KEM-768` | `kem_encapsulation` | `0.1990` | `0.1955` | `0.0102` | `0.2198` | `[0.1971, 0.2012]` |
| Primitive | `ML-KEM-768` | `kem_decapsulation` | `0.2386` | `0.2323` | `0.0178` | `0.2748` | `[0.2353, 0.2422]` |
| Primitive | `ML-DSA-65` | `dsa_key_generation` | `0.4727` | `0.4653` | `0.0257` | `0.5435` | `[0.4678, 0.4781]` |
| Primitive | `ML-DSA-65` | `dsa_signing` | `1.5739` | `1.2601` | `0.9968` | `3.5357` | `[1.3852, 1.7801]` |
| Primitive | `ML-DSA-65` | `dsa_verification` | `0.5113` | `0.5051` | `0.0264` | `0.5642` | `[0.5064, 0.5167]` |
| Primitive | `HKDF-SHA-256` | `session_key_derivation` (2-stage) | `0.0289` | `0.0281` | `0.0020` | `0.0341` | `[0.0285, 0.0293]` |
| Primitive | `AES-256-GCM` | `aes_encrypt_signed_payload` (6,747 B) | `0.0038` | `0.0037` | `0.0001` | `0.0040` | `[0.0037, 0.0038]` |
| Primitive | `AES-256-GCM` | `aes_decrypt_signed_payload` (6,747 B) | `0.0037` | `0.0037` | `0.0001` | `0.0038` | `[0.0037, 0.0037]` |
| Serialization | `JSON+Struct` | `command_serialize_and_frame` | `0.0200` | `0.0197` | `0.0009` | `0.0219` | `[0.0198, 0.0202]` |
| Serialization | `JSON+Struct` | `command_parse_and_unframe` | `0.0219` | `0.0212` | `0.0029` | `0.0244` | `[0.0214, 0.0226]` |
| Serialization | `JSON+Struct` | `handshake_serialize_and_parse` | `0.0898` | `0.0894` | `0.0031` | `0.0946` | `[0.0892, 0.0904]` |
| Protocol_E2E | `Layer2-Handshake` | `full_authenticated_handshake` | `9.3599` | `9.0252` | `2.2486` | `14.4036` | `[8.9284, 9.8106]` |
| Protocol_E2E | `Layer2-Command` | `command_send_protect` | `2.0475` | `1.5718` | `1.7093` | `4.6199` | `[1.7394, 2.4192]` |
| Protocol_E2E | `Layer2-Command` | `command_recv_validate` | `0.5785` | `0.5570` | `0.0560` | `0.6924` | `[0.5680, 0.5902]` |
| Protocol_E2E | `Layer2-Command` | `command_e2e_roundtrip` | `2.6260` | `2.1382` | `1.7135` | `5.1789` | `[2.3194, 2.9971]` |
| Protocol_E2E | `Layer2-Rekey` | `session_rekey_e2e` | `6.1461` | `5.6427` | `1.8937` | `9.4626` | `[5.7887, 6.5302]` |

### 4.2 Wire-Size Overhead by Message Type (`v2`)

| Message Type | Header (B) | Nonce (B) | GCM Tag (B) | Crypto Payload (B) | Total Wire Bytes (B) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `HANDSHAKE_INIT` | `22` | `0` | `0` | `13,265` | `13,287` |
| `HANDSHAKE_RESPONSE` | `22` | `0` | `0` | `15,429` | `15,451` |
| `HANDSHAKE_CONFIRM` | `22` | `12` | `16` | `3,309` | `3,359` |
| **`FULL_HANDSHAKE_3_MSG_TOTAL`** | **`66`** | **`12`** | **`16`** | **`32,003`** | **`32,097`** |
| `COMMAND (TAKEOFF ALTITUDE 10)` | `22` | `12` | `16` | `6,748` | `6,798` |
| `REKEY_INIT` | `22` | `12` | `16` | `9,189` | `9,239` |
| `REKEY_RESPONSE` | `22` | `12` | `16` | `11,429` | `11,479` |
| `TERMINATE` | `22` | `12` | `16` | `6,738` | `6,788` |

---

## 5. Limitations & Scope Disclaimer
See [`NOT_REVIEWED_AND_LIMITATIONS.md`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/NOT_REVIEWED_AND_LIMITATIONS.md). This implementation is a single-process Layer 2 research and engineering prototype evaluated over `LocalTransport`; it has not undergone formal symbolic/computational proof (Tamarin/ProVerif/CryptoVerif), FIPS 140-3 module validation, or hardware flight qualification.
