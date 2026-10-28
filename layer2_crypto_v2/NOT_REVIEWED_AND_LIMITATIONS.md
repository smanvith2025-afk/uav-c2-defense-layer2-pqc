# UAV-C2-PQ-L2 v2 — Not Reviewed & Engineering Limitations

To maintain strict scientific and engineering honesty, this document records what was **not** assessed or cannot be guaranteed within the scope of this Python Layer 2 reference implementation.

---

## 1. No Formal Symbolic or Computational Verification
- **Not Formally Verified:** `UAV-C2-PQ-L2 v2` has **not** been modeled or proven in symbolic protocol verifiers (such as **Tamarin Prover** or **ProVerif**) or computational mechanized verifiers (such as **CryptoVerif** or **EasyCrypt**).
- Security assurance in this repository derives from manual cryptographic protocol review, remediating `F-01` through `F-17`, and executing the `157`-test unit, regression, and adversarial test suite in `test_protocol.py`.

---

## 2. Third-Party Cryptographic Library Internals (`liboqs` and OpenSSL)
- **Out of Audit Scope:** The C and assembly implementations inside `liboqs 0.16.0` (`ML-KEM-768`, `ML-DSA-65`) and `cryptography 50.0.1` / OpenSSL (`AES-256-GCM`, `HKDF-SHA-256`, `HMAC-SHA-256`) were treated as black-box dependencies and were **not** audited at the C/assembly source or binary level.
- **Not FIPS 140-3 Validated:** `liboqs` is an open-source prototyping library from the Open Quantum Safe project and is not a NIST CMVP FIPS 140-3 validated cryptographic module.

---

## 3. Side-Channel Resistance & CPython Memory Model Limitations
- **Physical & Microarchitectural Side Channels Not Assessed:** Timing side channels inside C libraries, cache-timing attacks, power analysis (SPA/DPA), electromagnetic emanations (EMA), and fault injection on flight hardware were not tested.
- **CPython Immutable `bytes` Limitation (`F-16`):** While `SessionKeys.clear()` and `Session._clear_secrets()` overwrite mutable `bytearray` mirrors (`_sender_key_buf`, `_receiver_key_buf`, `_root_secret_buf`) in place upon session termination or rekeying, Python's `cryptography` and `liboqs-python` bindings require and return immutable Python `bytes` objects. In CPython, immutable `bytes` buffers cannot be safely zeroed from pure Python prior to garbage collection, and copies may persist in allocator pages or swap space. Production flight systems require keys to reside inside a hardware security module (HSM), Secure Element, or C/Rust memory locked via `mlock`/`VirtualLock` and wiped via `explicit_bzero`/`SecureZeroMemory`.

---

## 4. Transport, Radio Link (Layer 1) & Flight Control (Layer 3) Boundaries
- **In-Memory Transport Only:** All benchmarks and tests run over `LocalTransport` (in-process Python `collections.deque` queues). No real RF modem, MAVLink framing, packet fragmentation/reassembly, forward error correction (FEC), or UDP/serial socket transport is implemented in Layer 2.
- **Volumetric Jamming & Link Flooding:** While `Receiver` enforces sliding-window handshake rate limiting and validates sequence windows prior to `ML-DSA-65` signature verification, a volumetric RF jammer or packet flooder can still saturate the physical channel (Layer 1).
- **Clock Synchronization Requirement (`F-10`):** Replay/freshness checks on `HANDSHAKE_INIT` and `COMMAND` require the Ground Station and UAV wall clocks to be synchronized within `±60 seconds` (`HANDSHAKE_MAX_TIMESTAMP_SKEW_SECONDS = 60.0`, `COMMAND_MAX_TIMESTAMP_SKEW_SECONDS = 60.0`), while session duration uses `time.monotonic()`.
- **Desktop x86_64 Benchmarks Only:** All timings in `layer2_protocol_benchmark_results.csv` were collected on a 16-logical-CPU Intel desktop running Windows 11 and Python 3.14.5. Performance on embedded companion computers (e.g., ARM Cortex-A72/A53 or Cortex-M microcontrollers) was not measured and will differ substantially.
