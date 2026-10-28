# UAV-C2-PQ-L2: Layer 2 Post-Quantum Cryptographic Security for UAV Command and Control

## 1. Project Overview

This repository presents the Layer 2 contribution to a UAV Command-and-Control (C2) security framework. It focuses on protecting communications between a ground station and an unmanned aerial vehicle (UAV) using post-quantum cryptography, authenticated encryption, secure session establishment, and replay protection.

The implementation is a Python-based research prototype intended for testing and evaluation in a simulated environment.

## 2. Objectives

- Establish cryptographic sessions using post-quantum key encapsulation.
- Authenticate protocol peers and messages using post-quantum digital signatures.
- Protect command messages with authenticated encryption.
- Derive session keys using a cryptographic key-derivation function.
- Validate message structure, sequence numbers, timestamps, and replay conditions.
- Support authenticated session rekeying and termination.
- Evaluate protocol correctness, message overhead, and processing latency.

## 3. Cryptographic Suite

The Layer 2 implementation uses the following algorithms and standards:

| Component | Algorithm | Purpose |
|---|---|---|
| Key establishment | ML-KEM-768 (FIPS 203) | Establish shared cryptographic secrets |
| Digital signatures | ML-DSA-65 (FIPS 204) | Authenticate protocol messages and peers |
| Key derivation | HKDF-SHA-256 (RFC 5869) | Derive session cryptographic keys |
| Authenticated encryption | AES-256-GCM (NIST SP 800-38D) | Protect message confidentiality and integrity |

## 4. Protocol Features

The version 2 implementation includes:

- Authenticated handshake and explicit key confirmation.
- Peer identity and role validation.
- Session key derivation and rekeying.
- Encrypted command, rekey, and termination messages.
- Input validation and command whitelisting.
- Sequence-number validation and bounded replay tracking.
- Timestamp freshness checks.
- Regression and adversarial protocol tests.

See `layer2_crypto_v2/PROTOCOL_V2_SPEC.md` for the protocol specification and `layer2_crypto_v2/SECURITY_REMEDIATION_REPORT.md` for the documented remediation work.

## 5. Repository Structure

```text
uav-c2-defense-layer2-pqc/
└── layer2_crypto_v2/
    ├── protocol/
    │   ├── constants.py
    │   ├── crypto_core.py
    │   ├── errors.py
    │   ├── identity.py
    │   ├── messages.py
    │   ├── session.py
    │   ├── sender.py
    │   ├── receiver.py
    │   └── transport.py
    ├── test_protocol.py
    ├── layer2_protocol_benchmark.py
    ├── PROTOCOL_V2_SPEC.md
    ├── SECURITY_REMEDIATION_REPORT.md
    ├── SECURITY_TRACEABILITY.csv
    ├── BENCHMARK_METHODOLOGY.md
    ├── NOT_REVIEWED_AND_LIMITATIONS.md
    └── FINAL_VALIDATION_REPORT.md
```

## 6. Environment and Dependencies

The documented test environment is Windows 11 with Python 3.14.5. The implementation uses `liboqs-python`, `cryptography`, `pytest`, and `matplotlib` for cryptographic operations, testing, and benchmarking.

Install the required dependencies according to the package requirements and the supported installation instructions for the installed Open Quantum Safe library.

## 7. Running the Tests

From the `layer2_crypto_v2` directory, run:

```powershell
python -m pytest test_protocol.py -v
```

The existing project report records 157 passing tests. Re-run the test suite in your own environment to confirm the result for the current checkout.

## 8. Running the Benchmarks

From the `layer2_crypto_v2` directory, run:

```powershell
python layer2_protocol_benchmark.py
```

The benchmark script records cryptographic primitive timings, serialization costs, end-to-end protocol latency, and message wire-size overhead. See `BENCHMARK_METHODOLOGY.md` and the generated results for details.

## 9. Scope and Limitations

This repository focuses on **Layer 2 cryptographic communication security**. It does not implement mission-intent authorization or reinforcement-learning-based anti-jamming as part of this contribution.

The implementation is a research prototype. Benchmark results depend on the execution environment, and simulation results alone do not establish flight readiness, formal security proof, or cryptographic module certification. Review `NOT_REVIEWED_AND_LIMITATIONS.md` before interpreting the security claims.

## 10. Research Contribution

This work investigates the engineering design and evaluation of a post-quantum cryptographic protocol for UAV command-and-control messages. It documents the protocol design, security-related checks, test evidence, benchmark methodology, and implementation limitations to support reproducible research and further evaluation.
