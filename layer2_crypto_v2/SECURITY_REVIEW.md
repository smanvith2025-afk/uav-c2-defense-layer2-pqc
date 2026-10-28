# Layer 2 Security Review, Threat Model, and Known Limitations

## 1. Threat Model (Dolev-Yao Adversary on the UAV C2 Link)

We evaluate the Layer 2 protocol (`UAV-C2-PQ-L2 v1`) against an active, quantum-capable Dolev-Yao adversary ($\mathcal{A}$) with full control over the wireless command-and-control communication channel between the Ground Station (`gs1`) and the UAV (`uav1`):

### Adversary Capabilities
1. **Passive Eavesdropping & Store-Now-Decrypt-Later (SNDL):** $\mathcal{A}$ records all handshake and command transcripts for future decryption on a Cryptographically Relevant Quantum Computer (CRQC) capable of running Shor's and Grover's algorithms.
2. **Active Packet Injection, Tampering, & Truncation:** $\mathcal{A}$ can flip bits in headers, nonces, ciphertexts, or authentication tags, inject forged commands, or truncate frames.
3. **Replay & Reordering:** $\mathcal{A}$ can capture valid encrypted command packets and replay them later within the same session, across sessions, or out of order.
4. **Man-in-the-Middle (MitM) & Public-Key Substitution:** $\mathcal{A}$ can intercept handshake messages and attempt to substitute its own `ML-KEM-768` or `ML-DSA-65` public keys.
5. **Session State Desynchronization:** $\mathcal{A}$ can inject bogus handshake, rekey, or terminate frames to disrupt or hijack session state.

### Explicit Trust Assumptions
1. **Endpoint Integrity:** The Ground Station and UAV operating environments are not compromised at runtime; private signing keys and active session keys reside in protected process memory.
2. **Out-of-Band Trust Provisioning:** Each peer's `TrustStore` is pre-provisioned out-of-band with authentic `ML-DSA-65` public keys mapped to peer identifiers (`gs1`, `uav1`).
3. **CSPRNG Availability:** The host operating system provides cryptographically secure randomness via `os.urandom` and `liboqs` internal CSPRNGs.

---

## 2. Security Analysis of Protocol Mechanisms

| Threat / Attack Vector | Defense Mechanism in `UAV-C2-PQ-L2 v1` | Verification Evidence (`test_protocol.py`) |
|---|---|---|
| Quantum Key Compromise (Shor's Algorithm) | Ephemeral `ML-KEM-768` (FIPS 203, NIST Security Category 3) key establishment + `ML-DSA-65` (FIPS 204, Category 3) signatures. | `TestSuccessfulHandshake`, `TestSessionKeyAgreement` |
| Symmetric Quantum Search (Grover's Algorithm) | `AES-256-GCM` (256-bit keys provide ~128-bit post-quantum security margin) + `HKDF-SHA-256`. | `TestValidCommand` |
| Unauthenticated KEM / MitM Key Substitution | `HANDSHAKE_INIT` and `HANDSHAKE_RESPONSE` are signed with `ML-DSA-65` and verified against pre-provisioned keys in `TrustStore`. `HANDSHAKE_CONFIRM` signs the full handshake transcript. | `TestPublicKeySubstitution`, `TestHandshakeTranscriptModification`, `TestHandshakeFailures` |
| Ciphertext or Command Bit-Flipping | `AES-256-GCM` 128-bit authentication tag verified prior to JSON parsing or command processing. | `TestModifiedCiphertext`, `TestModifiedCommand`, `TestCryptoFailures` |
| Header Tampering (Version, Type, Session ID, Sequence) | The 22-byte binary `MessageHeader` is authenticated as `AES-256-GCM` Associated Data (AAD) AND bound inside the canonical `ML-DSA-65` command signature. | `TestModifiedHeader`, `TestUnsupportedVersion`, `TestInvalidMessageTypes` |
| Compromised Session Key Command Forgery | Defense-in-depth: Every command carries an `ML-DSA-65` signature over `(version, sender_id, recipient_id, session_id, sequence, command, params, timestamp)`. Knowledge of the symmetric `AES-256-GCM` key alone is insufficient to forge a valid command without the sender's `ML-DSA-65` private key. | `TestInvalidSignature`, `TestWrongSessionKey` |
| Intra-Session Replay & Duplicate Sequence | Monotonic 32-bit sequence counter (`validate_recv_sequence`), seen-sequence tracking (`_seen_sequences`), and seen-nonce tracking (`_received_nonces`). | `TestReplayedMessage`, `TestDuplicateSequence` |
| Cross-Session & Post-Restart Replay | Random 128-bit `session_id` generated per handshake, included in `HKDF` salt, authenticated in header AAD, and signed inside every `CommandPayload`. | `TestSessionRestart`, `TestCrossSession` |
| AES-GCM Nonce Reuse | Deterministic 96-bit nonce (`4B HKDF prefix || 8B monotonic counter`) + explicit `_emitted_nonces` and `_received_nonces` sets + hard cap at $2^{20}$ messages per key epoch. | `TestNonceUniqueness` (`test_nonces_are_unique`, `test_nonce_reuse_rejected_by_receiver`, `test_nonce_counter_exhaustion`) |
| Peer Revocation | `TrustStore.revoke_peer` blocks both new handshakes and mid-session commands from revoked identities. | `TestUnknownRevokedPeer` (`test_revoked_peer_during_command`) |

---

## 3. Known Limitations & Engineering Boundaries

To maintain scientific and engineering rigor, we explicitly document what this implementation **does not** guarantee:

1. **Custom Protocol vs. Standardized Transport Security:**
   - While `UAV-C2-PQ-L2 v1` uses NIST-standardized primitives (`ML-KEM-768`, `ML-DSA-65`, `HKDF-SHA-256`, `AES-256-GCM`) and follows established authenticated key-exchange principles (signed ephemeral KEM + transcript confirmation), it is a research reference protocol and has **not** undergone formal symbolic/computational verification (e.g., Tamarin, ProVerif, or CryptoVerif). Production avionics should evaluate standardized post-quantum protocols (such as PQ-TLS 1.3 or IKEv2 with ML-KEM) once ratified for constrained C2 links, or subject this state machine to independent formal verification.
2. **In-Memory Replay State (Non-Persistent Across Power Loss):**
   - Session state, sequence counters, and seen-nonce sets reside in volatile RAM. Because each power cycle or process restart requires a fresh authenticated handshake with a newly generated 128-bit `session_id` and fresh ephemeral `ML-KEM-768` keys, packets from prior sessions are cryptographically rejected (`TestSessionRestart`). However, the prototype does not persist session state to non-volatile flash storage across reboots.
3. **Single-Threaded Execution Model:**
   - `TrustStore`, `Session`, `Sender`, and `Receiver` are designed for deterministic single-threaded event loops. If deployed in a multi-threaded runtime, callers must serialize access to `Session` state transitions and sequence counters with a mutex.
4. **Python Memory Zeroization Caveat:**
   - `SessionKeys.clear()` overwrites key buffers via `bytearray` mutation upon session termination or expiration. However, CPython's immutable `bytes` objects and garbage collector do not guarantee immediate physical RAM erasure or `mlock` protection against OS swap/core dumps. A flight-certified implementation should manage keys inside a C/Rust extension or Hardware Security Module (HSM / TPM).
5. **Handshake Denial-of-Service (DoS) & Fragmentation:**
   - `HANDSHAKE_INIT` (`13,041 B`), `HANDSHAKE_RESPONSE` (`12,839 B`), and `COMMAND` (`6,798 B` with hex-encoded `ML-DSA-65` signature) exceed standard 255-byte MAVLink v2 frames and 1,500-byte Ethernet MTUs. Over low-bandwidth sub-GHz telemetry radios, these packets require link-layer fragmentation and reassembly, which increases susceptibility to packet-loss amplification and unauthenticated `HANDSHAKE_INIT` signature-verification CPU exhaustion. Future work should replace hex-encoded JSON payloads with compact binary CBOR/struct serialization (reducing command wire size from `6,798 B` to `~3,420 B`) and consider stateless cookie challenges during handshake initiation.
6. **Microbenchmarks vs. Real-Time Flight Control:**
   - All latency measurements (`2.48 ms` mean end-to-end command round-trip; `9.52 ms` full handshake) were collected on an Intel64 Windows 11 workstation (`16 logical CPUs`) using an in-memory queue (`LocalTransport`). They do **not** include RF serialization delay, packet loss, embedded ARM Cortex-M/Cortex-A CPU constraints, or RTOS scheduling jitter.

---

## 4. Implementation Status Summary

| Category | Status | Details |
|---|---|---|
| **Implemented and Tested** | Complete | `ML-KEM-768`, `ML-DSA-65`, `HKDF-SHA-256`, `AES-256-GCM`, `TrustStore` (registration, rotation, revocation), 3-way authenticated handshake, per-command contextual signing + AAD encryption, deterministic 96-bit nonces + reuse detection, replay/out-of-order defense, in-session rekey, session expiration/termination, 120 automated `pytest` tests. |
| **Implemented, Prototype Scope** | Documented | `LocalTransport` in-memory queue, `CommandRecord` mock UAV command handler, JSON payload encoding inside AEAD ciphertext. |
| **Planned / Future Work** | Out of Scope | Binary CBOR/struct payload packing, UDP/serial link fragmentation layer, hardware security module (HSM) key storage, embedded ARM Cortex-A/M benchmarking. |
| **Requiring Independent Review** | Noted | Formal symbolic verification (Tamarin/ProVerif) of the handshake and rekey state machine; side-channel analysis on target avionics hardware. |
