# Layer 2 Post-Quantum UAV Command Security Protocol Specification (`UAV-C2-PQ-L2 v1`)

## 1. Protocol Overview

- **Protocol Name:** `UAV-C2-PQ-L2`
- **Protocol Version:** `1` (`0x01`)
- **Roles:**
  - **Initiator / Command Sender (`ground_station`):** Initiates authenticated session establishment, signs and encrypts UAV commands, initiates in-session rekeying, and terminates sessions.
  - **Responder / Command Receiver (`uav`):** Validates handshake initiation, encapsulates post-quantum session entropy, enforces strict fail-closed command verification, and dispatches accepted commands to a flight-control interface (mocked in Layer 2).

---

## 2. Cryptographic Suite & Parameters

| Function | Algorithm | Standard / Reference | Key / Output Sizes |
|---|---|---|---|
| Key Encapsulation Mechanism (KEM) | `ML-KEM-768` | NIST FIPS 203 | Public Key: `1,184 B`; Secret Key: `2,400 B`; Ciphertext: `1,088 B`; Shared Secret: `32 B` |
| Digital Signature | `ML-DSA-65` | NIST FIPS 204 | Public Key: `1,952 B`; Secret Key: `4,032 B`; Signature: `3,309 B` |
| Key Derivation Function (KDF) | `HKDF-SHA-256` | IETF RFC 5869 | Input Keying Material: `32 B`; Salt: `20 B` (`session_id \|\| epoch`); Derived Keys: `32 B` (`256-bit`) |
| Authenticated Encryption (AEAD) | `AES-256-GCM` | NIST SP 800-38D | Key: `32 B` (`256-bit`); Nonce: `12 B` (`96-bit`); Authentication Tag: `16 B` (`128-bit`) |

---

## 3. Identity & Trust Provisioning (`protocol/identity.py`)

Because `ML-KEM-768` alone is an unauthenticated key encapsulation mechanism vulnerable to active Man-in-the-Middle (MitM) public-key substitution, peer authentication relies on long-term `ML-DSA-65` identity keys registered out-of-band in an explicit `TrustStore`:

1. **Registration (`TrustStore.register_peer`):** Binds a unique string `peer_id`, a role (`ground_station` or `uav`), and the peer's `1,952`-byte `ML-DSA-65` public key.
2. **Key Verification (`TrustStore.verify_signing_key`):** During handshake and command processing, the presented or lookup signing key is compared byte-for-byte against the registered trusted key for `peer_id`. Mismatches raise `TrustError` (`Possible key substitution attack`).
3. **Key Rotation:** Re-registering an existing `peer_id` atomically updates its trusted `ML-DSA-65` public key and clears prior revocation state.
4. **Revocation (`TrustStore.revoke_peer`):** Marks a peer identity as revoked with a timestamp. Any subsequent handshake or in-session command from a revoked peer raises `TrustError` and fails closed.

---

## 4. Wire Framing & Message Formats (`protocol/messages.py`)

### 4.1 Binary Wire Header (22 Bytes, Big-Endian)

Every protocol packet begins with a fixed 22-byte binary header encoded via `struct.Struct(">BB16sI")`:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (1B) | Msg Type (1B) |       Session ID (16B) ...    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  ... Session ID (continued)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      ... Session ID           |     Sequence Number (4B)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Sequence Number (continued)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Version (`uint8`, offset 0):** Must equal `1` (`PROTOCOL_VERSION`). Any other value raises `VersionError`.
- **Message Type (`uint8`, offset 1):**
  - `1`: `MSG_TYPE_HANDSHAKE_INIT`
  - `2`: `MSG_TYPE_HANDSHAKE_RESPONSE`
  - `3`: `MSG_TYPE_HANDSHAKE_CONFIRM`
  - `4`: `MSG_TYPE_COMMAND`
  - `5`: `MSG_TYPE_REKEY`
  - `6`: `MSG_TYPE_TERMINATE`
- **Session ID (`16 bytes`, offset 2..17):** Cryptographically random 128-bit session identifier generated via `os.urandom(16)`.
- **Sequence Number (`uint32`, big-endian, offset 18..21):** `0` for handshake control messages; strictly positive monotonic integer (`>= 1`) for encrypted session packets (`COMMAND`, `REKEY_INIT`, `TERMINATE`).

### 4.2 Encrypted Packet Wire Layout

For all post-establishment messages (`MSG_TYPE_HANDSHAKE_CONFIRM`, `MSG_TYPE_COMMAND`, `MSG_TYPE_REKEY`, `MSG_TYPE_TERMINATE`), the wire packet layout is:

$$\text{Packet} = \underbrace{\text{Header}}_{22\text{ B (AAD)}} \parallel \underbrace{\text{Nonce}}_{12\text{ B}} \parallel \underbrace{\text{Ciphertext} \parallel \text{GCM Tag}}_{\text{Variable} + 16\text{ B}}$$

- **Authenticated Associated Data (AAD):** The exact 22-byte binary header is passed as `associated_data` to `AES-256-GCM`. Modifying any bit of the version, message type, session ID, or sequence number causes `AES-256-GCM` tag verification to fail with `AuthenticationError`.
- **Packet Size Bounds:**
  - `MIN_PACKET_SIZE = 50 bytes` (`22B header + 12B nonce + 16B GCM tag`).
  - `MAX_PACKET_SIZE = 65,536 bytes`.
  - `MAX_COMMAND_SIZE = 16,384 bytes` (accommodating the hex-encoded `3,309`-byte `ML-DSA-65` signature plus command JSON fields).

---

## 5. Authenticated Handshake & Key Derivation (`protocol/sender.py`, `protocol/receiver.py`)

```mermaid
sequenceDiagram
    participant GS as Sender (Ground Station: gs1)
    participant UAV as Receiver (UAV: uav1)

    Note over GS,UAV: Pre-provisioned TrustStore holds ML-DSA-65 public keys for gs1 and uav1
    GS->>GS: Generate session_id (16B) & ephemeral ML-KEM-768 keypair (ek_pk, ek_sk)
    GS->>GS: Sign canonical HandshakeInit context with gs1 ML-DSA-65 sk
    GS->>UAV: 1. HANDSHAKE_INIT (Header + HandshakePayload[gs1, ek_pk, sig_gs]) [13,041 B]
    UAV->>UAV: Verify gs1 identity & ML-DSA-65 sig_gs against TrustStore
    UAV->>UAV: Encapsulate (kem_ct, shared_secret) = ML-KEM-768.Encap(ek_pk)
    UAV->>UAV: Derive directional keys & nonce prefixes via HKDF-SHA-256(shared_secret, salt=session_id||0)
    UAV->>UAV: Sign canonical HandshakeResponse context with uav1 ML-DSA-65 sk
    UAV->>GS: 2. HANDSHAKE_RESPONSE (Header + HandshakePayload[uav1, kem_ct, sig_uav]) [12,839 B]
    GS->>GS: Verify uav1 identity & ML-DSA-65 sig_uav against TrustStore
    GS->>GS: Decapsulate shared_secret = ML-KEM-768.Decap(kem_ct, ek_sk)
    GS->>GS: Derive directional keys & nonce prefixes via HKDF-SHA-256; erase ek_sk
    GS->>GS: Sign full transcript (Init || Response) with gs1 ML-DSA-65 sk & encrypt under sender_enc_key
    GS->>UAV: 3. HANDSHAKE_CONFIRM (Header [AAD] + Nonce + AES-GCM(sig_transcript)) [3,359 B]
    UAV->>UAV: Decrypt under sender_enc_key & verify sig_transcript over (Init || Response)
    Note over GS,UAV: Session ESTABLISHED (Mutual Authentication + Ephemeral PQ Forward Secrecy)
```

### 5.1 Canonical Handshake Signing Context

Both `HANDSHAKE_INIT` and `HANDSHAKE_RESPONSE` sign a deterministic UTF-8 JSON object (`sort_keys=True, separators=(",", ":")`) covering:
- `protocol_version` (`1`)
- `sender_id` and `sender_role`
- `recipient_id` (explicitly binds the intended peer identity)
- `session_id` (hex)
- `sender_signing_key` (hex)
- `sender_kem_key` (hex; ephemeral `ML-KEM-768` public key in `INIT`, empty in `RESPONSE`)
- `kem_ciphertext` (hex; empty in `INIT`, `1,088`-byte ciphertext in `RESPONSE`)

### 5.2 Context-Bound HKDF-SHA-256 Key Schedule

Given the 32-byte `ML-KEM-768` `shared_secret`, the 16-byte `session_id`, and the 4-byte big-endian `rekey_epoch` (`0` initially), the protocol constructs `salt = session_id || struct.pack(">I", epoch)` (`20 bytes`) and derives four distinct outputs via `HKDF-SHA-256`:

1. **Sender Encryption Key (`32 bytes`):** `info = b"UAV-C2-PQ-L2-v1-sender-enc"`
2. **Receiver Encryption Key (`32 bytes`):** `info = b"UAV-C2-PQ-L2-v1-receiver-enc"`
3. **Sender Nonce Fixed Prefix (`4 bytes`):** `info = b"UAV-C2-PQ-L2-v1-sender-auth"`
4. **Receiver Nonce Fixed Prefix (`4 bytes`):** `info = b"UAV-C2-PQ-L2-v1-receiver-auth"`

---

## 6. Protected Command Format & Multi-Stage Validation Pipeline

### 6.1 Command Canonical Signing Context vs. Encrypted Payload

Before encrypting a command, the sender constructs a `CommandPayload` and signs the deterministic canonical JSON representation of:

```json
{
  "command": "TAKEOFF",
  "params": "ALTITUDE 10",
  "protocol_version": 1,
  "recipient_id": "uav1",
  "sender_id": "gs1",
  "sequence": 1,
  "session_id": "<32-char hex>",
  "timestamp": 1793123456.789
}
```

The resulting `3,309`-byte `ML-DSA-65` signature is hex-encoded inside the JSON payload (`6,748 bytes` for `TAKEOFF ALTITUDE 10`), which is then encrypted with `AES-256-GCM` using `sender_enc_key`, the deterministic 96-bit sender nonce, and the 22-byte binary `MessageHeader` as AAD (`6,798 bytes` total on the wire).

### 6.2 Receiver 8-Stage Fail-Closed Validation Pipeline (`Receiver.receive_packet`)

The UAV receiver executes the following strict validation order:
1. **Framing & Bounds Check (`parse_packet`):** Verify `Packet` is `bytes` and `50 <= len(packet) <= 65,536`.
2. **Header & Version Validation (`MessageHeader.from_bytes`):** Unpack header; verify `version == 1` and `msg_type` in `{1..6}`.
3. **Session Liveness & Binding (`Session.check_alive`):** Verify an active session exists in `ESTABLISHED` state, `header.session_id == session.session_id`, elapsed time `<= 1,800 s`, and `message_count < 2^20`.
4. **AEAD Decryption & Header Authentication (`aes_gcm_decrypt`):** Authenticate the 22-byte header AAD and decrypt the ciphertext using `sender_enc_key`. Reject immediately on `InvalidTag`.
5. **Payload Structure & Identity Binding (`CommandPayload.from_json_bytes`):** Verify `len(plaintext) <= 16,384`, validate JSON schema and field types (rejecting Python `bool` where `int`/`float` is required), and verify `payload.sender_id == session.remote_peer_id` and `payload.recipient_id == receiver.peer_id`.
6. **Peer Trust & ML-DSA-65 Signature Verification:** Query `TrustStore.get_peer(payload.sender_id)` (checking revocation) and verify the `ML-DSA-65` signature over the reconstructed canonical command context (which includes `header.sequence` and `session.session_id`).
7. **Sequence Number & Nonce Uniqueness Check:** Verify `header.sequence` via `validate_recv_sequence` (rejecting `<= 0`, duplicates, stale sequences, or gaps `> 100`) and verify the 96-bit `nonce` has never been used in this key epoch via `validate_and_record_nonce`.
8. **State Commit & Command Dispatch:** Commit `header.sequence` (`accept_recv_sequence`), record acceptance in `CommandRecord`, and invoke `command_handler`.

---

## 7. AES-GCM Nonce Uniqueness, Replay Policy, & Session Lifecycle (`protocol/session.py`)

1. **Deterministic 96-Bit Nonce Construction (NIST SP 800-38D §8.2.1):**
   $$\text{Nonce}_{96} = \text{Prefix}_{32\text{ (HKDF)}} \parallel \text{Counter}_{64\text{ (Big-Endian Monotonic)}}$$
   In addition to monotonic counter generation, `Session` maintains `_emitted_nonces` on the sender and `_received_nonces` on the receiver to guarantee that a `(key, nonce)` pair is never reused.
2. **Counter Exhaustion & Lifetime Limits:**
   - Maximum session duration: `SESSION_MAX_LIFETIME_SECONDS = 1,800` (30 minutes).
   - Maximum messages per key epoch: `SESSION_MAX_MESSAGES = 1,048,576` ($2^{20}$). Reaching either limit transitions the session to `EXPIRED`, zeroes key material, and raises `SessionExpiredError` / `NonceError`.
3. **Replay & Out-of-Order Policy:**
   - Default policy (`allow_out_of_order = False`): Strict monotonic sequence numbers (`sequence > recv_sequence` and `sequence <= recv_sequence + 100`), preventing late execution of superseded flight commands.
   - Optional sliding-window policy (`allow_out_of_order = True`): Accepts out-of-order packets within a window of `MAX_SEQUENCE_GAP = 100` while rejecting duplicates via `_seen_sequences`.
4. **In-Session Ephemeral Rekey (`MSG_TYPE_REKEY`):**
   - Generates a fresh ephemeral `ML-KEM-768` keypair, encapsulates a new shared secret over the encrypted session, increments `rekey_epoch`, derives fresh directional keys and nonce prefixes via `HKDF-SHA-256`, and resets nonce counters and seen-nonce sets.
5. **Session Termination (`MSG_TYPE_TERMINATE`):**
   - Sends an authenticated `TERMINATE` packet, overwrites in-memory key bytearrays with zeros (`SessionKeys.clear()`), and transitions to `TERMINATED`.
