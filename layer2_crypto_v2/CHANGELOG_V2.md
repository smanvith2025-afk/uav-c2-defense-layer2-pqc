# UAV-C2-PQ-L2 v2 — Changelog (`v1.0.0` $\to$ `v2.0.0`)

## Version `2.0.0` (`PROTOCOL_VERSION = 2`) — 2026-10-28

### Breaking Wire-Protocol Changes (`v1` $\to$ `v2`)
1. **Protocol Version Bumped to `2`:**
   - `PROTOCOL_VERSION` in `protocol/constants.py` and `protocol/__init__.py` incremented from `1` to `2` (`__version__ = "2.0.0"`).
   - `MessageHeader.from_bytes()` rejects any packet with `version != 2` (including `v1` packets) with `VersionError`.
2. **`HandshakePayload` Schema Expanded (`F-01`, `F-03`, `F-05`, `F-10`):**
   - Added mandatory fields: `protocol_version`, `kem_algorithm`, `sig_algorithm`, `aead_algorithm`, `kdf_algorithm`, `recipient_id`, `timestamp` (finite float), and `handshake_nonce` (`16 B` hex).
   - `HANDSHAKE_RESPONSE` now echoes the initiator's `1,184 B` `sender_kem_key` (`2,368` hex chars) so the responder's `ML-DSA-65` signature is cryptographically bound to the initiator's ephemeral KEM public key.
   - Wire size changed from `13,128 B` $\to$ `13,287 B` (`HANDSHAKE_INIT`) and `10,740 B` $\to$ `15,451 B` (`HANDSHAKE_RESPONSE`).
3. **Length-Framed & Domain-Separated Handshake Confirmation (`F-04`):**
   - `HANDSHAKE_CONFIRM` now signs `TRANSCRIPT_CONFIRM_LABEL || uint32_be(len(init_pkt)) || init_pkt || uint32_be(len(resp_pkt)) || resp_pkt` instead of raw unframed packet concatenation.
4. **Two-Stage `HKDF-SHA-256` Key Schedule (`F-06`, `F-12`):**
   - Replaced single-stage `SessionKeys.from_shared_secret()` derivation with two-stage `derive_epoch_root_secret()` + `SessionKeys.from_root_secret()` binding `session_id`, `epoch`, `SHA256(transcript)`, `initiator_id`, and `responder_id` under `UAV-C2-PQ-L2-v2-*` domain labels.
5. **Identity-Signed & Key-Confirmed `RekeyPayload` (`F-12`, `F-13`):**
   - Replaced raw unauthenticated KEM public key / ciphertext payloads in `REKEY_INIT` (`1,234 B` in `v1`) and `REKEY_RESPONSE` (`1,138 B` in `v1`) with JSON-encoded, `ML-DSA-65`-signed `RekeyPayload` (`9,239 B` and `11,479 B` in `v2`) containing epoch numbers, `16 B` `rekey_nonce`, echoed `sender_kem_key`, `32 B` `HMAC-SHA-256` `key_confirm_tag`, and a `3,309 B` `ML-DSA-65` signature.
   - Epoch root secrets now chain `prev_root_secret || kem_shared_secret`.
6. **Identity-Signed `TerminatePayload` (`F-13`):**
   - Replaced raw 9-byte `b"TERMINATE"` (`59 B` wire packet in `v1`) with JSON-encoded, `ML-DSA-65`-signed `TerminatePayload` (`6,788 B` wire packet in `v2`) bound to `session_id`, `epoch`, `sequence`, `timestamp`, and `reason`.

### State Machine, Authorization & Validation Improvements
7. **Isolated Pending Handshake Slot & Explicit Confirmation State (`F-01`, `F-02`):**
   - Added `SessionState.AWAITING_CONFIRM` and isolated `Receiver._pending_session` from active `Receiver._session`.
   - Unauthenticated, malformed, stale, or replayed `HANDSHAKE_INIT` packets never overwrite or disrupt an active `ESTABLISHED` session.
8. **End-to-End Role Enforcement (`F-15`):**
   - Added `TrustStore.verify_peer_role()`. Enforced `ROLE_GROUND_STATION` for initiators/command senders and `ROLE_UAV` for responders/command receivers across handshake initiation, handshake response, command processing, rekeying, and session termination.
9. **Atomic Rekey Rollback (`F-13`):**
   - Added `Session.prepare_rekey()`, `Session.commit_rekey()`, and `Session.abort_rekey()`. A failed `complete_rekey()` on the initiator rolls back cleanly to `SessionState.ESTABLISHED` on the current epoch.
10. **Whitelisted Commands & Strict JSON/Timestamp Validation (`F-09`, `F-10`):**
    - Enforced `command in VALID_COMMANDS` in `CommandPayload` and `Sender.send_command()`.
    - Rejected `NaN`, `Infinity`, `-Infinity`, booleans, negative timestamps, and timestamps outside $\pm 60\text{ s}$.
11. **Pre-FFI FIPS Length Checks & Sequence-Before-Signature Ordering (`F-05`, `F-11`):**
    - Enforced exact FIPS 203/204 byte lengths in `protocol/crypto_core.py`.
    - Moved `session.validate_recv_sequence()` before `sig_verify()` in `Receiver.receive_packet()`.
12. **Bounded Nonce Tracking, Monotonic Session Clock & Key Hygiene (`F-07`, `F-08`, `F-14`, `F-16`, `F-17`):**
    - Bounded `_emitted_nonces` and `_received_nonces` to `NONCE_WINDOW_SIZE = 200` entries (`O(1)` memory) and validated nonces on all control packets.
    - Switched session lifetime tracking to `time.monotonic()`.
    - Added mutable `bytearray` zero-fill in `SessionKeys.clear()` and `hmac.compare_digest` in `TrustStore.verify_signing_key()`.
