# UAV-C2-PQ-L2 v2 — Security Remediation Report

**Target Workspace:** `C:\Users\smanv\UAV_Security_Project\layer2_crypto_v2`
**Baseline Audited Workspace (Preserved Read-Only):** `C:\Users\smanv\UAV_Security_Project\layer2_crypto`
**Protocol Version:** `UAV-C2-PQ-L2 v2` (`PROTOCOL_VERSION = 2`, `__version__ = "2.0.0"`)
**Verification Suite:** `test_protocol.py` (`157 passed in 2.02s` on Python 3.14.5, pytest 9.1.1, liboqs 0.16.0, cryptography 50.0.1)

---

## 1. Threat Model & Severity Grading Scale

### 1.1 Threat Model
1. **Network Attacker (Dolev–Yao):** Full control over the untrusted UAV command-and-control transport channel (`inject`, `replay`, `reorder`, `drop`, `modify`, `delay`).
2. **Compromised Past/Current Session Key Attacker:** Holds stolen symmetric traffic keys (`sender_enc_key`, `receiver_enc_key`) from a previous epoch or the current epoch, without holding long-term `ML-DSA-65` identity secret keys.
3. **Revoked or Unauthenticated Identity Key Attacker:** Holds a valid `ML-DSA-65` keypair that is either unregistered or revoked in the peer's `TrustStore`.
4. **Authorized Peer with Wrong Role (Malicious/Buggy Peer in TrustStore):** Holds a registered, non-revoked `ML-DSA-65` keypair in `TrustStore`, but is provisioned with an unauthorized role (e.g., a second UAV `"uav2"` attempting to impersonate a ground station to send commands to `"uav1"`, or a ground station `"gs2"` attempting to act as a UAV responder).

### 1.2 Severity Scale
- **Critical:** Remote key compromise or authentication bypass.
- **High:** Session hijack, replay acceptance, unauthorized role assumption, or MITM-capable unauthenticated rekey/termination.
- **Medium:** Remote denial-of-service (DoS) or state corruption by an unauthenticated peer, or missing protocol input validation.
- **Low:** Defense-in-depth hardening, clock-jump sensitivity, or bounded memory growth.
- **Info:** Documentation, language runtime limitation, or informational note.

---

## 2. Summary of Finding Dispositions (`F-01` through `F-17`)

| Finding ID | Title | Severity | Priority Group | v2 Status | Primary v2 Code Locations | Primary Regression Tests |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F-01** | Unauthenticated `HANDSHAKE_INIT` overwrites active `ESTABLISHED` session and lacks replay/freshness protection | **Medium** | P0-A | **FIXED** | `protocol/receiver.py`, `protocol/messages.py` | `TestV2HandshakeStateAndSessionPreservation::test_f01_*` |
| **F-02** | Responder transitions to `ESTABLISHED` before verifying `HANDSHAKE_CONFIRM` | **High** | P0-A | **FIXED** | `protocol/session.py`, `protocol/receiver.py` | `TestV2HandshakeStateAndSessionPreservation::test_f02_*` |
| **F-03** | `HANDSHAKE_RESPONSE` omits initiator KEM public key, recipient identity, and freshness nonce | **Medium** | P0-A | **FIXED** | `protocol/messages.py`, `protocol/sender.py`, `protocol/receiver.py` | `TestV2HandshakeStateAndSessionPreservation::test_f03_*` |
| **F-04** | Handshake transcript concatenates raw packets without length framing or domain label | **Low** | P0-A | **FIXED** | `protocol/session.py`, `protocol/sender.py`, `protocol/receiver.py` | `TestV2HandshakeStateAndSessionPreservation::test_f04_*` |
| **F-05** | Missing explicit FIPS 203/204 byte-length validation before `liboqs` C FFI calls and missing suite binding | **Medium** | P1 | **FIXED** | `protocol/crypto_core.py`, `protocol/messages.py` | `TestV2HandshakeStateAndSessionPreservation::test_f05_*` |
| **F-06** | Single-stage HKDF key schedule omits handshake transcript hash and peer identities | **Medium** | P0-A / P0-C | **FIXED** | `protocol/session.py` | `TestV2RekeyAndKeyScheduleSecurity::test_f06_*` |
| **F-07** | Receiver does not record or check AEAD nonces on control packets (`CONFIRM`, `REKEY`, `TERMINATE`) | **Low** | P1 | **FIXED** | `protocol/receiver.py`, `protocol/sender.py` | `TestV2BoundsReplayAndLifecycle::test_f07_*` |
| **F-08** | Unbounded `_emitted_nonces` and `_received_nonces` sets grow `O(N)` over session lifetime | **Low** | P1 | **FIXED** | `protocol/session.py` | `TestV2BoundsReplayAndLifecycle::test_f08_*` |
| **F-09** | `VALID_COMMANDS` whitelist defined in `constants.py` is never enforced in `CommandPayload` or `Receiver` | **Medium** | P1 | **FIXED** | `protocol/messages.py`, `protocol/sender.py` | `TestV2CommandValidationAndTimestamps::test_f09_*` |
| **F-10** | `CommandPayload` accepts `NaN`/`Infinity`/negative timestamps and Receiver does not enforce command timestamp freshness | **Medium** | P1 | **FIXED** | `protocol/messages.py`, `protocol/receiver.py` | `TestV2CommandValidationAndTimestamps::test_f10_*` |
| **F-11** | Receiver performs expensive `ML-DSA-65` signature verification before sequence-window replay check | **Medium** | P1 | **FIXED** | `protocol/receiver.py` | `TestV2BoundsReplayAndLifecycle::test_f11_*` |
| **F-12** | Session rekey (`REKEY_INIT`/`REKEY_RESPONSE`) is not signed by `ML-DSA-65` long-term identity keys and does not chain root secrets | **High** | P0-C | **FIXED** | `protocol/messages.py`, `protocol/session.py`, `protocol/sender.py`, `protocol/receiver.py` | `TestV2RekeyAndKeyScheduleSecurity::test_f12_*` |
| **F-13** | Non-atomic initiator rekey state transition (`complete_rekey` leaves session unusable on failure) and unsigned `TERMINATE` | **Medium** | P0-C | **FIXED** | `protocol/session.py`, `protocol/sender.py`, `protocol/receiver.py` | `TestV2RekeyAndKeyScheduleSecurity::test_f13_*` |
| **F-14** | Session lifetime expiration uses wall-clock `time.time()` instead of monotonic clock `time.monotonic()` | **Low** | P2 | **FIXED** | `protocol/session.py` | `TestV2BoundsReplayAndLifecycle::test_f14_*` |
| **F-15** | Peer role (`ground_station` vs. `uav`) is never enforced in `TrustStore`, handshake, or command processing | **High** | P0-B | **FIXED** | `protocol/identity.py`, `protocol/sender.py`, `protocol/receiver.py` | `TestV2RoleEnforcement::test_f15_*` |
| **F-16** | `Session._clear_secrets()` sets references to `None` without zeroing mutable key buffers | **Info** | P2 | **FIXED (Best-Effort)** | `protocol/session.py` | `TestV2BoundsReplayAndLifecycle::test_f16_*` |
| **F-17** | `TrustStore.verify_signing_key` uses `==` instead of `hmac.compare_digest` | **Info** | P2 | **FIXED** | `protocol/identity.py` | `TestV2BoundsReplayAndLifecycle::test_f17_*` |

---

## 3. Detailed Finding-by-Finding Remediation & Evidence

### F-01 — Unauthenticated `HANDSHAKE_INIT` Overwrites Active Session and Lacks Freshness/Replay Protection
- **Severity:** Medium (Remote DoS / session teardown by replaying a captured `HANDSHAKE_INIT` or sending a malformed `HANDSHAKE_INIT`).
- **v1 Root Cause:** In `v1` `protocol/receiver.py:114-121`, `Receiver.process_handshake_init()` unconditionally executed `if self._session is not None: self._session.terminate(); self._session = None` at the very start of the method before parsing or verifying anything. Furthermore, `HANDSHAKE_INIT` had no timestamp, no challenge nonce, and no replay cache on the responder.
- **v2 Remediation:**
  1. Separated `Receiver._pending_session` (for handshakes in `AWAITING_CONFIRM`) from `Receiver._session` (for the active `ESTABLISHED` session) in [`protocol/receiver.py`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L64-L82).
  2. Added `timestamp` and 16-byte `handshake_nonce` to [`HandshakePayload`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/messages.py#L315-L337).
  3. Added timestamp freshness check (`HANDSHAKE_MAX_TIMESTAMP_SKEW_SECONDS = 60.0`), bounded replay cache (`_seen_handshake_ids`, max `1024`), sliding-window rate limiting (`50` attempts per `10.0s`), and pending-slot timeout (`10.0s`) in [`Receiver.process_handshake_init`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L140-L280).
  4. Active `Receiver._session` is only replaced when `process_handshake_confirm()` succeeds in [`Receiver.process_handshake_confirm`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L282-L356).
- **Regression Tests:**
  - `TestV2HandshakeStateAndSessionPreservation::test_f01_malformed_handshake_init_preserves_established_session`
  - `TestV2HandshakeStateAndSessionPreservation::test_f01_replayed_handshake_init_rejected_and_preserves_session`
  - `TestV2HandshakeStateAndSessionPreservation::test_f01_stale_handshake_init_rejected`
  - `TestV2HandshakeStateAndSessionPreservation::test_f01_failed_handshake_confirm_preserves_established_session`

### F-02 — Responder Transitions to `ESTABLISHED` Before Verifying `HANDSHAKE_CONFIRM`
- **Severity:** High (Premature session activation before explicit key confirmation and initiator transcript verification).
- **v1 Root Cause:** In `v1` `protocol/receiver.py:194`, `process_handshake_init()` called `session.complete_handshake(shared_secret)`, placing the responder session directly into `SessionState.ESTABLISHED` after message 2 (`HANDSHAKE_RESPONSE`) before message 3 (`HANDSHAKE_CONFIRM`) arrived.
- **v2 Remediation:**
  1. Added `SessionState.AWAITING_CONFIRM` to [`SessionState`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L67-L76).
  2. Added [`Session.stage_handshake()`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L345-L398) which derives the epoch-0 keys and transitions `HANDSHAKE_RECEIVED -> AWAITING_CONFIRM`.
  3. Added [`Session.confirm_handshake()`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L400-L412) which transitions `AWAITING_CONFIRM -> ESTABLISHED` only after `HANDSHAKE_CONFIRM` is decrypted and its `ML-DSA-65` transcript signature is verified.
  4. Commands, rekeys, and terminates arriving before `HANDSHAKE_CONFIRM` are rejected because `Receiver._session` is still `None` (or still bound to the prior confirmed session).
- **Regression Tests:**
  - `TestV2HandshakeStateAndSessionPreservation::test_f02_responder_is_awaiting_confirm_before_confirm_message`
  - `TestV2HandshakeStateAndSessionPreservation::test_f02_commands_rejected_before_handshake_confirm`

### F-03 — `HANDSHAKE_RESPONSE` Omits Initiator KEM Public Key, Recipient Identity, and Freshness Nonce
- **Severity:** Medium (Incomplete cryptographic binding of responder's signature to the specific initiator ephemeral key and peer identity).
- **v1 Root Cause:** In `v1` `protocol/messages.py:216-245`, `HANDSHAKE_RESPONSE` set `sender_kem_key = b""` and did not include `recipient_id` or a responder nonce in the signed JSON structure.
- **v2 Remediation:**
  1. In [`Receiver.process_handshake_init`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L244-L265), `HANDSHAKE_RESPONSE` echoes `sender_kem_key=init_payload.sender_kem_key`, sets `recipient_id=init_payload.sender_id`, and generates a fresh 16-byte `handshake_nonce`.
  2. In [`Sender.process_handshake_response`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/sender.py#L186-L202), the initiator verifies that `resp_payload.sender_kem_key == self._ephemeral_kem.public_key` and `resp_payload.recipient_id == self._peer_id` before decapsulating.
- **Regression Tests:**
  - `TestV2HandshakeStateAndSessionPreservation::test_f03_handshake_response_wrong_recipient_rejected`
  - `TestV2HandshakeStateAndSessionPreservation::test_f03_handshake_response_mismatched_echoed_kem_key_rejected`

### F-04 — Handshake Transcript Concatenates Raw Packets Without Length Framing or Domain Label
- **Severity:** Low (Ambiguous boundary between `init_packet` and `resp_packet` in transcript signing).
- **v1 Root Cause:** In `v1`, `transcript = init_packet + resp_packet` was signed directly without length prefixes or a domain-separation label.
- **v2 Remediation:**
  1. Added [`Session.append_transcript(packet)`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L329-L334) which appends `struct.pack(">I", len(packet)) + packet`.
  2. Added [`Session.transcript_bytes_for_confirm()`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L336-L343) which prepends `TRANSCRIPT_CONFIRM_LABEL = b"UAV-C2-PQ-L2-v2-HANDSHAKE-CONFIRM\x00"` to the length-prefixed transcript before `ML-DSA-65` signing and verification.
- **Regression Tests:**
  - `TestV2HandshakeStateAndSessionPreservation::test_f04_length_framed_transcript_prevents_boundary_ambiguity`

### F-05 — Missing Pre-FFI FIPS 203/204 Byte-Length Checks and Algorithm Suite Binding
- **Severity:** Medium (Passing malformed key/ciphertext/signature buffers across the C FFI boundary into `liboqs`).
- **v1 Root Cause:** `protocol/crypto_core.py` passed caller-supplied `public_key`, `secret_key`, `ciphertext`, and `signature` directly to `oqs.KeyEncapsulation` and `oqs.Signature` without checking exact byte lengths first.
- **v2 Remediation:**
  1. Added exact FIPS 203 (`1184`, `2400`, `1088`) and FIPS 204 (`1952`, `4032`, `3309`) byte-length assertions in [`protocol/crypto_core.py`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/crypto_core.py#L72-L195) before any `liboqs` call.
  2. Enforced exact hex string lengths and algorithm suite identifiers (`ML-KEM-768`, `ML-DSA-65`, `AES-256-GCM`, `HKDF-SHA-256`) during JSON deserialization in [`protocol/messages.py`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/messages.py#L405-L498).
- **Regression Tests:**
  - `TestV2HandshakeStateAndSessionPreservation::test_f05_crypto_core_enforces_exact_fips_byte_lengths`
  - `TestV2HandshakeStateAndSessionPreservation::test_f05_algorithm_mismatch_in_handshake_rejected`

### F-06 — Single-Stage HKDF Key Schedule Omits Transcript Hash and Peer Identities
- **Severity:** Medium (Session traffic keys were derived solely from `shared_secret`, `session_id`, and `epoch`, without binding the handshake transcript or peer IDs).
- **v1 Root Cause:** `SessionKeys.from_shared_secret()` used `salt = session_id + epoch` and fixed info labels without `SHA256(transcript)` or `initiator_id`/`responder_id`.
- **v2 Remediation:**
  1. Implemented a two-stage `HKDF-SHA-256` key schedule in [`derive_epoch_root_secret`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L79-L145) and [`SessionKeys.from_root_secret`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L170-L224).
  2. Both stages bind `session_id`, `epoch`, `SHA256(transcript)`, `initiator_id`, and `responder_id`.
- **Regression Tests:**
  - `TestV2RekeyAndKeyScheduleSecurity::test_f06_two_stage_key_schedule_binds_transcript_and_identities`

### F-07 — Receiver Does Not Record/Validate Nonces on Control Packets (`CONFIRM`, `REKEY`, `TERMINATE`)
- **Severity:** Low (Inconsistent nonce tracking across message types).
- **v1 Root Cause:** `validate_received_nonce` was only called in `_handle_command`, not in `process_handshake_confirm`, `_handle_rekey`, or `_handle_terminate`, nor in `Sender.complete_rekey`.
- **v2 Remediation:**
  1. Added `validate_received_nonce(nonce)` to [`Receiver.process_handshake_confirm`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L316), [`Receiver._handle_rekey`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L469), [`Receiver._handle_terminate`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L569), and [`Sender.complete_rekey`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/sender.py#L367).
- **Regression Tests:**
  - `TestV2BoundsReplayAndLifecycle::test_f07_control_packet_nonce_recorded_and_duplicate_rejected`

### F-08 — Unbounded `_emitted_nonces` and `_received_nonces` Sets Grow `O(N)`
- **Severity:** Low (Linear memory growth over up to $2^{20}$ messages per epoch).
- **v1 Root Cause:** `Session._emitted_nonces` and `Session._received_nonces` were plain Python `set` objects that never evicted old entries.
- **v2 Remediation:**
  1. Replaced unbounded sets in [`Session`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L298-L327) with a bounded sliding-window deque + set (`NONCE_WINDOW_SIZE = 200`) combined with a monotonic counter floor (`_highest_received_nonce_counter - NONCE_WINDOW_SIZE`).
  2. Verified that after 600 commands, both `_emitted_nonces` and `_received_nonces` have `len <= 200`.
- **Regression Tests:**
  - `TestV2BoundsReplayAndLifecycle::test_f08_bounded_nonce_tracking_constant_memory`

### F-09 — `VALID_COMMANDS` Whitelist Never Enforced
- **Severity:** Medium (Arbitrary command verbs accepted despite `VALID_COMMANDS` specification).
- **v1 Root Cause:** `VALID_COMMANDS` was defined in `protocol/constants.py` but never referenced in `protocol/messages.py`, `protocol/sender.py`, or `protocol/receiver.py`.
- **v2 Remediation:**
  1. Enforced `command in VALID_COMMANDS` in [`CommandPayload.from_json_bytes`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/messages.py#L279-L282) and [`Sender.send_command`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/sender.py#L251-L261).
  2. Enforced printable ASCII and length limits (`MAX_COMMAND_VERB_LENGTH = 32`, `MAX_COMMAND_PARAMS_LENGTH = 512`).
- **Regression Tests:**
  - `TestV2CommandValidationAndTimestamps::test_f09_unwhitelisted_command_rejected_at_sender_and_parser`

### F-10 — `CommandPayload` Accepts Non-Finite Timestamps (`NaN`/`Infinity`) and Lacks Freshness Enforcement
- **Severity:** Medium (Malformed floating-point timestamps accepted; stale timestamps not rejected).
- **v1 Root Cause:** `json.loads()` in Python accepts `NaN`, `Infinity`, and `-Infinity` by default, and `CommandPayload` only checked `isinstance(timestamp, (int, float))`.
- **v2 Remediation:**
  1. Added `_strict_json_loads()` with `parse_constant=_reject_json_constant` and `math.isfinite(ts) and ts > 0.0` in [`protocol/messages.py`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/messages.py#L75-L134).
  2. Enforced `abs(now_wall - payload.timestamp) <= COMMAND_MAX_TIMESTAMP_SKEW_SECONDS` (`60.0s`) in [`Receiver._handle_command`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L430-L437).
- **Regression Tests:**
  - `TestV2CommandValidationAndTimestamps::test_f10_nan_infinity_and_negative_timestamps_rejected`
  - `TestV2CommandValidationAndTimestamps::test_f10_stale_or_future_command_timestamp_rejected`

### F-11 — Expensive `ML-DSA-65` Signature Verification Executed Before Sequence Replay Check
- **Severity:** Medium (Avoidable CPU amplification when an attacker holding a compromised session key floods replayed or out-of-window sequence numbers).
- **v1 Root Cause:** In `v1` `Receiver._handle_command`, `sig_verify()` (~0.51 ms) ran before `session.validate_recv_sequence()`.
- **v2 Remediation:**
  1. Moved `session.validate_recv_sequence(header.sequence)` to [`Receiver.receive_packet`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L384) before dispatching to `_handle_command`, `_handle_rekey`, or `_handle_terminate`, and before any `sig_verify()` call.
- **Regression Tests:**
  - `TestV2BoundsReplayAndLifecycle::test_f11_sequence_validated_before_signature_verification`

### F-12 — Session Rekey Not Bound to Long-Term `ML-DSA-65` Identity Keys and Root Secret Not Chained
- **Severity:** High (An attacker who compromises current symmetric session traffic keys can inject `REKEY_INIT` with their own `ML-KEM-768` public key and hijack future epochs without possessing the peer's long-term `ML-DSA-65` identity key).
- **v1 Root Cause:** In `v1`, `REKEY_INIT` encrypted a raw 1,184-byte `ML-KEM-768` public key under the current `AES-256-GCM` key with no `ML-DSA-65` signature, and `Session.rekey()` derived new keys solely from the new KEM shared secret without mixing the previous epoch's secret.
- **v2 Remediation:**
  1. Created structured [`RekeyPayload`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/messages.py#L501-L698) carrying `sender_id`, `recipient_id`, `current_epoch`, `next_epoch`, `rekey_nonce` (`16 B`), `sender_kem_key` (`1,184 B`, echoed in response), `kem_ciphertext` (`1,088 B`), `key_confirm_tag` (`32 B` `HMAC-SHA-256`), and an `ML-DSA-65` `signature` (`3,309 B`) verified against the peer's pinned `TrustStore` key.
  2. Chained epoch root secrets in [`derive_epoch_root_secret`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L123-L135): `IKM = prev_root_secret || kem_shared_secret`, combining post-compromise security (via fresh `ML-KEM-768` + `ML-DSA-65`) with forward-secrecy continuity (via `prev_root_secret`).
- **Regression Tests:**
  - `TestV2RekeyAndKeyScheduleSecurity::test_f12_rekey_requires_valid_mldsa65_signature_and_chains_root_secret`
  - `TestV2RekeyAndKeyScheduleSecurity::test_f12_rekey_confirm_tag_tampering_aborts_rekey_and_preserves_session`

### F-13 — Non-Atomic Initiator Rekey State Transition and Unsigned `TERMINATE`
- **Severity:** Medium (Malformed `REKEY_RESPONSE` permanently bricks the initiator's active session; `TERMINATE` is not signed by long-term identity key).
- **v1 Root Cause:** In `v1`, `Sender.initiate_rekey()` set `session.state = SessionState.REKEYING`, and if `complete_rekey()` failed, the session remained stuck in `REKEYING` (where `send_command` refused to operate). Also, `TERMINATE` was a raw 9-byte string `b"TERMINATE"` without an `ML-DSA-65` signature.
- **v2 Remediation:**
  1. Added [`Session.prepare_rekey()`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L648-L711), [`Session.commit_rekey()`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L713-L751), and [`Session.abort_rekey()`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L753-L766). If `Sender.complete_rekey()` fails at any step, `abort_rekey()` atomically restores `SessionState.ESTABLISHED` on the current epoch so the session remains operational.
  2. Created structured [`TerminatePayload`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/messages.py#L701-L811) signed with `ML-DSA-65` over `protocol_version`, `sender_id`, `recipient_id`, `session_id`, `epoch`, `sequence`, `timestamp`, and `reason`.
- **Regression Tests:**
  - `TestV2RekeyAndKeyScheduleSecurity::test_f13_failed_rekey_response_rolls_back_cleanly_to_established`
  - `TestV2RekeyAndKeyScheduleSecurity::test_f13_terminate_requires_valid_mldsa65_signature`

### F-14 — Session Lifetime Uses Wall-Clock `time.time()` Instead of Monotonic Clock
- **Severity:** Low (NTP/RTC clock jumps can prematurely expire or extend session lifetime).
- **v1 Root Cause:** `Session.is_expired()` computed `time.time() - self.created_at`.
- **v2 Remediation:**
  1. Added `_created_monotonic = time.monotonic()` and [`Session._elapsed_seconds()`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L510-L523), which uses `time.monotonic() - self._created_monotonic` during normal operation while honoring explicit test adjustments to `self.created_at`.
- **Regression Tests:**
  - `TestV2BoundsReplayAndLifecycle::test_f14_session_uses_monotonic_clock`

### F-15 — Missing End-to-End Peer Role Enforcement (`ground_station` vs. `uav`)
- **Severity:** High (An authenticated UAV peer in `TrustStore` can impersonate a Ground Station to initiate handshakes and send flight commands to another UAV).
- **v1 Root Cause:** `TrustStore` stored `peer.role`, and `HandshakePayload` carried `sender_role`, but neither `TrustStore`, `Sender`, nor `Receiver` ever checked `peer.role` against expected roles (`ROLE_GROUND_STATION` vs. `ROLE_UAV`) or against `HandshakePayload.sender_role`.
- **v2 Remediation:**
  1. Added [`TrustStore.verify_peer_role(peer_id, expected_role, claimed_role=None)`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/identity.py#L140-L176).
  2. [`Sender.initiate_handshake`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/sender.py#L96-L108) enforces that the local peer is `ROLE_GROUND_STATION` and the target peer is `ROLE_UAV` before sending `HANDSHAKE_INIT`.
  3. [`Sender.process_handshake_response`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/sender.py#L172-L185) enforces that the responder is `ROLE_UAV` in `TrustStore` and claimed `ROLE_UAV` in `HANDSHAKE_RESPONSE`.
  4. [`Receiver.process_handshake_init`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L194-L214) enforces that the local peer is `ROLE_UAV` and the initiator is `ROLE_GROUND_STATION` in both `TrustStore` and `HandshakePayload.sender_role`.
  5. [`Receiver._verify_established_sender`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/receiver.py#L396-L420) re-verifies on every `COMMAND`, `REKEY`, and `TERMINATE` packet that `payload_sender_id == session.peer_id`, that the peer is still trusted and non-revoked in `TrustStore`, that its role is `ROLE_GROUND_STATION`, and that its signing public key matches `session.peer_signing_key`.
- **Regression Tests:**
  - `TestV2RoleEnforcement::test_f15_uav_peer_cannot_initiate_handshake_as_sender`
  - `TestV2RoleEnforcement::test_f15_receiver_rejects_handshake_init_from_uav_peer_claiming_gs_role`
  - `TestV2RoleEnforcement::test_f15_receiver_rejects_handshake_init_from_uav_peer_claiming_uav_role`
  - `TestV2RoleEnforcement::test_f15_sender_rejects_handshake_with_another_ground_station`
  - `TestV2RoleEnforcement::test_f15_sender_rejects_handshake_response_with_wrong_role`
  - `TestV2RoleEnforcement::test_f15_role_change_after_handshake_blocks_commands`

### F-16 — Best-Effort Key Zeroization in Python
- **Severity:** Info (Language runtime limitation in CPython for immutable `bytes`).
- **v1 Root Cause:** `Session._clear_secrets()` only reassigned attributes to `None`.
- **v2 Remediation:**
  1. Added mutable `bytearray` mirrors and [`SessionKeys.clear()`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L261-L272) + [`_zero_bytearray()`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/session.py#L275-L279) in `Session._clear_secrets()` to overwrite mutable key buffers in place before dropping references, while explicitly documenting CPython's immutable `bytes` limitation in `NOT_REVIEWED_AND_LIMITATIONS.md`.
- **Regression Tests:**
  - `TestV2BoundsReplayAndLifecycle::test_f16_session_keys_clear_zeroes_buffers`

### F-17 — Constant-Time Public Key Comparison in `TrustStore.verify_signing_key`
- **Severity:** Info (Hardening).
- **v1 Root Cause:** `TrustStore.verify_signing_key` used `peer.signing_public_key == public_key`.
- **v2 Remediation:**
  1. Replaced `==` with `hmac.compare_digest(peer.signing_public_key, bytes(public_key))` in [`TrustStore.verify_signing_key`](file:///C:/Users/smanv/UAV_Security_Project/layer2_crypto_v2/protocol/identity.py#L136).
- **Regression Tests:**
  - `TestV2BoundsReplayAndLifecycle::test_f17_verify_signing_key_uses_constant_time_compare`
