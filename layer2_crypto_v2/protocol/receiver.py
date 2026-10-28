"""Command receiver (UAV) role (UAV-C2-PQ-L2 v2).

Implements the UAV side of the Layer 2 protocol:
1. Stages incoming handshakes in a separate `_pending_session` slot (`AWAITING_CONFIRM`)
   so malformed, unauthenticated, or replayed handshakes NEVER tear down or
   overwrite an active `ESTABLISHED` session (`_session`).
2. Enforces pending-handshake timeouts, admission rate limits, timestamp
   freshness, and bounded handshake replay caches.
3. Enforces role authorization (`ROLE_GROUND_STATION` vs. `ROLE_UAV`) and
   pinned public keys at handshake init, confirm, command reception, rekeying,
   and session termination.
4. Performs cheap header/session/sequence/whitelist checks before expensive
   ML-DSA-65 signature verification during command processing.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import os
import time
from typing import Callable

from protocol.constants import (
    COMMAND_MAX_TIMESTAMP_SKEW_SECONDS,
    HANDSHAKE_MAX_TIMESTAMP_SKEW_SECONDS,
    HANDSHAKE_NONCE_BYTES,
    HANDSHAKE_PENDING_TIMEOUT_SECONDS,
    HANDSHAKE_RATE_LIMIT_MAX_ATTEMPTS,
    HANDSHAKE_RATE_LIMIT_WINDOW_SECONDS,
    HANDSHAKE_REPLAY_CACHE_SIZE,
    HEADER_SIZE,
    MAX_COMMAND_SIZE,
    MAX_HANDSHAKE_PAYLOAD_SIZE,
    MSG_TYPE_COMMAND,
    MSG_TYPE_HANDSHAKE_CONFIRM,
    MSG_TYPE_HANDSHAKE_INIT,
    MSG_TYPE_HANDSHAKE_RESPONSE,
    MSG_TYPE_REKEY,
    MSG_TYPE_TERMINATE,
    PROTOCOL_VERSION,
    ROLE_GROUND_STATION,
    ROLE_UAV,
    TRANSCRIPT_CONFIRM_LABEL,
)
from protocol.crypto_core import (
    SigningKeyPair,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    compute_hmac_sha256,
    kem_encapsulate,
    sig_sign,
    sig_verify,
)
from protocol.errors import (
    AuthenticationError,
    HandshakeError,
    IdentityError,
    MessageFormatError,
    NonceError,
    ProtocolError,
    ReplayError,
    SequenceError,
    SessionError,
    SessionExpiredError,
    TrustError,
    VersionError,
)
from protocol.identity import TrustStore
from protocol.messages import (
    CommandPayload,
    HandshakePayload,
    MessageHeader,
    RekeyPayload,
    TerminatePayload,
    _validate_safe_str,
    build_packet,
    parse_packet,
)
from protocol.session import Session, SessionState
from protocol.transport import Transport


class CommandRecord:
    """Audit record of accepted and rejected commands on the UAV receiver."""

    def __init__(self) -> None:
        self.accepted: list[dict] = []
        self.rejected: list[dict] = []

    def record_accepted(
        self,
        command: str,
        params: str,
        sender_id: str,
        sequence: int,
    ) -> None:
        self.accepted.append({
            "command": command,
            "params": params,
            "sender_id": sender_id,
            "sequence": sequence,
            "timestamp": time.time(),
        })

    def record_rejected(
        self,
        reason: str,
        error_type: str = "",
    ) -> None:
        self.rejected.append({
            "reason": reason,
            "error_type": error_type,
            "timestamp": time.time(),
        })

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    def clear(self) -> None:
        self.accepted.clear()
        self.rejected.clear()


class Receiver:
    """UAV command receiver (v2)."""

    def __init__(
        self,
        peer_id: str,
        signing_keys: SigningKeyPair,
        trust_store: TrustStore,
        transport: Transport,
        command_handler: Callable[[str, str, str, int], None] | None = None,
        handshake_timeout: float = HANDSHAKE_PENDING_TIMEOUT_SECONDS,
        max_timestamp_skew: float = HANDSHAKE_MAX_TIMESTAMP_SKEW_SECONDS,
        command_timestamp_skew: float = COMMAND_MAX_TIMESTAMP_SKEW_SECONDS,
        rate_limit_max_attempts: int = HANDSHAKE_RATE_LIMIT_MAX_ATTEMPTS,
        rate_limit_window: float = HANDSHAKE_RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        _validate_safe_str(peer_id, "peer_id", 64)
        self.peer_id = peer_id
        self._signing_keys = signing_keys
        self._trust_store = trust_store
        self._transport = transport
        self._command_handler = command_handler
        self._handshake_timeout = float(handshake_timeout)
        self._max_timestamp_skew = float(max_timestamp_skew)
        self._command_timestamp_skew = float(command_timestamp_skew)
        self._rate_limit_max_attempts = int(rate_limit_max_attempts)
        self._rate_limit_window = float(rate_limit_window)

        # Active ESTABLISHED session is strictly isolated from pending handshakes
        self._session: Session | None = None
        self._pending_session: Session | None = None
        self._pending_handshake_started_at: float | None = None

        # Bounded replay cache for seen handshake session_ids and nonces
        self._seen_handshake_ids: collections.OrderedDict[bytes, float] = (
            collections.OrderedDict()
        )
        self._handshake_attempt_times: collections.deque[float] = (
            collections.deque()
        )

        self.command_record = CommandRecord()

    @property
    def session(self) -> Session | None:
        """Return the currently ESTABLISHED session (None if unconfirmed)."""
        return self._session

    @property
    def pending_session(self) -> Session | None:
        """Return the staged pending handshake session (if awaiting confirm)."""
        return self._pending_session

    # ------------------------------------------------------------------
    # Handshake rate-limiting & replay cache helpers
    # ------------------------------------------------------------------

    def _check_handshake_rate_limit(self) -> None:
        now = time.monotonic()
        cutoff = now - self._rate_limit_window
        while (
            self._handshake_attempt_times
            and self._handshake_attempt_times[0] < cutoff
        ):
            self._handshake_attempt_times.popleft()
        if len(self._handshake_attempt_times) >= self._rate_limit_max_attempts:
            raise HandshakeError(
                "Handshake rate limit exceeded; try again later"
            )
        self._handshake_attempt_times.append(now)

    def _record_seen_handshake_token(self, token: bytes) -> None:
        self._seen_handshake_ids[token] = time.monotonic()
        self._seen_handshake_ids.move_to_end(token)
        while len(self._seen_handshake_ids) > HANDSHAKE_REPLAY_CACHE_SIZE:
            self._seen_handshake_ids.popitem(last=False)

    def _expire_stale_pending_handshake(self) -> None:
        if (
            self._pending_session is not None
            and self._pending_handshake_started_at is not None
        ):
            if (
                time.monotonic() - self._pending_handshake_started_at
                > self._handshake_timeout
            ):
                self._abort_pending_handshake()

    def _abort_pending_handshake(self) -> None:
        """Clean up ONLY the pending handshake slot; never touches self._session."""
        if self._pending_session is not None:
            self._pending_session.terminate()
            self._pending_session = None
        self._pending_handshake_started_at = None

    # ------------------------------------------------------------------
    # Handshake (responder side)
    # ------------------------------------------------------------------

    def process_handshake_init(self, packet: bytes) -> bytes:
        """Process HANDSHAKE_INIT and stage a pending session in AWAITING_CONFIRM.

        Guarantees that invalid, replayed, or unauthenticated packets NEVER
        terminate or overwrite an existing `ESTABLISHED` session in `self._session`.
        """
        self._check_handshake_rate_limit()
        self._expire_stale_pending_handshake()

        # If a valid pending handshake is already in progress, reject concurrent attempt
        # without destroying the in-flight pending session or the established session.
        if (
            self._pending_session is not None
            and self._pending_session.state == SessionState.AWAITING_CONFIRM
        ):
            raise HandshakeError(
                "A pending handshake is already awaiting confirmation"
            )

        try:
            if not isinstance(packet, (bytes, bytearray)):
                raise MessageFormatError("Handshake packet must be bytes")
            if len(packet) <= HEADER_SIZE:
                raise MessageFormatError("Handshake packet too short")
            if len(packet) > MAX_HANDSHAKE_PAYLOAD_SIZE + HEADER_SIZE:
                raise MessageFormatError("Handshake packet exceeds maximum size")

            header = MessageHeader.from_bytes(packet[:HEADER_SIZE])
            if header.msg_type != MSG_TYPE_HANDSHAKE_INIT:
                raise HandshakeError(
                    f"Expected handshake init, got type {header.msg_type}"
                )
            if header.sequence != 0:
                raise HandshakeError("Handshake init sequence must be 0")

            # Reject session_id collision with active session or replay cache
            if self._session and hmac.compare_digest(
                header.session_id, self._session.session_id
            ):
                raise HandshakeError(
                    "Handshake session_id collides with active session"
                )
            sid_token = b"sid:" + header.session_id
            if sid_token in self._seen_handshake_ids:
                raise HandshakeError("Replayed handshake session_id rejected")

            payload_bytes = bytes(packet[HEADER_SIZE:])
            hs_payload = HandshakePayload.from_json_bytes(payload_bytes)

            if hs_payload.recipient_id != self.peer_id:
                raise HandshakeError(
                    f"Handshake init not addressed to '{self.peer_id}'"
                )
            if hs_payload.kem_ciphertext != b"":
                raise HandshakeError(
                    "Handshake init must not contain kem_ciphertext"
                )

            nonce_token = b"nonce:" + hs_payload.handshake_nonce
            if nonce_token in self._seen_handshake_ids:
                raise HandshakeError("Replayed handshake_nonce rejected")

            # Enforce timestamp freshness
            if abs(time.time() - hs_payload.timestamp) > self._max_timestamp_skew:
                raise HandshakeError(
                    "Handshake init timestamp expired or outside skew window"
                )

            # Enforce local role if registered
            if self._trust_store.is_registered(self.peer_id):
                self._trust_store.verify_peer_role(self.peer_id, ROLE_UAV)

            # Enforce initiator is registered, non-revoked, and has ROLE_GROUND_STATION
            initiator = self._trust_store.verify_peer_role(
                hs_payload.sender_id,
                ROLE_GROUND_STATION,
                claimed_role=hs_payload.sender_role,
            )
            self._trust_store.verify_signing_key(
                hs_payload.sender_id,
                hs_payload.sender_signing_key,
            )

            unsigned_payload = HandshakePayload(
                sender_id=hs_payload.sender_id,
                sender_role=hs_payload.sender_role,
                recipient_id=hs_payload.recipient_id,
                timestamp=hs_payload.timestamp,
                handshake_nonce=hs_payload.handshake_nonce,
                sender_signing_key=hs_payload.sender_signing_key,
                sender_kem_key=hs_payload.sender_kem_key,
                kem_ciphertext=b"",
                signature=b"",
                kem_algorithm=hs_payload.kem_algorithm,
                sig_algorithm=hs_payload.sig_algorithm,
                aead_algorithm=hs_payload.aead_algorithm,
                kdf_algorithm=hs_payload.kdf_algorithm,
            )
            canonical = unsigned_payload.canonical_bytes_for_signing(
                session_id=header.session_id,
                recipient_id=self.peer_id,
            )
            if not sig_verify(
                canonical,
                hs_payload.signature,
                initiator.signing_public_key,
            ):
                raise HandshakeError("Initiator handshake signature invalid")

            # Record tokens in bounded replay cache after signature verification
            self._record_seen_handshake_token(sid_token)
            self._record_seen_handshake_token(nonce_token)

            # Stage pending session (isolated from self._session)
            pending = Session(
                local_peer_id=self.peer_id,
                remote_peer_id=hs_payload.sender_id,
                session_id=header.session_id,
                initiator_id=hs_payload.sender_id,
                responder_id=self.peer_id,
                remote_signing_public_key=initiator.signing_public_key,
                remote_role=initiator.role,
            )
            pending.mark_handshake_received()
            pending.append_transcript(bytes(packet))

            encap_result = kem_encapsulate(hs_payload.sender_kem_key)

            resp_payload = HandshakePayload(
                sender_id=self.peer_id,
                sender_role=ROLE_UAV,
                recipient_id=hs_payload.sender_id,
                timestamp=time.time(),
                handshake_nonce=os.urandom(HANDSHAKE_NONCE_BYTES),
                sender_signing_key=self._signing_keys.public_key,
                sender_kem_key=hs_payload.sender_kem_key,  # Echo initiator KEM key
                kem_ciphertext=encap_result.ciphertext,
            )
            resp_canonical = resp_payload.canonical_bytes_for_signing(
                session_id=pending.session_id,
                recipient_id=hs_payload.sender_id,
            )
            resp_signature = sig_sign(
                resp_canonical, self._signing_keys.secret_key
            )

            signed_resp = HandshakePayload(
                sender_id=resp_payload.sender_id,
                sender_role=resp_payload.sender_role,
                recipient_id=resp_payload.recipient_id,
                timestamp=resp_payload.timestamp,
                handshake_nonce=resp_payload.handshake_nonce,
                sender_signing_key=resp_payload.sender_signing_key,
                sender_kem_key=resp_payload.sender_kem_key,
                kem_ciphertext=resp_payload.kem_ciphertext,
                signature=resp_signature,
            )

            resp_bytes = signed_resp.to_json_bytes()
            resp_header = MessageHeader(
                version=PROTOCOL_VERSION,
                msg_type=MSG_TYPE_HANDSHAKE_RESPONSE,
                session_id=pending.session_id,
                sequence=0,
            )
            resp_packet = resp_header.to_bytes() + resp_bytes

            # Append full framed response packet before deriving keys
            pending.append_transcript(resp_packet)
            pending.stage_handshake(encap_result.shared_secret)

            self._pending_session = pending
            self._pending_handshake_started_at = time.monotonic()

            self._transport.send(resp_packet)
            return resp_packet

        except (IdentityError, TrustError, VersionError, HandshakeError):
            self._abort_pending_handshake()
            raise
        except ProtocolError as exc:
            self._abort_pending_handshake()
            raise HandshakeError("Handshake init processing failed") from exc
        except Exception as exc:
            self._abort_pending_handshake()
            raise HandshakeError("Handshake init processing failed") from exc

    def process_handshake_confirm(self, packet: bytes) -> bool:
        """Verify HANDSHAKE_CONFIRM and promote `_pending_session` to `_session`."""
        if (
            not self._pending_session
            or self._pending_session.state != SessionState.AWAITING_CONFIRM
        ):
            raise HandshakeError("Not expecting handshake confirm")

        if (
            self._pending_handshake_started_at is not None
            and (time.monotonic() - self._pending_handshake_started_at)
            > self._handshake_timeout
        ):
            self._abort_pending_handshake()
            raise HandshakeError("Pending handshake timed out")

        try:
            header, nonce, ciphertext = parse_packet(packet)

            if header.msg_type != MSG_TYPE_HANDSHAKE_CONFIRM:
                raise HandshakeError("Expected handshake confirm")
            if header.sequence != 0:
                raise HandshakeError("Handshake confirm sequence must be 0")
            if not hmac.compare_digest(
                header.session_id, self._pending_session.session_id
            ):
                raise HandshakeError("Session ID mismatch in confirm")

            self._pending_session.validate_nonce(nonce)

            transcript_sig = aes_gcm_decrypt(
                self._pending_session.get_sender_enc_key(
                    allow_pending_confirm=True
                ),
                nonce,
                ciphertext,
                header.to_bytes(),
            )

            # Re-verify initiator identity, role, and pinned public key
            remote = self._trust_store.verify_peer_role(
                self._pending_session.remote_peer_id,
                ROLE_GROUND_STATION,
            )
            if (
                self._pending_session.remote_signing_public_key
                and not hmac.compare_digest(
                    remote.signing_public_key,
                    self._pending_session.remote_signing_public_key,
                )
            ):
                raise TrustError(
                    "Initiator signing key changed before handshake confirm"
                )

            confirm_context = (
                TRANSCRIPT_CONFIRM_LABEL + self._pending_session.transcript
            )
            if not sig_verify(
                confirm_context,
                transcript_sig,
                remote.signing_public_key,
            ):
                raise HandshakeError("Handshake transcript signature invalid")

            self._pending_session.record_nonce(nonce)
            self._pending_session.confirm_handshake()

            # Promote confirmed pending session to active established session
            if self._session is not None:
                self._session.terminate()
            self._session = self._pending_session
            self._pending_session = None
            self._pending_handshake_started_at = None
            return True

        except (HandshakeError, TrustError, IdentityError, VersionError):
            self._abort_pending_handshake()
            raise
        except Exception as exc:
            self._abort_pending_handshake()
            raise HandshakeError("Confirm processing failed") from exc

    # ------------------------------------------------------------------
    # Command & Control Packet Reception
    # ------------------------------------------------------------------

    def receive_packet(self, packet: bytes) -> tuple[bool, str]:
        """Process an incoming encrypted packet through the v2 validation pipeline.

        Validation order for MSG_TYPE_COMMAND:
        1. Packet framing, size bounds, and header parsing (version == 2).
        2. Active ESTABLISHED session check, liveness, and session_id match.
        3. Fast pre-check of sequence number (`validate_recv_sequence`) and
           nonce freshness (`validate_nonce`) BEFORE decryption/signature verification.
        4. AES-256-GCM decryption and header AAD authentication.
        5. Payload schema, command whitelist (`VALID_COMMANDS`), sender/recipient,
           and timestamp freshness validation.
        6. TrustStore role (`ROLE_GROUND_STATION`), revocation, and pinned key check.
        7. ML-DSA-65 signature verification.
        8. Commit sequence (`accept_recv_sequence`) and nonce (`record_nonce`),
           record acceptance, and invoke command handler.
        """
        try:
            header, nonce, ciphertext = parse_packet(packet)

            if header.msg_type == MSG_TYPE_TERMINATE:
                return self._handle_terminate(header, nonce, ciphertext)

            if header.msg_type == MSG_TYPE_REKEY:
                return self._handle_rekey(header, nonce, ciphertext)

            if header.msg_type != MSG_TYPE_COMMAND:
                self.command_record.record_rejected(
                    f"Unexpected message type: {header.msg_type}",
                    "MessageFormatError",
                )
                return False, f"Unexpected message type: {header.msg_type}"

            if not self._session:
                self.command_record.record_rejected(
                    "No active session", "SessionError"
                )
                return False, "No active session"

            self._session.check_alive()

            if not hmac.compare_digest(
                header.session_id, self._session.session_id
            ):
                self.command_record.record_rejected(
                    "Session ID mismatch", "SessionError"
                )
                return False, "Session ID mismatch"

            # Decrypt and authenticate header AAD first (0.003 ms)
            plaintext = aes_gcm_decrypt(
                self._session.get_sender_enc_key(),
                nonce,
                ciphertext,
                header.to_bytes(),
            )

            if len(plaintext) > MAX_COMMAND_SIZE:
                self.command_record.record_rejected(
                    "Payload too large", "MessageFormatError"
                )
                return False, "Payload too large"

            payload = CommandPayload.from_json_bytes(plaintext)

            if payload.sender_id != self._session.remote_peer_id:
                self.command_record.record_rejected(
                    "Sender identity mismatch", "AuthenticationError"
                )
                return False, "Sender identity mismatch"

            if payload.recipient_id != self.peer_id:
                self.command_record.record_rejected(
                    "Not addressed to this receiver", "MessageFormatError"
                )
                return False, "Not addressed to this receiver"

            if (
                abs(time.time() - payload.timestamp)
                > self._command_timestamp_skew
            ):
                self.command_record.record_rejected(
                    "Command timestamp outside freshness window",
                    "MessageFormatError",
                )
                return False, "Command timestamp outside freshness window"

            # Enforce sender is still active, non-revoked, ROLE_GROUND_STATION,
            # and matches the session's pinned signing key
            remote = self._trust_store.verify_peer_role(
                payload.sender_id, ROLE_GROUND_STATION
            )
            if (
                self._session.remote_signing_public_key
                and not hmac.compare_digest(
                    remote.signing_public_key,
                    self._session.remote_signing_public_key,
                )
            ):
                raise TrustError(
                    "Sender signing key changed during active session"
                )

            # Cheap sequence replay/gap validation BEFORE expensive ML-DSA-65 sig_verify (F-11)
            self._session.validate_recv_sequence(header.sequence)

            unsigned_payload = CommandPayload(
                sender_id=payload.sender_id,
                recipient_id=payload.recipient_id,
                command=payload.command,
                params=payload.params,
                timestamp=payload.timestamp,
            )
            verify_canonical = unsigned_payload.canonical_bytes_for_signing(
                session_id=self._session.session_id,
                sequence=header.sequence,
            )

            if not sig_verify(
                verify_canonical,
                payload.signature,
                remote.signing_public_key,
            ):
                self.command_record.record_rejected(
                    "Command signature verification failed",
                    "AuthenticationError",
                )
                return False, "Command signature verification failed"

            # Validate and commit nonce + sequence only after signature verification succeeds
            self._session.validate_and_record_nonce(nonce)
            self._session.accept_recv_sequence(header.sequence)

            full_command = payload.command
            if payload.params:
                full_command += " " + payload.params

            self.command_record.record_accepted(
                payload.command,
                payload.params,
                payload.sender_id,
                header.sequence,
            )

            if self._command_handler:
                self._command_handler(
                    payload.command,
                    payload.params,
                    payload.sender_id,
                    header.sequence,
                )

            return True, full_command

        except VersionError as exc:
            self.command_record.record_rejected(str(exc), "VersionError")
            return False, str(exc)
        except MessageFormatError as exc:
            self.command_record.record_rejected(str(exc), "MessageFormatError")
            return False, str(exc)
        except AuthenticationError as exc:
            self.command_record.record_rejected(str(exc), "AuthenticationError")
            return False, str(exc)
        except ReplayError as exc:
            self.command_record.record_rejected(str(exc), "ReplayError")
            return False, str(exc)
        except SequenceError as exc:
            self.command_record.record_rejected(str(exc), "SequenceError")
            return False, str(exc)
        except NonceError as exc:
            self.command_record.record_rejected(str(exc), "NonceError")
            return False, str(exc)
        except (TrustError, IdentityError) as exc:
            self.command_record.record_rejected(str(exc), "TrustError")
            return False, str(exc)
        except SessionError as exc:
            self.command_record.record_rejected(str(exc), "SessionError")
            return False, str(exc)
        except ProtocolError as exc:
            self.command_record.record_rejected(str(exc), "ProtocolError")
            return False, str(exc)
        except Exception:
            self.command_record.record_rejected(
                "Internal error", "InternalError"
            )
            return False, "Internal error"

    def _handle_terminate(
        self,
        header: MessageHeader,
        nonce: bytes,
        ciphertext: bytes,
    ) -> tuple[bool, str]:
        """Handle an authenticated, ML-DSA-65-signed session termination message."""
        if not self._session:
            return False, "No session to terminate"

        try:
            self._session.check_alive()
            if not hmac.compare_digest(
                header.session_id, self._session.session_id
            ):
                return False, "Session ID mismatch in terminate"

            self._session.validate_recv_sequence(header.sequence)
            self._session.validate_nonce(nonce)

            plaintext = aes_gcm_decrypt(
                self._session.get_sender_enc_key(),
                nonce,
                ciphertext,
                header.to_bytes(),
            )
            term_payload = TerminatePayload.from_json_bytes(plaintext)

            if term_payload.sender_id != self._session.remote_peer_id:
                return False, "Terminate sender identity mismatch"
            if term_payload.recipient_id != self.peer_id:
                return False, "Terminate recipient mismatch"
            if term_payload.epoch != self._session.rekey_epoch:
                return False, "Terminate epoch mismatch"
            if (
                abs(time.time() - term_payload.timestamp)
                > self._command_timestamp_skew
            ):
                return False, "Terminate timestamp outside freshness window"

            remote = self._trust_store.verify_peer_role(
                term_payload.sender_id, ROLE_GROUND_STATION
            )
            if (
                self._session.remote_signing_public_key
                and not hmac.compare_digest(
                    remote.signing_public_key,
                    self._session.remote_signing_public_key,
                )
            ):
                return False, "Terminate sender signing key changed"

            unsigned_term = TerminatePayload(
                sender_id=term_payload.sender_id,
                recipient_id=term_payload.recipient_id,
                epoch=term_payload.epoch,
                timestamp=term_payload.timestamp,
                reason=term_payload.reason,
                signature=b"",
            )
            if not sig_verify(
                unsigned_term.canonical_bytes_for_signing(
                    self._session.session_id, header.sequence
                ),
                term_payload.signature,
                remote.signing_public_key,
            ):
                return False, "Terminate signature verification failed"

            self._session.record_nonce(nonce)
            self._session.accept_recv_sequence(header.sequence)
            self._session.terminate()
            self._session = None
            return True, "Session terminated"
        except Exception as exc:
            return False, f"Invalid terminate message: {exc}"

    def _handle_rekey(
        self,
        header: MessageHeader,
        nonce: bytes,
        ciphertext: bytes,
    ) -> tuple[bool, str]:
        """Handle an authenticated, ML-DSA-65-signed in-session rekey request."""
        if not self._session:
            return False, "No session for rekey"

        try:
            self._session.check_alive()
            if not hmac.compare_digest(
                header.session_id, self._session.session_id
            ):
                return False, "Session ID mismatch in rekey"

            self._session.validate_recv_sequence(header.sequence)
            self._session.validate_nonce(nonce)

            plaintext = aes_gcm_decrypt(
                self._session.get_sender_enc_key(),
                nonce,
                ciphertext,
                header.to_bytes(),
            )
            rekey_init = RekeyPayload.from_json_bytes(plaintext)

            if rekey_init.sender_id != self._session.remote_peer_id:
                return False, "Rekey sender identity mismatch"
            if rekey_init.recipient_id != self.peer_id:
                return False, "Rekey recipient mismatch"
            if rekey_init.current_epoch != self._session.rekey_epoch:
                return False, "Rekey current_epoch mismatch"
            if rekey_init.next_epoch != self._session.rekey_epoch + 1:
                return False, "Rekey next_epoch mismatch"
            if rekey_init.kem_ciphertext != b"" or rekey_init.key_confirm_tag != b"":
                return False, "Rekey init must not contain response fields"

            remote = self._trust_store.verify_peer_role(
                rekey_init.sender_id, ROLE_GROUND_STATION
            )
            if (
                self._session.remote_signing_public_key
                and not hmac.compare_digest(
                    remote.signing_public_key,
                    self._session.remote_signing_public_key,
                )
            ):
                return False, "Rekey sender signing key changed"

            unsigned_init = RekeyPayload(
                sender_id=rekey_init.sender_id,
                recipient_id=rekey_init.recipient_id,
                current_epoch=rekey_init.current_epoch,
                next_epoch=rekey_init.next_epoch,
                rekey_nonce=rekey_init.rekey_nonce,
                sender_kem_key=rekey_init.sender_kem_key,
                kem_ciphertext=b"",
                key_confirm_tag=b"",
                signature=b"",
            )
            if not sig_verify(
                unsigned_init.canonical_bytes_for_signing(
                    self._session.session_id, header.sequence
                ),
                rekey_init.signature,
                remote.signing_public_key,
            ):
                return False, "Rekey signature verification failed"

            # Encapsulate new shared secret using initiator's ephemeral KEM key
            encap_result = kem_encapsulate(rekey_init.sender_kem_key)

            resp_header = MessageHeader(
                version=PROTOCOL_VERSION,
                msg_type=MSG_TYPE_REKEY,
                session_id=self._session.session_id,
                sequence=0,
            )

            rekey_init_transcript = header.to_bytes() + plaintext
            rekey_transcript_data = (
                rekey_init_transcript
                + resp_header.to_bytes()
                + rekey_init.rekey_nonce
                + rekey_init.sender_kem_key
                + encap_result.ciphertext
            )
            rekey_transcript_hash = hashlib.sha256(
                rekey_transcript_data
            ).digest()

            next_root_secret, next_keys, next_confirm_key = (
                self._session.prepare_rekey(
                    encap_result.shared_secret,
                    rekey_transcript_hash,
                )
            )
            confirm_tag = compute_hmac_sha256(
                next_confirm_key, rekey_transcript_data
            )

            unsigned_resp = RekeyPayload(
                sender_id=self.peer_id,
                recipient_id=rekey_init.sender_id,
                current_epoch=rekey_init.current_epoch,
                next_epoch=rekey_init.next_epoch,
                rekey_nonce=rekey_init.rekey_nonce,
                sender_kem_key=rekey_init.sender_kem_key,
                kem_ciphertext=encap_result.ciphertext,
                key_confirm_tag=confirm_tag,
                signature=b"",
            )
            resp_sig = sig_sign(
                unsigned_resp.canonical_bytes_for_signing(
                    self._session.session_id, resp_header.sequence
                ),
                self._signing_keys.secret_key,
            )
            signed_resp = RekeyPayload(
                sender_id=unsigned_resp.sender_id,
                recipient_id=unsigned_resp.recipient_id,
                current_epoch=unsigned_resp.current_epoch,
                next_epoch=unsigned_resp.next_epoch,
                rekey_nonce=unsigned_resp.rekey_nonce,
                sender_kem_key=unsigned_resp.sender_kem_key,
                kem_ciphertext=unsigned_resp.kem_ciphertext,
                key_confirm_tag=unsigned_resp.key_confirm_tag,
                signature=resp_sig,
            )

            # Record incoming rekey nonce and sequence on current epoch before encrypting response
            self._session.record_nonce(nonce)
            self._session.accept_recv_sequence(header.sequence)

            resp_nonce = self._session.next_receiver_nonce()
            _, resp_ct = aes_gcm_encrypt(
                self._session.get_receiver_enc_key(),
                signed_resp.to_json_bytes(),
                resp_header.to_bytes(),
                nonce=resp_nonce,
            )
            resp_packet = build_packet(resp_header, resp_nonce, resp_ct)

            # Transition state before/atomically with sending response (F-13)
            self._session.begin_rekey()
            self._session.commit_rekey(
                next_root_secret, next_keys, next_confirm_key
            )
            self._transport.send(resp_packet)

            return True, "Rekey completed"

        except Exception as exc:
            return False, f"Rekey failed: {exc}"

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def terminate_session(self) -> None:
        """Terminate the current session and any pending handshake."""
        self._abort_pending_handshake()
        if self._session:
            self._session.terminate()
        self._session = None
