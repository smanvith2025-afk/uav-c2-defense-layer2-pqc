"""Command sender (ground station) role (UAV-C2-PQ-L2 v2).

Implements the Ground Station side of the Layer 2 protocol:
1. Initiates a mutually authenticated, freshness-protected post-quantum
   handshake with a UAV peer registered as ROLE_UAV.
2. Verifies the responder's role, pinned ML-DSA-65 signing key, echoed
   ephemeral ML-KEM-768 public key, and signature before deriving keys.
3. Sends encrypted, transcript-bound HANDSHAKE_CONFIRM.
4. Sends signed, encrypted, whitelist-validated, replay-protected commands.
5. Initiates and completes signed, root-secret-chained in-session rekeys
   with explicit key confirmation and safe rollback on failure.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

from protocol.constants import (
    HANDSHAKE_MAX_TIMESTAMP_SKEW_SECONDS,
    HANDSHAKE_NONCE_BYTES,
    HEADER_SIZE,
    MAX_COMMAND_PARAMS_LENGTH,
    MAX_COMMAND_VERB_LENGTH,
    MAX_HANDSHAKE_PAYLOAD_SIZE,
    ML_KEM_768_CIPHERTEXT_BYTES,
    MSG_TYPE_COMMAND,
    MSG_TYPE_HANDSHAKE_CONFIRM,
    MSG_TYPE_HANDSHAKE_INIT,
    MSG_TYPE_HANDSHAKE_RESPONSE,
    MSG_TYPE_REKEY,
    MSG_TYPE_TERMINATE,
    PROTOCOL_VERSION,
    REKEY_CONFIRM_TAG_BYTES,
    REKEY_NONCE_BYTES,
    ROLE_GROUND_STATION,
    ROLE_UAV,
    TRANSCRIPT_CONFIRM_LABEL,
    VALID_COMMANDS,
)
from protocol.crypto_core import (
    KEMKeyPair,
    SigningKeyPair,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    kem_decapsulate,
    kem_generate_keypair,
    sig_sign,
    sig_verify,
    verify_hmac_sha256,
)
from protocol.errors import (
    AuthenticationError,
    HandshakeError,
    IdentityError,
    MessageFormatError,
    ProtocolError,
    SessionError,
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


class Sender:
    """Ground station command sender (v2)."""

    def __init__(
        self,
        peer_id: str,
        signing_keys: SigningKeyPair,
        trust_store: TrustStore,
        transport: Transport,
        max_timestamp_skew: float = HANDSHAKE_MAX_TIMESTAMP_SKEW_SECONDS,
    ) -> None:
        _validate_safe_str(peer_id, "peer_id", 64)
        self.peer_id = peer_id
        self._signing_keys = signing_keys
        self._trust_store = trust_store
        self._transport = transport
        self._max_timestamp_skew = float(max_timestamp_skew)
        self._session: Session | None = None
        self._ephemeral_kem: KEMKeyPair | None = None
        self._rekey_nonce: bytes | None = None
        self._rekey_init_transcript: bytes = b""

    @property
    def session(self) -> Session | None:
        """Current active session (if any)."""
        return self._session

    # ------------------------------------------------------------------
    # Handshake (initiator side)
    # ------------------------------------------------------------------

    def initiate_handshake(self, remote_peer_id: str) -> bytes:
        """Initiate a v2 handshake with an authorized UAV peer."""
        if self._session and self._session.state == SessionState.ESTABLISHED:
            raise HandshakeError("Session already established. Terminate first.")
        if self._session and self._session.state != SessionState.ESTABLISHED:
            self._abort_handshake()

        # Enforce local role if local peer is in TrustStore
        if self._trust_store.is_registered(self.peer_id):
            self._trust_store.verify_peer_role(
                self.peer_id, ROLE_GROUND_STATION
            )

        # Verify target peer is registered, non-revoked, and has role ROLE_UAV
        remote_identity = self._trust_store.verify_peer_role(
            remote_peer_id, ROLE_UAV
        )

        # Generate fresh ephemeral ML-KEM-768 keypair
        self._ephemeral_kem = kem_generate_keypair()

        # Create session in INIT state
        self._session = Session(
            local_peer_id=self.peer_id,
            remote_peer_id=remote_peer_id,
            initiator_id=self.peer_id,
            responder_id=remote_peer_id,
            remote_signing_public_key=remote_identity.signing_public_key,
            remote_role=remote_identity.role,
        )

        init_ts = time.time()
        init_nonce = os.urandom(HANDSHAKE_NONCE_BYTES)

        hs_payload = HandshakePayload(
            sender_id=self.peer_id,
            sender_role=ROLE_GROUND_STATION,
            recipient_id=remote_peer_id,
            timestamp=init_ts,
            handshake_nonce=init_nonce,
            sender_signing_key=self._signing_keys.public_key,
            sender_kem_key=self._ephemeral_kem.public_key,
            kem_ciphertext=b"",
        )

        canonical = hs_payload.canonical_bytes_for_signing(
            session_id=self._session.session_id,
            recipient_id=remote_peer_id,
        )
        signature = sig_sign(canonical, self._signing_keys.secret_key)

        signed_payload = HandshakePayload(
            sender_id=hs_payload.sender_id,
            sender_role=hs_payload.sender_role,
            recipient_id=hs_payload.recipient_id,
            timestamp=hs_payload.timestamp,
            handshake_nonce=hs_payload.handshake_nonce,
            sender_signing_key=hs_payload.sender_signing_key,
            sender_kem_key=hs_payload.sender_kem_key,
            kem_ciphertext=hs_payload.kem_ciphertext,
            signature=signature,
        )

        payload_bytes = signed_payload.to_json_bytes()
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_HANDSHAKE_INIT,
            session_id=self._session.session_id,
            sequence=0,
        )
        packet = header.to_bytes() + payload_bytes

        # Bind full framed packet (header + payload) into transcript
        self._session.append_transcript(packet)
        self._session.mark_handshake_sent()
        self._transport.send(packet)
        return packet

    def process_handshake_response(self, packet: bytes) -> bool:
        """Process the responder's HANDSHAKE_RESPONSE, derive keys, and send HANDSHAKE_CONFIRM."""
        if not self._session or self._session.state != SessionState.HANDSHAKE_SENT:
            raise HandshakeError("Not expecting a handshake response")
        if not self._ephemeral_kem:
            raise HandshakeError("No ephemeral KEM keys available")

        try:
            if not isinstance(packet, (bytes, bytearray)):
                raise MessageFormatError("Handshake response must be bytes")
            if len(packet) <= HEADER_SIZE:
                raise MessageFormatError("Handshake response packet too short")
            if len(packet) > MAX_HANDSHAKE_PAYLOAD_SIZE + HEADER_SIZE:
                raise MessageFormatError("Handshake response packet too large")

            header = MessageHeader.from_bytes(packet[:HEADER_SIZE])
            if header.msg_type != MSG_TYPE_HANDSHAKE_RESPONSE:
                raise HandshakeError(
                    f"Expected handshake response, got type {header.msg_type}"
                )
            if header.sequence != 0:
                raise HandshakeError("Handshake response sequence must be 0")
            if not hmac.compare_digest(
                header.session_id, self._session.session_id
            ):
                raise HandshakeError("Session ID mismatch in handshake response")

            payload_bytes = bytes(packet[HEADER_SIZE:])
            hs_payload = HandshakePayload.from_json_bytes(payload_bytes)

            if hs_payload.sender_id != self._session.remote_peer_id:
                raise HandshakeError("Responder identity mismatch")
            if hs_payload.recipient_id != self.peer_id:
                raise HandshakeError("Handshake response recipient mismatch")

            # Enforce responder role (must be ROLE_UAV in both TrustStore and payload)
            remote_identity = self._trust_store.verify_peer_role(
                hs_payload.sender_id,
                ROLE_UAV,
                claimed_role=hs_payload.sender_role,
            )
            self._trust_store.verify_signing_key(
                hs_payload.sender_id,
                hs_payload.sender_signing_key,
            )

            # Check timestamp freshness
            if abs(time.time() - hs_payload.timestamp) > self._max_timestamp_skew:
                raise HandshakeError(
                    "Handshake response timestamp outside freshness window"
                )

            # Verify responder echoed our exact ephemeral KEM public key
            if not hmac.compare_digest(
                hs_payload.sender_kem_key, self._ephemeral_kem.public_key
            ):
                raise HandshakeError(
                    "Responder echoed mismatched ephemeral KEM public key"
                )
            if len(hs_payload.kem_ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
                raise HandshakeError("Missing or invalid KEM ciphertext in response")

            unsigned_payload = HandshakePayload(
                sender_id=hs_payload.sender_id,
                sender_role=hs_payload.sender_role,
                recipient_id=hs_payload.recipient_id,
                timestamp=hs_payload.timestamp,
                handshake_nonce=hs_payload.handshake_nonce,
                sender_signing_key=hs_payload.sender_signing_key,
                sender_kem_key=hs_payload.sender_kem_key,
                kem_ciphertext=hs_payload.kem_ciphertext,
                signature=b"",
                kem_algorithm=hs_payload.kem_algorithm,
                sig_algorithm=hs_payload.sig_algorithm,
                aead_algorithm=hs_payload.aead_algorithm,
                kdf_algorithm=hs_payload.kdf_algorithm,
            )
            verify_canonical = unsigned_payload.canonical_bytes_for_signing(
                session_id=self._session.session_id,
                recipient_id=self.peer_id,
            )
            if not sig_verify(
                verify_canonical,
                hs_payload.signature,
                remote_identity.signing_public_key,
            ):
                raise HandshakeError("Responder handshake signature invalid")

            # Record full framed response packet in transcript before key derivation
            self._session.append_transcript(bytes(packet))

            shared_secret = kem_decapsulate(
                hs_payload.kem_ciphertext,
                self._ephemeral_kem.secret_key,
            )
            self._session.establish(shared_secret)

            self._send_confirm()
            self._ephemeral_kem = None
            return True

        except (HandshakeError, TrustError, IdentityError, VersionError):
            self._abort_handshake()
            raise
        except Exception as exc:
            self._abort_handshake()
            raise HandshakeError(
                "Handshake response processing failed"
            ) from exc

    def _send_confirm(self) -> None:
        """Send encrypted, domain-separated HANDSHAKE_CONFIRM message."""
        if not self._session:
            raise HandshakeError("No session for handshake confirm")
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_HANDSHAKE_CONFIRM,
            session_id=self._session.session_id,
            sequence=0,
        )
        confirm_context = TRANSCRIPT_CONFIRM_LABEL + self._session.transcript
        transcript_sig = sig_sign(
            confirm_context,
            self._signing_keys.secret_key,
        )
        nonce, ciphertext = aes_gcm_encrypt(
            self._session.get_sender_enc_key(),
            transcript_sig,
            header.to_bytes(),
            nonce=self._session.next_sender_nonce(),
        )
        packet = build_packet(header, nonce, ciphertext)
        self._transport.send(packet)

    def _abort_handshake(self) -> None:
        """Clean up local handshake state on failure."""
        if self._session:
            self._session.terminate()
        self._session = None
        self._ephemeral_kem = None

    # ------------------------------------------------------------------
    # Command sending
    # ------------------------------------------------------------------

    def send_command(
        self,
        command: str,
        params: str = "",
    ) -> bytes:
        """Send a signed, encrypted, whitelist-validated command."""
        if not self._session:
            raise SessionError("No active session")

        # Check session liveness and validate command/params BEFORE incrementing counters
        self._session.check_alive()

        _validate_safe_str(command, "command", MAX_COMMAND_VERB_LENGTH)
        if command not in VALID_COMMANDS:
            raise MessageFormatError(
                f"Unauthorized or unrecognized command verb: '{command}'"
            )
        _validate_safe_str(
            params, "params", MAX_COMMAND_PARAMS_LENGTH, allow_empty=True
        )

        sequence = self._session.next_send_sequence()
        nonce = self._session.next_sender_nonce()
        timestamp = time.time()

        cmd_payload = CommandPayload(
            sender_id=self.peer_id,
            recipient_id=self._session.remote_peer_id,
            command=command,
            params=params,
            timestamp=timestamp,
        )
        canonical = cmd_payload.canonical_bytes_for_signing(
            session_id=self._session.session_id,
            sequence=sequence,
        )
        signature = sig_sign(canonical, self._signing_keys.secret_key)

        signed_payload = CommandPayload(
            sender_id=cmd_payload.sender_id,
            recipient_id=cmd_payload.recipient_id,
            command=cmd_payload.command,
            params=cmd_payload.params,
            timestamp=cmd_payload.timestamp,
            signature=signature,
        )

        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=self._session.session_id,
            sequence=sequence,
        )

        _, ciphertext = aes_gcm_encrypt(
            self._session.get_sender_enc_key(),
            signed_payload.to_json_bytes(),
            header.to_bytes(),
            nonce=nonce,
        )

        packet = build_packet(header, nonce, ciphertext)
        self._transport.send(packet)
        return packet

    # ------------------------------------------------------------------
    # Session management (Rekey & Terminate)
    # ------------------------------------------------------------------

    def terminate_session(self) -> bytes | None:
        """Send a signed, encrypted session termination message and clean up."""
        if not self._session or self._session.state != SessionState.ESTABLISHED:
            if self._session:
                self._session.terminate()
            self._session = None
            return None

        self._session.check_alive()
        sequence = self._session.next_send_sequence()
        nonce = self._session.next_sender_nonce()
        ts = time.time()

        unsigned_term = TerminatePayload(
            sender_id=self.peer_id,
            recipient_id=self._session.remote_peer_id,
            epoch=self._session.rekey_epoch,
            timestamp=ts,
            reason="TERMINATE",
        )
        sig = sig_sign(
            unsigned_term.canonical_bytes_for_signing(
                self._session.session_id, sequence
            ),
            self._signing_keys.secret_key,
        )
        signed_term = TerminatePayload(
            sender_id=unsigned_term.sender_id,
            recipient_id=unsigned_term.recipient_id,
            epoch=unsigned_term.epoch,
            timestamp=unsigned_term.timestamp,
            reason=unsigned_term.reason,
            signature=sig,
        )

        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_TERMINATE,
            session_id=self._session.session_id,
            sequence=sequence,
        )

        _, ciphertext = aes_gcm_encrypt(
            self._session.get_sender_enc_key(),
            signed_term.to_json_bytes(),
            header.to_bytes(),
            nonce=nonce,
        )

        packet = build_packet(header, nonce, ciphertext)
        self._transport.send(packet)
        self._session.terminate()
        self._session = None
        return packet

    def initiate_rekey(self) -> bytes:
        """Initiate an authenticated in-session rekey (epoch e -> e+1)."""
        if not self._session or self._session.state != SessionState.ESTABLISHED:
            raise SessionError("No established session to rekey")

        self._session.check_alive()
        if self._trust_store.is_registered(self.peer_id):
            self._trust_store.verify_peer_role(
                self.peer_id, ROLE_GROUND_STATION
            )

        self._ephemeral_kem = kem_generate_keypair()
        self._rekey_nonce = os.urandom(REKEY_NONCE_BYTES)

        sequence = self._session.next_send_sequence()
        nonce = self._session.next_sender_nonce()

        unsigned_rekey = RekeyPayload(
            sender_id=self.peer_id,
            recipient_id=self._session.remote_peer_id,
            current_epoch=self._session.rekey_epoch,
            next_epoch=self._session.rekey_epoch + 1,
            rekey_nonce=self._rekey_nonce,
            sender_kem_key=self._ephemeral_kem.public_key,
            kem_ciphertext=b"",
            key_confirm_tag=b"",
        )
        sig = sig_sign(
            unsigned_rekey.canonical_bytes_for_signing(
                self._session.session_id, sequence
            ),
            self._signing_keys.secret_key,
        )
        signed_rekey = RekeyPayload(
            sender_id=unsigned_rekey.sender_id,
            recipient_id=unsigned_rekey.recipient_id,
            current_epoch=unsigned_rekey.current_epoch,
            next_epoch=unsigned_rekey.next_epoch,
            rekey_nonce=unsigned_rekey.rekey_nonce,
            sender_kem_key=unsigned_rekey.sender_kem_key,
            kem_ciphertext=b"",
            key_confirm_tag=b"",
            signature=sig,
        )

        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_REKEY,
            session_id=self._session.session_id,
            sequence=sequence,
        )
        rekey_json = signed_rekey.to_json_bytes()

        _, ciphertext = aes_gcm_encrypt(
            self._session.get_sender_enc_key(),
            rekey_json,
            header.to_bytes(),
            nonce=nonce,
        )

        packet = build_packet(header, nonce, ciphertext)
        self._rekey_init_transcript = header.to_bytes() + rekey_json
        self._session.begin_rekey()
        self._transport.send(packet)
        return packet

    def complete_rekey(self, packet: bytes) -> bool:
        """Complete rekey by verifying the responder's signed REKEY_RESPONSE
        and explicit key confirmation tag before committing the new epoch."""
        if not self._session or self._session.state != SessionState.REKEYING:
            raise SessionError("Not in rekeying state")
        if not self._ephemeral_kem or not self._rekey_nonce:
            raise SessionError("No ephemeral KEM state for rekey")

        try:
            header, nonce, ciphertext = parse_packet(packet)

            if header.msg_type != MSG_TYPE_REKEY:
                raise SessionError(
                    f"Expected MSG_TYPE_REKEY ({MSG_TYPE_REKEY}), got {header.msg_type}"
                )
            if header.sequence != 0:
                raise SessionError("Rekey response header sequence must be 0")
            if not hmac.compare_digest(
                header.session_id, self._session.session_id
            ):
                raise SessionError("Session ID mismatch in rekey response")

            self._session.validate_nonce(nonce)

            plaintext = aes_gcm_decrypt(
                self._session.get_receiver_enc_key(allow_rekeying=True),
                nonce,
                ciphertext,
                header.to_bytes(),
            )
            resp_payload = RekeyPayload.from_json_bytes(plaintext)

            if resp_payload.sender_id != self._session.remote_peer_id:
                raise SessionError("Rekey responder identity mismatch")
            if resp_payload.recipient_id != self.peer_id:
                raise SessionError("Rekey response recipient mismatch")
            if resp_payload.current_epoch != self._session.rekey_epoch:
                raise SessionError("Rekey current_epoch mismatch")
            if resp_payload.next_epoch != self._session.rekey_epoch + 1:
                raise SessionError("Rekey next_epoch mismatch")
            if not hmac.compare_digest(
                resp_payload.rekey_nonce, self._rekey_nonce
            ):
                raise SessionError("Rekey nonce mismatch in response")
            if not hmac.compare_digest(
                resp_payload.sender_kem_key, self._ephemeral_kem.public_key
            ):
                raise SessionError("Rekey echoed KEM public key mismatch")
            if len(resp_payload.kem_ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
                raise SessionError("Invalid KEM ciphertext in rekey response")
            if len(resp_payload.key_confirm_tag) != REKEY_CONFIRM_TAG_BYTES:
                raise SessionError("Missing key confirmation tag in rekey response")

            # Verify responder is still trusted with role ROLE_UAV and pinned signing key
            remote = self._trust_store.verify_peer_role(
                resp_payload.sender_id, ROLE_UAV
            )
            if (
                self._session.remote_signing_public_key
                and not hmac.compare_digest(
                    remote.signing_public_key,
                    self._session.remote_signing_public_key,
                )
            ):
                raise TrustError(
                    "Responder signing key changed during active session"
                )

            unsigned_resp = RekeyPayload(
                sender_id=resp_payload.sender_id,
                recipient_id=resp_payload.recipient_id,
                current_epoch=resp_payload.current_epoch,
                next_epoch=resp_payload.next_epoch,
                rekey_nonce=resp_payload.rekey_nonce,
                sender_kem_key=resp_payload.sender_kem_key,
                kem_ciphertext=resp_payload.kem_ciphertext,
                key_confirm_tag=resp_payload.key_confirm_tag,
                signature=b"",
            )
            if not sig_verify(
                unsigned_resp.canonical_bytes_for_signing(
                    self._session.session_id, header.sequence
                ),
                resp_payload.signature,
                remote.signing_public_key,
            ):
                raise AuthenticationError(
                    "Responder ML-DSA-65 signature invalid on rekey response"
                )

            new_secret = kem_decapsulate(
                resp_payload.kem_ciphertext,
                self._ephemeral_kem.secret_key,
            )

            rekey_transcript_data = (
                self._rekey_init_transcript
                + header.to_bytes()
                + resp_payload.rekey_nonce
                + resp_payload.sender_kem_key
                + resp_payload.kem_ciphertext
            )
            rekey_transcript_hash = hashlib.sha256(
                rekey_transcript_data
            ).digest()

            next_root_secret, next_keys, next_confirm_key = (
                self._session.prepare_rekey(
                    new_secret, rekey_transcript_hash
                )
            )

            if not verify_hmac_sha256(
                next_confirm_key,
                rekey_transcript_data,
                resp_payload.key_confirm_tag,
            ):
                raise AuthenticationError(
                    "Rekey explicit key confirmation tag verification failed"
                )

            # Atomically transition to the new epoch
            self._session.commit_rekey(
                next_root_secret, next_keys, next_confirm_key
            )
            self._ephemeral_kem = None
            self._rekey_nonce = None
            self._rekey_init_transcript = b""
            return True

        except SessionError:
            raise
        except Exception as exc:
            raise SessionError(f"Rekey failed: {exc}") from exc

    def abort_rekey(self) -> None:
        """Roll back an uncompleted rekey so the current epoch remains usable."""
        if self._session and self._session.state == SessionState.REKEYING:
            self._session.abort_rekey()
        self._ephemeral_kem = None
        self._rekey_nonce = None
        self._rekey_init_transcript = b""
