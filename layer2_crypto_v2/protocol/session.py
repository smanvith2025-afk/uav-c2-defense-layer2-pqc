"""Session lifecycle, two-stage key schedule, and bounded replay state (v2).

Session state machine:
    Initiator (Sender):
        INIT -> HANDSHAKE_SENT -> ESTABLISHED -> TERMINATED
                                      |
                                      +-> REKEYING -> ESTABLISHED (or abort -> ESTABLISHED)
                                      +-> EXPIRED

    Responder (Receiver):
        INIT -> HANDSHAKE_RECEIVED -> AWAITING_CONFIRM -> ESTABLISHED -> TERMINATED
                                                              |
                                                              +-> REKEYING -> ESTABLISHED
                                                              +-> EXPIRED

Security invariants (v2):
- Responder sessions never enter ESTABLISHED until HANDSHAKE_CONFIRM is verified.
- Key derivation uses a two-stage HKDF-SHA-256 schedule:
  Stage 1 derives an epoch `root_secret` bound to `session_id`, `epoch`,
  `SHA256(transcript)`, peer identities, and (for epoch >= 1) the previous
  epoch's `root_secret` mixed with the new ML-KEM-768 shared secret.
  Stage 2 derives directional traffic keys (`sender_enc_key`, `receiver_enc_key`)
  and 4-byte deterministic nonce prefixes from `root_secret`.
- Session lifetime checks use monotonic time (`time.monotonic()`) while remaining
  compatible with explicit `created_at` test adjustments.
- Nonce and sequence replay tracking structures are strictly bounded in memory
  to O(NONCE_WINDOW_SIZE) = 200 entries.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from enum import Enum, auto

from protocol.constants import (
    AES_KEY_BYTES,
    AES_NONCE_BYTES,
    HKDF_INFO_RECEIVER_AUTH,
    HKDF_INFO_RECEIVER_ENC,
    HKDF_INFO_REKEY_CONFIRM,
    HKDF_INFO_ROOT_INIT,
    HKDF_INFO_ROOT_REKEY,
    HKDF_INFO_SENDER_AUTH,
    HKDF_INFO_SENDER_ENC,
    MAX_SEQUENCE_GAP,
    NONCE_WINDOW_SIZE,
    SEQUENCE_START,
    SESSION_MAX_LIFETIME_SECONDS,
    SESSION_MAX_MESSAGES,
)
from protocol.crypto_core import derive_key
from protocol.errors import (
    NonceError,
    ReplayError,
    SequenceError,
    SessionError,
    SessionExpiredError,
)


class SessionState(Enum):
    """Protocol session states (v2)."""
    INIT = auto()
    HANDSHAKE_SENT = auto()
    HANDSHAKE_RECEIVED = auto()
    AWAITING_CONFIRM = auto()
    ESTABLISHED = auto()
    REKEYING = auto()
    TERMINATED = auto()
    EXPIRED = auto()


def derive_epoch_root_secret(
    kem_shared_secret: bytes,
    session_id: bytes,
    epoch: int = 0,
    transcript_hash: bytes = b"",
    initiator_id: str = "",
    responder_id: str = "",
    prev_root_secret: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Derive `(root_secret, rekey_confirm_key)` for a given session epoch.

    For epoch == 0:
        IKM = kem_shared_secret (32 B)
        Salt = session_id (16 B) || uint32(0) || transcript_hash (32 B)
        Info = HKDF_INFO_ROOT_INIT || "|" || initiator_id || "|" || responder_id

    For epoch >= 1 (rekeying):
        IKM = prev_root_secret (32 B) || kem_shared_secret (32 B)
        Salt = session_id (16 B) || uint32(epoch) || rekey_transcript_hash (32 B)
        Info = HKDF_INFO_ROOT_REKEY || "|" || initiator_id || "|" || responder_id || "|epoch=" || epoch
    """
    if not isinstance(kem_shared_secret, (bytes, bytearray)) or len(kem_shared_secret) != 32:
        raise ValueError("kem_shared_secret must be 32 bytes")
    if not isinstance(session_id, (bytes, bytearray)) or len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise ValueError("epoch must be a non-negative integer")

    th = (
        bytes(transcript_hash)
        if transcript_hash
        else hashlib.sha256(b"").digest()
    )
    salt = bytes(session_id) + struct.pack(">I", epoch) + th
    peer_ctx = (
        b"|"
        + initiator_id.encode("utf-8")
        + b"|"
        + responder_id.encode("utf-8")
    )

    if epoch == 0:
        ikm = bytes(kem_shared_secret)
        info = HKDF_INFO_ROOT_INIT + peer_ctx
    else:
        prev = bytes(prev_root_secret) if prev_root_secret is not None else (b"\x00" * 32)
        if len(prev) != 32:
            raise ValueError("prev_root_secret must be 32 bytes")
        ikm = prev + bytes(kem_shared_secret)
        info = (
            HKDF_INFO_ROOT_REKEY
            + peer_ctx
            + b"|epoch="
            + str(epoch).encode("ascii")
        )

    root_secret = derive_key(ikm, info=info, salt=salt, length=AES_KEY_BYTES)
    confirm_info = (
        HKDF_INFO_REKEY_CONFIRM
        + peer_ctx
        + b"|epoch="
        + str(epoch).encode("ascii")
    )
    rekey_confirm_key = derive_key(
        root_secret, info=confirm_info, salt=salt, length=32
    )
    return root_secret, rekey_confirm_key


@dataclass
class SessionKeys:
    """Direction-specific session encryption keys and deterministic nonce prefixes."""
    sender_enc_key: bytes
    receiver_enc_key: bytes
    sender_nonce_prefix: bytes = b"\x00\x00\x00\x00"
    receiver_nonce_prefix: bytes = b"\x00\x00\x00\x00"
    cleared: bool = False

    def __post_init__(self) -> None:
        if len(self.sender_enc_key) != AES_KEY_BYTES:
            raise ValueError(f"sender_enc_key must be {AES_KEY_BYTES} bytes")
        if len(self.receiver_enc_key) != AES_KEY_BYTES:
            raise ValueError(f"receiver_enc_key must be {AES_KEY_BYTES} bytes")
        if len(self.sender_nonce_prefix) != 4:
            raise ValueError("sender_nonce_prefix must be 4 bytes")
        if len(self.receiver_nonce_prefix) != 4:
            raise ValueError("receiver_nonce_prefix must be 4 bytes")
        self._sender_key_buf = bytearray(self.sender_enc_key)
        self._receiver_key_buf = bytearray(self.receiver_enc_key)

    @classmethod
    def from_root_secret(
        cls,
        root_secret: bytes,
        session_id: bytes,
        epoch: int = 0,
        transcript_hash: bytes = b"",
        initiator_id: str = "",
        responder_id: str = "",
    ) -> "SessionKeys":
        """Stage 2: Derive directional traffic keys and nonce prefixes from root_secret."""
        th = (
            bytes(transcript_hash)
            if transcript_hash
            else hashlib.sha256(b"").digest()
        )
        salt = bytes(session_id) + struct.pack(">I", epoch) + th
        peer_ctx = (
            b"|"
            + initiator_id.encode("utf-8")
            + b"|"
            + responder_id.encode("utf-8")
            + b"|epoch="
            + str(epoch).encode("ascii")
        )
        sender_enc_key = derive_key(
            root_secret,
            info=HKDF_INFO_SENDER_ENC + peer_ctx,
            salt=salt,
            length=AES_KEY_BYTES,
        )
        receiver_enc_key = derive_key(
            root_secret,
            info=HKDF_INFO_RECEIVER_ENC + peer_ctx,
            salt=salt,
            length=AES_KEY_BYTES,
        )
        sender_nonce_prefix = derive_key(
            root_secret,
            info=HKDF_INFO_SENDER_AUTH + peer_ctx,
            salt=salt,
            length=4,
        )
        receiver_nonce_prefix = derive_key(
            root_secret,
            info=HKDF_INFO_RECEIVER_AUTH + peer_ctx,
            salt=salt,
            length=4,
        )
        return cls(
            sender_enc_key=sender_enc_key,
            receiver_enc_key=receiver_enc_key,
            sender_nonce_prefix=sender_nonce_prefix,
            receiver_nonce_prefix=receiver_nonce_prefix,
        )

    @classmethod
    def from_shared_secret(
        cls,
        shared_secret: bytes,
        session_id: bytes,
        epoch: int = 0,
        transcript_hash: bytes = b"",
        initiator_id: str = "",
        responder_id: str = "",
        prev_root_secret: bytes | None = None,
    ) -> "SessionKeys":
        """Derive root secret and traffic keys from a KEM shared secret."""
        root_secret, _ = derive_epoch_root_secret(
            kem_shared_secret=shared_secret,
            session_id=session_id,
            epoch=epoch,
            transcript_hash=transcript_hash,
            initiator_id=initiator_id,
            responder_id=responder_id,
            prev_root_secret=prev_root_secret,
        )
        return cls.from_root_secret(
            root_secret=root_secret,
            session_id=session_id,
            epoch=epoch,
            transcript_hash=transcript_hash,
            initiator_id=initiator_id,
            responder_id=responder_id,
        )

    def clear(self) -> None:
        """Best-effort logical cleanup of key references and mutable buffers.

        Limitation: Python `bytes` objects returned by OpenSSL/cryptography are
        immutable heap objects and cannot be physically overwritten in place from
        pure Python before garbage collection. This method zeroes the internal
        mutable `bytearray` buffers and replaces `bytes` attributes with zeroed
        placeholders so active references are dropped immediately.
        """
        for i in range(len(self._sender_key_buf)):
            self._sender_key_buf[i] = 0
        for i in range(len(self._receiver_key_buf)):
            self._receiver_key_buf[i] = 0
        self.sender_enc_key = bytes(AES_KEY_BYTES)
        self.receiver_enc_key = bytes(AES_KEY_BYTES)
        self.sender_nonce_prefix = b"\x00\x00\x00\x00"
        self.receiver_nonce_prefix = b"\x00\x00\x00\x00"
        self.cleared = True


class Session:
    """Manages the state and security context of a single protocol session."""

    def __init__(
        self,
        local_peer_id: str,
        remote_peer_id: str,
        session_id: bytes | None = None,
        allow_out_of_order: bool = False,
        initiator_id: str | None = None,
        responder_id: str | None = None,
        remote_signing_public_key: bytes | None = None,
        remote_role: str | None = None,
    ) -> None:
        self.session_id: bytes = bytes(session_id) if session_id else os.urandom(16)
        if len(self.session_id) != 16:
            raise SessionError("session_id must be 16 bytes")
        self.local_peer_id: str = local_peer_id
        self.remote_peer_id: str = remote_peer_id
        self.initiator_id: str = initiator_id if initiator_id is not None else local_peer_id
        self.responder_id: str = responder_id if responder_id is not None else remote_peer_id
        self.remote_signing_public_key: bytes | None = (
            bytes(remote_signing_public_key) if remote_signing_public_key else None
        )
        self.remote_role: str | None = remote_role
        self.allow_out_of_order: bool = allow_out_of_order
        self.state: SessionState = SessionState.INIT
        self.keys: SessionKeys | None = None

        now_wall = time.time()
        self._initial_created_at: float = now_wall
        self.created_at: float = now_wall
        self._created_monotonic: float = time.monotonic()

        self.send_sequence: int = SEQUENCE_START
        self.recv_sequence: int = 0
        self.message_count: int = 0
        self.rekey_epoch: int = 0

        self._sender_nonce_counter: int = 0
        self._receiver_nonce_counter: int = 0
        self._max_emitted_sender_counter: int = 0
        self._max_emitted_receiver_counter: int = 0
        self._max_received_nonce_counter: int = 0

        # Strictly bounded O(NONCE_WINDOW_SIZE) replay/nonce tracking structures
        self._emitted_nonces: set[bytes] = set()
        self._emitted_nonce_order: collections.deque[bytes] = collections.deque()
        self._received_nonces: set[bytes] = set()
        self._received_nonce_order: collections.deque[bytes] = collections.deque()
        self._received_nonce_counters: set[int] = set()
        self._seen_sequences: set[int] = set()

        self._handshake_transcript: bytes = b""
        self._root_secret_buf: bytearray | None = None
        self._rekey_confirm_key: bytes | None = None
        self._shared_secret: bytes | None = None

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def mark_handshake_sent(self) -> None:
        """Transition from INIT to HANDSHAKE_SENT (initiator)."""
        if self.state != SessionState.INIT:
            raise SessionError(
                f"Cannot send handshake in state {self.state.name}"
            )
        self.initiator_id = self.local_peer_id
        self.responder_id = self.remote_peer_id
        self.state = SessionState.HANDSHAKE_SENT

    def mark_handshake_received(self) -> None:
        """Transition from INIT to HANDSHAKE_RECEIVED (responder)."""
        if self.state != SessionState.INIT:
            raise SessionError(
                f"Cannot receive handshake in state {self.state.name}"
            )
        self.initiator_id = self.remote_peer_id
        self.responder_id = self.local_peer_id
        self.state = SessionState.HANDSHAKE_RECEIVED

    def stage_handshake(self, shared_secret: bytes) -> None:
        """Derive epoch-0 keys on the responder and enter AWAITING_CONFIRM.

        Unlike v1, the session is NOT marked ESTABLISHED until
        `confirm_handshake()` is called after HANDSHAKE_CONFIRM verification.
        """
        if self.state != SessionState.HANDSHAKE_RECEIVED:
            raise SessionError(
                f"Cannot stage handshake in state {self.state.name}"
            )
        root_secret, confirm_key = derive_epoch_root_secret(
            kem_shared_secret=shared_secret,
            session_id=self.session_id,
            epoch=0,
            transcript_hash=self.transcript_hash,
            initiator_id=self.initiator_id,
            responder_id=self.responder_id,
            prev_root_secret=None,
        )
        self._set_root_secret(root_secret)
        self._rekey_confirm_key = confirm_key
        self._shared_secret = bytes(shared_secret)
        self.keys = SessionKeys.from_root_secret(
            root_secret=root_secret,
            session_id=self.session_id,
            epoch=0,
            transcript_hash=self.transcript_hash,
            initiator_id=self.initiator_id,
            responder_id=self.responder_id,
        )
        self.state = SessionState.AWAITING_CONFIRM

    def confirm_handshake(self) -> None:
        """Promote a staged responder session from AWAITING_CONFIRM to ESTABLISHED."""
        if self.state != SessionState.AWAITING_CONFIRM:
            raise SessionError(
                f"Cannot confirm handshake in state {self.state.name}"
            )
        if not self.keys:
            raise SessionError("Cannot confirm handshake without derived keys")
        self.state = SessionState.ESTABLISHED

    def establish(
        self,
        shared_secret: bytes,
        rekey_transcript_hash: bytes = b"",
    ) -> None:
        """Establish the session (or complete a rekey) and derive keys."""
        valid_pre_states = {
            SessionState.HANDSHAKE_SENT,
            SessionState.HANDSHAKE_RECEIVED,
            SessionState.AWAITING_CONFIRM,
            SessionState.REKEYING,
        }
        if self.state not in valid_pre_states:
            raise SessionError(
                f"Cannot establish session in state {self.state.name}"
            )

        if self.state == SessionState.REKEYING:
            next_epoch = self.rekey_epoch + 1
            ctx_hash = (
                rekey_transcript_hash
                if rekey_transcript_hash
                else self.transcript_hash
            )
            prev_root = self.root_secret
            root_secret, confirm_key = derive_epoch_root_secret(
                kem_shared_secret=shared_secret,
                session_id=self.session_id,
                epoch=next_epoch,
                transcript_hash=ctx_hash,
                initiator_id=self.initiator_id,
                responder_id=self.responder_id,
                prev_root_secret=prev_root,
            )
            next_keys = SessionKeys.from_root_secret(
                root_secret=root_secret,
                session_id=self.session_id,
                epoch=next_epoch,
                transcript_hash=ctx_hash,
                initiator_id=self.initiator_id,
                responder_id=self.responder_id,
            )
            self.commit_rekey(root_secret, next_keys, confirm_key)
            self._shared_secret = bytes(shared_secret)
            return

        root_secret, confirm_key = derive_epoch_root_secret(
            kem_shared_secret=shared_secret,
            session_id=self.session_id,
            epoch=0,
            transcript_hash=self.transcript_hash,
            initiator_id=self.initiator_id,
            responder_id=self.responder_id,
            prev_root_secret=None,
        )
        self._set_root_secret(root_secret)
        self._rekey_confirm_key = confirm_key
        self._shared_secret = bytes(shared_secret)
        self.keys = SessionKeys.from_root_secret(
            root_secret=root_secret,
            session_id=self.session_id,
            epoch=0,
            transcript_hash=self.transcript_hash,
            initiator_id=self.initiator_id,
            responder_id=self.responder_id,
        )
        self.state = SessionState.ESTABLISHED

    def prepare_rekey(
        self,
        new_shared_secret: bytes,
        rekey_transcript_hash: bytes,
    ) -> tuple[bytes, SessionKeys, bytes]:
        """Compute candidate next-epoch root secret, traffic keys, and confirm key
        without mutating the current epoch state."""
        if self.state not in (SessionState.ESTABLISHED, SessionState.REKEYING):
            raise SessionError(
                f"Cannot prepare rekey in state {self.state.name}"
            )
        next_epoch = self.rekey_epoch + 1
        root_secret, confirm_key = derive_epoch_root_secret(
            kem_shared_secret=new_shared_secret,
            session_id=self.session_id,
            epoch=next_epoch,
            transcript_hash=rekey_transcript_hash,
            initiator_id=self.initiator_id,
            responder_id=self.responder_id,
            prev_root_secret=self.root_secret,
        )
        next_keys = SessionKeys.from_root_secret(
            root_secret=root_secret,
            session_id=self.session_id,
            epoch=next_epoch,
            transcript_hash=rekey_transcript_hash,
            initiator_id=self.initiator_id,
            responder_id=self.responder_id,
        )
        return root_secret, next_keys, confirm_key

    def commit_rekey(
        self,
        next_root_secret: bytes,
        next_keys: SessionKeys,
        next_confirm_key: bytes | None = None,
    ) -> None:
        """Atomically transition to the next epoch and wipe previous epoch keys."""
        if self.state not in (SessionState.ESTABLISHED, SessionState.REKEYING):
            raise SessionError(
                f"Cannot commit rekey in state {self.state.name}"
            )
        if self.keys:
            self.keys.clear()
        self.rekey_epoch += 1
        self._set_root_secret(next_root_secret)
        self._rekey_confirm_key = next_confirm_key
        self.keys = next_keys

        # Reset per-epoch nonce counters and bounded nonce windows
        self._sender_nonce_counter = 0
        self._receiver_nonce_counter = 0
        self._max_emitted_sender_counter = 0
        self._max_emitted_receiver_counter = 0
        self._max_received_nonce_counter = 0
        self._emitted_nonces.clear()
        self._emitted_nonce_order.clear()
        self._received_nonces.clear()
        self._received_nonce_order.clear()
        self._received_nonce_counters.clear()

        self.state = SessionState.ESTABLISHED

    def begin_rekey(self) -> None:
        """Transition from ESTABLISHED to REKEYING while preserving current epoch keys."""
        if self.state != SessionState.ESTABLISHED:
            raise SessionError(
                f"Cannot rekey in state {self.state.name}"
            )
        self.state = SessionState.REKEYING

    def abort_rekey(self) -> None:
        """Safely roll back from REKEYING to ESTABLISHED on the current epoch if
        rekey completion fails before epoch commit."""
        if self.state == SessionState.REKEYING and self.keys and not self.keys.cleared:
            self.state = SessionState.ESTABLISHED

    def _set_root_secret(self, root_secret: bytes) -> None:
        """Store root_secret in a mutable bytearray buffer and zero any previous one."""
        if self._root_secret_buf is not None:
            for i in range(len(self._root_secret_buf)):
                self._root_secret_buf[i] = 0
        self._root_secret_buf = bytearray(root_secret)

    @property
    def root_secret(self) -> bytes | None:
        """Return current epoch root secret as bytes (or None if cleared)."""
        if self._root_secret_buf is None:
            return None
        return bytes(self._root_secret_buf)

    def _clear_secrets(self) -> None:
        if self.keys:
            self.keys.clear()
        self.keys = None
        if self._root_secret_buf is not None:
            for i in range(len(self._root_secret_buf)):
                self._root_secret_buf[i] = 0
            self._root_secret_buf = None
        self._rekey_confirm_key = None
        self._shared_secret = None

    def terminate(self) -> None:
        """Terminate the session and clear key material."""
        self._clear_secrets()
        self.state = SessionState.TERMINATED

    def expire(self) -> None:
        """Expire the session due to timeout or counter exhaustion."""
        self._clear_secrets()
        self.state = SessionState.EXPIRED

    # ------------------------------------------------------------------
    # Liveness checks
    # ------------------------------------------------------------------

    def _elapsed_seconds(self) -> float:
        """Compute session age using monotonic clock, honoring test adjustments to created_at."""
        monotonic_elapsed = time.monotonic() - self._created_monotonic
        if self.created_at != self._initial_created_at:
            adjusted = monotonic_elapsed + (
                self._initial_created_at - self.created_at
            )
            return max(monotonic_elapsed, adjusted)
        return monotonic_elapsed

    def check_alive(self) -> None:
        """Check that the session is established and within lifetime/message bounds."""
        if self.state == SessionState.TERMINATED:
            raise SessionError("Session has been terminated")
        if self.state == SessionState.EXPIRED:
            raise SessionExpiredError("Session has expired")
        if self.state != SessionState.ESTABLISHED:
            raise SessionError(
                f"Session is not established (state={self.state.name})"
            )
        elapsed = self._elapsed_seconds()
        if elapsed > SESSION_MAX_LIFETIME_SECONDS:
            self.expire()
            raise SessionExpiredError(
                f"Session expired after {elapsed:.0f}s "
                f"(max {SESSION_MAX_LIFETIME_SECONDS}s)"
            )
        if self.message_count >= SESSION_MAX_MESSAGES:
            self.expire()
            raise SessionExpiredError(
                f"Session exhausted after {self.message_count} messages"
            )

    # ------------------------------------------------------------------
    # Sequence number management
    # ------------------------------------------------------------------

    def next_send_sequence(self) -> int:
        """Get and increment the next outgoing sequence number."""
        self.check_alive()
        seq = self.send_sequence
        self.send_sequence += 1
        self.message_count += 1
        return seq

    def validate_recv_sequence(self, sequence: int) -> None:
        """Validate an incoming sequence number without mutating state."""
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise SequenceError(
                f"Invalid sequence number type: {type(sequence)}"
            )
        if sequence < SEQUENCE_START:
            raise SequenceError(
                f"Sequence number {sequence} below minimum {SEQUENCE_START}"
            )
        if sequence in self._seen_sequences:
            raise ReplayError(f"Duplicate sequence number: {sequence}")
        if not self.allow_out_of_order:
            if sequence <= self.recv_sequence:
                raise ReplayError(
                    f"Sequence {sequence} <= last accepted {self.recv_sequence}"
                )
        else:
            cutoff = max(0, self.recv_sequence - MAX_SEQUENCE_GAP)
            if sequence <= cutoff:
                raise ReplayError(
                    f"Sequence {sequence} outside sliding window (cutoff {cutoff})"
                )
        if sequence > self.recv_sequence + MAX_SEQUENCE_GAP:
            raise SequenceError(
                f"Sequence gap too large: {sequence} - "
                f"{self.recv_sequence} > {MAX_SEQUENCE_GAP}"
            )

    def accept_recv_sequence(self, sequence: int) -> None:
        """Record a validated sequence number as accepted after all checks pass."""
        self._seen_sequences.add(sequence)
        if sequence > self.recv_sequence:
            self.recv_sequence = sequence
        self.message_count += 1

        if len(self._seen_sequences) > MAX_SEQUENCE_GAP * 2:
            cutoff = self.recv_sequence - MAX_SEQUENCE_GAP
            self._seen_sequences = {
                s for s in self._seen_sequences if s > cutoff
            }

    # ------------------------------------------------------------------
    # Bounded deterministic 96-bit nonce management (NIST SP 800-38D)
    # ------------------------------------------------------------------

    def _record_emitted_nonce(self, nonce: bytes) -> None:
        if nonce in self._emitted_nonces:
            raise NonceError("Duplicate emitted nonce detected")
        self._emitted_nonces.add(nonce)
        self._emitted_nonce_order.append(nonce)
        while len(self._emitted_nonce_order) > NONCE_WINDOW_SIZE:
            oldest = self._emitted_nonce_order.popleft()
            self._emitted_nonces.discard(oldest)

    def next_sender_nonce(self, allow_handshake_confirm: bool = False) -> bytes:
        """Generate a unique 96-bit deterministic nonce for the sender key."""
        if not allow_handshake_confirm:
            self.check_alive()
        if not self.keys:
            raise SessionError("No session keys available")
        if self._sender_nonce_counter >= SESSION_MAX_MESSAGES:
            self.expire()
            raise NonceError("Sender nonce counter exhausted; rekey required")
        next_counter = self._sender_nonce_counter + 1
        if next_counter <= self._max_emitted_sender_counter:
            raise NonceError("Non-monotonic sender nonce counter")
        self._sender_nonce_counter = next_counter
        self._max_emitted_sender_counter = next_counter
        nonce = self.keys.sender_nonce_prefix + struct.pack(
            ">Q", self._sender_nonce_counter
        )
        self._record_emitted_nonce(nonce)
        return nonce

    def next_receiver_nonce(self) -> bytes:
        """Generate a unique 96-bit deterministic nonce for the receiver key."""
        self.check_alive()
        if not self.keys:
            raise SessionError("No session keys available")
        if self._receiver_nonce_counter >= SESSION_MAX_MESSAGES:
            self.expire()
            raise NonceError("Receiver nonce counter exhausted; rekey required")
        next_counter = self._receiver_nonce_counter + 1
        if next_counter <= self._max_emitted_receiver_counter:
            raise NonceError("Non-monotonic receiver nonce counter")
        self._receiver_nonce_counter = next_counter
        self._max_emitted_receiver_counter = next_counter
        nonce = self.keys.receiver_nonce_prefix + struct.pack(
            ">Q", self._receiver_nonce_counter
        )
        self._record_emitted_nonce(nonce)
        return nonce

    def validate_nonce(self, nonce: bytes) -> None:
        """Check without state mutation that an incoming 96-bit nonce is fresh."""
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != AES_NONCE_BYTES:
            raise NonceError(f"Invalid nonce length: {len(nonce) if isinstance(nonce, (bytes, bytearray)) else 'non-bytes'}")
        nonce_bytes = bytes(nonce)
        if nonce_bytes in self._received_nonces:
            raise NonceError("Duplicate nonce rejected (nonce reuse detected)")

        # If nonce uses the session's deterministic prefix, enforce O(1) counter window
        if self.keys:
            prefix = nonce_bytes[:4]
            if hmac.compare_digest(prefix, self.keys.sender_nonce_prefix) or hmac.compare_digest(
                prefix, self.keys.receiver_nonce_prefix
            ):
                counter = struct.unpack(">Q", nonce_bytes[4:])[0]
                if counter < 1 or counter > SESSION_MAX_MESSAGES:
                    raise NonceError(f"Nonce counter out of range: {counter}")
                if counter in self._received_nonce_counters:
                    raise NonceError(
                        "Duplicate nonce counter rejected (nonce reuse detected)"
                    )
                cutoff = max(
                    0, self._max_received_nonce_counter - NONCE_WINDOW_SIZE
                )
                if counter <= cutoff:
                    raise NonceError(
                        f"Stale nonce counter {counter} <= cutoff {cutoff} rejected"
                    )

    def record_nonce(self, nonce: bytes) -> None:
        """Record a validated 96-bit nonce in the bounded O(1) sliding window."""
        nonce_bytes = bytes(nonce)
        self._received_nonces.add(nonce_bytes)
        self._received_nonce_order.append(nonce_bytes)
        while len(self._received_nonce_order) > NONCE_WINDOW_SIZE:
            oldest = self._received_nonce_order.popleft()
            self._received_nonces.discard(oldest)

        if self.keys:
            prefix = nonce_bytes[:4]
            if hmac.compare_digest(prefix, self.keys.sender_nonce_prefix) or hmac.compare_digest(
                prefix, self.keys.receiver_nonce_prefix
            ):
                counter = struct.unpack(">Q", nonce_bytes[4:])[0]
                self._received_nonce_counters.add(counter)
                if counter > self._max_received_nonce_counter:
                    self._max_received_nonce_counter = counter
                cutoff = max(
                    0, self._max_received_nonce_counter - NONCE_WINDOW_SIZE
                )
                if len(self._received_nonce_counters) > NONCE_WINDOW_SIZE:
                    self._received_nonce_counters = {
                        c for c in self._received_nonce_counters if c > cutoff
                    }

    def validate_and_record_nonce(self, nonce: bytes) -> None:
        """Validate and immediately record a 96-bit nonce."""
        self.validate_nonce(nonce)
        self.record_nonce(nonce)

    # ------------------------------------------------------------------
    # Framed handshake transcript
    # ------------------------------------------------------------------

    def append_transcript(self, data: bytes) -> None:
        """Append length-delimited packet bytes to the handshake transcript."""
        if not isinstance(data, (bytes, bytearray)):
            raise SessionError("Transcript data must be bytes")
        raw = bytes(data)
        self._handshake_transcript += struct.pack(">I", len(raw)) + raw

    @property
    def transcript(self) -> bytes:
        """Return the accumulated framed handshake transcript."""
        return self._handshake_transcript

    @property
    def transcript_hash(self) -> bytes:
        """Return the 32-byte SHA-256 digest of the accumulated transcript."""
        return hashlib.sha256(self._handshake_transcript).digest()

    # ------------------------------------------------------------------
    # Key access
    # ------------------------------------------------------------------

    def get_sender_enc_key(self, allow_pending_confirm: bool = False) -> bytes:
        """Get the sender's encryption key."""
        if not allow_pending_confirm:
            self.check_alive()
        elif self.state not in (SessionState.AWAITING_CONFIRM, SessionState.ESTABLISHED):
            raise SessionError(
                f"Sender key unavailable in state {self.state.name}"
            )
        if not self.keys:
            raise SessionError("No session keys available")
        return self.keys.sender_enc_key

    def get_receiver_enc_key(self, allow_rekeying: bool = False) -> bytes:
        """Get the receiver's encryption key."""
        if allow_rekeying and self.state == SessionState.REKEYING:
            if not self.keys:
                raise SessionError("No session keys available")
            return self.keys.receiver_enc_key
        self.check_alive()
        if not self.keys:
            raise SessionError("No session keys available")
        return self.keys.receiver_enc_key
