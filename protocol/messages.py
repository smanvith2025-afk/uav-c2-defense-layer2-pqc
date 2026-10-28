"""Canonical message formats, schemas, and serialization (UAV-C2-PQ-L2 v2).

Wire format for encrypted messages (HANDSHAKE_CONFIRM, COMMAND, REKEY, TERMINATE):
    [Header (22 bytes, AAD)] [Nonce (12 bytes)] [Ciphertext + 16-byte GCM tag]

Wire format for unencrypted handshake negotiation messages (INIT, RESPONSE):
    [Header (22 bytes)] [JSON-encoded HandshakePayload]

Header layout (22 bytes, big-endian):
    Offset  Size  Field
    0       1     Protocol version (uint8, must equal PROTOCOL_VERSION = 2)
    1       1     Message type (uint8, 1..6)
    2       16    Session ID (raw bytes)
    18      4     Sequence number (uint32, big-endian)
"""

from __future__ import annotations

import json
import math
import os
import struct
import time
from dataclasses import dataclass, field

from protocol.constants import (
    AEAD_ALGORITHM,
    AES_NONCE_BYTES,
    AES_TAG_BYTES,
    HANDSHAKE_NONCE_BYTES,
    HEADER_SIZE,
    KDF_ALGORITHM,
    KEM_ALGORITHM,
    MAX_COMMAND_PARAMS_LENGTH,
    MAX_COMMAND_SIZE,
    MAX_COMMAND_VERB_LENGTH,
    MAX_HANDSHAKE_PAYLOAD_SIZE,
    MAX_PACKET_SIZE,
    MAX_PEER_ID_LENGTH,
    MAX_REKEY_PAYLOAD_SIZE,
    MAX_TERMINATE_PAYLOAD_SIZE,
    MIN_PACKET_SIZE,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    MSG_TYPE_COMMAND,
    MSG_TYPE_HANDSHAKE_CONFIRM,
    MSG_TYPE_HANDSHAKE_INIT,
    MSG_TYPE_HANDSHAKE_RESPONSE,
    MSG_TYPE_REKEY,
    MSG_TYPE_TERMINATE,
    PROTOCOL_VERSION,
    REKEY_CONFIRM_TAG_BYTES,
    REKEY_NONCE_BYTES,
    SIG_ALGORITHM,
    VALID_COMMANDS,
    VALID_ROLES,
)
from protocol.errors import MessageFormatError, VersionError

# Header struct: version(B) + msg_type(B) + session_id(16s) + sequence(>I)
_HEADER_STRUCT = struct.Struct(">BB16sI")

VALID_MSG_TYPES: set[int] = {
    MSG_TYPE_HANDSHAKE_INIT,
    MSG_TYPE_HANDSHAKE_RESPONSE,
    MSG_TYPE_HANDSHAKE_CONFIRM,
    MSG_TYPE_COMMAND,
    MSG_TYPE_REKEY,
    MSG_TYPE_TERMINATE,
}


def _reject_json_constant(val: str) -> None:
    """Reject NaN, Infinity, and -Infinity in JSON numbers."""
    raise MessageFormatError(f"Non-finite JSON numeric constant rejected: {val}")


def _strict_json_loads(data: bytes, max_size: int, context: str) -> dict:
    """Safely parse a UTF-8 JSON object with size and constant guards."""
    if not isinstance(data, (bytes, bytearray)):
        raise MessageFormatError(f"{context} data must be bytes")
    if len(data) == 0:
        raise MessageFormatError(f"{context} data is empty")
    if len(data) > max_size:
        raise MessageFormatError(
            f"{context} payload too large: {len(data)} > {max_size} bytes"
        )
    try:
        obj = json.loads(
            bytes(data).decode("utf-8"),
            parse_constant=_reject_json_constant,
        )
    except MessageFormatError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MessageFormatError(f"Invalid {context} JSON") from exc
    if not isinstance(obj, dict):
        raise MessageFormatError(f"{context} JSON root must be an object")
    return obj


def _validate_safe_str(
    value: object,
    field_name: str,
    max_len: int,
    allow_empty: bool = False,
) -> str:
    """Validate that a field is a printable string within bounds."""
    if not isinstance(value, str):
        raise MessageFormatError(f"{field_name} must be a string")
    if not allow_empty and len(value) == 0:
        raise MessageFormatError(f"{field_name} must not be empty")
    if len(value) > max_len:
        raise MessageFormatError(
            f"{field_name} exceeds maximum length ({max_len})"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise MessageFormatError(
            f"{field_name} contains disallowed control characters"
        )
    return value


def _validate_finite_timestamp(value: object, field_name: str = "timestamp") -> float:
    """Validate that a timestamp is a finite positive number (never a bool)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MessageFormatError(f"{field_name} must be a finite number")
    ts = float(value)
    if not math.isfinite(ts) or ts <= 0.0:
        raise MessageFormatError(f"{field_name} must be a finite positive number")
    return ts


@dataclass(frozen=True)
class MessageHeader:
    """Parsed and validated 22-byte protocol message header."""
    version: int
    msg_type: int
    session_id: bytes
    sequence: int

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise MessageFormatError("Header version must be an int")
        if isinstance(self.msg_type, bool) or not isinstance(self.msg_type, int):
            raise MessageFormatError("Header msg_type must be an int")
        if (
            not isinstance(self.session_id, (bytes, bytearray))
            or len(self.session_id) != 16
        ):
            raise MessageFormatError("Header session_id must be 16 bytes")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or not (0 <= self.sequence <= 0xFFFFFFFF)
        ):
            raise MessageFormatError("Header sequence must be uint32")

    def to_bytes(self) -> bytes:
        """Serialize the header to wire format (22 bytes)."""
        return _HEADER_STRUCT.pack(
            self.version,
            self.msg_type,
            bytes(self.session_id),
            self.sequence,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "MessageHeader":
        """Parse and validate a header from wire format bytes."""
        if not isinstance(data, (bytes, bytearray)):
            raise MessageFormatError("Packet data must be bytes")
        if len(data) < HEADER_SIZE:
            raise MessageFormatError(
                f"Header too short: {len(data)} < {HEADER_SIZE} bytes"
            )
        version, msg_type, session_id, sequence = _HEADER_STRUCT.unpack_from(
            data, 0
        )
        if version != PROTOCOL_VERSION:
            raise VersionError(
                f"Unsupported protocol version: {version} "
                f"(expected {PROTOCOL_VERSION})"
            )
        if msg_type not in VALID_MSG_TYPES:
            raise MessageFormatError(f"Invalid message type: {msg_type}")
        return cls(
            version=version,
            msg_type=msg_type,
            session_id=session_id,
            sequence=sequence,
        )


@dataclass(frozen=True)
class CommandPayload:
    """Structured command payload for signing and encryption."""
    sender_id: str
    recipient_id: str
    command: str
    params: str
    timestamp: float
    signature: bytes = b""

    def canonical_bytes_for_signing(
        self,
        session_id: bytes,
        sequence: int,
    ) -> bytes:
        """Produce the canonical byte string that is signed by ML-DSA-65."""
        if (
            not isinstance(session_id, (bytes, bytearray))
            or len(session_id) != 16
        ):
            raise MessageFormatError("session_id must be 16 bytes")
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise MessageFormatError("sequence must be an integer")
        ts = _validate_finite_timestamp(self.timestamp)
        obj = {
            "protocol_version": PROTOCOL_VERSION,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "session_id": bytes(session_id).hex(),
            "sequence": sequence,
            "command": self.command,
            "params": self.params,
            "timestamp": ts,
        }
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    def to_json_bytes(self) -> bytes:
        """Serialize the command payload for AES-256-GCM encryption."""
        ts = _validate_finite_timestamp(self.timestamp)
        obj = {
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "command": self.command,
            "params": self.params,
            "timestamp": ts,
            "signature": bytes(self.signature).hex(),
        }
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "CommandPayload":
        """Deserialize and validate a command payload from JSON bytes."""
        obj = _strict_json_loads(data, MAX_COMMAND_SIZE, "command")

        required = {
            "sender_id",
            "recipient_id",
            "command",
            "params",
            "timestamp",
            "signature",
        }
        missing = required - set(obj.keys())
        if missing:
            raise MessageFormatError(f"Missing payload fields: {missing}")
        extra = set(obj.keys()) - required
        if extra:
            raise MessageFormatError(f"Unexpected payload fields: {extra}")

        sender_id = _validate_safe_str(
            obj["sender_id"], "sender_id", MAX_PEER_ID_LENGTH
        )
        recipient_id = _validate_safe_str(
            obj["recipient_id"], "recipient_id", MAX_PEER_ID_LENGTH
        )
        command = _validate_safe_str(
            obj["command"], "command", MAX_COMMAND_VERB_LENGTH
        )
        if command not in VALID_COMMANDS:
            raise MessageFormatError(
                f"Unauthorized or unrecognized command verb: '{command}'"
            )
        params = _validate_safe_str(
            obj["params"],
            "params",
            MAX_COMMAND_PARAMS_LENGTH,
            allow_empty=True,
        )
        timestamp = _validate_finite_timestamp(obj["timestamp"])

        if not isinstance(obj["signature"], str):
            raise MessageFormatError("signature must be a hex string")
        if len(obj["signature"]) != ML_DSA_65_SIGNATURE_BYTES * 2:
            raise MessageFormatError(
                f"Invalid signature hex length: {len(obj['signature'])}"
            )
        try:
            sig_bytes = bytes.fromhex(obj["signature"])
        except ValueError as exc:
            raise MessageFormatError("Invalid signature hex") from exc
        if len(sig_bytes) != ML_DSA_65_SIGNATURE_BYTES:
            raise MessageFormatError("Invalid ML-DSA-65 signature length")

        return cls(
            sender_id=sender_id,
            recipient_id=recipient_id,
            command=command,
            params=params,
            timestamp=timestamp,
            signature=sig_bytes,
        )


@dataclass(frozen=True)
class HandshakePayload:
    """Payload for v2 handshake messages (INIT and RESPONSE).

    Binds protocol version, algorithm suite identifiers, peer identities and
    roles, timestamp, 16-byte freshness nonce, signing public key, initiator
    ephemeral ML-KEM-768 public key (echoed in response), and KEM ciphertext.
    """
    sender_id: str
    sender_role: str
    sender_signing_key: bytes
    sender_kem_key: bytes
    kem_ciphertext: bytes
    signature: bytes = b""
    recipient_id: str = ""
    timestamp: float = field(default_factory=time.time)
    handshake_nonce: bytes = field(
        default_factory=lambda: os.urandom(HANDSHAKE_NONCE_BYTES)
    )
    kem_algorithm: str = KEM_ALGORITHM
    sig_algorithm: str = SIG_ALGORITHM
    aead_algorithm: str = AEAD_ALGORITHM
    kdf_algorithm: str = KDF_ALGORITHM

    def canonical_bytes_for_signing(
        self,
        session_id: bytes,
        recipient_id: str | None = None,
    ) -> bytes:
        """Produce the canonical byte string for handshake signing."""
        if (
            not isinstance(session_id, (bytes, bytearray))
            or len(session_id) != 16
        ):
            raise MessageFormatError("session_id must be 16 bytes")
        target_recipient = (
            recipient_id if recipient_id is not None else self.recipient_id
        )
        ts = _validate_finite_timestamp(self.timestamp)
        obj = {
            "protocol_version": PROTOCOL_VERSION,
            "kem_algorithm": self.kem_algorithm,
            "sig_algorithm": self.sig_algorithm,
            "aead_algorithm": self.aead_algorithm,
            "kdf_algorithm": self.kdf_algorithm,
            "sender_id": self.sender_id,
            "sender_role": self.sender_role,
            "recipient_id": target_recipient,
            "session_id": bytes(session_id).hex(),
            "timestamp": ts,
            "handshake_nonce": bytes(self.handshake_nonce).hex(),
            "sender_signing_key": bytes(self.sender_signing_key).hex(),
            "sender_kem_key": bytes(self.sender_kem_key).hex(),
            "kem_ciphertext": bytes(self.kem_ciphertext).hex(),
        }
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    def to_json_bytes(self) -> bytes:
        """Serialize handshake payload for wire transmission."""
        ts = _validate_finite_timestamp(self.timestamp)
        obj = {
            "protocol_version": PROTOCOL_VERSION,
            "kem_algorithm": self.kem_algorithm,
            "sig_algorithm": self.sig_algorithm,
            "aead_algorithm": self.aead_algorithm,
            "kdf_algorithm": self.kdf_algorithm,
            "sender_id": self.sender_id,
            "sender_role": self.sender_role,
            "recipient_id": self.recipient_id,
            "timestamp": ts,
            "handshake_nonce": bytes(self.handshake_nonce).hex(),
            "sender_signing_key": bytes(self.sender_signing_key).hex(),
            "sender_kem_key": bytes(self.sender_kem_key).hex(),
            "kem_ciphertext": bytes(self.kem_ciphertext).hex(),
            "signature": bytes(self.signature).hex(),
        }
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "HandshakePayload":
        """Deserialize and strictly validate a v2 handshake payload."""
        obj = _strict_json_loads(data, MAX_HANDSHAKE_PAYLOAD_SIZE, "handshake")

        required = {
            "protocol_version",
            "kem_algorithm",
            "sig_algorithm",
            "aead_algorithm",
            "kdf_algorithm",
            "sender_id",
            "sender_role",
            "recipient_id",
            "timestamp",
            "handshake_nonce",
            "sender_signing_key",
            "sender_kem_key",
            "kem_ciphertext",
            "signature",
        }
        missing = required - set(obj.keys())
        if missing:
            raise MessageFormatError(f"Missing handshake fields: {missing}")
        extra = set(obj.keys()) - required
        if extra:
            raise MessageFormatError(f"Unexpected handshake fields: {extra}")

        if (
            isinstance(obj["protocol_version"], bool)
            or obj["protocol_version"] != PROTOCOL_VERSION
        ):
            raise VersionError(
                f"Unsupported handshake protocol_version: {obj['protocol_version']}"
            )
        if obj["kem_algorithm"] != KEM_ALGORITHM:
            raise MessageFormatError(
                f"Unsupported KEM algorithm: {obj['kem_algorithm']}"
            )
        if obj["sig_algorithm"] != SIG_ALGORITHM:
            raise MessageFormatError(
                f"Unsupported signature algorithm: {obj['sig_algorithm']}"
            )
        if obj["aead_algorithm"] != AEAD_ALGORITHM:
            raise MessageFormatError(
                f"Unsupported AEAD algorithm: {obj['aead_algorithm']}"
            )
        if obj["kdf_algorithm"] != KDF_ALGORITHM:
            raise MessageFormatError(
                f"Unsupported KDF algorithm: {obj['kdf_algorithm']}"
            )

        sender_id = _validate_safe_str(
            obj["sender_id"], "sender_id", MAX_PEER_ID_LENGTH
        )
        sender_role = _validate_safe_str(
            obj["sender_role"], "sender_role", MAX_PEER_ID_LENGTH
        )
        if sender_role not in VALID_ROLES:
            raise MessageFormatError(
                f"Invalid handshake sender_role: '{sender_role}'"
            )
        recipient_id = _validate_safe_str(
            obj["recipient_id"], "recipient_id", MAX_PEER_ID_LENGTH
        )
        timestamp = _validate_finite_timestamp(obj["timestamp"])

        for hex_field in (
            "handshake_nonce",
            "sender_signing_key",
            "sender_kem_key",
            "kem_ciphertext",
            "signature",
        ):
            if not isinstance(obj[hex_field], str):
                raise MessageFormatError(f"{hex_field} must be a hex string")

        try:
            handshake_nonce = bytes.fromhex(obj["handshake_nonce"])
            sender_signing_key = bytes.fromhex(obj["sender_signing_key"])
            sender_kem_key = bytes.fromhex(obj["sender_kem_key"])
            kem_ciphertext = bytes.fromhex(obj["kem_ciphertext"])
            signature = bytes.fromhex(obj["signature"])
        except ValueError as exc:
            raise MessageFormatError(
                "Invalid hex encoding in handshake fields"
            ) from exc

        if len(handshake_nonce) != HANDSHAKE_NONCE_BYTES:
            raise MessageFormatError(
                f"handshake_nonce must be {HANDSHAKE_NONCE_BYTES} bytes"
            )
        if len(sender_signing_key) != ML_DSA_65_PUBLIC_KEY_BYTES:
            raise MessageFormatError(
                f"sender_signing_key must be {ML_DSA_65_PUBLIC_KEY_BYTES} bytes"
            )
        if len(sender_kem_key) != ML_KEM_768_PUBLIC_KEY_BYTES:
            raise MessageFormatError(
                f"sender_kem_key must be {ML_KEM_768_PUBLIC_KEY_BYTES} bytes"
            )
        if kem_ciphertext and len(kem_ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
            raise MessageFormatError(
                f"kem_ciphertext must be 0 or {ML_KEM_768_CIPHERTEXT_BYTES} bytes"
            )
        if len(signature) != ML_DSA_65_SIGNATURE_BYTES:
            raise MessageFormatError(
                f"signature must be {ML_DSA_65_SIGNATURE_BYTES} bytes"
            )

        return cls(
            sender_id=sender_id,
            sender_role=sender_role,
            recipient_id=recipient_id,
            timestamp=timestamp,
            handshake_nonce=handshake_nonce,
            sender_signing_key=sender_signing_key,
            sender_kem_key=sender_kem_key,
            kem_ciphertext=kem_ciphertext,
            signature=signature,
            kem_algorithm=obj["kem_algorithm"],
            sig_algorithm=obj["sig_algorithm"],
            aead_algorithm=obj["aead_algorithm"],
            kdf_algorithm=obj["kdf_algorithm"],
        )


@dataclass(frozen=True)
class RekeyPayload:
    """Authenticated in-session rekey payload (v2).

    Binds session_id, sequence, current_epoch, next_epoch, peer identities,
    16-byte rekey_nonce, ephemeral ML-KEM-768 public key, KEM ciphertext,
    explicit key confirmation HMAC tag, and ML-DSA-65 signature.
    """
    sender_id: str
    recipient_id: str
    current_epoch: int
    next_epoch: int
    rekey_nonce: bytes
    sender_kem_key: bytes
    kem_ciphertext: bytes = b""
    key_confirm_tag: bytes = b""
    signature: bytes = b""

    def canonical_bytes_for_signing(
        self,
        session_id: bytes,
        sequence: int,
    ) -> bytes:
        """Produce canonical byte representation for ML-DSA-65 signing."""
        obj = {
            "protocol_version": PROTOCOL_VERSION,
            "msg_type": MSG_TYPE_REKEY,
            "session_id": bytes(session_id).hex(),
            "sequence": sequence,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "current_epoch": self.current_epoch,
            "next_epoch": self.next_epoch,
            "rekey_nonce": bytes(self.rekey_nonce).hex(),
            "sender_kem_key": bytes(self.sender_kem_key).hex(),
            "kem_ciphertext": bytes(self.kem_ciphertext).hex(),
            "key_confirm_tag": bytes(self.key_confirm_tag).hex(),
        }
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    def to_json_bytes(self) -> bytes:
        """Serialize for AES-256-GCM encryption."""
        obj = {
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "current_epoch": self.current_epoch,
            "next_epoch": self.next_epoch,
            "rekey_nonce": bytes(self.rekey_nonce).hex(),
            "sender_kem_key": bytes(self.sender_kem_key).hex(),
            "kem_ciphertext": bytes(self.kem_ciphertext).hex(),
            "key_confirm_tag": bytes(self.key_confirm_tag).hex(),
            "signature": bytes(self.signature).hex(),
        }
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "RekeyPayload":
        """Deserialize and validate a rekey payload."""
        obj = _strict_json_loads(data, MAX_REKEY_PAYLOAD_SIZE, "rekey")
        required = {
            "sender_id",
            "recipient_id",
            "current_epoch",
            "next_epoch",
            "rekey_nonce",
            "sender_kem_key",
            "kem_ciphertext",
            "key_confirm_tag",
            "signature",
        }
        missing = required - set(obj.keys())
        if missing:
            raise MessageFormatError(f"Missing rekey fields: {missing}")
        extra = set(obj.keys()) - required
        if extra:
            raise MessageFormatError(f"Unexpected rekey fields: {extra}")

        sender_id = _validate_safe_str(
            obj["sender_id"], "sender_id", MAX_PEER_ID_LENGTH
        )
        recipient_id = _validate_safe_str(
            obj["recipient_id"], "recipient_id", MAX_PEER_ID_LENGTH
        )
        for epoch_field in ("current_epoch", "next_epoch"):
            val = obj[epoch_field]
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise MessageFormatError(
                    f"{epoch_field} must be a non-negative int"
                )
        current_epoch = obj["current_epoch"]
        next_epoch = obj["next_epoch"]
        if next_epoch != current_epoch + 1:
            raise MessageFormatError(
                f"Invalid epoch transition: {current_epoch} -> {next_epoch}"
            )

        for hex_field in (
            "rekey_nonce",
            "sender_kem_key",
            "kem_ciphertext",
            "key_confirm_tag",
            "signature",
        ):
            if not isinstance(obj[hex_field], str):
                raise MessageFormatError(f"{hex_field} must be a hex string")

        try:
            rekey_nonce = bytes.fromhex(obj["rekey_nonce"])
            sender_kem_key = bytes.fromhex(obj["sender_kem_key"])
            kem_ciphertext = bytes.fromhex(obj["kem_ciphertext"])
            key_confirm_tag = bytes.fromhex(obj["key_confirm_tag"])
            signature = bytes.fromhex(obj["signature"])
        except ValueError as exc:
            raise MessageFormatError("Invalid hex in rekey payload") from exc

        if len(rekey_nonce) != REKEY_NONCE_BYTES:
            raise MessageFormatError(
                f"rekey_nonce must be {REKEY_NONCE_BYTES} bytes"
            )
        if len(sender_kem_key) != ML_KEM_768_PUBLIC_KEY_BYTES:
            raise MessageFormatError(
                f"sender_kem_key must be {ML_KEM_768_PUBLIC_KEY_BYTES} bytes"
            )
        if kem_ciphertext and len(kem_ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
            raise MessageFormatError(
                f"kem_ciphertext must be 0 or {ML_KEM_768_CIPHERTEXT_BYTES} bytes"
            )
        if key_confirm_tag and len(key_confirm_tag) != REKEY_CONFIRM_TAG_BYTES:
            raise MessageFormatError(
                f"key_confirm_tag must be 0 or {REKEY_CONFIRM_TAG_BYTES} bytes"
            )
        if len(signature) != ML_DSA_65_SIGNATURE_BYTES:
            raise MessageFormatError(
                f"signature must be {ML_DSA_65_SIGNATURE_BYTES} bytes"
            )

        return cls(
            sender_id=sender_id,
            recipient_id=recipient_id,
            current_epoch=current_epoch,
            next_epoch=next_epoch,
            rekey_nonce=rekey_nonce,
            sender_kem_key=sender_kem_key,
            kem_ciphertext=kem_ciphertext,
            key_confirm_tag=key_confirm_tag,
            signature=signature,
        )


@dataclass(frozen=True)
class TerminatePayload:
    """Authenticated session termination payload (v2)."""
    sender_id: str
    recipient_id: str
    epoch: int
    timestamp: float
    reason: str = "TERMINATE"
    signature: bytes = b""

    def canonical_bytes_for_signing(
        self,
        session_id: bytes,
        sequence: int,
    ) -> bytes:
        ts = _validate_finite_timestamp(self.timestamp)
        obj = {
            "protocol_version": PROTOCOL_VERSION,
            "msg_type": MSG_TYPE_TERMINATE,
            "session_id": bytes(session_id).hex(),
            "sequence": sequence,
            "epoch": self.epoch,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "timestamp": ts,
            "reason": self.reason,
        }
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    def to_json_bytes(self) -> bytes:
        ts = _validate_finite_timestamp(self.timestamp)
        obj = {
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "epoch": self.epoch,
            "timestamp": ts,
            "reason": self.reason,
            "signature": bytes(self.signature).hex(),
        }
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "TerminatePayload":
        obj = _strict_json_loads(data, MAX_TERMINATE_PAYLOAD_SIZE, "terminate")
        required = {
            "sender_id",
            "recipient_id",
            "epoch",
            "timestamp",
            "reason",
            "signature",
        }
        missing = required - set(obj.keys())
        if missing:
            raise MessageFormatError(f"Missing terminate fields: {missing}")
        extra = set(obj.keys()) - required
        if extra:
            raise MessageFormatError(f"Unexpected terminate fields: {extra}")

        sender_id = _validate_safe_str(
            obj["sender_id"], "sender_id", MAX_PEER_ID_LENGTH
        )
        recipient_id = _validate_safe_str(
            obj["recipient_id"], "recipient_id", MAX_PEER_ID_LENGTH
        )
        if (
            isinstance(obj["epoch"], bool)
            or not isinstance(obj["epoch"], int)
            or obj["epoch"] < 0
        ):
            raise MessageFormatError("epoch must be a non-negative integer")
        timestamp = _validate_finite_timestamp(obj["timestamp"])
        reason = _validate_safe_str(obj["reason"], "reason", 64)
        if reason != "TERMINATE":
            raise MessageFormatError(f"Invalid terminate reason: {reason}")
        if not isinstance(obj["signature"], str):
            raise MessageFormatError("signature must be a hex string")
        try:
            sig_bytes = bytes.fromhex(obj["signature"])
        except ValueError as exc:
            raise MessageFormatError("Invalid signature hex") from exc
        if len(sig_bytes) != ML_DSA_65_SIGNATURE_BYTES:
            raise MessageFormatError("Invalid ML-DSA-65 signature length")

        return cls(
            sender_id=sender_id,
            recipient_id=recipient_id,
            epoch=obj["epoch"],
            timestamp=timestamp,
            reason=reason,
            signature=sig_bytes,
        )


def build_packet(
    header: MessageHeader,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    """Assemble a complete encrypted wire packet."""
    header_bytes = header.to_bytes()
    if len(nonce) != AES_NONCE_BYTES:
        raise MessageFormatError(
            f"Nonce must be {AES_NONCE_BYTES} bytes, got {len(nonce)}"
        )
    if len(ciphertext) < AES_TAG_BYTES:
        raise MessageFormatError("Ciphertext shorter than GCM tag")
    total = len(header_bytes) + len(nonce) + len(ciphertext)
    if total > MAX_PACKET_SIZE:
        raise MessageFormatError(
            f"Packet exceeds maximum size: {total} > {MAX_PACKET_SIZE}"
        )
    return header_bytes + bytes(nonce) + bytes(ciphertext)


def parse_packet(data: bytes) -> tuple[MessageHeader, bytes, bytes]:
    """Disassemble a raw encrypted wire packet into (header, nonce, ciphertext)."""
    if not isinstance(data, (bytes, bytearray)):
        raise MessageFormatError(
            f"Packet must be bytes, got {type(data).__name__}"
        )
    if len(data) < MIN_PACKET_SIZE:
        raise MessageFormatError(
            f"Packet too short: {len(data)} < {MIN_PACKET_SIZE} bytes"
        )
    if len(data) > MAX_PACKET_SIZE:
        raise MessageFormatError(
            f"Packet too large: {len(data)} > {MAX_PACKET_SIZE} bytes"
        )
    header = MessageHeader.from_bytes(data[:HEADER_SIZE])
    nonce = bytes(data[HEADER_SIZE : HEADER_SIZE + AES_NONCE_BYTES])
    ciphertext = bytes(data[HEADER_SIZE + AES_NONCE_BYTES :])
    return header, nonce, ciphertext
