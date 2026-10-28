"""Protocol-specific exception hierarchy.

Every protocol failure maps to a specific exception so that callers
can distinguish authentication failures from replay attacks, malformed
messages, session errors, and internal faults without inspecting
string messages.
"""


class ProtocolError(Exception):
    """Base class for all Layer 2 protocol errors."""


class IdentityError(ProtocolError):
    """Raised when a peer identity is unknown, revoked, or invalid."""


class TrustError(ProtocolError):
    """Raised when a peer's public key or role is not trusted or has been substituted."""


class HandshakeError(ProtocolError):
    """Raised when the session handshake fails for any reason."""


class SessionError(ProtocolError):
    """Raised for session lifecycle violations (expired, terminated, not established)."""


class SessionExpiredError(SessionError):
    """Raised when a session has exceeded its maximum lifetime or message count."""


class MessageFormatError(ProtocolError):
    """Raised when a message is malformed, truncated, or has invalid fields."""


class AuthenticationError(ProtocolError):
    """Raised when a message fails AES-GCM authentication or ML-DSA verification."""


class ReplayError(ProtocolError):
    """Raised when a replayed or duplicate message is detected."""


class SequenceError(ProtocolError):
    """Raised when a sequence number is invalid, duplicate, or out of policy."""


class NonceError(ProtocolError):
    """Raised when nonce uniqueness cannot be guaranteed or reuse is detected."""


class VersionError(ProtocolError):
    """Raised when a protocol version is unsupported."""


class CryptoError(ProtocolError):
    """Raised for unexpected cryptographic operation failures."""
