"""Protocol v2 constants and configuration.

All security-critical parameters are defined here with rationale.
These values MUST NOT be weakened without a documented security review.
"""

# ---------------------------------------------------------------------------
# Protocol identification (v2 breaks wire compatibility with v1 intentionally)
# ---------------------------------------------------------------------------
PROTOCOL_VERSION: int = 2
PROTOCOL_NAME: str = "UAV-C2-PQ-L2"

# ---------------------------------------------------------------------------
# Cryptographic algorithm identifiers
# ---------------------------------------------------------------------------
KEM_ALGORITHM: str = "ML-KEM-768"
SIG_ALGORITHM: str = "ML-DSA-65"
AEAD_ALGORITHM: str = "AES-256-GCM"
KDF_ALGORITHM: str = "HKDF-SHA-256"

# ---------------------------------------------------------------------------
# FIPS 203 (ML-KEM-768) & FIPS 204 (ML-DSA-65) exact byte sizes
# ---------------------------------------------------------------------------
ML_KEM_768_PUBLIC_KEY_BYTES: int = 1184
ML_KEM_768_SECRET_KEY_BYTES: int = 2400
ML_KEM_768_CIPHERTEXT_BYTES: int = 1088
ML_KEM_768_SHARED_SECRET_BYTES: int = 32

ML_DSA_65_PUBLIC_KEY_BYTES: int = 1952
ML_DSA_65_SECRET_KEY_BYTES: int = 4032
ML_DSA_65_SIGNATURE_BYTES: int = 3309

# ---------------------------------------------------------------------------
# AES-GCM parameters
# ---------------------------------------------------------------------------
AES_KEY_BITS: int = 256
AES_KEY_BYTES: int = AES_KEY_BITS // 8   # 32
AES_NONCE_BYTES: int = 12                 # 96-bit nonce per NIST SP 800-38D
AES_TAG_BYTES: int = 16                   # 128-bit authentication tag

# ---------------------------------------------------------------------------
# HKDF parameters for v2 two-stage key schedule (root secret + traffic keys)
# ---------------------------------------------------------------------------
HKDF_HASH: str = "SHA256"
HKDF_KEY_LENGTH: int = AES_KEY_BYTES      # 32 bytes

# Context labels for domain separation in HKDF (v2)
HKDF_INFO_ROOT_INIT: bytes = b"UAV-C2-PQ-L2-v2-root-init"
HKDF_INFO_ROOT_REKEY: bytes = b"UAV-C2-PQ-L2-v2-root-rekey"
HKDF_INFO_REKEY_CONFIRM: bytes = b"UAV-C2-PQ-L2-v2-rekey-confirm"
HKDF_INFO_SENDER_ENC: bytes = b"UAV-C2-PQ-L2-v2-sender-enc"
HKDF_INFO_RECEIVER_ENC: bytes = b"UAV-C2-PQ-L2-v2-receiver-enc"
HKDF_INFO_SENDER_AUTH: bytes = b"UAV-C2-PQ-L2-v2-sender-nonce"
HKDF_INFO_RECEIVER_AUTH: bytes = b"UAV-C2-PQ-L2-v2-receiver-nonce"

# Transcript confirmation domain separator
TRANSCRIPT_CONFIRM_LABEL: bytes = b"UAV-C2-PQ-L2-v2-HANDSHAKE-CONFIRM\x00"

# ---------------------------------------------------------------------------
# Session & freshness parameters
# ---------------------------------------------------------------------------
# Maximum session lifetime in seconds (30 minutes for prototype).
SESSION_MAX_LIFETIME_SECONDS: int = 1800

# Maximum messages per session/epoch before mandatory rekey or expiration.
SESSION_MAX_MESSAGES: int = 2**20  # 1,048,576 messages

# Sequence number starts at 1; 0 is reserved for handshake/rekey-response headers.
SEQUENCE_START: int = 1

# Maximum tolerable gap in sequence numbers for out-of-order messages.
MAX_SEQUENCE_GAP: int = 100

# Bounded sliding window size for nonce/sequence replay tracking (O(1) memory).
NONCE_WINDOW_SIZE: int = MAX_SEQUENCE_GAP * 2  # 200 entries

# Handshake freshness, challenge nonce, and pending-slot protection
HANDSHAKE_NONCE_BYTES: int = 16
REKEY_NONCE_BYTES: int = 16
REKEY_CONFIRM_TAG_BYTES: int = 32
HANDSHAKE_PENDING_TIMEOUT_SECONDS: float = 10.0
HANDSHAKE_MAX_TIMESTAMP_SKEW_SECONDS: float = 60.0
COMMAND_MAX_TIMESTAMP_SKEW_SECONDS: float = 60.0
HANDSHAKE_REPLAY_CACHE_SIZE: int = 1024
HANDSHAKE_RATE_LIMIT_WINDOW_SECONDS: float = 10.0
HANDSHAKE_RATE_LIMIT_MAX_ATTEMPTS: int = 50

# ---------------------------------------------------------------------------
# Message format constants & pre-authentication input bounds
# ---------------------------------------------------------------------------
MSG_TYPE_HANDSHAKE_INIT: int = 1
MSG_TYPE_HANDSHAKE_RESPONSE: int = 2
MSG_TYPE_HANDSHAKE_CONFIRM: int = 3
MSG_TYPE_COMMAND: int = 4
MSG_TYPE_REKEY: int = 5
MSG_TYPE_TERMINATE: int = 6

# Header size: version(1) + msg_type(1) + session_id(16) + sequence(4) = 22
HEADER_SIZE: int = 22

# Minimum encrypted packet size: header(22) + nonce(12) + tag(16) = 50
MIN_PACKET_SIZE: int = HEADER_SIZE + AES_NONCE_BYTES + AES_TAG_BYTES

# Maximum payload sizes (bytes) — enforced before JSON/hex parsing
MAX_COMMAND_SIZE: int = 16384
MAX_HANDSHAKE_PAYLOAD_SIZE: int = 24576
MAX_REKEY_PAYLOAD_SIZE: int = 16384
MAX_TERMINATE_PAYLOAD_SIZE: int = 8192

# Maximum total wire packet size
MAX_PACKET_SIZE: int = 65536

# Field length bounds
MAX_PEER_ID_LENGTH: int = 64
MAX_COMMAND_VERB_LENGTH: int = 32
MAX_COMMAND_PARAMS_LENGTH: int = 512

# ---------------------------------------------------------------------------
# Peer roles
# ---------------------------------------------------------------------------
ROLE_GROUND_STATION: str = "ground_station"
ROLE_UAV: str = "uav"
VALID_ROLES: frozenset[str] = frozenset({ROLE_GROUND_STATION, ROLE_UAV})

# ---------------------------------------------------------------------------
# Valid command set
# ---------------------------------------------------------------------------
VALID_COMMANDS: set[str] = {
    "TAKEOFF",
    "LAND",
    "HOVER",
    "RTL",         # Return to Launch
    "WAYPOINT",
    "SET_ALTITUDE",
    "SET_SPEED",
    "EMERGENCY_STOP",
    "ABORT",
}
