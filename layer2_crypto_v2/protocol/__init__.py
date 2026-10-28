"""
Layer 2 Post-Quantum UAV Command Security Protocol (UAV-C2-PQ-L2 v2).

This package implements a post-quantum command-and-control security
protocol for UAV operations, using:

- ML-KEM-768 (FIPS 203) for post-quantum ephemeral key establishment
- HKDF-SHA-256 (RFC 5869) for transcript- and root-secret-bound key derivation
- AES-256-GCM (NIST SP 800-38D) for authenticated encryption with header AAD
- ML-DSA-65 (FIPS 204) for digital signatures across handshake, commands,
  rekeying, and session termination

Modules:
    identity    - Peer identity management, role binding, and trust store
    crypto_core - Low-level cryptographic operations with FIPS length guards
    session     - Session lifecycle, two-stage key schedule, and bounded replay state
    messages    - Canonical message formats, schemas, and serialization
    sender      - Command sender (ground station) role
    receiver    - Command receiver (UAV) role
    transport   - Transport interface and local test transport
    errors      - Protocol-specific exception hierarchy
    constants   - Protocol v2 constants and security parameters
"""

from protocol.constants import PROTOCOL_NAME, PROTOCOL_VERSION

__version__ = "2.0.0"
__all__ = ["PROTOCOL_NAME", "PROTOCOL_VERSION", "__version__"]
