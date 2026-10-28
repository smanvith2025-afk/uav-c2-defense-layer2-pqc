"""Peer identity management, role binding, and trust store (v2).

Provides a PeerIdentity data class and a TrustStore that manages the
mapping from peer IDs to their trusted ML-DSA-65 public keys and
authorized protocol roles (ROLE_GROUND_STATION or ROLE_UAV).

Security invariants:
- Only registered, non-revoked peers with valid ML-DSA-65 public keys (1952 B)
  and valid roles are accepted.
- Public key comparison uses constant-time hmac.compare_digest.
- Peer roles (ROLE_GROUND_STATION vs. ROLE_UAV) are enforced at registration,
  handshake initiation, handshake response, handshake confirmation, command
  reception, rekeying, and termination.
- No secret keys are stored in the trust store.
"""

from __future__ import annotations

import copy
import hmac
import time
from dataclasses import dataclass, field

from protocol.constants import (
    MAX_PEER_ID_LENGTH,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    ROLE_GROUND_STATION,
    ROLE_UAV,
    VALID_ROLES,
)
from protocol.errors import IdentityError, TrustError


def _validate_peer_id_str(peer_id: str) -> None:
    """Validate that a peer_id is a safe, non-empty printable string."""
    if not isinstance(peer_id, str) or not peer_id:
        raise IdentityError("peer_id must be a non-empty string")
    if len(peer_id) > MAX_PEER_ID_LENGTH:
        raise IdentityError(
            f"peer_id exceeds maximum length ({MAX_PEER_ID_LENGTH})"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in peer_id):
        raise IdentityError("peer_id contains control characters")


@dataclass(frozen=False)
class PeerIdentity:
    """Represents a registered peer identity in the TrustStore."""
    peer_id: str
    role: str
    signing_public_key: bytes
    kem_public_key: bytes | None = None
    registered_at: float = field(default_factory=time.time)
    revoked: bool = False
    revoked_at: float | None = None

    def __post_init__(self) -> None:
        _validate_peer_id_str(self.peer_id)
        if not isinstance(self.role, str) or self.role not in VALID_ROLES:
            raise IdentityError(
                f"Invalid role '{self.role}'. "
                f"Must be '{ROLE_GROUND_STATION}' or '{ROLE_UAV}'."
            )
        if (
            not isinstance(self.signing_public_key, (bytes, bytearray))
            or len(self.signing_public_key) != ML_DSA_65_PUBLIC_KEY_BYTES
        ):
            raise IdentityError(
                f"signing_public_key must be {ML_DSA_65_PUBLIC_KEY_BYTES} bytes "
                f"(ML-DSA-65 public key)"
            )
        self.signing_public_key = bytes(self.signing_public_key)
        if self.kem_public_key is not None:
            if (
                not isinstance(self.kem_public_key, (bytes, bytearray))
                or len(self.kem_public_key) != ML_KEM_768_PUBLIC_KEY_BYTES
            ):
                raise IdentityError(
                    f"kem_public_key must be {ML_KEM_768_PUBLIC_KEY_BYTES} bytes "
                    f"(ML-KEM-768 public key)"
                )
            self.kem_public_key = bytes(self.kem_public_key)


class TrustStore:
    """Local trust store for pre-provisioned peer identities and roles."""

    def __init__(self) -> None:
        self._peers: dict[str, PeerIdentity] = {}

    def register_peer(
        self,
        peer_id: str,
        role: str,
        signing_public_key: bytes,
        kem_public_key: bytes | None = None,
    ) -> PeerIdentity:
        """Register or update a peer identity and authorized role."""
        identity = PeerIdentity(
            peer_id=peer_id,
            role=role,
            signing_public_key=signing_public_key,
            kem_public_key=kem_public_key,
            registered_at=time.time(),
            revoked=False,
            revoked_at=None,
        )
        self._peers[peer_id] = identity
        return identity

    def get_peer(self, peer_id: str) -> PeerIdentity:
        """Retrieve a registered, non-revoked peer identity."""
        if not isinstance(peer_id, str) or not peer_id:
            raise IdentityError("peer_id must be a non-empty string")
        identity = self._peers.get(peer_id)
        if identity is None:
            raise IdentityError(f"Unknown peer: {peer_id}")
        if identity.revoked:
            raise TrustError(f"Peer '{peer_id}' has been revoked")
        return identity

    def verify_signing_key(
        self, peer_id: str, signing_public_key: bytes
    ) -> bool:
        """Verify in constant time that a signing key matches the trusted key."""
        if (
            not isinstance(signing_public_key, (bytes, bytearray))
            or len(signing_public_key) != ML_DSA_65_PUBLIC_KEY_BYTES
        ):
            raise TrustError(
                f"Invalid signing key length for peer '{peer_id}'"
            )
        identity = self.get_peer(peer_id)
        if not hmac.compare_digest(
            identity.signing_public_key, bytes(signing_public_key)
        ):
            raise TrustError(
                f"Signing key mismatch for peer '{peer_id}'. "
                "Possible key substitution attack."
            )
        return True

    def verify_peer_role(
        self,
        peer_id: str,
        expected_role: str,
        claimed_role: str | None = None,
    ) -> PeerIdentity:
        """Verify that a registered peer has the expected role (and optional claimed role)."""
        identity = self.get_peer(peer_id)
        if identity.role != expected_role:
            raise TrustError(
                f"Peer '{peer_id}' has registered role '{identity.role}', "
                f"expected '{expected_role}'"
            )
        if claimed_role is not None and claimed_role != expected_role:
            raise TrustError(
                f"Peer '{peer_id}' claimed role '{claimed_role}', "
                f"expected '{expected_role}'"
            )
        return identity

    def revoke_peer(self, peer_id: str) -> None:
        """Revoke a peer identity, preventing future handshakes or commands."""
        identity = self._peers.get(peer_id)
        if identity is None:
            raise IdentityError(f"Unknown peer: {peer_id}")
        identity.revoked = True
        identity.revoked_at = time.time()

    def is_registered(self, peer_id: str) -> bool:
        """Check whether a peer is registered (regardless of revocation)."""
        return peer_id in self._peers

    def list_peers(self) -> list[PeerIdentity]:
        """Return a list of all registered peer identities (copies)."""
        return [copy.copy(p) for p in self._peers.values()]

    def clear(self) -> None:
        """Remove all registered peers. Use only in testing."""
        self._peers.clear()
