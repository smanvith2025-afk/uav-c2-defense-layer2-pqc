"""Low-level cryptographic operations (v2).

Wraps liboqs and the Python cryptography library to provide a clean
interface for the protocol layer. No protocol state is managed here.

Security invariants:
- Exact FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) key, ciphertext,
  and signature byte lengths are validated before crossing the C FFI boundary.
- AES-GCM nonces are always 12 bytes (96-bit).
- HKDF uses explicit info labels and salts for domain separation.
- Private keys and shared secrets are never included in exception messages.
"""

from __future__ import annotations

import hmac
import hashlib
import os
from typing import NamedTuple

import oqs
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from protocol.constants import (
    AES_KEY_BYTES,
    AES_NONCE_BYTES,
    AES_TAG_BYTES,
    HKDF_KEY_LENGTH,
    KEM_ALGORITHM,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SECRET_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    ML_KEM_768_SECRET_KEY_BYTES,
    ML_KEM_768_SHARED_SECRET_BYTES,
    SIG_ALGORITHM,
)
from protocol.errors import AuthenticationError, CryptoError


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class KEMKeyPair(NamedTuple):
    """ML-KEM-768 key pair — public_key (1184 B) is shareable, secret_key (2400 B) is not."""
    public_key: bytes
    secret_key: bytes


class KEMEncapResult(NamedTuple):
    """Result of ML-KEM-768 encapsulation."""
    ciphertext: bytes
    shared_secret: bytes


class SigningKeyPair(NamedTuple):
    """ML-DSA-65 key pair — public_key (1952 B) is shareable, secret_key (4032 B) is not."""
    public_key: bytes
    secret_key: bytes


# ---------------------------------------------------------------------------
# ML-KEM-768 operations (FIPS 203)
# ---------------------------------------------------------------------------

def kem_generate_keypair() -> KEMKeyPair:
    """Generate a fresh ML-KEM-768 key pair."""
    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            public_key = bytes(kem.generate_keypair())
            secret_key = bytes(kem.export_secret_key())
            if (
                len(public_key) != ML_KEM_768_PUBLIC_KEY_BYTES
                or len(secret_key) != ML_KEM_768_SECRET_KEY_BYTES
            ):
                raise CryptoError("Generated ML-KEM-768 key lengths invalid")
            return KEMKeyPair(public_key=public_key, secret_key=secret_key)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError("ML-KEM key generation failed") from exc


def kem_encapsulate(public_key: bytes) -> KEMEncapResult:
    """Encapsulate a shared secret using the peer's ML-KEM-768 public key (1184 B)."""
    if (
        not isinstance(public_key, (bytes, bytearray))
        or len(public_key) != ML_KEM_768_PUBLIC_KEY_BYTES
    ):
        raise CryptoError(
            f"ML-KEM-768 public key must be {ML_KEM_768_PUBLIC_KEY_BYTES} bytes"
        )
    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(bytes(public_key))
            ct_bytes = bytes(ciphertext)
            ss_bytes = bytes(shared_secret)
            if (
                len(ct_bytes) != ML_KEM_768_CIPHERTEXT_BYTES
                or len(ss_bytes) != ML_KEM_768_SHARED_SECRET_BYTES
            ):
                raise CryptoError("ML-KEM-768 encapsulation output length invalid")
            return KEMEncapResult(ciphertext=ct_bytes, shared_secret=ss_bytes)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError("ML-KEM encapsulation failed") from exc


def kem_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Decapsulate a shared secret using the local ML-KEM-768 secret key (2400 B)."""
    if (
        not isinstance(ciphertext, (bytes, bytearray))
        or len(ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES
    ):
        raise CryptoError(
            f"ML-KEM-768 ciphertext must be {ML_KEM_768_CIPHERTEXT_BYTES} bytes"
        )
    if (
        not isinstance(secret_key, (bytes, bytearray))
        or len(secret_key) != ML_KEM_768_SECRET_KEY_BYTES
    ):
        raise CryptoError(
            f"ML-KEM-768 secret key must be {ML_KEM_768_SECRET_KEY_BYTES} bytes"
        )
    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM, bytes(secret_key)) as kem:
            shared_secret = bytes(kem.decap_secret(bytes(ciphertext)))
            if len(shared_secret) != ML_KEM_768_SHARED_SECRET_BYTES:
                raise CryptoError("ML-KEM-768 shared secret length invalid")
            return shared_secret
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError("ML-KEM decapsulation failed") from exc


# ---------------------------------------------------------------------------
# ML-DSA-65 operations (FIPS 204)
# ---------------------------------------------------------------------------

def sig_generate_keypair() -> SigningKeyPair:
    """Generate a fresh ML-DSA-65 signing key pair."""
    try:
        with oqs.Signature(SIG_ALGORITHM) as sig:
            public_key = bytes(sig.generate_keypair())
            secret_key = bytes(sig.export_secret_key())
            if (
                len(public_key) != ML_DSA_65_PUBLIC_KEY_BYTES
                or len(secret_key) != ML_DSA_65_SECRET_KEY_BYTES
            ):
                raise CryptoError("Generated ML-DSA-65 key lengths invalid")
            return SigningKeyPair(public_key=public_key, secret_key=secret_key)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError("ML-DSA key generation failed") from exc


def sig_sign(message: bytes, secret_key: bytes) -> bytes:
    """Sign a message with an ML-DSA-65 secret key (4032 B)."""
    if not isinstance(message, (bytes, bytearray)):
        raise CryptoError("Message to sign must be bytes")
    if (
        not isinstance(secret_key, (bytes, bytearray))
        or len(secret_key) != ML_DSA_65_SECRET_KEY_BYTES
    ):
        raise CryptoError(
            f"ML-DSA-65 secret key must be {ML_DSA_65_SECRET_KEY_BYTES} bytes"
        )
    try:
        with oqs.Signature(SIG_ALGORITHM, bytes(secret_key)) as sig:
            signature = bytes(sig.sign(bytes(message)))
            if len(signature) != ML_DSA_65_SIGNATURE_BYTES:
                raise CryptoError("ML-DSA-65 signature output length invalid")
            return signature
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError("ML-DSA signing failed") from exc


def sig_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an ML-DSA-65 signature (3309 B) against a public key (1952 B)."""
    if (
        not isinstance(message, (bytes, bytearray))
        or not isinstance(signature, (bytes, bytearray))
        or not isinstance(public_key, (bytes, bytearray))
    ):
        return False
    if (
        len(signature) != ML_DSA_65_SIGNATURE_BYTES
        or len(public_key) != ML_DSA_65_PUBLIC_KEY_BYTES
    ):
        return False
    try:
        with oqs.Signature(SIG_ALGORITHM) as sig:
            return bool(
                sig.verify(bytes(message), bytes(signature), bytes(public_key))
            )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# HKDF-SHA-256 & HMAC-SHA-256 operations
# ---------------------------------------------------------------------------

def derive_key(
    shared_secret: bytes,
    info: bytes,
    salt: bytes | None = None,
    length: int = HKDF_KEY_LENGTH,
) -> bytes:
    """Derive key material using HKDF-SHA-256."""
    if not isinstance(shared_secret, (bytes, bytearray)) or len(shared_secret) == 0:
        raise CryptoError("HKDF input key material must be non-empty bytes")
    if not isinstance(info, (bytes, bytearray)):
        raise CryptoError("HKDF info must be bytes")
    if salt is not None and not isinstance(salt, (bytes, bytearray)):
        raise CryptoError("HKDF salt must be bytes or None")
    try:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=bytes(salt) if salt is not None else None,
            info=bytes(info),
        ).derive(bytes(shared_secret))
    except Exception as exc:
        raise CryptoError("HKDF key derivation failed") from exc


def compute_hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute a 32-byte HMAC-SHA-256 tag for key confirmation."""
    if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
        raise CryptoError("HMAC key must be non-empty bytes")
    if not isinstance(data, (bytes, bytearray)):
        raise CryptoError("HMAC data must be bytes")
    return hmac.new(bytes(key), bytes(data), hashlib.sha256).digest()


def verify_hmac_sha256(key: bytes, data: bytes, expected_tag: bytes) -> bool:
    """Verify a 32-byte HMAC-SHA-256 tag in constant time."""
    if (
        not isinstance(expected_tag, (bytes, bytearray))
        or len(expected_tag) != 32
    ):
        return False
    actual = compute_hmac_sha256(key, data)
    return hmac.compare_digest(actual, bytes(expected_tag))


# ---------------------------------------------------------------------------
# AES-256-GCM authenticated encryption
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes | None = None,
    nonce: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM using a 96-bit nonce.

    Note: Production protocol paths in Sender and Receiver ALWAYS pass an
    explicit deterministic 96-bit nonce from Session.next_sender_nonce()
    or Session.next_receiver_nonce(). The `nonce=None` fallback is retained
    strictly for standalone primitive benchmarks and unit-test fixtures.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) != AES_KEY_BYTES:
        raise CryptoError(f"AES key must be {AES_KEY_BYTES} bytes")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise CryptoError("Plaintext must be bytes")
    if nonce is None:
        nonce = os.urandom(AES_NONCE_BYTES)
    elif not isinstance(nonce, (bytes, bytearray)) or len(nonce) != AES_NONCE_BYTES:
        raise CryptoError(f"AES nonce must be {AES_NONCE_BYTES} bytes")
    else:
        nonce = bytes(nonce)
    aad = bytes(associated_data) if associated_data is not None else None
    try:
        aes = AESGCM(bytes(key))
        ciphertext = aes.encrypt(nonce, bytes(plaintext), aad)
        return nonce, ciphertext
    except Exception as exc:
        raise CryptoError("AES-GCM encryption failed") from exc


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and authenticate with AES-256-GCM."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != AES_KEY_BYTES:
        raise CryptoError(f"AES key must be {AES_KEY_BYTES} bytes")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != AES_NONCE_BYTES:
        raise CryptoError(f"AES nonce must be {AES_NONCE_BYTES} bytes")
    if (
        not isinstance(ciphertext, (bytes, bytearray))
        or len(ciphertext) < AES_TAG_BYTES
    ):
        raise AuthenticationError("Ciphertext shorter than AES-GCM tag")
    aad = bytes(associated_data) if associated_data is not None else None
    try:
        aes = AESGCM(bytes(key))
        return aes.decrypt(bytes(nonce), bytes(ciphertext), aad)
    except InvalidTag:
        raise AuthenticationError("AES-GCM authentication failed")
    except Exception as exc:
        raise CryptoError("AES-GCM decryption failed") from exc
