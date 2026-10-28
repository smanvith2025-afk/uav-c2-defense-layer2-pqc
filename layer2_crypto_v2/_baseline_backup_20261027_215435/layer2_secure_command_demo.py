
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KEM_ALGORITHM = "ML-KEM-768"
SIG_ALGORITHM = "ML-DSA-65"
AAD = b"UAV-C2-LAYER2-v1"
COMMAND = "TAKEOFF ALTITUDE 10"


def canonical_message(command, sequence):
    """Create a stable byte representation of signed command data."""
    return json.dumps(
        {"command": command, "sequence": sequence},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def derive_aes_key(shared_secret):
    """Derive a 256-bit AES key from the ML-KEM shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"UAV-C2-AES-GCM",
    ).derive(shared_secret)


def main():
    print("Layer 2 Secure Command Demonstration")
    print("------------------------------------")

    # Simulate the receiver generating a KEM key pair.
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as receiver_kem:
        receiver_public_key = receiver_kem.generate_keypair()

        # Keep the sender KEM object alive while using its result.
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as sender_kem:
            # Correct liboqs-python order: ciphertext, shared secret.
            kem_ciphertext, sender_secret = (
                sender_kem.encap_secret(receiver_public_key)
            )

        receiver_secret = receiver_kem.decap_secret(kem_ciphertext)

    if sender_secret != receiver_secret:
        raise RuntimeError("ML-KEM shared-secret mismatch")

    print("[PASS] ML-KEM shared-secret agreement")

    # Demo only: both simulated roles use the derived session key.
    aes = AESGCM(derive_aes_key(sender_secret))

    with oqs.Signature(SIG_ALGORITHM) as signer:
        signing_public_key = signer.generate_keypair()

        with oqs.Signature(SIG_ALGORITHM) as verifier:

            def make_packet(command, sequence, signature, nonce=None):
                payload = json.dumps(
                    {
                        "command": command,
                        "sequence": sequence,
                        "signature": signature.hex(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")

                if nonce is None:
                    nonce = os.urandom(12)

                return nonce + aes.encrypt(nonce, payload, AAD)

            sequence = 1
            signed_data = canonical_message(COMMAND, sequence)
            signature = signer.sign(signed_data)
            packet = make_packet(COMMAND, sequence, signature)

            last_accepted_sequence = 0

            def receive(encrypted_packet):
                nonlocal last_accepted_sequence

                try:
                    if len(encrypted_packet) < 12 + 16:
                        return False, "Malformed packet"

                    nonce = encrypted_packet[:12]
                    ciphertext = encrypted_packet[12:]

                    plaintext = aes.decrypt(nonce, ciphertext, AAD)
                    data = json.loads(plaintext.decode("utf-8"))

                    command = data["command"]
                    sequence_number = data["sequence"]
                    signature_bytes = bytes.fromhex(data["signature"])

                    if not isinstance(command, str):
                        return False, "Invalid command"

                    # bool is a subclass of int in Python, so reject it.
                    if (
                        isinstance(sequence_number, bool)
                        or not isinstance(sequence_number, int)
                        or sequence_number < 1
                    ):
                        return False, "Invalid sequence number"

                    signed_data = canonical_message(
                        command, sequence_number
                    )

                    valid_signature = verifier.verify(
                        signed_data,
                        signature_bytes,
                        signing_public_key,
                    )

                    if not valid_signature:
                        return False, "Signature verification failed"

                    if sequence_number <= last_accepted_sequence:
                        return False, "Replay rejected"

                    # Accept only after all checks have succeeded.
                    last_accepted_sequence = sequence_number
                    return True, command

                except Exception:
                    # Fail closed on malformed, corrupted, or invalid packets.
                    return False, "Authentication or decryption failed"

            # 1. A valid command should be accepted.
            accepted, result = receive(packet)

            if not accepted or result != COMMAND:
                raise RuntimeError(
                    f"Valid command was rejected: {result}"
                )

            print("[PASS] Encrypted command authenticated and accepted")
            print("Accepted command:", result)

            # 2. Replaying the same packet should be rejected.
            accepted, result = receive(packet)

            if accepted:
                raise RuntimeError("Replay protection failed")

            print("[PASS] Replayed command rejected")

            # 3. A modified ciphertext should be rejected.
            tampered_packet = bytearray(packet)
            tampered_packet[-1] ^= 1

            accepted, result = receive(bytes(tampered_packet))

            if accepted:
                raise RuntimeError("Tampered packet was accepted")

            print("[PASS] Tampered ciphertext rejected")

            # 4. Encrypt a command carrying an invalid signature.
            invalid_signature = bytes(len(signature))
            invalid_packet = make_packet(
                "LAND", 2, invalid_signature
            )

            accepted, result = receive(invalid_packet)

            if accepted:
                raise RuntimeError("Invalid signature was accepted")

            print("[PASS] Invalid command signature rejected")

    print()
    print("All Layer 2 integration checks passed.")
    print("Note: this is a single-process simulation, not a flight test.")


if __name__ == "__main__":
    main()
