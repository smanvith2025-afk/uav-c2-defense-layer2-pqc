
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import oqs


KEM_ALGORITHM = "ML-KEM-768"
SIG_ALGORITHM = "ML-DSA-65"
AAD = b"UAV-C2-LAYER2-v1"
COMMAND = "TAKEOFF ALTITUDE 10"


def canonical_message(command, sequence):
    return json.dumps(
        {"command": command, "sequence": sequence},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def derive_aes_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"UAV-C2-AES-GCM",
    ).derive(shared_secret)


def main():
    print("Layer 2 Secure Command Demonstration")
    print("------------------------------------")

    # Simulate receiver key generation and sender encapsulation.
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as receiver_kem:
        receiver_public_key = receiver_kem.generate_keypair()

        with oqs.KeyEncapsulation(KEM_ALGORITHM) as sender_kem:
            sender_secret, kem_ciphertext = (
                sender_kem.encap_secret(receiver_public_key)
            )

        receiver_secret = receiver_kem.decap_secret(kem_ciphertext)

    if sender_secret != receiver_secret:
        raise RuntimeError("ML-KEM shared-secret mismatch")

    print("[PASS] ML-KEM shared-secret agreement")

    aes_key = derive_aes_key(sender_secret)
    aes = AESGCM(aes_key)

    with oqs.Signature(SIG_ALGORITHM) as signer:
        signing_public_key = signer.generate_keypair()

        with oqs.Signature(SIG_ALGORITHM) as verifier:
            sequence = 1
            signed_data = canonical_message(COMMAND, sequence)
            signature = signer.sign(signed_data)

            # Encrypt command metadata and signature together.
            payload = json.dumps({
                "command": COMMAND,
                "sequence": sequence,
                "signature": signature.hex(),
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")

            nonce = os.urandom(12)
            ciphertext = aes.encrypt(nonce, payload, AAD)
            packet = nonce + ciphertext

            last_accepted_sequence = 0

            def receive(encrypted_packet):
                nonlocal last_accepted_sequence

                try:
                    if len(encrypted_packet) < 13:
                        return False, "Malformed packet"

                    packet_nonce = encrypted_packet[:12]
                    packet_ciphertext = encrypted_packet[12:]

                    plaintext = aes.decrypt(
                        packet_nonce, packet_ciphertext, AAD
                    )
                    data = json.loads(plaintext.decode("utf-8"))

                    command = data["command"]
                    sequence = data["sequence"]
                    signature_bytes = bytes.fromhex(data["signature"])

                    if not isinstance(sequence, int) or sequence < 1:
                        return False, "Invalid sequence number"

                    signed_data = canonical_message(command, sequence)

                    if not verifier.verify(
                        signed_data, signature_bytes, signing_public_key
                    ):
                        return False, "Signature verification failed"

                    if sequence <= last_accepted_sequence:
                        return False, "Replay rejected"

                    # Accept only after decryption, signature verification,
                    # and replay checks have all succeeded.
                    last_accepted_sequence = sequence
                    return True, command

                except (ValueError, TypeError, KeyError, UnicodeDecodeError):
                    return False, "Invalid message"
                except Exception:
                    return False, "Authentication or decryption failed"

            accepted, result = receive(packet)
            if not accepted or result != COMMAND:
                raise RuntimeError(f"Valid command rejected: {result}")

            print("[PASS] Encrypted command authenticated and accepted")
            print("Accepted command:", result)

            # Replaying the same valid packet must be rejected.
            accepted, result = receive(packet)
            if accepted:
                raise RuntimeError("Replay protection failed")

            print("[PASS] Replayed command rejected")

            # Modified ciphertext must not be accepted.
            tampered_packet = bytearray(packet)
            tampered_packet[-1] ^= 1

            accepted, result = receive(bytes(tampered_packet))
            if accepted:
                raise RuntimeError("Tampered packet was accepted")

            print("[PASS] Tampered ciphertext rejected")

            # A validly encrypted packet with an invalid signature must fail.
            bad_payload = json.dumps({
                "command": "LAND",
                "sequence": 2,
                "signature": signature.hex(),
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")

            bad_nonce = os.urandom(12)
            bad_packet = bad_nonce + aes.encrypt(
                bad_nonce, bad_payload, AAD
            )

            accepted, result = receive(bad_packet)
            if accepted:
                raise RuntimeError("Invalid signature was accepted")

            print("[PASS] Invalid command signature rejected")

    print("\nAll Layer 2 integration checks passed.")
    print("Note: this is a single-process simulation, not a flight test.")


if __name__ == "__main__":
    main()
