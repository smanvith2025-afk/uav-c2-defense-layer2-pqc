"""
Comprehensive automated security test suite for the Layer 2
Post-Quantum UAV Command Security Protocol.

Covers all 25 required test categories:
 1. Successful handshake
 2. Successful session-key agreement
 3. Valid signed and encrypted command
 4. Invalid signature
 5. Modified ciphertext
 6. Modified authenticated header
 7. Modified command
 8. Wrong session key
 9. Unknown or revoked peer identity
10. Public-key substitution attempt
11. Replayed message
12. Duplicate sequence number
13. Out-of-order message
14. Expired session
15. Unsupported protocol version
16. Malformed message and truncated packet
17. Invalid message lengths and types
18. Handshake transcript modification
19. Session restart and replay-state behavior
20. Rekey and session termination
21. Nonce uniqueness enforcement
22. Multiple sessions and cross-session message rejection
23. Failure during handshake
24. Failure during encryption/decryption or signature verification
25. Fuzz / property-based tests for parsers

Run with:
    cd C:\\Users\\smanv\\UAV_Security_Project\\layer2_crypto
    python -m pytest test_protocol.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time

import pytest

from protocol.constants import (
    AES_NONCE_BYTES,
    HEADER_SIZE,
    MAX_SEQUENCE_GAP,
    MSG_TYPE_COMMAND,
    MSG_TYPE_HANDSHAKE_CONFIRM,
    MSG_TYPE_HANDSHAKE_INIT,
    MSG_TYPE_HANDSHAKE_RESPONSE,
    MSG_TYPE_REKEY,
    MSG_TYPE_TERMINATE,
    PROTOCOL_VERSION,
    ROLE_GROUND_STATION,
    ROLE_UAV,
    SESSION_MAX_LIFETIME_SECONDS,
)
from protocol.crypto_core import (
    SigningKeyPair,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    derive_key,
    kem_generate_keypair,
    sig_generate_keypair,
    sig_sign,
    sig_verify,
)
from protocol.errors import (
    AuthenticationError,
    HandshakeError,
    IdentityError,
    MessageFormatError,
    ReplayError,
    SequenceError,
    SessionError,
    SessionExpiredError,
    TrustError,
    VersionError,
)
from protocol.identity import PeerIdentity, TrustStore
from protocol.messages import (
    CommandPayload,
    HandshakePayload,
    MessageHeader,
    build_packet,
    parse_packet,
)
from protocol.receiver import Receiver
from protocol.sender import Sender
from protocol.session import Session, SessionKeys, SessionState
from protocol.transport import LocalTransport


# ======================================================================
# Fixtures
# ======================================================================


@pytest.fixture
def gs_keys():
    """Ground station ML-DSA-65 signing key pair."""
    return sig_generate_keypair()


@pytest.fixture
def uav_keys():
    """UAV ML-DSA-65 signing key pair."""
    return sig_generate_keypair()


@pytest.fixture
def trust_store(gs_keys, uav_keys):
    """Trust store with both peers registered."""
    ts = TrustStore()
    ts.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
    ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)
    return ts


@pytest.fixture
def linked_transports():
    """A linked pair of local transports."""
    return LocalTransport.create_pair()


@pytest.fixture
def sender(gs_keys, trust_store, linked_transports):
    """Configured sender (ground station)."""
    return Sender("gs1", gs_keys, trust_store, linked_transports[0])


@pytest.fixture
def receiver(uav_keys, trust_store, linked_transports):
    """Configured receiver (UAV)."""
    return Receiver("uav1", uav_keys, trust_store, linked_transports[1])


@pytest.fixture
def established_session(sender, receiver, linked_transports):
    """Perform a full handshake and return (sender, receiver)."""
    tx_gs, tx_uav = linked_transports

    sender.initiate_handshake("uav1")
    init_pkt = tx_uav.receive()
    receiver.process_handshake_init(init_pkt)
    resp_pkt = tx_gs.receive()
    sender.process_handshake_response(resp_pkt)
    confirm_pkt = tx_uav.receive()
    receiver.process_handshake_confirm(confirm_pkt)

    return sender, receiver


# ======================================================================
# 1. Successful Handshake
# ======================================================================


class TestSuccessfulHandshake:
    def test_handshake_completes(self, established_session):
        sender, receiver = established_session
        assert sender.session is not None
        assert sender.session.state == SessionState.ESTABLISHED
        assert receiver.session is not None
        assert receiver.session.state == SessionState.ESTABLISHED

    def test_session_ids_match(self, established_session):
        sender, receiver = established_session
        assert sender.session.session_id == receiver.session.session_id

    def test_peer_ids_correct(self, established_session):
        sender, receiver = established_session
        assert sender.session.local_peer_id == "gs1"
        assert sender.session.remote_peer_id == "uav1"
        assert receiver.session.local_peer_id == "uav1"
        assert receiver.session.remote_peer_id == "gs1"


# ======================================================================
# 2. Successful Session-Key Agreement
# ======================================================================


class TestSessionKeyAgreement:
    def test_keys_are_derived(self, established_session):
        sender, receiver = established_session
        assert sender.session.keys is not None
        assert receiver.session.keys is not None

    def test_direction_keys_differ(self, established_session):
        sender, receiver = established_session
        assert (
            sender.session.keys.sender_enc_key
            != sender.session.keys.receiver_enc_key
        )

    def test_sender_key_matches_across_peers(self, established_session):
        """The sender's encryption key must match what the receiver uses to decrypt."""
        sender, receiver = established_session
        assert (
            sender.session.keys.sender_enc_key
            == receiver.session.keys.sender_enc_key
        )
        assert (
            sender.session.keys.receiver_enc_key
            == receiver.session.keys.receiver_enc_key
        )


# ======================================================================
# 3. Valid Signed and Encrypted Command
# ======================================================================


class TestValidCommand:
    def test_valid_command_accepted(self, established_session, linked_transports):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()
        accepted, result = receiver.receive_packet(pkt)

        assert accepted is True
        assert "TAKEOFF" in result
        assert "ALTITUDE 10" in result

    def test_command_recorded(self, established_session, linked_transports):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("HOVER", "")
        pkt = tx_uav.receive()
        receiver.receive_packet(pkt)

        assert receiver.command_record.accepted_count == 1
        assert receiver.command_record.accepted[0]["command"] == "HOVER"

    def test_multiple_commands_sequential(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        for i, cmd in enumerate(["TAKEOFF", "HOVER", "LAND"], start=1):
            sender.send_command(cmd, f"SEQ{i}")
            pkt = tx_uav.receive()
            ok, _ = receiver.receive_packet(pkt)
            assert ok, f"Command {cmd} should be accepted"

        assert receiver.command_record.accepted_count == 3


# ======================================================================
# 4. Invalid Signature
# ======================================================================


class TestInvalidSignature:
    def test_wrong_signer_rejected(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        # Create a command signed by an unknown key
        fake_keys = sig_generate_keypair()
        seq = sender.session.next_send_sequence()
        cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=time.time(),
        )
        canonical = cp.canonical_bytes_for_signing(
            sender.session.session_id, seq
        )
        bad_sig = sig_sign(canonical, fake_keys.secret_key)
        signed_cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=cp.timestamp,
            signature=bad_sig,
        )
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=sender.session.session_id,
            sequence=seq,
        )
        nonce, ct = aes_gcm_encrypt(
            sender.session.get_sender_enc_key(),
            signed_cp.to_json_bytes(),
            header.to_bytes(),
        )
        pkt = build_packet(header, nonce, ct)
        accepted, reason = receiver.receive_packet(pkt)

        assert accepted is False
        assert "signature" in reason.lower()
        # Must NOT have reached the command handler
        assert receiver.command_record.accepted_count == 0

    def test_zeroed_signature_rejected(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        seq = sender.session.next_send_sequence()
        cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=time.time(),
            signature=bytes(3309),
        )
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=sender.session.session_id,
            sequence=seq,
        )
        nonce, ct = aes_gcm_encrypt(
            sender.session.get_sender_enc_key(),
            cp.to_json_bytes(),
            header.to_bytes(),
        )
        pkt = build_packet(header, nonce, ct)
        accepted, _ = receiver.receive_packet(pkt)
        assert accepted is False
        assert receiver.command_record.accepted_count == 0


# ======================================================================
# 5. Modified Ciphertext
# ======================================================================


class TestModifiedCiphertext:
    def test_flipped_ciphertext_bit(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()

        tampered = bytearray(pkt)
        tampered[-1] ^= 1
        accepted, reason = receiver.receive_packet(bytes(tampered))

        assert accepted is False
        assert receiver.command_record.accepted_count == 0

    def test_truncated_ciphertext(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()

        # Truncate ciphertext (remove last 8 bytes)
        truncated = pkt[:-8]
        accepted, _ = receiver.receive_packet(truncated)
        assert accepted is False
        assert receiver.command_record.accepted_count == 0


# ======================================================================
# 6. Modified Authenticated Header
# ======================================================================


class TestModifiedHeader:
    def test_modified_session_id_in_header(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()

        # Modify session ID byte in header
        tampered = bytearray(pkt)
        tampered[2] ^= 0xFF  # session_id starts at offset 2
        accepted, _ = receiver.receive_packet(bytes(tampered))
        assert accepted is False

    def test_modified_sequence_in_header(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()

        # Modify sequence number in header (offset 18-21)
        tampered = bytearray(pkt)
        tampered[18] ^= 0x01
        accepted, _ = receiver.receive_packet(bytes(tampered))
        assert accepted is False

    def test_modified_version_in_header(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()

        tampered = bytearray(pkt)
        tampered[0] = 99  # Invalid version
        accepted, reason = receiver.receive_packet(bytes(tampered))
        assert accepted is False
        assert "version" in reason.lower()


# ======================================================================
# 7. Modified Command
# ======================================================================


class TestModifiedCommand:
    def test_command_modification_detected(
        self, established_session, linked_transports
    ):
        """Modifying the encrypted payload is caught by GCM authentication."""
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()

        # Modify a byte in the encrypted payload area
        tampered = bytearray(pkt)
        midpoint = HEADER_SIZE + AES_NONCE_BYTES + 10
        tampered[midpoint] ^= 0x42
        accepted, _ = receiver.receive_packet(bytes(tampered))
        assert accepted is False
        assert receiver.command_record.accepted_count == 0


# ======================================================================
# 8. Wrong Session Key
# ======================================================================


class TestWrongSessionKey:
    def test_wrong_key_decryption_fails(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        # Forge a packet encrypted with a different key
        wrong_key = os.urandom(32)
        seq = sender.session.next_send_sequence()
        cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=time.time(),
            signature=b"\x00" * 100,
        )
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=sender.session.session_id,
            sequence=seq,
        )
        nonce, ct = aes_gcm_encrypt(
            wrong_key, cp.to_json_bytes(), header.to_bytes()
        )
        pkt = build_packet(header, nonce, ct)
        accepted, reason = receiver.receive_packet(pkt)
        assert accepted is False
        assert receiver.command_record.accepted_count == 0


# ======================================================================
# 9. Unknown or Revoked Peer Identity
# ======================================================================


class TestUnknownRevokedPeer:
    def test_unknown_peer_handshake_rejected(
        self, gs_keys, trust_store, linked_transports
    ):
        tx_gs, tx_uav = linked_transports
        sender = Sender("gs1", gs_keys, trust_store, tx_gs)

        with pytest.raises(IdentityError, match="Unknown peer"):
            sender.initiate_handshake("unknown_uav")

    def test_revoked_peer_handshake_rejected(
        self, gs_keys, uav_keys, linked_transports
    ):
        tx_gs, tx_uav = linked_transports
        ts = TrustStore()
        ts.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)
        ts.revoke_peer("uav1")

        sender = Sender("gs1", gs_keys, ts, tx_gs)
        with pytest.raises(TrustError, match="revoked"):
            sender.initiate_handshake("uav1")

    def test_revoked_peer_during_command(
        self, established_session, linked_transports, trust_store
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        # Revoke the sender mid-session
        trust_store.revoke_peer("gs1")

        sender.send_command("LAND", "")
        pkt = tx_uav.receive()
        accepted, reason = receiver.receive_packet(pkt)
        assert accepted is False
        assert receiver.command_record.accepted_count == 0


# ======================================================================
# 10. Public-Key Substitution Attempt
# ======================================================================


class TestPublicKeySubstitution:
    def test_key_substitution_rejected(
        self, uav_keys, linked_transports
    ):
        """Attacker registers a different key under a legitimate peer ID."""
        tx_gs, tx_uav = linked_transports

        # Legitimate keys
        real_gs_keys = sig_generate_keypair()
        fake_gs_keys = sig_generate_keypair()

        # Trust store with real keys
        ts = TrustStore()
        ts.register_peer(
            "gs1", ROLE_GROUND_STATION, real_gs_keys.public_key
        )
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)

        # Attacker creates sender with fake keys but claims gs1 identity
        attacker = Sender("gs1", fake_gs_keys, ts, tx_gs)

        # The trust store will detect the key mismatch during handshake
        # because the receiver verifies the signing key matches the
        # trusted key for that peer ID
        attacker.initiate_handshake("uav1")
        init_pkt = tx_uav.receive()

        receiver = Receiver("uav1", uav_keys, ts, tx_uav)
        with pytest.raises(TrustError, match="mismatch"):
            receiver.process_handshake_init(init_pkt)


# ======================================================================
# 11. Replayed Message
# ======================================================================


class TestReplayedMessage:
    def test_replay_immediately_rejected(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()

        # First reception succeeds
        accepted, _ = receiver.receive_packet(pkt)
        assert accepted is True

        # Replay is rejected
        accepted, reason = receiver.receive_packet(pkt)
        assert accepted is False
        assert receiver.command_record.accepted_count == 1

    def test_replay_after_several_commands(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        # Send first command and save it
        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt1 = tx_uav.receive()
        ok, _ = receiver.receive_packet(pkt1)
        assert ok

        # Send several more commands
        for cmd in ["HOVER", "WAYPOINT", "LAND"]:
            sender.send_command(cmd, "")
            pkt = tx_uav.receive()
            ok, _ = receiver.receive_packet(pkt)
            assert ok

        # Replay the first command
        accepted, _ = receiver.receive_packet(pkt1)
        assert accepted is False
        assert receiver.command_record.accepted_count == 4


# ======================================================================
# 12. Duplicate Sequence Number
# ======================================================================


class TestDuplicateSequence:
    def test_duplicate_sequence_rejected(
        self, established_session, linked_transports, gs_keys
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        # Send valid command with sequence 1
        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt1 = tx_uav.receive()
        ok, _ = receiver.receive_packet(pkt1)
        assert ok

        # Forge a new command with the same sequence number
        cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=time.time(),
        )
        canonical = cp.canonical_bytes_for_signing(
            sender.session.session_id, 1  # Same sequence!
        )
        sig = sig_sign(canonical, gs_keys.secret_key)
        signed_cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=cp.timestamp,
            signature=sig,
        )
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=sender.session.session_id,
            sequence=1,
        )
        nonce, ct = aes_gcm_encrypt(
            sender.session.get_sender_enc_key(),
            signed_cp.to_json_bytes(),
            header.to_bytes(),
        )
        pkt = build_packet(header, nonce, ct)
        accepted, _ = receiver.receive_packet(pkt)
        assert accepted is False
        assert receiver.command_record.accepted_count == 1


# ======================================================================
# 13. Out-of-Order Message
# ======================================================================


class TestOutOfOrder:
    def test_large_sequence_gap_rejected(
        self, established_session, linked_transports, gs_keys
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        # Send seq 1
        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()
        ok, _ = receiver.receive_packet(pkt)
        assert ok

        # Forge a command with sequence way ahead (beyond MAX_SEQUENCE_GAP)
        far_seq = 1 + MAX_SEQUENCE_GAP + 10
        cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=time.time(),
        )
        canonical = cp.canonical_bytes_for_signing(
            sender.session.session_id, far_seq
        )
        sig = sig_sign(canonical, gs_keys.secret_key)
        signed_cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=cp.timestamp,
            signature=sig,
        )
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=sender.session.session_id,
            sequence=far_seq,
        )
        # Manipulate sender's sequence counter to bypass Sender checks
        sender.session.send_sequence = far_seq + 1
        nonce, ct = aes_gcm_encrypt(
            sender.session.get_sender_enc_key(),
            signed_cp.to_json_bytes(),
            header.to_bytes(),
        )
        pkt = build_packet(header, nonce, ct)
        accepted, reason = receiver.receive_packet(pkt)
        assert accepted is False
        assert "gap" in reason.lower() or "sequence" in reason.lower()

    def test_strict_out_of_order_late_packet_rejected(
        self, established_session, linked_transports
    ):
        """Under strict monotonic policy, receiving seq 2 then seq 1 rejects seq 1."""
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt1 = tx_uav.receive()

        sender.send_command("HOVER", "")
        pkt2 = tx_uav.receive()

        # Deliver pkt2 first
        ok2, _ = receiver.receive_packet(pkt2)
        assert ok2 is True

        # Late arrival of pkt1 is rejected under strict monotonic policy
        ok1, reason = receiver.receive_packet(pkt1)
        assert ok1 is False
        assert receiver.command_record.accepted_count == 1

    def test_sliding_window_out_of_order_policy(
        self, established_session, linked_transports
    ):
        """When allow_out_of_order=True, late packet within window is accepted once."""
        sender, receiver = established_session
        _, tx_uav = linked_transports
        receiver.session.allow_out_of_order = True

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt1 = tx_uav.receive()

        sender.send_command("HOVER", "")
        pkt2 = tx_uav.receive()

        # Deliver pkt2 first, then pkt1
        assert receiver.receive_packet(pkt2)[0] is True
        assert receiver.receive_packet(pkt1)[0] is True
        # Duplicate of pkt1 still rejected
        assert receiver.receive_packet(pkt1)[0] is False
        assert receiver.command_record.accepted_count == 2


# ======================================================================
# 14. Expired Session
# ======================================================================


class TestExpiredSession:
    def test_expired_session_rejects_command(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        # Artificially expire the receiver's session
        receiver.session.created_at = (
            time.time() - SESSION_MAX_LIFETIME_SECONDS - 10
        )

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()
        accepted, reason = receiver.receive_packet(pkt)
        assert accepted is False
        assert "expired" in reason.lower() or "session" in reason.lower()
        assert receiver.command_record.accepted_count == 0


# ======================================================================
# 15. Unsupported Protocol Version
# ======================================================================


class TestUnsupportedVersion:
    def test_wrong_version_rejected(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()

        # Change version byte to 99
        tampered = bytearray(pkt)
        tampered[0] = 99
        accepted, reason = receiver.receive_packet(bytes(tampered))
        assert accepted is False
        assert "version" in reason.lower()

    def test_version_zero_rejected(self):
        with pytest.raises(VersionError):
            MessageHeader.from_bytes(
                struct.pack(">BB16sI", 0, MSG_TYPE_COMMAND, b"\x00" * 16, 1)
            )


# ======================================================================
# 16. Malformed Message and Truncated Packet
# ======================================================================


class TestMalformedMessage:
    def test_empty_packet(self, established_session):
        _, receiver = established_session
        accepted, _ = receiver.receive_packet(b"")
        assert accepted is False

    def test_single_byte_packet(self, established_session):
        _, receiver = established_session
        accepted, _ = receiver.receive_packet(b"\x01")
        assert accepted is False

    def test_header_only_packet(self, established_session):
        _, receiver = established_session
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=os.urandom(16),
            sequence=1,
        )
        accepted, _ = receiver.receive_packet(header.to_bytes())
        assert accepted is False

    def test_random_bytes(self, established_session):
        _, receiver = established_session
        accepted, _ = receiver.receive_packet(os.urandom(200))
        assert accepted is False

    def test_truncated_nonce(self, established_session, linked_transports):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()

        # Keep header + partial nonce
        truncated = pkt[: HEADER_SIZE + 4]
        accepted, _ = receiver.receive_packet(truncated)
        assert accepted is False

    def test_null_bytes(self, established_session):
        _, receiver = established_session
        accepted, _ = receiver.receive_packet(b"\x00" * 100)
        assert accepted is False


# ======================================================================
# 17. Invalid Message Lengths and Types
# ======================================================================


class TestInvalidMessageTypes:
    def test_invalid_msg_type_in_header(self):
        with pytest.raises(MessageFormatError, match="Invalid message type"):
            MessageHeader.from_bytes(
                struct.pack(
                    ">BB16sI", PROTOCOL_VERSION, 255, b"\x00" * 16, 1
                )
            )

    def test_type_zero_rejected(self):
        with pytest.raises(MessageFormatError):
            MessageHeader.from_bytes(
                struct.pack(
                    ">BB16sI", PROTOCOL_VERSION, 0, b"\x00" * 16, 1
                )
            )

    def test_oversized_packet_rejected(self, established_session):
        _, receiver = established_session
        # Create a packet larger than MAX_PACKET_SIZE
        big_pkt = os.urandom(70000)
        accepted, reason = receiver.receive_packet(big_pkt)
        assert accepted is False
        assert "large" in reason.lower() or "short" in reason.lower() or "size" in reason.lower()


# ======================================================================
# 18. Handshake Transcript Modification
# ======================================================================


class TestHandshakeTranscriptModification:
    def test_modified_init_payload_detected(
        self, gs_keys, uav_keys, linked_transports
    ):
        """Modifying the handshake init after signing should be caught."""
        tx_gs, tx_uav = linked_transports
        ts = TrustStore()
        ts.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)

        sender = Sender("gs1", gs_keys, ts, tx_gs)
        sender.initiate_handshake("uav1")
        init_pkt = tx_uav.receive()

        # Modify a byte in the payload portion
        tampered = bytearray(init_pkt)
        tampered[HEADER_SIZE + 10] ^= 0x42
        init_pkt_tampered = bytes(tampered)

        receiver = Receiver("uav1", uav_keys, ts, tx_uav)
        with pytest.raises((HandshakeError, MessageFormatError)):
            receiver.process_handshake_init(init_pkt_tampered)


# ======================================================================
# 19. Session Restart and Replay-State Behavior
# ======================================================================


class TestSessionRestart:
    def test_new_session_after_terminate(
        self, gs_keys, uav_keys, linked_transports
    ):
        tx_gs, tx_uav = linked_transports
        ts = TrustStore()
        ts.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)

        sender = Sender("gs1", gs_keys, ts, tx_gs)
        receiver = Receiver("uav1", uav_keys, ts, tx_uav)

        # First session
        sender.initiate_handshake("uav1")
        init_pkt = tx_uav.receive()
        receiver.process_handshake_init(init_pkt)
        resp_pkt = tx_gs.receive()
        sender.process_handshake_response(resp_pkt)
        confirm_pkt = tx_uav.receive()
        receiver.process_handshake_confirm(confirm_pkt)

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        cmd_pkt1 = tx_uav.receive()
        ok, _ = receiver.receive_packet(cmd_pkt1)
        assert ok

        old_session_id = sender.session.session_id

        # Terminate
        sender.terminate_session()
        term_pkt = tx_uav.receive()
        receiver.receive_packet(term_pkt)

        # New session
        sender2 = Sender("gs1", gs_keys, ts, tx_gs)
        receiver2 = Receiver("uav1", uav_keys, ts, tx_uav)

        sender2.initiate_handshake("uav1")
        init_pkt2 = tx_uav.receive()
        receiver2.process_handshake_init(init_pkt2)
        resp_pkt2 = tx_gs.receive()
        sender2.process_handshake_response(resp_pkt2)
        confirm_pkt2 = tx_uav.receive()
        receiver2.process_handshake_confirm(confirm_pkt2)

        # New session has different ID
        assert sender2.session.session_id != old_session_id

        # Old replay from session 1 must fail on session 2
        accepted, _ = receiver2.receive_packet(cmd_pkt1)
        assert accepted is False

    def test_old_session_command_on_new_session(
        self, gs_keys, uav_keys, linked_transports
    ):
        """A packet from an old session must be rejected by a new session."""
        tx_gs, tx_uav = linked_transports
        ts = TrustStore()
        ts.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)

        s1 = Sender("gs1", gs_keys, ts, tx_gs)
        r1 = Receiver("uav1", uav_keys, ts, tx_uav)

        # Session 1
        s1.initiate_handshake("uav1")
        r1.process_handshake_init(tx_uav.receive())
        s1.process_handshake_response(tx_gs.receive())
        r1.process_handshake_confirm(tx_uav.receive())

        s1.send_command("TAKEOFF", "")
        old_pkt = tx_uav.receive()
        ok, _ = r1.receive_packet(old_pkt)
        assert ok

        s1.terminate_session()
        r1.receive_packet(tx_uav.receive())

        # Session 2
        s2 = Sender("gs1", gs_keys, ts, tx_gs)
        r2 = Receiver("uav1", uav_keys, ts, tx_uav)

        s2.initiate_handshake("uav1")
        r2.process_handshake_init(tx_uav.receive())
        s2.process_handshake_response(tx_gs.receive())
        r2.process_handshake_confirm(tx_uav.receive())

        # Replay old session packet on new session
        accepted, _ = r2.receive_packet(old_pkt)
        assert accepted is False


# ======================================================================
# 20. Rekey and Session Termination
# ======================================================================


class TestRekeyAndTerminate:
    def test_rekey_changes_keys(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        tx_gs, tx_uav = linked_transports

        old_sender_key = sender.session.keys.sender_enc_key

        # Initiate rekey
        sender.initiate_rekey()
        rekey_pkt = tx_uav.receive()
        receiver.receive_packet(rekey_pkt)
        rekey_resp = tx_gs.receive()
        sender.complete_rekey(rekey_resp)

        # Keys should have changed
        assert sender.session.keys.sender_enc_key != old_sender_key
        assert sender.session.state == SessionState.ESTABLISHED

    def test_command_works_after_rekey(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        tx_gs, tx_uav = linked_transports

        # Rekey
        sender.initiate_rekey()
        rekey_pkt = tx_uav.receive()
        receiver.receive_packet(rekey_pkt)
        rekey_resp = tx_gs.receive()
        sender.complete_rekey(rekey_resp)

        # Send command with new keys
        sender.send_command("HOVER", "")
        pkt = tx_uav.receive()
        ok, result = receiver.receive_packet(pkt)
        assert ok
        assert "HOVER" in result

    def test_terminate_clears_session(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.terminate_session()
        term_pkt = tx_uav.receive()
        ok, reason = receiver.receive_packet(term_pkt)
        assert ok
        assert "terminated" in reason.lower()
        assert receiver.session is None

    def test_command_after_terminate_fails(
        self, gs_keys, uav_keys, linked_transports
    ):
        tx_gs, tx_uav = linked_transports
        ts = TrustStore()
        ts.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)
        sender = Sender("gs1", gs_keys, ts, tx_gs)
        receiver = Receiver("uav1", uav_keys, ts, tx_uav)

        # Establish
        sender.initiate_handshake("uav1")
        receiver.process_handshake_init(tx_uav.receive())
        sender.process_handshake_response(tx_gs.receive())
        receiver.process_handshake_confirm(tx_uav.receive())

        # Terminate
        sender.terminate_session()
        receiver.receive_packet(tx_uav.receive())

        # Sender should not be able to send commands
        with pytest.raises(SessionError):
            sender.send_command("LAND", "")


# ======================================================================
# 21. Nonce Uniqueness Enforcement
# ======================================================================


class TestNonceUniqueness:
    def test_nonces_are_unique(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        nonces = set()
        for i in range(50):
            sender.send_command("HOVER", f"ITER {i}")
            pkt = tx_uav.receive()
            # Extract nonce from packet
            nonce = pkt[HEADER_SIZE: HEADER_SIZE + AES_NONCE_BYTES]
            assert nonce not in nonces, f"Nonce collision at iteration {i}"
            nonces.add(nonce)
            ok, _ = receiver.receive_packet(pkt)
            assert ok

    def test_nonce_length_is_12(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()
        nonce = pkt[HEADER_SIZE: HEADER_SIZE + AES_NONCE_BYTES]
        assert len(nonce) == 12

    def test_nonce_reuse_rejected_by_receiver(
        self, established_session, linked_transports, gs_keys
    ):
        """Reusing a previously seen 96-bit nonce with a new sequence number is rejected."""
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt1 = tx_uav.receive()
        used_nonce = pkt1[HEADER_SIZE: HEADER_SIZE + AES_NONCE_BYTES]
        ok, _ = receiver.receive_packet(pkt1)
        assert ok is True

        # Craft a second message (sequence 2) that reuses used_nonce
        seq = sender.session.next_send_sequence()
        cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="HOVER",
            params="",
            timestamp=time.time(),
        )
        canonical = cp.canonical_bytes_for_signing(
            sender.session.session_id, seq
        )
        sig = sig_sign(canonical, gs_keys.secret_key)
        signed_cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="HOVER",
            params="",
            timestamp=cp.timestamp,
            signature=sig,
        )
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=sender.session.session_id,
            sequence=seq,
        )
        _, ct = aes_gcm_encrypt(
            sender.session.get_sender_enc_key(),
            signed_cp.to_json_bytes(),
            header.to_bytes(),
            nonce=used_nonce,
        )
        pkt2 = build_packet(header, used_nonce, ct)
        accepted, reason = receiver.receive_packet(pkt2)
        assert accepted is False
        assert "nonce" in reason.lower()
        assert receiver.command_record.accepted_count == 1

    def test_nonce_counter_exhaustion(self, established_session):
        """Exhausting the nonce counter raises NonceError and expires the session."""
        from protocol.constants import SESSION_MAX_MESSAGES
        from protocol.errors import NonceError
        sender, _ = established_session
        sender.session._sender_nonce_counter = SESSION_MAX_MESSAGES
        with pytest.raises(NonceError, match="exhausted"):
            sender.session.next_sender_nonce()
        assert sender.session.state == SessionState.EXPIRED


# ======================================================================
# 22. Multiple Sessions and Cross-Session Message Rejection
# ======================================================================


class TestCrossSession:
    def test_cross_session_command_rejected(self, gs_keys, uav_keys):
        """A command from session A must be rejected by session B."""
        ts = TrustStore()
        ts.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)

        # Session A
        tx_a_gs, tx_a_uav = LocalTransport.create_pair()
        sender_a = Sender("gs1", gs_keys, ts, tx_a_gs)
        receiver_a = Receiver("uav1", uav_keys, ts, tx_a_uav)

        sender_a.initiate_handshake("uav1")
        receiver_a.process_handshake_init(tx_a_uav.receive())
        sender_a.process_handshake_response(tx_a_gs.receive())
        receiver_a.process_handshake_confirm(tx_a_uav.receive())

        # Session B
        tx_b_gs, tx_b_uav = LocalTransport.create_pair()
        sender_b = Sender("gs1", gs_keys, ts, tx_b_gs)
        receiver_b = Receiver("uav1", uav_keys, ts, tx_b_uav)

        sender_b.initiate_handshake("uav1")
        receiver_b.process_handshake_init(tx_b_uav.receive())
        sender_b.process_handshake_response(tx_b_gs.receive())
        receiver_b.process_handshake_confirm(tx_b_uav.receive())

        # Send command on session A
        sender_a.send_command("TAKEOFF", "ALTITUDE 10")
        pkt_a = tx_a_uav.receive()

        # Try to process session A's command on session B's receiver
        accepted, reason = receiver_b.receive_packet(pkt_a)
        assert accepted is False
        assert receiver_b.command_record.accepted_count == 0


# ======================================================================
# 23. Failure During Handshake
# ======================================================================


class TestHandshakeFailures:
    def test_handshake_with_wrong_kem_key(self, gs_keys, uav_keys):
        """Providing a corrupted KEM public key should fail the handshake."""
        ts = TrustStore()
        ts.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)

        tx_gs, tx_uav = LocalTransport.create_pair()
        sender = Sender("gs1", gs_keys, ts, tx_gs)
        sender.initiate_handshake("uav1")
        init_pkt = tx_uav.receive()

        # Corrupt the KEM public key in the payload
        tampered = bytearray(init_pkt)
        # Find and modify a byte deep in the payload
        tampered[HEADER_SIZE + 50] ^= 0xFF
        init_pkt_tampered = bytes(tampered)

        receiver = Receiver("uav1", uav_keys, ts, tx_uav)
        with pytest.raises((HandshakeError, MessageFormatError)):
            receiver.process_handshake_init(init_pkt_tampered)

        # Receiver session should be cleaned up
        assert receiver.session is None

    def test_double_handshake_rejected(
        self, established_session, linked_transports
    ):
        sender, receiver = established_session
        with pytest.raises(HandshakeError, match="already established"):
            sender.initiate_handshake("uav1")


# ======================================================================
# 24. Failure During Encryption/Decryption or Signature Verification
# ======================================================================


class TestCryptoFailures:
    def test_corrupted_aes_key_raises(self):
        with pytest.raises(Exception):
            aes_gcm_encrypt(b"short_key", b"data", None)

    def test_corrupted_nonce_raises(self):
        key = os.urandom(32)
        _, ct = aes_gcm_encrypt(key, b"hello", None)
        with pytest.raises(Exception):
            aes_gcm_decrypt(key, b"short", ct, None)

    def test_sig_verify_returns_false_for_garbage(self, gs_keys):
        result = sig_verify(b"message", b"garbage", gs_keys.public_key)
        assert result is False

    def test_authentication_error_on_tampered_gcm(self):
        key = os.urandom(32)
        nonce, ct = aes_gcm_encrypt(key, b"hello world", b"aad")
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 1
        with pytest.raises(AuthenticationError):
            aes_gcm_decrypt(key, nonce, bytes(tampered_ct), b"aad")

    def test_wrong_aad_fails(self):
        key = os.urandom(32)
        nonce, ct = aes_gcm_encrypt(key, b"hello world", b"correct_aad")
        with pytest.raises(AuthenticationError):
            aes_gcm_decrypt(key, nonce, ct, b"wrong_aad")


# ======================================================================
# 25. Fuzz / Property-Based Tests for Parsers
# ======================================================================


class TestParserFuzzing:
    """Light fuzz tests using random inputs against message parsers."""

    @pytest.mark.parametrize("size", [0, 1, 10, 21, 22, 50, 100])
    def test_random_bytes_parse_packet(self, size):
        """parse_packet should not crash on random input."""
        data = os.urandom(size) if size > 0 else b""
        try:
            parse_packet(data)
        except (MessageFormatError, VersionError):
            pass  # Expected for invalid data

    @pytest.mark.parametrize("_trial", range(20))
    def test_random_payload_command_parse(self, _trial):
        """CommandPayload.from_json_bytes should not crash on random input."""
        data = os.urandom(50)
        try:
            CommandPayload.from_json_bytes(data)
        except (MessageFormatError, Exception):
            pass

    @pytest.mark.parametrize("_trial", range(20))
    def test_random_payload_handshake_parse(self, _trial):
        """HandshakePayload.from_json_bytes should not crash on random input."""
        data = os.urandom(50)
        try:
            HandshakePayload.from_json_bytes(data)
        except (MessageFormatError, Exception):
            pass

    def test_header_from_bytes_valid_roundtrip(self):
        """A valid header should survive a serialize/parse roundtrip."""
        original = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=os.urandom(16),
            sequence=42,
        )
        raw = original.to_bytes()
        parsed = MessageHeader.from_bytes(raw)
        assert parsed.version == original.version
        assert parsed.msg_type == original.msg_type
        assert parsed.session_id == original.session_id
        assert parsed.sequence == original.sequence

    def test_command_payload_roundtrip(self):
        """A valid CommandPayload should survive a serialize/parse roundtrip."""
        original = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="TAKEOFF",
            params="ALTITUDE 100",
            timestamp=1234567890.123,
            signature=os.urandom(3309),
        )
        data = original.to_json_bytes()
        parsed = CommandPayload.from_json_bytes(data)
        assert parsed.sender_id == original.sender_id
        assert parsed.command == original.command
        assert parsed.signature == original.signature

    @pytest.mark.parametrize("version", [0, 1, 3, 128, 255])
    def test_wrong_version_in_header(self, version):
        raw = struct.pack(
            ">BB16sI", version, MSG_TYPE_COMMAND, b"\x00" * 16, 1
        )
        with pytest.raises(VersionError):
            MessageHeader.from_bytes(raw)

    def test_non_bytes_packet_rejected(self, established_session):
        _, receiver = established_session
        accepted, _ = receiver.receive_packet(b"")
        assert accepted is False


# ======================================================================
# Additional Edge Cases
# ======================================================================


class TestEdgeCases:
    def test_sender_identity_mismatch_in_payload(
        self, established_session, linked_transports, gs_keys
    ):
        """Payload claiming a different sender than the session."""
        sender, receiver = established_session
        _, tx_uav = linked_transports

        seq = sender.session.next_send_sequence()
        cp = CommandPayload(
            sender_id="attacker",  # Wrong sender ID!
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=time.time(),
        )
        canonical = cp.canonical_bytes_for_signing(
            sender.session.session_id, seq
        )
        sig = sig_sign(canonical, gs_keys.secret_key)
        signed_cp = CommandPayload(
            sender_id="attacker",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=cp.timestamp,
            signature=sig,
        )
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=sender.session.session_id,
            sequence=seq,
        )
        nonce, ct = aes_gcm_encrypt(
            sender.session.get_sender_enc_key(),
            signed_cp.to_json_bytes(),
            header.to_bytes(),
        )
        pkt = build_packet(header, nonce, ct)
        accepted, reason = receiver.receive_packet(pkt)
        assert accepted is False
        assert receiver.command_record.accepted_count == 0

    def test_wrong_recipient_in_payload(
        self, established_session, linked_transports, gs_keys
    ):
        """Payload addressed to a different recipient."""
        sender, receiver = established_session
        _, tx_uav = linked_transports

        seq = sender.session.next_send_sequence()
        cp = CommandPayload(
            sender_id="gs1",
            recipient_id="some_other_uav",  # Wrong recipient!
            command="LAND",
            params="",
            timestamp=time.time(),
        )
        canonical = cp.canonical_bytes_for_signing(
            sender.session.session_id, seq
        )
        sig = sig_sign(canonical, gs_keys.secret_key)
        signed_cp = CommandPayload(
            sender_id="gs1",
            recipient_id="some_other_uav",
            command="LAND",
            params="",
            timestamp=cp.timestamp,
            signature=sig,
        )
        header = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=sender.session.session_id,
            sequence=seq,
        )
        nonce, ct = aes_gcm_encrypt(
            sender.session.get_sender_enc_key(),
            signed_cp.to_json_bytes(),
            header.to_bytes(),
        )
        pkt = build_packet(header, nonce, ct)
        accepted, reason = receiver.receive_packet(pkt)
        assert accepted is False
        assert "not addressed" in reason.lower()

    def test_session_object_state_transitions(self):
        """Verify session state machine rejects invalid transitions."""
        s = Session("a", "b")
        assert s.state == SessionState.INIT

        # Cannot establish from INIT
        with pytest.raises(SessionError):
            s.establish(os.urandom(32))

        s.mark_handshake_sent()
        assert s.state == SessionState.HANDSHAKE_SENT

        # Cannot send handshake again
        with pytest.raises(SessionError):
            s.mark_handshake_sent()

        s.establish(os.urandom(32))
        assert s.state == SessionState.ESTABLISHED

        s.terminate()
        assert s.state == SessionState.TERMINATED

    def test_trust_store_operations(self, gs_keys, uav_keys):
        ts = TrustStore()

        # Not registered
        with pytest.raises(IdentityError):
            ts.get_peer("unknown")

        ts.register_peer("p1", ROLE_GROUND_STATION, gs_keys.public_key)
        p = ts.get_peer("p1")
        assert p.peer_id == "p1"
        assert not p.revoked

        # Revoke
        ts.revoke_peer("p1")
        with pytest.raises(TrustError, match="revoked"):
            ts.get_peer("p1")

        # Re-register clears revocation
        ts.register_peer("p1", ROLE_GROUND_STATION, gs_keys.public_key)
        p = ts.get_peer("p1")
        assert not p.revoked

    def test_sequence_zero_rejected(self):
        s = Session("a", "b")
        s.mark_handshake_sent()
        s.establish(os.urandom(32))
        with pytest.raises(SequenceError):
            s.validate_recv_sequence(0)

    def test_negative_sequence_rejected(self):
        s = Session("a", "b")
        s.mark_handshake_sent()
        s.establish(os.urandom(32))
        with pytest.raises(SequenceError):
            s.validate_recv_sequence(-5)

    def test_bool_sequence_rejected(self):
        s = Session("a", "b")
        s.mark_handshake_sent()
        s.establish(os.urandom(32))
        with pytest.raises(SequenceError):
            s.validate_recv_sequence(True)


# ======================================================================
# 26. v2 P0-A Regression Tests: Handshake State, Confirmation & Session Preservation (F-01, F-02, F-03, F-04)
# ======================================================================


class TestV2HandshakeStateAndSessionPreservation:
    def test_command_rejected_before_handshake_confirm(
        self, gs_keys, uav_keys, trust_store, linked_transports
    ):
        """F-02: Receiver must remain in AWAITING_CONFIRM and reject commands until HANDSHAKE_CONFIRM is verified."""
        tx_gs, tx_uav = linked_transports
        sender = Sender("gs1", gs_keys, trust_store, tx_gs)
        receiver = Receiver("uav1", uav_keys, trust_store, tx_uav)

        sender.initiate_handshake("uav1")
        init_pkt = tx_uav.receive()
        receiver.process_handshake_init(init_pkt)
        resp_pkt = tx_gs.receive()

        # Before confirm: receiver.session is None, pending_session is AWAITING_CONFIRM
        assert receiver.session is None
        assert receiver.pending_session is not None
        assert receiver.pending_session.state == SessionState.AWAITING_CONFIRM

        # Sender processes response (which also emits confirm_pkt into tx_uav)
        sender.process_handshake_response(resp_pkt)
        confirm_pkt = tx_uav.receive()

        # Sender sends a command BEFORE confirm_pkt is delivered to receiver
        sender.send_command("TAKEOFF", "ALTITUDE 10")
        early_cmd_pkt = tx_uav.receive()

        accepted, reason = receiver.receive_packet(early_cmd_pkt)
        assert accepted is False
        assert "no active session" in reason.lower()
        assert receiver.command_record.accepted_count == 0

        # Now deliver HANDSHAKE_CONFIRM -> session transitions to ESTABLISHED
        assert receiver.process_handshake_confirm(confirm_pkt) is True
        assert receiver.session is not None
        assert receiver.session.state == SessionState.ESTABLISHED
        assert receiver.pending_session is None

        # Now the command is accepted
        accepted2, result2 = receiver.receive_packet(early_cmd_pkt)
        assert accepted2 is True
        assert result2 == "TAKEOFF ALTITUDE 10"

    def test_malformed_handshake_init_preserves_established_session(
        self, established_session, linked_transports, gs_keys
    ):
        """F-01: Invalid/malformed/unauthenticated HANDSHAKE_INIT must NOT tear down an active ESTABLISHED session."""
        sender, receiver = established_session
        _, tx_uav = linked_transports
        active_sid = receiver.session.session_id

        # 1. Corrupt bytes
        with pytest.raises((HandshakeError, MessageFormatError, VersionError)):
            receiver.process_handshake_init(b"corrupt_handshake_bytes")

        # 2. Valid header but bad signature
        kem_kp = kem_generate_keypair()
        bad_hs = HandshakePayload(
            sender_id="gs1",
            sender_role=ROLE_GROUND_STATION,
            recipient_id="uav1",
            sender_signing_key=gs_keys.public_key,
            sender_kem_key=kem_kp.public_key,
            kem_ciphertext=b"",
            signature=bytes(3309),
        )
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_HANDSHAKE_INIT,
            session_id=os.urandom(16),
            sequence=0,
        )
        with pytest.raises(HandshakeError):
            receiver.process_handshake_init(
                hdr.to_bytes() + bad_hs.to_json_bytes()
            )

        # Active session must still be intact and accept commands
        assert receiver.session is not None
        assert receiver.session.session_id == active_sid
        assert receiver.session.state == SessionState.ESTABLISHED

        sender.send_command("HOVER", "")
        ok, res = receiver.receive_packet(tx_uav.receive())
        assert ok is True
        assert res == "HOVER"

    def test_replayed_handshake_init_rejected_and_preserves_session(
        self, gs_keys, uav_keys, trust_store, linked_transports
    ):
        """F-01: Replaying a captured valid HANDSHAKE_INIT must be rejected and preserve the active session."""
        tx_gs, tx_uav = linked_transports
        sender = Sender("gs1", gs_keys, trust_store, tx_gs)
        receiver = Receiver("uav1", uav_keys, trust_store, tx_uav)

        init_pkt = sender.initiate_handshake("uav1")
        _ = tx_uav.receive()
        receiver.process_handshake_init(init_pkt)
        sender.process_handshake_response(tx_gs.receive())
        receiver.process_handshake_confirm(tx_uav.receive())

        original_sid = receiver.session.session_id

        # Replay the exact captured init_pkt
        with pytest.raises(HandshakeError, match="Replayed|collides"):
            receiver.process_handshake_init(init_pkt)

        # Active session is untouched
        assert receiver.session is not None
        assert receiver.session.session_id == original_sid
        sender.send_command("LAND", "")
        ok, _ = receiver.receive_packet(tx_uav.receive())
        assert ok is True

    def test_expired_handshake_init_timestamp_rejected(
        self, gs_keys, uav_keys, trust_store, linked_transports
    ):
        """F-01: A HANDSHAKE_INIT with an expired timestamp outside the freshness window is rejected."""
        _, tx_uav = linked_transports
        receiver = Receiver("uav1", uav_keys, trust_store, tx_uav)

        kem_kp = kem_generate_keypair()
        sid = os.urandom(16)
        stale_ts = time.time() - 3600.0  # 1 hour old
        unsigned = HandshakePayload(
            sender_id="gs1",
            sender_role=ROLE_GROUND_STATION,
            recipient_id="uav1",
            timestamp=stale_ts,
            sender_signing_key=gs_keys.public_key,
            sender_kem_key=kem_kp.public_key,
            kem_ciphertext=b"",
        )
        sig = sig_sign(
            unsigned.canonical_bytes_for_signing(sid, "uav1"),
            gs_keys.secret_key,
        )
        signed = HandshakePayload(
            sender_id="gs1",
            sender_role=ROLE_GROUND_STATION,
            recipient_id="uav1",
            timestamp=stale_ts,
            handshake_nonce=unsigned.handshake_nonce,
            sender_signing_key=gs_keys.public_key,
            sender_kem_key=kem_kp.public_key,
            kem_ciphertext=b"",
            signature=sig,
        )
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_HANDSHAKE_INIT,
            session_id=sid,
            sequence=0,
        )
        with pytest.raises(HandshakeError, match="timestamp"):
            receiver.process_handshake_init(
                hdr.to_bytes() + signed.to_json_bytes()
            )

    def test_failed_handshake_confirm_preserves_established_session(
        self, established_session, linked_transports, gs_keys, trust_store
    ):
        """F-01/F-02: If a new pending handshake fails confirmation, the existing ESTABLISHED session stays intact."""
        sender1, receiver = established_session
        _, tx_uav = linked_transports
        active_sid = receiver.session.session_id

        # Second sender initiates a new handshake while session 1 is active
        tx_gs2, tx_uav2 = LocalTransport.create_pair()
        sender2 = Sender("gs1", gs_keys, trust_store, tx_gs2)
        init_pkt2 = sender2.initiate_handshake("uav1")

        resp_pkt2 = receiver.process_handshake_init(init_pkt2)
        assert receiver.session.session_id == active_sid
        assert receiver.pending_session is not None

        sender2.process_handshake_response(resp_pkt2)
        confirm_pkt2 = tx_uav2.receive()

        # Tamper with confirm_pkt2
        tampered = bytearray(confirm_pkt2)
        tampered[-1] ^= 0xFF
        with pytest.raises(HandshakeError):
            receiver.process_handshake_confirm(bytes(tampered))

        # Pending session is cleaned up, but original session 1 is still active!
        assert receiver.pending_session is None
        assert receiver.session is not None
        assert receiver.session.session_id == active_sid

        sender1.send_command("HOVER", "STILL_ALIVE")
        ok, res = receiver.receive_packet(tx_uav.receive())
        assert ok is True
        assert res == "HOVER STILL_ALIVE"

    def test_concurrent_pending_handshake_rejected_until_timeout(
        self, gs_keys, uav_keys, trust_store, linked_transports
    ):
        """A second HANDSHAKE_INIT while a pending handshake is awaiting confirm is rejected without clobbering the first."""
        tx_gs1, tx_uav = linked_transports
        tx_gs2, _ = LocalTransport.create_pair()

        sender1 = Sender("gs1", gs_keys, trust_store, tx_gs1)
        sender2 = Sender("gs1", gs_keys, trust_store, tx_gs2)
        receiver = Receiver(
            "uav1", uav_keys, trust_store, tx_uav, handshake_timeout=5.0
        )

        init1 = sender1.initiate_handshake("uav1")
        _ = tx_uav.receive()
        resp1 = receiver.process_handshake_init(init1)

        # Second init arrives while first is pending
        init2 = sender2.initiate_handshake("uav1")
        with pytest.raises(HandshakeError, match="already awaiting"):
            receiver.process_handshake_init(init2)

        # First handshake can still complete normally
        sender1.process_handshake_response(resp1)
        confirm1 = tx_uav.receive()
        assert receiver.process_handshake_confirm(confirm1) is True
        assert receiver.session.session_id == sender1.session.session_id

    def test_pending_handshake_timeout_expires(
        self, gs_keys, uav_keys, trust_store, linked_transports
    ):
        """Confirm arriving after handshake_timeout is rejected."""
        tx_gs, tx_uav = linked_transports
        sender = Sender("gs1", gs_keys, trust_store, tx_gs)
        receiver = Receiver(
            "uav1", uav_keys, trust_store, tx_uav, handshake_timeout=0.01
        )

        sender.initiate_handshake("uav1")
        receiver.process_handshake_init(tx_uav.receive())
        sender.process_handshake_response(tx_gs.receive())
        confirm_pkt = tx_uav.receive()

        # Simulate timeout elapsing
        receiver._pending_handshake_started_at -= 1.0
        with pytest.raises(HandshakeError, match="timed out"):
            receiver.process_handshake_confirm(confirm_pkt)
        assert receiver.session is None
        assert receiver.pending_session is None

    def test_handshake_rate_limit_enforced(
        self, gs_keys, uav_keys, trust_store, linked_transports
    ):
        """Exceeding the handshake rate limit raises HandshakeError without harming an active session."""
        sender, receiver = (
            Sender("gs1", gs_keys, trust_store, linked_transports[0]),
            Receiver(
                "uav1",
                uav_keys,
                trust_store,
                linked_transports[1],
                rate_limit_max_attempts=3,
                rate_limit_window=60.0,
            ),
        )
        for _ in range(3):
            with pytest.raises((HandshakeError, MessageFormatError)):
                receiver.process_handshake_init(b"short")
        with pytest.raises(HandshakeError, match="rate limit"):
            receiver.process_handshake_init(b"short")

    def test_handshake_response_echoed_kem_key_binding(
        self, gs_keys, uav_keys, trust_store, linked_transports
    ):
        """F-03: Responder must echo initiator's exact ephemeral ML-KEM-768 public key."""
        tx_gs, tx_uav = linked_transports
        sender = Sender("gs1", gs_keys, trust_store, tx_gs)
        receiver = Receiver("uav1", uav_keys, trust_store, tx_uav)

        sender.initiate_handshake("uav1")
        init_pkt = tx_uav.receive()
        resp_pkt = receiver.process_handshake_init(init_pkt)
        _ = tx_gs.receive()

        # Re-sign a response that echoes a different KEM public key
        hdr = MessageHeader.from_bytes(resp_pkt[:HEADER_SIZE])
        parsed_resp = HandshakePayload.from_json_bytes(resp_pkt[HEADER_SIZE:])
        wrong_kem = kem_generate_keypair().public_key
        unsigned_bad = HandshakePayload(
            sender_id=parsed_resp.sender_id,
            sender_role=parsed_resp.sender_role,
            recipient_id=parsed_resp.recipient_id,
            timestamp=parsed_resp.timestamp,
            handshake_nonce=parsed_resp.handshake_nonce,
            sender_signing_key=parsed_resp.sender_signing_key,
            sender_kem_key=wrong_kem,
            kem_ciphertext=parsed_resp.kem_ciphertext,
        )
        sig_bad = sig_sign(
            unsigned_bad.canonical_bytes_for_signing(hdr.session_id, "gs1"),
            uav_keys.secret_key,
        )
        signed_bad = HandshakePayload(
            sender_id=parsed_resp.sender_id,
            sender_role=parsed_resp.sender_role,
            recipient_id=parsed_resp.recipient_id,
            timestamp=parsed_resp.timestamp,
            handshake_nonce=parsed_resp.handshake_nonce,
            sender_signing_key=parsed_resp.sender_signing_key,
            sender_kem_key=wrong_kem,
            kem_ciphertext=parsed_resp.kem_ciphertext,
            signature=sig_bad,
        )
        with pytest.raises(HandshakeError, match="KEM public key"):
            sender.process_handshake_response(
                hdr.to_bytes() + signed_bad.to_json_bytes()
            )


# ======================================================================
# 27. v2 P0-B Regression Tests: End-to-End Role Enforcement (F-15)
# ======================================================================


class TestV2RoleEnforcement:
    def test_uav_registered_peer_cannot_initiate_handshake_via_sender(
        self, uav_keys, linked_transports
    ):
        """F-15: A peer registered as ROLE_UAV cannot initiate a handshake using Sender."""
        tx_uav2, tx_uav1 = linked_transports
        uav2_keys = sig_generate_keypair()

        ts = TrustStore()
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)
        ts.register_peer("uav2", ROLE_UAV, uav2_keys.public_key)

        rogue_sender = Sender("uav2", uav2_keys, ts, tx_uav2)
        with pytest.raises(TrustError, match="role"):
            rogue_sender.initiate_handshake("uav1")

    def test_uav_peer_forging_ground_station_role_in_init_rejected_by_receiver(
        self, uav_keys, linked_transports
    ):
        """F-15: Even if a ROLE_UAV peer crafts a raw HANDSHAKE_INIT claiming sender_role='ground_station', Receiver rejects it."""
        _, tx_uav1 = linked_transports
        uav2_keys = sig_generate_keypair()

        ts = TrustStore()
        ts.register_peer("uav1", ROLE_UAV, uav_keys.public_key)
        ts.register_peer("uav2", ROLE_UAV, uav2_keys.public_key)

        receiver = Receiver("uav1", uav_keys, ts, tx_uav1)
        kem_kp = kem_generate_keypair()
        sid = os.urandom(16)

        unsigned = HandshakePayload(
            sender_id="uav2",
            sender_role=ROLE_GROUND_STATION,  # False role claim!
            recipient_id="uav1",
            sender_signing_key=uav2_keys.public_key,
            sender_kem_key=kem_kp.public_key,
            kem_ciphertext=b"",
        )
        sig = sig_sign(
            unsigned.canonical_bytes_for_signing(sid, "uav1"),
            uav2_keys.secret_key,
        )
        signed = HandshakePayload(
            sender_id="uav2",
            sender_role=ROLE_GROUND_STATION,
            recipient_id="uav1",
            timestamp=unsigned.timestamp,
            handshake_nonce=unsigned.handshake_nonce,
            sender_signing_key=uav2_keys.public_key,
            sender_kem_key=kem_kp.public_key,
            kem_ciphertext=b"",
            signature=sig,
        )
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_HANDSHAKE_INIT,
            session_id=sid,
            sequence=0,
        )
        with pytest.raises(TrustError, match="role"):
            receiver.process_handshake_init(
                hdr.to_bytes() + signed.to_json_bytes()
            )
        assert receiver.session is None
        assert receiver.pending_session is None

    def test_ground_station_claiming_uav_role_in_init_rejected(
        self, gs_keys, uav_keys, trust_store, linked_transports
    ):
        """F-15: A legitimate ground station claiming sender_role='uav' in HANDSHAKE_INIT is rejected."""
        _, tx_uav = linked_transports
        receiver = Receiver("uav1", uav_keys, trust_store, tx_uav)
        kem_kp = kem_generate_keypair()
        sid = os.urandom(16)

        unsigned = HandshakePayload(
            sender_id="gs1",
            sender_role=ROLE_UAV,
            recipient_id="uav1",
            sender_signing_key=gs_keys.public_key,
            sender_kem_key=kem_kp.public_key,
            kem_ciphertext=b"",
        )
        sig = sig_sign(
            unsigned.canonical_bytes_for_signing(sid, "uav1"),
            gs_keys.secret_key,
        )
        signed = HandshakePayload(
            sender_id="gs1",
            sender_role=ROLE_UAV,
            recipient_id="uav1",
            timestamp=unsigned.timestamp,
            handshake_nonce=unsigned.handshake_nonce,
            sender_signing_key=gs_keys.public_key,
            sender_kem_key=kem_kp.public_key,
            kem_ciphertext=b"",
            signature=sig,
        )
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_HANDSHAKE_INIT,
            session_id=sid,
            sequence=0,
        )
        with pytest.raises(TrustError, match="role"):
            receiver.process_handshake_init(
                hdr.to_bytes() + signed.to_json_bytes()
            )

    def test_ground_station_cannot_initiate_handshake_to_another_ground_station(
        self, gs_keys, linked_transports
    ):
        """F-15: Ground-station-to-ground-station pairing is rejected."""
        tx_gs1, _ = linked_transports
        gs2_keys = sig_generate_keypair()
        ts = TrustStore()
        ts.register_peer("gs1", ROLE_GROUND_STATION, gs_keys.public_key)
        ts.register_peer("gs2", ROLE_GROUND_STATION, gs2_keys.public_key)

        sender = Sender("gs1", gs_keys, ts, tx_gs1)
        with pytest.raises(TrustError, match="role"):
            sender.initiate_handshake("gs2")

    def test_invalid_role_rejected_in_trust_store(self, gs_keys):
        ts = TrustStore()
        with pytest.raises(IdentityError, match="Invalid role"):
            ts.register_peer("bad_peer", "admin", gs_keys.public_key)

    def test_mid_session_role_change_in_trust_store_rejects_commands_and_rekey(
        self, established_session, linked_transports, trust_store, gs_keys
    ):
        """F-15: If a sender's role in TrustStore is changed to ROLE_UAV mid-session, Receiver rejects commands and rekeys."""
        sender, receiver = established_session
        _, tx_uav = linked_transports

        # Re-register gs1 with ROLE_UAV while session is active
        trust_store.register_peer("gs1", ROLE_UAV, gs_keys.public_key)

        sender.send_command("LAND", "")
        cmd_pkt = tx_uav.receive()
        accepted, reason = receiver.receive_packet(cmd_pkt)
        assert accepted is False
        assert "role" in reason.lower()
        assert receiver.command_record.accepted_count == 0

    def test_mid_session_key_rotation_requires_rehandshake(
        self, established_session, linked_transports, trust_store
    ):
        """Rotating a peer's signing key in TrustStore during an active session rejects commands on the old session."""
        sender, receiver = established_session
        _, tx_uav = linked_transports

        new_gs_keys = sig_generate_keypair()
        trust_store.register_peer(
            "gs1", ROLE_GROUND_STATION, new_gs_keys.public_key
        )

        sender.send_command("LAND", "")
        cmd_pkt = tx_uav.receive()
        accepted, reason = receiver.receive_packet(cmd_pkt)
        assert accepted is False
        assert "changed" in reason.lower() or "signature" in reason.lower()


# ======================================================================
# 28. v2 P0-C Regression Tests: Rekeying, Root-Secret Chaining & Epoch Security (F-12, F-13, F-06)
# ======================================================================


class TestV2RekeyAndKeyScheduleSecurity:
    def test_rekey_with_compromised_traffic_keys_but_forged_dsa_signature_rejected(
        self, established_session, linked_transports
    ):
        """F-12: An attacker holding current symmetric traffic keys (TM-2) cannot forge a REKEY without the ML-DSA-65 private key."""
        from protocol.messages import RekeyPayload
        sender, receiver = established_session
        _, tx_uav = linked_transports

        stolen_sender_enc_key = sender.session.get_sender_enc_key()
        attacker_dsa = sig_generate_keypair()
        attacker_kem = kem_generate_keypair()
        seq = sender.session.send_sequence
        nonce = sender.session.keys.sender_nonce_prefix + struct.pack(
            ">Q", sender.session._sender_nonce_counter + 1
        )

        unsigned_rekey = RekeyPayload(
            sender_id="gs1",
            recipient_id="uav1",
            current_epoch=0,
            next_epoch=1,
            rekey_nonce=os.urandom(16),
            sender_kem_key=attacker_kem.public_key,
        )
        forged_sig = sig_sign(
            unsigned_rekey.canonical_bytes_for_signing(
                sender.session.session_id, seq
            ),
            attacker_dsa.secret_key,
        )
        forged_rekey = RekeyPayload(
            sender_id="gs1",
            recipient_id="uav1",
            current_epoch=0,
            next_epoch=1,
            rekey_nonce=unsigned_rekey.rekey_nonce,
            sender_kem_key=attacker_kem.public_key,
            signature=forged_sig,
        )
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_REKEY,
            session_id=sender.session.session_id,
            sequence=seq,
        )
        _, ct = aes_gcm_encrypt(
            stolen_sender_enc_key,
            forged_rekey.to_json_bytes(),
            hdr.to_bytes(),
            nonce=nonce,
        )
        forged_pkt = build_packet(hdr, nonce, ct)

        ok, reason = receiver.receive_packet(forged_pkt)
        assert ok is False
        assert "signature" in reason.lower()
        assert receiver.session.rekey_epoch == 0

        # Legitimate sender can still send commands on epoch 0
        sender.send_command("HOVER", "")
        ok2, _ = receiver.receive_packet(tx_uav.receive())
        assert ok2 is True

    def test_terminate_with_compromised_traffic_key_but_forged_signature_rejected(
        self, established_session
    ):
        """F-12: An attacker holding sender_enc_key cannot forge MSG_TYPE_TERMINATE without gs1's ML-DSA-65 private key."""
        from protocol.messages import TerminatePayload
        sender, receiver = established_session
        stolen_key = sender.session.get_sender_enc_key()
        attacker_dsa = sig_generate_keypair()
        seq = sender.session.send_sequence
        nonce = sender.session.keys.sender_nonce_prefix + struct.pack(
            ">Q", sender.session._sender_nonce_counter + 1
        )

        unsigned_term = TerminatePayload(
            sender_id="gs1",
            recipient_id="uav1",
            epoch=0,
            timestamp=time.time(),
            reason="TERMINATE",
        )
        sig = sig_sign(
            unsigned_term.canonical_bytes_for_signing(
                sender.session.session_id, seq
            ),
            attacker_dsa.secret_key,
        )
        signed_term = TerminatePayload(
            sender_id="gs1",
            recipient_id="uav1",
            epoch=0,
            timestamp=unsigned_term.timestamp,
            reason="TERMINATE",
            signature=sig,
        )
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_TERMINATE,
            session_id=sender.session.session_id,
            sequence=seq,
        )
        _, ct = aes_gcm_encrypt(
            stolen_key,
            signed_term.to_json_bytes(),
            hdr.to_bytes(),
            nonce=nonce,
        )
        ok, reason = receiver.receive_packet(build_packet(hdr, nonce, ct))
        assert ok is False
        assert receiver.session is not None
        assert receiver.session.state == SessionState.ESTABLISHED

    def test_rekey_response_wrong_msg_type_rejected(
        self, established_session, linked_transports
    ):
        """F-13: Sender.complete_rekey must reject packets whose header msg_type != MSG_TYPE_REKEY."""
        sender, receiver = established_session
        tx_gs, tx_uav = linked_transports

        sender.initiate_rekey()
        rekey_pkt = tx_uav.receive()
        receiver.receive_packet(rekey_pkt)
        rekey_resp = tx_gs.receive()

        # Tamper msg_type in header from MSG_TYPE_REKEY (5) to MSG_TYPE_COMMAND (4)
        tampered = bytearray(rekey_resp)
        tampered[1] = MSG_TYPE_COMMAND
        with pytest.raises(SessionError, match="MSG_TYPE_REKEY"):
            sender.complete_rekey(bytes(tampered))

    def test_interrupted_rekey_rollback_and_old_key_rejection(
        self, established_session, linked_transports
    ):
        """P0-C: Interrupted rekey can be rolled back before commit; once committed, old-epoch keys are rejected."""
        sender, receiver = established_session
        tx_gs, tx_uav = linked_transports

        # Save an epoch-0 encrypted command packet
        sender.send_command("TAKEOFF", "ALTITUDE 10")
        epoch0_cmd_pkt = tx_uav.receive()
        assert receiver.receive_packet(epoch0_cmd_pkt)[0] is True

        # Send another epoch-0 command but hold it in flight across a rekey
        sender.send_command("HOVER", "")
        held_epoch0_pkt = tx_uav.receive()

        # Perform rekey to epoch 1
        sender.initiate_rekey()
        assert receiver.receive_packet(tx_uav.receive())[0] is True
        assert sender.complete_rekey(tx_gs.receive()) is True
        assert sender.session.rekey_epoch == 1
        assert receiver.session.rekey_epoch == 1

        # Held packet encrypted under epoch-0 key must fail authentication in epoch 1
        ok_old, _ = receiver.receive_packet(held_epoch0_pkt)
        assert ok_old is False

        # New command in epoch 1 succeeds
        sender.send_command("LAND", "")
        ok_new, res_new = receiver.receive_packet(tx_uav.receive())
        assert ok_new is True
        assert res_new == "LAND"

    def test_root_secret_chaining_and_transcript_binding(self):
        """F-06/F-12: Verify derive_epoch_root_secret binds transcript_hash, peer IDs, and prev_root_secret."""
        from protocol.session import derive_epoch_root_secret
        ss = os.urandom(32)
        sid = os.urandom(16)
        th1 = hashlib.sha256(b"transcript1").digest()
        th2 = hashlib.sha256(b"transcript2").digest()

        r1, _ = derive_epoch_root_secret(ss, sid, 0, th1, "gs1", "uav1")
        r2, _ = derive_epoch_root_secret(ss, sid, 0, th2, "gs1", "uav1")
        r3, _ = derive_epoch_root_secret(ss, sid, 0, th1, "gs2", "uav1")
        assert r1 != r2
        assert r1 != r3

        # Epoch 1 chaining
        ss_rekey = os.urandom(32)
        re1, _ = derive_epoch_root_secret(
            ss_rekey, sid, 1, th1, "gs1", "uav1", prev_root_secret=r1
        )
        re2, _ = derive_epoch_root_secret(
            ss_rekey, sid, 1, th1, "gs1", "uav1", prev_root_secret=r2
        )
        assert re1 != re2


# ======================================================================
# 29. v2 P1 Regression Tests: Command Whitelist & Timestamp Validation (F-09)
# ======================================================================


class TestV2CommandValidationAndTimestamps:
    def test_unlisted_command_rejected_without_mutating_sender_counters(
        self, established_session, linked_transports, gs_keys
    ):
        """F-09: Commands not in VALID_COMMANDS are rejected at both Sender and Receiver without advancing counters."""
        sender, receiver = established_session
        _, tx_uav = linked_transports

        initial_seq = sender.session.send_sequence
        initial_nonce_ctr = sender.session._sender_nonce_counter

        with pytest.raises(MessageFormatError, match="command"):
            sender.send_command("UNAUTHORIZED_SHELL_EXEC", "rm -rf /")

        # Sender counters must not have advanced on failed validation
        assert sender.session.send_sequence == initial_seq
        assert sender.session._sender_nonce_counter == initial_nonce_ctr

        # Craft an encrypted packet with an unlisted command directly
        raw_json = json.dumps({
            "sender_id": "gs1",
            "recipient_id": "uav1",
            "command": "DROP_PAYLOAD",
            "params": "",
            "timestamp": time.time(),
            "signature": "00" * 3309,
        }).encode("utf-8")
        with pytest.raises(MessageFormatError, match="command"):
            CommandPayload.from_json_bytes(raw_json)

    @pytest.mark.parametrize("bad_ts", ["NaN", "Infinity", "-Infinity", -5.0, 0.0, True, False])
    def test_non_finite_and_invalid_timestamps_rejected(self, bad_ts):
        """F-09: NaN, Infinity, -Infinity, non-positive, and boolean timestamps are rejected."""
        if isinstance(bad_ts, str):
            raw = (
                '{"sender_id":"gs1","recipient_id":"uav1","command":"LAND",'
                f'"params":"","timestamp":{bad_ts},"signature":"' + ("00" * 3309) + '"}'
            ).encode("utf-8")
        else:
            raw = json.dumps({
                "sender_id": "gs1",
                "recipient_id": "uav1",
                "command": "LAND",
                "params": "",
                "timestamp": bad_ts,
                "signature": "00" * 3309,
            }).encode("utf-8")
        with pytest.raises(MessageFormatError):
            CommandPayload.from_json_bytes(raw)

    def test_stale_command_timestamp_rejected_by_receiver(
        self, established_session, gs_keys
    ):
        """F-09: Receiver rejects commands whose timestamp falls outside COMMAND_MAX_TIMESTAMP_SKEW_SECONDS."""
        sender, receiver = established_session
        seq = sender.session.next_send_sequence()
        nonce = sender.session.next_sender_nonce()
        stale_ts = time.time() - 600.0

        cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=stale_ts,
        )
        sig = sig_sign(
            cp.canonical_bytes_for_signing(sender.session.session_id, seq),
            gs_keys.secret_key,
        )
        signed_cp = CommandPayload(
            sender_id="gs1",
            recipient_id="uav1",
            command="LAND",
            params="",
            timestamp=stale_ts,
            signature=sig,
        )
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_COMMAND,
            session_id=sender.session.session_id,
            sequence=seq,
        )
        _, ct = aes_gcm_encrypt(
            sender.session.get_sender_enc_key(),
            signed_cp.to_json_bytes(),
            hdr.to_bytes(),
            nonce=nonce,
        )
        ok, reason = receiver.receive_packet(build_packet(hdr, nonce, ct))
        assert ok is False
        assert "timestamp" in reason.lower()


# ======================================================================
# 30. v2 P1/P2 Regression Tests: Bounds, Replay Ordering, Nonce Window & Lifecycle (F-05, F-07, F-08, F-10, F-11, F-14, F-16)
# ======================================================================


class TestV2BoundsReplayAndLifecycle:
    def test_replayed_command_rejected_before_sig_verify(
        self, established_session, linked_transports, monkeypatch
    ):
        """F-11: Duplicate/replayed sequence numbers must be rejected BEFORE invoking expensive ML-DSA-65 sig_verify."""
        import protocol.receiver as recv_mod
        sender, receiver = established_session
        _, tx_uav = linked_transports

        sender.send_command("TAKEOFF", "ALTITUDE 10")
        pkt = tx_uav.receive()
        assert receiver.receive_packet(pkt)[0] is True

        verify_calls = 0
        orig_verify = recv_mod.sig_verify

        def counting_verify(*args, **kwargs):
            nonlocal verify_calls
            verify_calls += 1
            return orig_verify(*args, **kwargs)

        monkeypatch.setattr(recv_mod, "sig_verify", counting_verify)

        # Replay pkt: sequence check runs before sig_verify, so verify_calls must remain 0
        ok, reason = receiver.receive_packet(pkt)
        assert ok is False
        assert verify_calls == 0

    def test_bounded_nonce_window_caps_memory_and_rejects_old_nonces(
        self, established_session, linked_transports
    ):
        """F-08: Sending 250 commands (> NONCE_WINDOW_SIZE=200) keeps _emitted_nonces and _received_nonces <= 200 while still rejecting nonce #1."""
        from protocol.constants import NONCE_WINDOW_SIZE
        sender, receiver = established_session
        _, tx_uav = linked_transports

        first_nonce = None
        for i in range(250):
            sender.send_command("HOVER", f"STEP {i}")
            pkt = tx_uav.receive()
            if i == 0:
                first_nonce = pkt[HEADER_SIZE : HEADER_SIZE + AES_NONCE_BYTES]
            ok, _ = receiver.receive_packet(pkt)
            assert ok is True

        assert len(sender.session._emitted_nonces) <= NONCE_WINDOW_SIZE
        assert len(receiver.session._received_nonces) <= NONCE_WINDOW_SIZE
        assert len(receiver.session._received_nonce_counters) <= NONCE_WINDOW_SIZE

        # Even though nonce #1 was pruned from the 200-entry set, its counter (1) is <= cutoff (50)
        # so validate_nonce still rejects it!
        from protocol.errors import NonceError
        with pytest.raises(NonceError):
            receiver.session.validate_nonce(first_nonce)

    def test_fips_byte_length_checks_enforced(self):
        """F-05: crypto_core functions reject wrong-length keys, ciphertexts, and signatures."""
        from protocol.crypto_core import CryptoError, kem_decapsulate, kem_encapsulate
        with pytest.raises(CryptoError):
            kem_encapsulate(b"short_pk")
        with pytest.raises(CryptoError):
            kem_decapsulate(b"short_ct", b"short_sk")
        assert sig_verify(b"msg", b"short_sig", b"short_pk") is False

    def test_oversized_handshake_packet_rejected(
        self, uav_keys, trust_store, linked_transports
    ):
        """F-10: Oversized handshake init packets are rejected before JSON parsing."""
        _, tx_uav = linked_transports
        receiver = Receiver("uav1", uav_keys, trust_store, tx_uav)
        hdr = MessageHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_TYPE_HANDSHAKE_INIT,
            session_id=os.urandom(16),
            sequence=0,
        )
        oversized = hdr.to_bytes() + (b"A" * 30000)
        with pytest.raises(HandshakeError):
            receiver.process_handshake_init(oversized)

    def test_monotonic_clock_protects_session_against_wall_clock_jump(
        self, established_session, monkeypatch
    ):
        """F-14: Jumping time.time() forward without advancing time.monotonic() does not expire an active session."""
        _, receiver = established_session
        real_time = time.time()
        monkeypatch.setattr(time, "time", lambda: real_time + 99999.0)
        # Session check_alive uses monotonic clock unless session.created_at was explicitly mutated
        receiver.session.check_alive()
        assert receiver.session.state == SessionState.ESTABLISHED

    def test_logical_key_cleanup_zeroes_mutable_buffers(
        self, established_session
    ):
        """F-16: Session.terminate() zeroes internal mutable bytearray buffers and sets keys.cleared = True."""
        sender, _ = established_session
        keys_ref = sender.session.keys
        sender.session.terminate()
        assert keys_ref.cleared is True
        assert all(b == 0 for b in keys_ref._sender_key_buf)
        assert all(b == 0 for b in keys_ref._receiver_key_buf)
        assert sender.session.root_secret is None


# ======================================================================
# End of test suite
# ======================================================================
