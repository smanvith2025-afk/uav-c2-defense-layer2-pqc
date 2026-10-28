"""Transport interface and local test transport.

Defines the abstract interface that separates the protocol from the
underlying communication channel. A LocalTransport implementation is
provided for in-process testing.

In a production deployment, the transport would wrap a UDP, TCP, or
serial link. The protocol layer is transport-agnostic.
"""

from __future__ import annotations

import collections
from abc import ABC, abstractmethod


class Transport(ABC):
    """Abstract transport interface for sending and receiving packets."""

    @abstractmethod
    def send(self, packet: bytes) -> None:
        """Send a packet to the remote peer.

        Args:
            packet: Complete wire-format packet bytes.
        """

    @abstractmethod
    def receive(self) -> bytes | None:
        """Receive the next available packet.

        Returns:
            Packet bytes, or None if no packet is available.
        """

    @abstractmethod
    def close(self) -> None:
        """Close the transport and release resources."""


class LocalTransport(Transport):
    """In-process transport using a shared queue.

    Two LocalTransport instances are linked via a shared pair of queues,
    enabling sender/receiver testing without networking.

    Usage:
        tx_a, tx_b = LocalTransport.create_pair()
        tx_a.send(b"hello")  # tx_b.receive() returns b"hello"
        tx_b.send(b"world")  # tx_a.receive() returns b"world"
    """

    def __init__(
        self,
        send_queue: collections.deque,
        recv_queue: collections.deque,
    ) -> None:
        self._send_queue = send_queue
        self._recv_queue = recv_queue
        self._closed = False

    @classmethod
    def create_pair(cls) -> tuple["LocalTransport", "LocalTransport"]:
        """Create a linked pair of local transports.

        Returns:
            (transport_a, transport_b) — a's sends go to b's receive and
            vice versa.
        """
        q_a_to_b: collections.deque = collections.deque()
        q_b_to_a: collections.deque = collections.deque()
        return (
            cls(send_queue=q_a_to_b, recv_queue=q_b_to_a),
            cls(send_queue=q_b_to_a, recv_queue=q_a_to_b),
        )

    def send(self, packet: bytes) -> None:
        if self._closed:
            raise RuntimeError("Transport is closed")
        self._send_queue.append(packet)

    def receive(self) -> bytes | None:
        if self._closed:
            raise RuntimeError("Transport is closed")
        try:
            return self._recv_queue.popleft()
        except IndexError:
            return None

    def close(self) -> None:
        self._closed = True

    @property
    def pending_count(self) -> int:
        """Number of packets waiting to be received."""
        return len(self._recv_queue)
