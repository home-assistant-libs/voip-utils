"""Test voip_utils VoIP functionality."""

import struct
from unittest.mock import Mock

from voip_utils.voip import RtpDatagramProtocol


def _no_task(coro):
    """Stand in for asyncio.create_task, which needs a running event loop."""
    coro.close()
    return Mock()


class MockRtpDatagramProtocol(RtpDatagramProtocol):
    def __init__(self):
        super().__init__(opus_payload_type=123, create_task=_no_task)
        self.chunks = []

    def on_chunk(self, audio_bytes: bytes) -> None:
        self.chunks.append(audio_bytes)


def _rtp_packet(payload_type: int, payload: bytes = b"\x00\x00\x00\x00") -> bytes:
    flags = 0b10000000  # version 2, no padding or extensions
    return struct.pack(">BBHLL", flags, payload_type, 1, 0, 0) + payload


def test_unknown_payload_type_does_not_end_the_call():
    """A payload type we don't handle is dropped, not treated as fatal.

    outgoing_call() offers telephone-event payload types in its SDP, so a phone
    is entitled to send DTMF mid-call. Tearing the call down in response would
    hang up on the user for pressing a key.
    """
    protocol = MockRtpDatagramProtocol()
    transport = Mock()
    transport.is_closing.return_value = False
    protocol.connection_made(transport)

    # 101 is the telephone-event payload type offered by outgoing_call().
    protocol.datagram_received(_rtp_packet(101), ("127.0.0.1", 5004))

    assert not protocol.chunks
    transport.close.assert_not_called()
