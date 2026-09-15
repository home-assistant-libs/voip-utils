"""Test voip_utils VoIP functionality."""

import struct
from unittest.mock import Mock, patch

import pytest

from voip_utils.error import VoipError
from voip_utils.sip import CallInfo, SdpInfo, get_sip_endpoint
from voip_utils.voip import (
    _RTP_PORT_ATTEMPTS,
    RtpDatagramProtocol,
    VoipDatagramProtocol,
)


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


class _NoFreePairSocket:
    """Socket whose RTCP port is always taken, so no consecutive pair is free."""

    binds = 0

    def __init__(self, *args, **kwargs):
        pass

    def setblocking(self, blocking):
        pass

    def bind(self, address):
        type(self).binds += 1
        if address[1] != 0:
            raise OSError("port in use")

    def getsockname(self):
        return ("0.0.0.0", 10000)

    def close(self):
        pass


def test_rtp_allocator_gives_up_instead_of_spinning():
    """Port exhaustion fails one call rather than stalling the event loop.

    The search runs on the loop, so looping until a pair frees up would block
    every other call for as long as the pressure lasts.
    """
    protocol = VoipDatagramProtocol(
        SdpInfo("username", 5, "session", "version"),
        valid_protocol_factory=lambda call_info, rtcp_state: Mock(),
    )
    protocol.connection_made(Mock())
    call_info = CallInfo(
        caller_endpoint=get_sip_endpoint("192.168.1.50"),
        local_endpoint=get_sip_endpoint("192.168.1.10"),
        caller_rtp_port=5004,
        server_ip="192.168.1.10",
        headers={},
    )

    _NoFreePairSocket.binds = 0
    with patch("voip_utils.voip.socket.socket", _NoFreePairSocket):
        with pytest.raises(VoipError):
            protocol.on_call(call_info)

    # Two binds per attempt: the RTP port, then the RTCP port above it.
    assert _NoFreePairSocket.binds == _RTP_PORT_ATTEMPTS * 2
