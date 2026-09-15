"""Test voip_utils VoIP functionality."""

import asyncio
import socket
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


class NullRtpDatagramProtocol(RtpDatagramProtocol):
    """RTP protocol that discards what it receives.

    Unlike MockRtpDatagramProtocol this one is driven by a real event loop, so
    it keeps the stock create_task.
    """

    def on_chunk(self, audio_bytes: bytes) -> None:
        pass


class MockVoipDatagramProtocol(VoipDatagramProtocol):
    def __init__(self):
        super().__init__(
            SdpInfo("username", 5, "session", "version"),
            lambda call_info, rtcp_state: NullRtpDatagramProtocol(
                rtcp_state=rtcp_state
            ),
        )


def _call_info(local_rtp_port=None):
    source = get_sip_endpoint("testsource")
    destination = get_sip_endpoint("destination")
    return CallInfo(
        caller_endpoint=destination,
        local_endpoint=source,
        caller_rtp_port=12345,
        # On the outgoing path this is the address from the remote SDP "c=" line
        server_ip="192.0.2.10",
        headers={
            "via": f"SIP/2.0/UDP {source.host}:{source.port}",
            "from": source.sip_header,
            "to": destination.sip_header,
            "contact": destination.sip_header,
            "call-id": "100",
            "cseq": "50 INVITE",
        },
        local_rtp_ip="127.0.0.1" if local_rtp_port else None,
        local_rtp_port=local_rtp_port,
    )


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


def _free_port_pair() -> int:
    """Find a free port whose neighbour is free too, for RTP and RTCP."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", port + 1))
        except OSError:
            continue
        return port


def _rtp_address(call_info):
    """Start an RTP server for call_info and return the protocol's address."""

    async def run():
        protocol = MockVoipDatagramProtocol()
        await protocol._create_rtp_server(  # pylint: disable=protected-access
            protocol.valid_protocol_factory, call_info, "127.0.0.1", _free_port_pair()
        )
        rtp_protocol = protocol._rtp_protocol  # pylint: disable=protected-access
        addr = rtp_protocol.addr
        rtp_protocol.disconnect()
        protocol._rtcp_protocol.disconnect()  # pylint: disable=protected-access
        return addr

    return asyncio.run(run())


def test_outgoing_call_rtp_address_comes_from_sdp():
    """An answered outgoing call knows where to send media straight away.

    Otherwise nothing is transmitted until the remote party sends to us first,
    which a listen-only callee never does.
    """
    assert _rtp_address(_call_info(local_rtp_port=23456)) == ("192.0.2.10", 12345)


def test_incoming_call_rtp_address_is_learned_from_traffic():
    """An incoming call still learns the address from the first packet.

    server_ip is our own address on that path, not the caller's.
    """
    assert _rtp_address(_call_info()) is None


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


def test_outgoing_call_rtp_address_must_be_an_ip_literal():
    """A c= line that is not an IPv4 literal is not used as an RTP destination.

    server_ip comes from the SDP of whoever answered, so it need not be an
    address at all. Handing a name to sendto() would resolve it on the event
    loop.
    """
    call_info = _call_info(local_rtp_port=23456)
    call_info.server_ip = "proxy.example.com"

    assert _rtp_address(call_info) is None
