"""Test voip_utils VoIP functionality."""

import asyncio
import socket

from voip_utils.sip import CallInfo, SdpInfo, get_sip_endpoint
from voip_utils.voip import RtpDatagramProtocol, VoipDatagramProtocol


class MockRtpDatagramProtocol(RtpDatagramProtocol):
    def on_chunk(self, audio_bytes: bytes) -> None:
        pass


class MockVoipDatagramProtocol(VoipDatagramProtocol):
    def __init__(self):
        super().__init__(
            SdpInfo("username", 5, "session", "version"),
            lambda call_info, rtcp_state: MockRtpDatagramProtocol(
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
        headers={},
        local_rtp_ip="127.0.0.1" if local_rtp_port else None,
        local_rtp_port=local_rtp_port,
    )


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
