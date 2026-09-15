"""Test voip_utils VoIP functionality."""

import asyncio
import struct
from unittest.mock import AsyncMock, Mock

from voip_utils.sip import CallInfo, SdpInfo, get_sip_endpoint
from voip_utils.voip import RtpDatagramProtocol, VoipDatagramProtocol


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


def _on_call(call_info):
    """Run on_call() with the RTP server stubbed out, return the answer mock."""

    async def run():
        # pylint: disable=protected-access
        protocol = MockVoipDatagramProtocol()
        protocol.connection_made(Mock())
        protocol.answer = Mock()
        protocol._create_rtp_server = AsyncMock()

        protocol.on_call(call_info)
        await asyncio.sleep(0)

        return protocol.answer

    return asyncio.run(run())


def test_incoming_call_is_answered():
    """An incoming INVITE is answered with a 200 OK."""
    answer = _on_call(_call_info())

    answer.assert_called_once()


def test_outgoing_call_is_not_answered():
    """A call we placed ourselves must not be answered with a 200 OK.

    on_call() also runs when our own outgoing INVITE receives its 200 OK. The
    remote party has already answered at that point, so sending a 200 OK back
    makes it believe one of its own INVITEs was answered, and the two ends
    trade 200 OK and ACK messages indefinitely.
    """
    answer = _on_call(_call_info(local_rtp_port=23456))

    answer.assert_not_called()
