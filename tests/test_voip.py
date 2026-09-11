"""Test voip_utils VoIP functionality."""

import asyncio
from unittest.mock import AsyncMock, Mock

from voip_utils.sip import CallInfo, SdpInfo, get_sip_endpoint
from voip_utils.voip import VoipDatagramProtocol


class MockVoipDatagramProtocol(VoipDatagramProtocol):
    def __init__(self):
        super().__init__(
            SdpInfo("username", 5, "session", "version"),
            lambda call_info, rtcp_state: Mock(),
        )


def _call_info(local_rtp_port=None):
    source = get_sip_endpoint("testsource")
    destination = get_sip_endpoint("destination")
    return CallInfo(
        caller_endpoint=destination,
        local_endpoint=source,
        caller_rtp_port=12345,
        server_ip=destination.host,
        headers={
            "via": f"SIP/2.0/UDP {source.host}:{source.port}",
            "from": source.sip_header,
            "to": destination.sip_header,
            "contact": destination.sip_header,
            "call-id": "100",
            "cseq": "50 INVITE",
        },
        local_rtp_ip=source.host if local_rtp_port else None,
        local_rtp_port=local_rtp_port,
    )


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
