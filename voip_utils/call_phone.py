import asyncio
import logging
from asyncio.transports import DatagramTransport
from functools import partial
from typing import Any, Callable, Optional, Set

from .sip import CallInfo, CallPhoneDatagramProtocol, SdpInfo, SipEndpoint
from .voip import RtcpDatagramProtocol, RtcpState

_LOGGER = logging.getLogger(__name__)

RATE = 16000
WIDTH = 2
CHANNELS = 1
RTP_AUDIO_SETTINGS = {
    "rate": RATE,
    "width": WIDTH,
    "channels": CHANNELS,
    "sleep_ratio": 0.99,
}

CallProtocolFactory = Callable[[CallInfo, RtcpState], asyncio.DatagramProtocol]


class VoipCallDatagramProtocol(CallPhoneDatagramProtocol):
    """UDP server for Voice over IP (VoIP)."""

    def __init__(
        self,
        sdp_info: SdpInfo | None,
        source_endpoint: SipEndpoint,
        dest_endpoint: SipEndpoint,
        rtp_port: int,
        call_protocol_factory: CallProtocolFactory,
    ) -> None:
        """Set up VoIP call handler."""
        super().__init__(sdp_info, source_endpoint, dest_endpoint, rtp_port)
        self.call_protocol_factory = call_protocol_factory
        self._tasks: Set[asyncio.Future[Any]] = set()
        self._rtp_transport: Optional[DatagramTransport] = None
        self._rtpc_transport: Optional[DatagramTransport] = None

    def on_call(self, call_info: CallInfo):
        """Answer incoming calls and start RTP server on specified port."""

        rtp_ip = self._source_endpoint.host

        _LOGGER.debug(
            "Starting RTP server on ip=%s, rtp_port=%s, rtcp_port=%s",
            rtp_ip,
            self._rtp_port,
            self._rtp_port + 1,
        )

        # Handle RTP packets in RTP server
        rtp_task = asyncio.create_task(
            self._create_rtp_server(
                self.call_protocol_factory, call_info, rtp_ip, self._rtp_port
            )
        )
        self._tasks.add(rtp_task)
        rtp_task.add_done_callback(self._tasks.remove)

        _LOGGER.debug("RTP server started")

    def call_cleanup(self):
        _LOGGER.debug("Closing RTP/C servers for end of call")
        if self._rtp_transport is not None:
            self._rtp_transport.close()
            self._rtp_transport = None
        if self._rtpc_transport is not None:
            self._rtpc_transport.close()
            self._rtpc_transport = None

    def end_call(self, task):
        """Callback for hanging up when call is ended."""
        self.hang_up()

    async def _create_rtp_server(
        self,
        protocol_factory: CallProtocolFactory,
        call_info: CallInfo,
        rtp_ip: str,
        rtp_port: int,
    ):
        # Shared state between RTP/RTCP servers
        rtcp_state = RtcpState()

        loop = asyncio.get_running_loop()

        # RTCP server
        self._rtpc_transport, _ = await loop.create_datagram_endpoint(
            lambda: RtcpDatagramProtocol(rtcp_state),
            (rtp_ip, rtp_port + 1),
        )

        # RTP server
        self._rtp_transport, _ = await loop.create_datagram_endpoint(
            partial(protocol_factory, call_info, rtcp_state),
            (rtp_ip, rtp_port),
        )
