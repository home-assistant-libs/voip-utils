import asyncio
import logging
import os
import socket
from functools import partial
from pathlib import Path
from typing import Any, Callable, Optional, Set

from dotenv import load_dotenv

from .sip import CallInfo, CallPhoneDatagramProtocol, SdpInfo, SipEndpoint
from .voip import RtcpDatagramProtocol, RtcpState, RtpDatagramProtocol

_LOGGER = logging.getLogger(__name__)

load_dotenv()

CALL_SRC_USER = os.getenv("CALL_SRC_USER")
CALL_SRC_IP = os.getenv("CALL_SRC_IP")
CALL_SRC_PORT = int(os.getenv("CALL_SRC_PORT"))
CALL_VIA_IP = os.getenv("CALL_VIA_IP")
CALL_DEST_IP = os.getenv("CALL_DEST_IP")
CALL_DEST_PORT = int(os.getenv("CALL_DEST_PORT"))
CALL_DEST_USER = os.getenv("CALL_DEST_USER")


RATE = 16000
WIDTH = 2
CHANNELS = 1
RTP_AUDIO_SETTINGS = {
    "rate": RATE,
    "width": WIDTH,
    "channels": CHANNELS,
    "sleep_ratio": 0.99,
}

CallProtocolFactory = Callable[[CallInfo, RtcpState], asyncio.Protocol]


class VoipCallDatagramProtocol(CallPhoneDatagramProtocol):
    """UDP server for Voice over IP (VoIP)."""

    def __init__(
        self,
        sdp_info: SdpInfo,
        source_endpoint: SipEndpoint,
        dest_endpoint: SipEndpoint,
        rtp_port: int,
        call_protocol_factory: CallProtocolFactory,
    ) -> None:
        """Set up VoIP call handler."""
        super().__init__(sdp_info, source_endpoint, dest_endpoint, rtp_port)
        self.call_protocol_factory = call_protocol_factory
        self._tasks: Set[asyncio.Future[Any]] = set()

    def on_call(self, call_info: CallInfo):
        """Answer incoming calls and start RTP server on a random port."""

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
        await loop.create_datagram_endpoint(
            lambda: RtcpDatagramProtocol(rtcp_state),
            (rtp_ip, rtp_port + 1),
        )

        # RTP server
        await loop.create_datagram_endpoint(
            partial(protocol_factory, call_info, rtcp_state),
            (rtp_ip, rtp_port),
        )


class PreRecordMessageProtocol(RtpDatagramProtocol):
    """Plays a pre-recorded message on a loop."""

    def __init__(
        self,
        file_name: str,
        opus_payload_type: int,
        message_delay: float = 1.0,
        loop_delay: float = 2.0,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        rtcp_state: RtcpState | None = None,
    ) -> None:
        """Set up RTP server."""
        super().__init__(
            rate=RATE,
            width=WIDTH,
            channels=CHANNELS,
            opus_payload_type=opus_payload_type,
            rtcp_state=rtcp_state,
        )
        self.loop = loop
        self.file_name = file_name
        self.message_delay = message_delay
        self.loop_delay = loop_delay
        self._audio_task: asyncio.Task | None = None
        self._audio_bytes: bytes | None = None
        _LOGGER.debug("Created PreRecordMessageProtocol")

    def on_chunk(self, audio_bytes: bytes) -> None:
        """Handle raw audio chunk."""
        _LOGGER.debug("on_chunk")
        if self.transport is None:
            return

        if self._audio_bytes is None:
            # 16Khz, 16-bit mono audio message
            file_path = Path(__file__).parent / self.file_name
            self._audio_bytes = file_path.read_bytes()

        if self._audio_task is None:
            self._audio_task = self.loop.create_task(
                self._play_message(),
                name="voip_not_connected",
            )

    async def _play_message(self) -> None:
        _LOGGER.debug("_play_message")
        self.send_audio(
            self._audio_bytes,
            self.rate,
            self.width,
            self.channels,
            self.addr,
            silence_before=self.message_delay,
        )

        await asyncio.sleep(self.loop_delay)

        # Allow message to play again - Only play once for testing
        # self._audio_task = None


async def main() -> None:
    logging.basicConfig(level=logging.DEBUG)

    loop = asyncio.get_event_loop()
    source = SipEndpoint(
        username=CALL_SRC_USER, host=CALL_SRC_IP, port=CALL_SRC_PORT, description=None
    )
    destination = SipEndpoint(
        username=CALL_DEST_USER,
        host=CALL_DEST_IP,
        port=CALL_DEST_PORT,
        description=None,
    )

    # Find free RTP/RTCP ports
    rtp_port = 0

    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        # Bind to a random UDP port
        sock.bind(("", 0))
        _, rtp_port = sock.getsockname()

        # Close socket to free port for re-use
        sock.close()

        # Check that the next port up is available for RTCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("", rtp_port + 1))

            # Will be opened again below
            sock.close()

            # Found our ports
            break
        except OSError:
            # RTCP port is taken
            pass

    _, protocol = await loop.create_datagram_endpoint(
        lambda: VoipCallDatagramProtocol(
            None,
            source,
            destination,
            rtp_port,
            lambda call_info, rtcp_state: PreRecordMessageProtocol(
                "problem.pcm", 96, loop=loop, rtcp_state=rtcp_state
            ),
        ),
        local_addr=(CALL_SRC_IP, CALL_SRC_PORT),
    )

    await protocol.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
