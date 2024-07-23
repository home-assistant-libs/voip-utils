import asyncio
import logging
import os
import socket
from functools import partial
from pathlib import Path
from typing import Any, Callable, Optional, Set

from dotenv import load_dotenv

from voip_utils.call_phone import VoipCallDatagramProtocol
from voip_utils.sip import CallInfo, CallPhoneDatagramProtocol, SdpInfo, SipEndpoint
from voip_utils.voip import RtcpDatagramProtocol, RtcpState, RtpDatagramProtocol

_LOGGER = logging.getLogger(__name__)

load_dotenv()


def get_env_int(env_var: str, default_val: int) -> int:
    value = os.getenv(env_var)
    if value is None:
        return default_val
    try:
        return int(value)
    except ValueError:
        return default_val


CALL_SRC_USER = os.getenv("CALL_SRC_USER")
CALL_SRC_IP = os.getenv("CALL_SRC_IP", "127.0.0.1")
CALL_SRC_PORT = get_env_int("CALL_SRC_PORT", 5060)
CALL_VIA_IP = os.getenv("CALL_VIA_IP")
CALL_DEST_IP = os.getenv("CALL_DEST_IP", "127.0.0.1")
CALL_DEST_PORT = get_env_int("CALL_DEST_PORT", 5060)
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
        file_path = Path(__file__).parent / self.file_name
        self._audio_bytes: bytes = file_path.read_bytes()
        _LOGGER.debug("Created PreRecordMessageProtocol")

    def on_chunk(self, audio_bytes: bytes) -> None:
        """Handle raw audio chunk."""
        _LOGGER.debug("on_chunk")
        if self.transport is None:
            return

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
                "problem.pcm",
                call_info.opus_payload_type,
                loop=loop,
                rtcp_state=rtcp_state,
            ),
        ),
        local_addr=(CALL_SRC_IP, CALL_SRC_PORT),
    )

    await protocol.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
