"""Voice over IP (VoIP) implementation."""
import asyncio
import logging
import socket
from abc import ABC, abstractmethod
from functools import partial
from typing import Any, Callable, Set

from .rtp_audio import RtpOpusInput, RtpOpusOutput
from .sip import CallInfo, SdpInfo, SipDatagramProtocol

_LOGGER = logging.getLogger(__name__)

CallProtocolFactory = Callable[[CallInfo], asyncio.Protocol]


class VoipDatagramProtocol(SipDatagramProtocol):
    """UDP server for Voice over IP (VoIP)."""

    def __init__(
        self, sdp_info: SdpInfo, protocol_factory: CallProtocolFactory
    ) -> None:
        """Set up VoIP call handler."""
        super().__init__(sdp_info)
        self.protocol_factory = protocol_factory
        self._tasks: Set[asyncio.Future[Any]] = set()

    def is_valid_call(self, call_info: CallInfo) -> bool:
        """Filter calls."""
        return True

    def on_call(self, call_info: CallInfo):
        """Answer incoming calls and start RTP server on a random port."""
        if not self.is_valid_call(call_info):
            _LOGGER.warning("Call rejected: %s", call_info)
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        # Bind to a random UDP port
        sock.bind((call_info.server_ip, 0))
        rtp_ip, rtp_port = sock.getsockname()
        _LOGGER.debug(
            "Starting RTP server on ip=%s, port=%s",
            rtp_ip,
            rtp_port,
        )

        # Handle RTP packets in RTP server
        loop = asyncio.get_running_loop()
        task = asyncio.create_task(
            loop.create_datagram_endpoint(
                partial(self.protocol_factory, call_info),
                (rtp_ip, rtp_port),
            )
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.remove)

        # Tell caller to start sending/receiving RTP audio
        self.answer(call_info, rtp_port)


class RtpDatagramProtocol(asyncio.DatagramProtocol, ABC):
    """Handle RTP audio input/output for a VoIP call."""

    def __init__(
        self,
        rate: int = 16000,
        width: int = 2,
        channels: int = 1,
    ) -> None:
        """Set up RTP server."""
        # Desired format for input audio
        self.rate = rate
        self.width = width
        self.channels = channels

        self.transport = None
        self.addr = None

        self._audio_queue: "asyncio.Queue[bytes]" = asyncio.Queue()
        self._rtp_input = RtpOpusInput()
        self._rtp_output = RtpOpusOutput()

    def connection_made(self, transport):
        """Server is ready."""
        self.transport = transport

    def datagram_received(self, data, addr):
        """Decode RTP + OPUS into raw audio."""
        if self.addr is None:
            self.addr = addr

        # STT expects 16Khz mono with 16-bit samples
        audio_bytes = self._rtp_input.process_packet(
            data,
            self.rate,
            self.width,
            self.channels,
        )

        self.on_chunk(audio_bytes)

    @abstractmethod
    def on_chunk(self, audio_bytes: bytes) -> None:
        """Handle raw audio chunk."""

    async def send_audio(
        self,
        audio_bytes: bytes,
        rate: int,
        width: int,
        channels: int,
        addr: Any = None,
        sleep_ratio: float = 0.99,
        silence_before: float = 0.0,
    ) -> None:
        """Send audio from WAV file in chunks over RTP."""
        if self.transport is None:
            raise ValueError("Transport not set")

        addr = addr or self.addr
        if addr is None:
            raise ValueError("Destination address not set")

        # Pause before sending to allow time for user to pick up phone.
        await asyncio.sleep(silence_before)

        bytes_per_sample = width * channels
        bytes_per_frame = self._rtp_output.opus_frame_size * bytes_per_sample
        seconds_per_rtp = self._rtp_output.opus_frame_size / self._rtp_output.opus_rate

        sample_offset = 0
        samples_left = len(audio_bytes) // bytes_per_sample
        while samples_left > 0:
            bytes_offset = sample_offset * bytes_per_sample
            chunk = audio_bytes[bytes_offset : bytes_offset + bytes_per_frame]
            samples_in_chunk = len(chunk) // bytes_per_sample
            samples_left -= samples_in_chunk

            for rtp_bytes in self._rtp_output.process_audio(
                chunk,
                rate,
                width,
                channels,
                is_end=samples_left <= 0,
            ):
                # _LOGGER.debug(len(rtp_bytes))
                self.transport.sendto(rtp_bytes, addr)

                # Wait almost the full amount of time for the chunk.
                #
                # Sending too fast will cause the phone to skip chunks,
                # since it doesn't seem to have a very large buffer.
                #
                # Sending too slow will cause audio artifacts if there is
                # network jitter, which is why programs like GStreamer are
                # much better at this.
                await asyncio.sleep(seconds_per_rtp * sleep_ratio)

            sample_offset += samples_in_chunk
