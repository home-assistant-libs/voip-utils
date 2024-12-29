"""Voice over IP (VoIP) implementation."""
import asyncio
import logging
import socket
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import partial
from typing import Any, Callable, Optional, Set

from .const import OPUS_PAYLOAD_TYPE
from .rtp_audio import RtpOpusInput, RtpOpusOutput
from .sip import CallInfo, SdpInfo, SipDatagramProtocol

_LOGGER = logging.getLogger(__name__)
_RTCP_BYE = 203


@dataclass
class RtcpState:
    """State of a call according to RTCP packets received."""

    bye_callback: Optional[Callable[[], None]] = None


CallProtocolFactory = Callable[[CallInfo, RtcpState], asyncio.Protocol]


class VoipDatagramProtocol(SipDatagramProtocol):
    """UDP server for Voice over IP (VoIP)."""

    def __init__(
        self,
        sdp_info: SdpInfo,
        valid_protocol_factory: CallProtocolFactory,
        invalid_protocol_factory: Optional[CallProtocolFactory] = None,
    ) -> None:
        """Set up VoIP call handler."""
        super().__init__(sdp_info)
        self.valid_protocol_factory = valid_protocol_factory
        self.invalid_protocol_factory = invalid_protocol_factory
        self._tasks: Set[asyncio.Future[Any]] = set()

    def is_valid_call(self, call_info: CallInfo) -> bool:
        """Filter calls."""
        return True

    def on_call(self, call_info: CallInfo):
        """Answer incoming calls and start RTP server on a random port."""
        protocol_factory = (
            self.valid_protocol_factory
            if self.is_valid_call(call_info)
            else self.invalid_protocol_factory
        )
        if protocol_factory is None:
            _LOGGER.debug("Call rejected: %s", call_info)
            return

        # Find free RTP/RTCP ports
        rtp_ip = ""
        rtp_port = 0

        while True:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)

            # Bind to a random UDP port
            sock.bind(("", 0))
            rtp_ip, rtp_port = sock.getsockname()

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

        _LOGGER.debug(
            "Starting RTP server on ip=%s, rtp_port=%s, rtcp_port=%s",
            rtp_ip,
            rtp_port,
            rtp_port + 1,
        )

        # Handle RTP packets in RTP server
        rtp_task = asyncio.create_task(
            self._create_rtp_server(protocol_factory, call_info, rtp_ip, rtp_port)
        )
        self._tasks.add(rtp_task)
        rtp_task.add_done_callback(self._tasks.remove)

        # Tell caller to start sending/receiving RTP audio
        self.answer(call_info, rtp_port)

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


class RtpDatagramProtocol(asyncio.DatagramProtocol, ABC):
    """Handle RTP audio input/output for a VoIP call."""

    def __init__(
        self,
        rate: int = 16000,
        width: int = 2,
        channels: int = 1,
        opus_payload_type: int = OPUS_PAYLOAD_TYPE,
        rtcp_state: Optional[RtcpState] = None,
    ) -> None:
        """Set up RTP server."""
        self.rtcp_state = rtcp_state

        if self.rtcp_state is not None:
            # Automatically disconnect when BYE is received over RTCP
            self.rtcp_state.bye_callback = self.disconnect

        # Desired format for input audio
        self.rate = rate
        self.width = width
        self.channels = channels

        self.transport = None
        self.addr = None

        self._audio_queue: "asyncio.Queue[bytes]" = asyncio.Queue()
        self._rtp_input = RtpOpusInput(opus_payload_type=opus_payload_type)
        self._rtp_output = RtpOpusOutput(opus_payload_type=opus_payload_type)
        self._is_connected: bool = False

    def disconnect(self):
        self._is_connected = False
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def connection_made(self, transport):
        """Server is ready."""
        self.transport = transport
        self._is_connected = True

    def datagram_received(self, data, addr):
        """Decode RTP + OPUS into raw audio."""
        if not self._is_connected:
            return

        self.addr = addr

        try:
            # STT expects 16Khz mono with 16-bit samples
            audio_bytes = self._rtp_input.process_packet(
                data,
                self.rate,
                self.width,
                self.channels,
            )

            self.on_chunk(audio_bytes)
        except Exception as err:
            self.disconnect()
            raise err

    @abstractmethod
    def on_chunk(self, audio_bytes: bytes) -> None:
        """Handle raw audio chunk."""

    def send_audio(
        self,
        audio_bytes: bytes,
        rate: int,
        width: int,
        channels: int,
        addr: Any = None,
        sleep_ratio: float = 1.0,
        silence_before: float = 0.0,
    ) -> None:
        """Send audio from WAV file in chunks over RTP."""
        if not self._is_connected:
            _LOGGER.debug("Not connected, can't send audio")
            return

        addr = addr or self.addr
        if addr is None:
            _LOGGER.debug("No destination address, can't send audio")
            raise ValueError("Destination address not set")

        bytes_per_sample = width * channels
        bytes_per_frame = self._rtp_output.opus_frame_size * bytes_per_sample

        # Generate all RTP packets up front
        sample_offset = 0
        samples_left = len(audio_bytes) // bytes_per_sample
        rtp_packets: list[bytes] = []
        while samples_left > 0:
            _LOGGER.debug("Preparing audio chunk to send")
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
                rtp_packets.append(rtp_bytes)

            sample_offset += samples_in_chunk

        # Pause before sending to allow time for user to pick up phone.
        _LOGGER.debug("Pause before sending")
        time.sleep(silence_before)

        # Send RTP in a steady stream, delaying between each packet to simulate real-time audio
        seconds_per_rtp = self._rtp_output.opus_frame_size / self._rtp_output.opus_rate
        for rtp_bytes in rtp_packets:
            if not self._is_connected:
                break

            if self.transport is not None:
                self.transport.sendto(rtp_bytes, addr)

            # Wait almost the full amount of time for the chunk.
            #
            # Sending too fast will cause the phone to skip chunks,
            # since it doesn't seem to have a very large buffer.
            #
            # Sending too slow will cause audio artifacts if there is
            # network jitter, which is why programs like GStreamer are
            # much better at this.
            time.sleep(seconds_per_rtp * sleep_ratio)


class RtcpDatagramProtocol(asyncio.DatagramProtocol, ABC):
    """UDP server for the Real-time Transport Control Protocol (RTCP)."""

    def __init__(self, state: RtcpState) -> None:
        """Set up RTCP server."""
        self.transport = None
        self.state = state
        self._is_connected = False

    def connection_made(self, transport):
        """Server ready."""
        self.transport = transport
        self._is_connected = True

    def disconnect(self):
        self._is_connected = False
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def datagram_received(self, data: bytes, addr):
        """Handle INVITE SIP messages."""
        if not self._is_connected:
            return

        try:
            if len(data) < 8:
                raise ValueError("RTCP packet is too small")

            # See: https://en.wikipedia.org/wiki/RTP_Control_Protocol#Packet_header
            _flags, packet_type, _packet_length, _ssrc = struct.unpack(
                ">BBHL", data[:8]
            )

            if packet_type == _RTCP_BYE:
                _LOGGER.debug("Received BYE message via RTCP from %s", addr)
                self.disconnect()

                if self.state.bye_callback is not None:
                    self.state.bye_callback()

        except Exception:
            _LOGGER.exception("Unexpected error handling RTCP packet")
