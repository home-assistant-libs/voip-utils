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


@dataclass
class AudioOutputChunk:
    data: bytes
    rate: int
    width: int
    channels: int
    is_end: bool = False


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
        self._rtp_transport: Optional[asyncio.BaseTransport] = None
        self._rtcp_transport: Optional[asyncio.BaseTransport] = None

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

        rtp_ip = ""
        if call_info.local_rtp_port is None:
            # Find free RTP/RTCP ports
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

        else:
            rtp_ip = call_info.local_rtp_ip if call_info.local_rtp_ip else ""
            rtp_port = call_info.local_rtp_port

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

    def on_hangup(self, call_info: CallInfo):
        """Handle the end of a call."""
        _LOGGER.debug("Clean up RTP/RTCP resources on hangup")
        if self._rtcp_transport:
            _LOGGER.debug("Shutting down RTCP transport")
            self._rtcp_transport.close()
            self._rtcp_transport = None
        if self._rtp_transport:
            _LOGGER.debug("Shutting down RTP transport")
            self._rtp_transport.close()
            self._rtp_transport = None

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
        self._rtcp_transport, _ = await loop.create_datagram_endpoint(
            lambda: RtcpDatagramProtocol(rtcp_state),
            (rtp_ip, rtp_port + 1),
        )

        # RTP server
        self._rtp_transport, _ = await loop.create_datagram_endpoint(
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
        create_task: Callable[[Coroutine], asyncio.Task] | None = None,
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
        self._create_task = create_task or asyncio.create_task
        self._sender_task = None
        self._output_audio_queue: asyncio.Queue = asyncio.Queue()
        self._rtp_queue: asyncio.Queue = asyncio.Queue()
        self._is_connected: bool = False

    def disconnect(self):
        self._is_connected = False
        if self.transport is not None:
            _LOGGER.debug("Closing RTP transport")
            self.transport.close()
            self.transport = None

    def connection_made(self, transport):
        """Server is ready."""
        self.transport = transport
        self._is_connected = True
        if self._sender_task is None:
            _LOGGER.debug("Starting output loop")
            self._sender_task = self._create_task(self._output_loop())
            self._sender_task.add_done_callback(self._output_finished)

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

        # Add silence before actual audio to allow time for the user to pick up the phone.
        silence_bytes = bytes(int(rate * silence_before) * width * channels)
        audio_bytes = silence_bytes + audio_bytes
        _LOGGER.debug("Adding %s bytes of audio to output queue", len(audio_bytes))

        self._output_audio_queue.put_nowait(
            AudioOutputChunk(audio_bytes, rate, width, channels, False)
        )

    def make_silence_frame(self):
        """Make a frame of silence to keep RTP alive."""
        return self._rtp_output.silence_frame()

    async def _output_loop(self) -> None:
        """Handles scheduling audio output."""
        loop = asyncio.get_running_loop()
        next_send = loop.time()
        while self._is_connected:
            try:
                audio = self._output_audio_queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            else:
                _LOGGER.debug("Got audio from output queue")
                for rtp_bytes in self._rtp_output.process_audio(
                    audio.data, audio.rate, audio.width, audio.channels, audio.is_end
                ):
                    self._rtp_queue.put_nowait(rtp_bytes)

            try:
                frame = self._rtp_queue.get_nowait()
            except asyncio.QueueEmpty:
                frame = self.make_silence_frame()

            if self.addr is not None and self.transport is not None:
                self.transport.sendto(frame, self.addr)

            # Maintain a fixed 20 ms RTP clock.
            next_send += 0.020
            await asyncio.sleep(max(0, next_send - loop.time()))

    def _output_finished(self, task: asyncio.Task) -> None:
        _LOGGER.debug("Clearing sender task")
        self._sender_task = None


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
