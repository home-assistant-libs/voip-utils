"""Call bridging implementation for intercom functionality."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, cast

from .sip import CallInfo, SipEndpoint
from .voip import VoipDatagramProtocol

if TYPE_CHECKING:
    from asyncio import BaseTransport, DatagramTransport

_LOGGER = logging.getLogger(__name__)

_RTCP_BYE = 203


def _rtcp_contains_bye(data: bytes) -> bool:
    """Return whether a (possibly compound) RTCP datagram contains a BYE packet.

    RTCP packets can be concatenated into a compound packet, so the BYE is not
    necessarily the first one. Walk each packet using its length field (in
    32-bit words, minus one) instead of only inspecting the first header.
    """
    offset = 0
    while offset + 4 <= len(data):
        packet_type = data[offset + 1]
        if packet_type == _RTCP_BYE:
            return True
        length_words = (data[offset + 2] << 8) | data[offset + 3]
        # length is in 32-bit words minus one, so a packet is always >= 4 bytes
        # and offset strictly advances; the loop bound guarantees termination.
        offset += (length_words + 1) * 4
    return False


def _negotiated_source(
    call: "BridgedCall | None", port_offset: int
) -> tuple[str, int] | None:
    """Return the SIP-negotiated remote (ip, port) for a dialog, or None.

    ``port_offset`` is 0 for RTP and 1 for the paired RTCP port. It becomes
    known once the call is answered (``on_call`` stores the answer's CallInfo).
    """
    if call is None or call.call_info is None:
        return None
    return (call.call_info.server_ip, call.call_info.caller_rtp_port + port_offset)


def _accept_and_latch(
    peer: tuple[str, int] | None,
    expected: tuple[str, int] | None,
    addr: tuple[str, int],
) -> tuple[bool, tuple[str, int] | None]:
    """Decide whether to accept a media packet and return the updated latch.

    When the negotiated ``expected`` source is known, require an exact match.
    Otherwise latch the first observed source and reject any other. This keeps
    a foreign host from injecting or redirecting media.
    """
    if expected is not None:
        return addr == expected, peer
    if peer is None:
        return True, addr
    return addr == peer, peer


@dataclass
class BridgedCall:
    """Information about one side of a bridged call."""

    call_info: CallInfo | None = None
    rtp_transport: DatagramTransport | None = None
    rtcp_transport: DatagramTransport | None = None
    rtp_port: int = 0
    remote_rtp_addr: tuple[str, int] | None = None
    remote_rtcp_addr: tuple[str, int] | None = None


@dataclass
class CallBridgeState:
    """State of a call bridge between two endpoints."""

    call_a: BridgedCall | None = None
    call_b: BridgedCall | None = None
    is_active: bool = False
    on_bridge_ended: Callable[[], None] | None = None


class BridgeRtpProtocol(asyncio.DatagramProtocol):
    """RTP protocol that forwards audio to the other side of the bridge."""

    def __init__(
        self,
        bridge_state: CallBridgeState,
        is_call_a: bool,
    ) -> None:
        """Set up bridged RTP handler."""
        self.bridge_state = bridge_state
        self.is_call_a = is_call_a
        self.transport: DatagramTransport | None = None
        # Source address latched from the first RTP packet of this dialog.
        self._peer: tuple[str, int] | None = None

    def connection_made(self, transport: BaseTransport) -> None:
        """Handle connection established."""
        dgram_transport = cast("DatagramTransport", transport)
        self.transport = dgram_transport
        if self.is_call_a and self.bridge_state.call_a is not None:
            self.bridge_state.call_a.rtp_transport = dgram_transport
        elif not self.is_call_a and self.bridge_state.call_b is not None:
            self.bridge_state.call_b.rtp_transport = dgram_transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Forward RTP packet to the other side of the bridge."""
        if not self.bridge_state.is_active:
            _LOGGER.debug("RTP received but bridge inactive, from %s", addr)
            return

        my_call = (
            self.bridge_state.call_a if self.is_call_a else self.bridge_state.call_b
        )

        # Only accept audio from the SIP-negotiated source; fall back to
        # latching the first packet when the call is not yet answered. This
        # stops another host from redirecting or injecting audio.
        accept, self._peer = _accept_and_latch(
            self._peer, _negotiated_source(my_call, 0), addr
        )
        if not accept:
            _LOGGER.debug("Dropping RTP from unexpected source %s", addr)
            return

        side = "A" if self.is_call_a else "B"

        # Store the remote address for this side and get the other call
        if my_call is not None:
            my_call.remote_rtp_addr = addr
        other_call = (
            self.bridge_state.call_b if self.is_call_a else self.bridge_state.call_a
        )

        # Forward to the other side if we know their address
        if (
            other_call is not None
            and other_call.rtp_transport is not None
            and other_call.remote_rtp_addr is not None
        ):
            _LOGGER.debug(
                "RTP: %s -> %s (%d bytes) from %s to %s",
                side,
                "B" if self.is_call_a else "A",
                len(data),
                addr,
                other_call.remote_rtp_addr,
            )
            other_call.rtp_transport.sendto(data, other_call.remote_rtp_addr)
        else:
            _LOGGER.debug(
                "RTP from %s: no destination yet (other_call=%s, transport=%s, addr=%s)",
                side,
                other_call is not None,
                other_call.rtp_transport is not None if other_call else None,
                other_call.remote_rtp_addr if other_call else None,
            )

    def connection_lost(self, exc: Exception | None) -> None:
        """Handle connection lost."""
        _LOGGER.debug("Bridge RTP connection lost: %s", exc)


class BridgeRtcpProtocol(asyncio.DatagramProtocol):
    """RTCP protocol for monitoring bridge call state."""

    def __init__(
        self,
        bridge_state: CallBridgeState,
        is_call_a: bool,
    ) -> None:
        """Set up bridged RTCP handler."""
        self.bridge_state = bridge_state
        self.is_call_a = is_call_a
        self.transport: DatagramTransport | None = None
        # Source address latched from the first RTCP packet of this dialog.
        self._peer: tuple[str, int] | None = None

    def connection_made(self, transport: BaseTransport) -> None:
        """Handle connection established."""
        dgram_transport = cast("DatagramTransport", transport)
        self.transport = dgram_transport
        if self.is_call_a and self.bridge_state.call_a is not None:
            self.bridge_state.call_a.rtcp_transport = dgram_transport
        elif not self.is_call_a and self.bridge_state.call_b is not None:
            self.bridge_state.call_b.rtcp_transport = dgram_transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Relay RTCP to the other dialog and end the bridge on BYE."""
        if not self.bridge_state.is_active:
            return

        my_call = (
            self.bridge_state.call_a if self.is_call_a else self.bridge_state.call_b
        )

        # Accept RTCP only from the negotiated peer (RTP port + 1), else latch
        # the first source, so a forged packet cannot tear down or hijack it.
        accept, self._peer = _accept_and_latch(
            self._peer, _negotiated_source(my_call, 1), addr
        )
        if not accept:
            _LOGGER.debug("Dropping RTCP from unexpected source %s", addr)
            return

        if my_call is not None:
            my_call.remote_rtcp_addr = addr
        other_call = (
            self.bridge_state.call_b if self.is_call_a else self.bridge_state.call_a
        )

        # Relay RTCP to the other side so it keeps receiving sender/receiver
        # reports and does not declare the media dead.
        if (
            other_call is not None
            and other_call.rtcp_transport is not None
            and other_call.remote_rtcp_addr is not None
        ):
            other_call.rtcp_transport.sendto(data, other_call.remote_rtcp_addr)

        if _rtcp_contains_bye(data):
            _LOGGER.debug("Received RTCP BYE on bridge")
            self.bridge_state.is_active = False
            if self.bridge_state.on_bridge_ended:
                self.bridge_state.on_bridge_ended()


class CallBridge:
    """Manages a bridged call between two VoIP endpoints (intercom)."""

    def __init__(
        self,
        sip_protocol: VoipDatagramProtocol,
        source_endpoint: SipEndpoint,
        local_ip: str,
    ) -> None:
        """Initialize the call bridge.

        Args:
            sip_protocol: The SIP protocol instance for making/receiving calls
            source_endpoint: The local SIP endpoint (Home Assistant)
            local_ip: Local IP address for RTP

        Raises:
            ValueError: If local_ip is not a valid IP address
        """
        # Validate IP address
        try:
            ipaddress.ip_address(local_ip)
        except ValueError as err:
            raise ValueError(f"Invalid local_ip address: {local_ip}") from err

        self.sip_protocol = sip_protocol
        self.source_endpoint = source_endpoint
        self.local_ip = local_ip
        self.bridge_state = CallBridgeState()

    def _create_rtp_socket_pair(
        self, max_attempts: int = 100
    ) -> tuple[socket.socket, socket.socket, int]:
        """Create a bound RTP/RTCP socket pair.

        Args:
            max_attempts: Maximum number of attempts to find a free port pair.

        Returns:
            Tuple of (rtp_socket, rtcp_socket, rtp_port).
            Sockets are kept open to prevent TOCTOU race conditions.

        Raises:
            OSError: If no free RTP/RTCP port pair found after max_attempts.
        """
        for _ in range(max_attempts):
            rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rtp_sock.setblocking(False)
            try:
                rtp_sock.bind((self.local_ip, 0))
            except OSError:
                rtp_sock.close()
                raise
            _, rtp_port = rtp_sock.getsockname()

            # Try to bind RTCP port (RTP port + 1)
            rtcp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rtcp_sock.setblocking(False)
            try:
                rtcp_sock.bind((self.local_ip, rtp_port + 1))
                return rtp_sock, rtcp_sock, rtp_port
            except OSError:
                # RTCP port not available, close both and retry
                rtp_sock.close()
                rtcp_sock.close()

        raise OSError("Failed to allocate RTP/RTCP port pair after max attempts")

    async def bridge_calls(
        self,
        destination_a: SipEndpoint,
        destination_b: SipEndpoint,
        on_bridge_ended: Callable[[], None] | None = None,
    ) -> bool:
        """Initiate a bridged call between two endpoints.

        This calls both endpoints and bridges their audio together,
        creating an intercom-like experience.

        Args:
            destination_a: First phone to call
            destination_b: Second phone to call
            on_bridge_ended: Callback when bridge ends

        Returns:
            True if bridge was established successfully
        """
        loop = asyncio.get_running_loop()
        self.bridge_state.on_bridge_ended = on_bridge_ended

        # Sockets that are bound but not yet owned by a transport. On failure
        # they must be closed here; end_bridge only closes transports.
        pending_socks: list[socket.socket] = []

        try:
            # Create bound socket pairs for both calls (prevents TOCTOU race)
            rtp_sock_a, rtcp_sock_a, rtp_port_a = self._create_rtp_socket_pair()
            pending_socks.extend((rtp_sock_a, rtcp_sock_a))
            rtp_sock_b, rtcp_sock_b, rtp_port_b = self._create_rtp_socket_pair()
            pending_socks.extend((rtp_sock_b, rtcp_sock_b))

            # Initialize call states
            self.bridge_state.call_a = BridgedCall(
                call_info=None,  # Will be set after call is made
                rtp_port=rtp_port_a,
            )
            self.bridge_state.call_b = BridgedCall(
                call_info=None,
                rtp_port=rtp_port_b,
            )

            # Create RTP/RTCP servers using the pre-bound sockets. Once a socket
            # is handed to a transport, the transport owns it (end_bridge closes
            # the transport), so drop it from the pending list.
            await loop.create_datagram_endpoint(
                lambda: BridgeRtpProtocol(self.bridge_state, is_call_a=True),
                sock=rtp_sock_a,
            )
            pending_socks.remove(rtp_sock_a)
            await loop.create_datagram_endpoint(
                lambda: BridgeRtcpProtocol(self.bridge_state, is_call_a=True),
                sock=rtcp_sock_a,
            )
            pending_socks.remove(rtcp_sock_a)
            await loop.create_datagram_endpoint(
                lambda: BridgeRtpProtocol(self.bridge_state, is_call_a=False),
                sock=rtp_sock_b,
            )
            pending_socks.remove(rtp_sock_b)
            await loop.create_datagram_endpoint(
                lambda: BridgeRtcpProtocol(self.bridge_state, is_call_a=False),
                sock=rtcp_sock_b,
            )
            pending_socks.remove(rtcp_sock_b)

            # Make outgoing calls to both endpoints
            call_info_a = self.sip_protocol.outgoing_call(
                source=self.source_endpoint,
                destination=destination_a,
                rtp_port=rtp_port_a,
            )
            self.bridge_state.call_a.call_info = call_info_a

            call_info_b = self.sip_protocol.outgoing_call(
                source=self.source_endpoint,
                destination=destination_b,
                rtp_port=rtp_port_b,
            )
            self.bridge_state.call_b.call_info = call_info_b

            # Mark bridge as active
            self.bridge_state.is_active = True
            _LOGGER.info(
                "Call bridge established between %s and %s",
                destination_a.host,
                destination_b.host,
            )
            return True

        except Exception:
            _LOGGER.exception("Failed to establish call bridge")
            for sock in pending_socks:
                sock.close()
            await self.end_bridge()
            return False

    async def end_bridge(self) -> None:
        """End the bridged call and clean up resources."""
        self.bridge_state.is_active = False

        # Hang up both calls
        if self.bridge_state.call_a and self.bridge_state.call_a.call_info:
            try:
                self.sip_protocol.hang_up(self.bridge_state.call_a.call_info)
            except Exception as err:
                _LOGGER.debug("Error hanging up call A: %s", err)

        if self.bridge_state.call_b and self.bridge_state.call_b.call_info:
            try:
                self.sip_protocol.hang_up(self.bridge_state.call_b.call_info)
            except Exception as err:
                _LOGGER.debug("Error hanging up call B: %s", err)

        # Close transports
        for call in [self.bridge_state.call_a, self.bridge_state.call_b]:
            if call:
                if call.rtp_transport:
                    call.rtp_transport.close()
                if call.rtcp_transport:
                    call.rtcp_transport.close()

        _LOGGER.info("Call bridge ended")
