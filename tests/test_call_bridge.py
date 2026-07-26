"""Tests for call_bridge module."""

from unittest.mock import MagicMock, patch

import pytest

from voip_utils.call_bridge import (
    BridgedCall,
    BridgeRtcpProtocol,
    BridgeRtpProtocol,
    CallBridge,
    CallBridgeState,
    _rtcp_contains_bye,
)
from voip_utils.sip import get_sip_endpoint


class TestBridgedCall:
    """Tests for BridgedCall dataclass."""

    def test_bridged_call_defaults(self):
        """Test BridgedCall default values."""
        call = BridgedCall()
        assert call.call_info is None
        assert call.rtp_transport is None
        assert call.rtcp_transport is None
        assert call.rtp_port == 0
        assert call.remote_rtp_addr is None

    def test_bridged_call_with_values(self):
        """Test BridgedCall with custom values."""
        mock_transport = MagicMock()
        call = BridgedCall(
            rtp_transport=mock_transport,
            rtp_port=16000,
            remote_rtp_addr=("192.168.1.100", 16000),
        )
        assert call.rtp_transport == mock_transport
        assert call.rtp_port == 16000
        assert call.remote_rtp_addr == ("192.168.1.100", 16000)


class TestCallBridgeState:
    """Tests for CallBridgeState dataclass."""

    def test_state_defaults(self):
        """Test CallBridgeState default values."""
        state = CallBridgeState()
        assert state.call_a is None
        assert state.call_b is None
        assert state.is_active is False
        assert state.on_bridge_ended is None

    def test_state_with_callback(self):
        """Test CallBridgeState with callback."""
        callback = MagicMock()
        state = CallBridgeState(on_bridge_ended=callback)
        assert state.on_bridge_ended == callback


class TestBridgeRtpProtocol:
    """Tests for BridgeRtpProtocol."""

    def test_connection_made_call_a(self):
        """Test connection_made for call A."""
        state = CallBridgeState()
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        protocol = BridgeRtpProtocol(state, is_call_a=True)
        mock_transport = MagicMock()

        protocol.connection_made(mock_transport)

        assert protocol.transport == mock_transport
        assert state.call_a.rtp_transport == mock_transport

    def test_connection_made_call_b(self):
        """Test connection_made for call B."""
        state = CallBridgeState()
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        protocol = BridgeRtpProtocol(state, is_call_a=False)
        mock_transport = MagicMock()

        protocol.connection_made(mock_transport)

        assert protocol.transport == mock_transport
        assert state.call_b.rtp_transport == mock_transport

    def test_connection_made_with_none_call(self):
        """Test connection_made when call is None (should not crash)."""
        state = CallBridgeState()
        # call_a and call_b are None

        protocol = BridgeRtpProtocol(state, is_call_a=True)
        mock_transport = MagicMock()

        # Should not raise
        protocol.connection_made(mock_transport)
        assert protocol.transport == mock_transport

    def test_datagram_received_inactive(self):
        """Test datagram_received when bridge is inactive."""
        state = CallBridgeState()
        state.is_active = False
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        protocol = BridgeRtpProtocol(state, is_call_a=True)

        # Should return early without processing
        protocol.datagram_received(b"test_data", ("192.168.1.100", 16000))

        # Address should not be stored since inactive
        assert state.call_a.remote_rtp_addr is None

    def test_datagram_received_forwards_to_other(self):
        """Test datagram_received forwards to other call."""
        state = CallBridgeState()
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        # Set up call_b with transport and address
        mock_transport_b = MagicMock()
        state.call_b.rtp_transport = mock_transport_b
        state.call_b.remote_rtp_addr = ("192.168.1.101", 16002)

        protocol = BridgeRtpProtocol(state, is_call_a=True)

        # Receive data on call A
        test_data = b"rtp_packet_data"
        protocol.datagram_received(test_data, ("192.168.1.100", 16000))

        # Should forward to call B
        mock_transport_b.sendto.assert_called_once_with(
            test_data, ("192.168.1.101", 16002)
        )
        # Should store remote address for call A
        assert state.call_a.remote_rtp_addr == ("192.168.1.100", 16000)

    def test_datagram_received_no_forward_without_other_address(self):
        """Test datagram_received doesn't forward if other side has no address."""
        state = CallBridgeState()
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        # call_b has transport but no remote address
        mock_transport_b = MagicMock()
        state.call_b.rtp_transport = mock_transport_b
        state.call_b.remote_rtp_addr = None

        protocol = BridgeRtpProtocol(state, is_call_a=True)

        protocol.datagram_received(b"test_data", ("192.168.1.100", 16000))

        # Should not forward
        mock_transport_b.sendto.assert_not_called()

    def test_datagram_received_drops_foreign_source(self):
        """Test RTP from a source other than the latched peer is dropped."""
        state = CallBridgeState()
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        mock_transport_b = MagicMock()
        state.call_b.rtp_transport = mock_transport_b
        state.call_b.remote_rtp_addr = ("192.168.1.101", 16002)

        protocol = BridgeRtpProtocol(state, is_call_a=True)

        # First packet latches the peer and is forwarded.
        protocol.datagram_received(b"one", ("192.168.1.100", 16000))
        # A packet from a different source is dropped.
        protocol.datagram_received(b"two", ("10.0.0.9", 40000))

        assert mock_transport_b.sendto.call_count == 1
        assert state.call_a.remote_rtp_addr == ("192.168.1.100", 16000)

    def test_datagram_received_forwards_from_b_leg(self):
        """Test the B leg stores on call_b and forwards to call A (mirror)."""
        state = CallBridgeState()
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        mock_transport_a = MagicMock()
        state.call_a.rtp_transport = mock_transport_a
        state.call_a.remote_rtp_addr = ("192.168.1.100", 16000)

        protocol = BridgeRtpProtocol(state, is_call_a=False)
        protocol.datagram_received(b"pkt", ("192.168.1.101", 16002))

        mock_transport_a.sendto.assert_called_once_with(
            b"pkt", ("192.168.1.100", 16000)
        )
        assert state.call_b.remote_rtp_addr == ("192.168.1.101", 16002)

    def test_datagram_received_validates_negotiated_source(self):
        """Test RTP is accepted only from the negotiated source once answered."""
        state = CallBridgeState()
        state.is_active = True
        state.call_a = BridgedCall(
            rtp_port=16000,
            call_info=MagicMock(server_ip="192.168.1.100", caller_rtp_port=16000),
        )
        state.call_b = BridgedCall(rtp_port=16002)
        mock_transport_b = MagicMock()
        state.call_b.rtp_transport = mock_transport_b
        state.call_b.remote_rtp_addr = ("192.168.1.101", 16002)

        protocol = BridgeRtpProtocol(state, is_call_a=True)

        # A packet from a spoofed source (not the negotiated one) is dropped,
        # even though it arrives first.
        protocol.datagram_received(b"spoof", ("10.0.0.9", 40000))
        mock_transport_b.sendto.assert_not_called()

        # A packet from the negotiated source is forwarded.
        protocol.datagram_received(b"real", ("192.168.1.100", 16000))
        mock_transport_b.sendto.assert_called_once_with(
            b"real", ("192.168.1.101", 16002)
        )


class TestBridgeRtcpProtocol:
    """Tests for BridgeRtcpProtocol."""

    def test_datagram_received_bye_packet(self):
        """Test RTCP BYE packet triggers callback."""
        callback = MagicMock()
        state = CallBridgeState(on_bridge_ended=callback)
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        protocol = BridgeRtcpProtocol(state, is_call_a=True)

        # RTCP BYE packet (packet_type = 203 at byte 1)
        bye_packet = bytes([0x80, 203, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])

        protocol.datagram_received(bye_packet, ("192.168.1.100", 16001))

        assert state.is_active is False
        callback.assert_called_once()

    def test_datagram_received_non_bye_packet(self):
        """Test non-BYE RTCP packet doesn't trigger callback."""
        callback = MagicMock()
        state = CallBridgeState(on_bridge_ended=callback)
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)

        protocol = BridgeRtcpProtocol(state, is_call_a=True)

        # RTCP SR packet (packet_type = 200)
        sr_packet = bytes([0x80, 200, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])

        protocol.datagram_received(sr_packet, ("192.168.1.100", 16001))

        assert state.is_active is True
        callback.assert_not_called()

    def test_datagram_received_short_packet(self):
        """Test short packet is ignored."""
        callback = MagicMock()
        state = CallBridgeState(on_bridge_ended=callback)
        state.is_active = True

        protocol = BridgeRtcpProtocol(state, is_call_a=True)

        # Too short packet (less than 8 bytes)
        short_packet = bytes([0x80, 203, 0x00])

        protocol.datagram_received(short_packet, ("192.168.1.100", 16001))

        assert state.is_active is True
        callback.assert_not_called()

    def test_datagram_received_relays_to_other(self):
        """Test RTCP is relayed to the other leg."""
        state = CallBridgeState()
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        mock_rtcp_b = MagicMock()
        state.call_b.rtcp_transport = mock_rtcp_b
        state.call_b.remote_rtcp_addr = ("192.168.1.101", 16003)

        protocol = BridgeRtcpProtocol(state, is_call_a=True)
        sr_packet = bytes([0x80, 200, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])

        protocol.datagram_received(sr_packet, ("192.168.1.100", 16001))

        mock_rtcp_b.sendto.assert_called_once_with(sr_packet, ("192.168.1.101", 16003))
        assert state.call_a.remote_rtcp_addr == ("192.168.1.100", 16001)

    def test_datagram_received_compound_bye(self):
        """Test a BYE that is not first in a compound RTCP packet is detected."""
        callback = MagicMock()
        state = CallBridgeState(on_bridge_ended=callback)
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)

        protocol = BridgeRtcpProtocol(state, is_call_a=True)
        sr_packet = bytes([0x80, 200, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])
        bye_packet = bytes([0x80, 203, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])

        protocol.datagram_received(sr_packet + bye_packet, ("192.168.1.100", 16001))

        assert state.is_active is False
        callback.assert_called_once()

    def test_datagram_received_drops_foreign_bye(self):
        """Test a forged BYE from an unexpected source does not end the bridge."""
        callback = MagicMock()
        state = CallBridgeState(on_bridge_ended=callback)
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)

        protocol = BridgeRtcpProtocol(state, is_call_a=True)
        sr_packet = bytes([0x80, 200, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])
        bye_packet = bytes([0x80, 203, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])

        # Latch the peer, then a BYE from a different source must be ignored.
        protocol.datagram_received(sr_packet, ("192.168.1.100", 16001))
        protocol.datagram_received(bye_packet, ("10.0.0.9", 40000))

        assert state.is_active is True
        callback.assert_not_called()

    def test_datagram_received_relays_from_b_leg(self):
        """Test the B leg relays RTCP to call A (mirror direction)."""
        state = CallBridgeState()
        state.is_active = True
        state.call_a = BridgedCall(rtp_port=16000)
        state.call_b = BridgedCall(rtp_port=16002)

        mock_rtcp_a = MagicMock()
        state.call_a.rtcp_transport = mock_rtcp_a
        state.call_a.remote_rtcp_addr = ("192.168.1.100", 16001)

        protocol = BridgeRtcpProtocol(state, is_call_a=False)
        sr_packet = bytes([0x80, 200, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])
        protocol.datagram_received(sr_packet, ("192.168.1.101", 16003))

        mock_rtcp_a.sendto.assert_called_once_with(sr_packet, ("192.168.1.100", 16001))
        assert state.call_b.remote_rtcp_addr == ("192.168.1.101", 16003)


def test_rtcp_contains_bye():
    """Test compound RTCP BYE detection helper."""
    sr_packet = bytes([0x80, 200, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])
    bye_packet = bytes([0x81, 203, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02])

    assert _rtcp_contains_bye(bye_packet) is True
    assert _rtcp_contains_bye(sr_packet + bye_packet) is True
    assert _rtcp_contains_bye(sr_packet) is False
    assert _rtcp_contains_bye(b"") is False
    assert _rtcp_contains_bye(b"\x80\x00") is False


class TestCallBridge:
    """Tests for CallBridge class."""

    def test_init(self):
        """Test CallBridge initialization."""
        mock_protocol = MagicMock()
        source = get_sip_endpoint(host="192.168.1.10", port=5060, username="ha")

        bridge = CallBridge(
            sip_protocol=mock_protocol,
            source_endpoint=source,
            local_ip="192.168.1.10",
        )

        assert bridge.sip_protocol == mock_protocol
        assert bridge.source_endpoint == source
        assert bridge.local_ip == "192.168.1.10"
        assert bridge.bridge_state.is_active is False

    def test_init_invalid_ip_raises(self):
        """Test CallBridge raises ValueError for invalid IP."""
        mock_protocol = MagicMock()
        source = get_sip_endpoint(host="192.168.1.10", port=5060)

        with pytest.raises(ValueError, match="Invalid local_ip address"):
            CallBridge(
                sip_protocol=mock_protocol,
                source_endpoint=source,
                local_ip="not-an-ip",
            )

    def test_init_invalid_ip_hostname_raises(self):
        """Test CallBridge raises ValueError for hostname instead of IP."""
        mock_protocol = MagicMock()
        source = get_sip_endpoint(host="192.168.1.10", port=5060)

        with pytest.raises(ValueError, match="Invalid local_ip address"):
            CallBridge(
                sip_protocol=mock_protocol,
                source_endpoint=source,
                local_ip="localhost",
            )

    def test_init_accepts_ipv6(self):
        """Test CallBridge accepts valid IPv6 address."""
        mock_protocol = MagicMock()
        source = get_sip_endpoint(host="192.168.1.10", port=5060)

        bridge = CallBridge(
            sip_protocol=mock_protocol,
            source_endpoint=source,
            local_ip="::1",
        )

        assert bridge.local_ip == "::1"

    def test_create_rtp_socket_pair(self):
        """Test _create_rtp_socket_pair returns bound sockets and port."""
        mock_protocol = MagicMock()
        source = get_sip_endpoint(host="127.0.0.1", port=5060)

        bridge = CallBridge(
            sip_protocol=mock_protocol,
            source_endpoint=source,
            local_ip="127.0.0.1",
        )

        rtp_sock, rtcp_sock, rtp_port = bridge._create_rtp_socket_pair()

        try:
            assert rtp_sock is not None
            assert rtcp_sock is not None
            assert isinstance(rtp_port, int)
            assert rtp_port > 0

            # Verify sockets are bound
            rtp_addr = rtp_sock.getsockname()
            rtcp_addr = rtcp_sock.getsockname()

            assert rtp_addr[1] == rtp_port
            assert rtcp_addr[1] == rtp_port + 1
        finally:
            rtp_sock.close()
            rtcp_sock.close()

    def test_create_rtp_socket_pair_returns_different_ports(self):
        """Test consecutive calls return different port pairs."""
        mock_protocol = MagicMock()
        source = get_sip_endpoint(host="127.0.0.1", port=5060)

        bridge = CallBridge(
            sip_protocol=mock_protocol,
            source_endpoint=source,
            local_ip="127.0.0.1",
        )

        rtp_sock_a, rtcp_sock_a, port_a = bridge._create_rtp_socket_pair()
        rtp_sock_b, rtcp_sock_b, port_b = bridge._create_rtp_socket_pair()

        try:
            assert port_a != port_b
        finally:
            rtp_sock_a.close()
            rtcp_sock_a.close()
            rtp_sock_b.close()
            rtcp_sock_b.close()

    def test_create_rtp_socket_pair_raises_after_max_attempts(self):
        """Test that OSError is raised after max_attempts exceeded."""
        mock_protocol = MagicMock()
        source = get_sip_endpoint(host="127.0.0.1", port=5060)

        bridge = CallBridge(
            sip_protocol=mock_protocol,
            source_endpoint=source,
            local_ip="127.0.0.1",
        )

        # With max_attempts=0, should raise immediately
        with pytest.raises(OSError, match="Failed to allocate RTP/RTCP port pair"):
            bridge._create_rtp_socket_pair(max_attempts=0)

    @pytest.mark.asyncio
    async def test_end_bridge_cleans_up(self):
        """Test end_bridge cleans up resources."""
        mock_protocol = MagicMock()
        source = get_sip_endpoint(host="192.168.1.10", port=5060)

        bridge = CallBridge(
            sip_protocol=mock_protocol,
            source_endpoint=source,
            local_ip="192.168.1.10",
        )

        # Set up mock calls
        mock_transport_a = MagicMock()
        mock_transport_b = MagicMock()
        mock_call_info_a = MagicMock()
        mock_call_info_b = MagicMock()

        bridge.bridge_state.call_a = BridgedCall(
            call_info=mock_call_info_a,
            rtp_transport=mock_transport_a,
        )
        bridge.bridge_state.call_b = BridgedCall(
            call_info=mock_call_info_b,
            rtp_transport=mock_transport_b,
        )
        bridge.bridge_state.is_active = True

        await bridge.end_bridge()

        assert bridge.bridge_state.is_active is False
        mock_protocol.hang_up.assert_any_call(mock_call_info_a)
        mock_protocol.hang_up.assert_any_call(mock_call_info_b)
        mock_transport_a.close.assert_called_once()
        mock_transport_b.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_end_bridge_sends_bye_before_closing_transports(self):
        """Test end_bridge hangs up (sends BYE) before closing, and closes RTCP."""
        manager = MagicMock()
        mock_protocol = MagicMock()
        mock_protocol.hang_up = manager.hang_up
        source = get_sip_endpoint(host="127.0.0.1", port=5060)

        bridge = CallBridge(
            sip_protocol=mock_protocol,
            source_endpoint=source,
            local_ip="127.0.0.1",
        )

        rtp_a = MagicMock()
        rtcp_a = MagicMock()
        rtp_a.close = manager.rtp_a_close
        rtcp_a.close = manager.rtcp_a_close
        bridge.bridge_state.call_a = BridgedCall(
            call_info=MagicMock(), rtp_transport=rtp_a, rtcp_transport=rtcp_a
        )
        bridge.bridge_state.call_b = BridgedCall(
            call_info=MagicMock(),
            rtp_transport=MagicMock(),
            rtcp_transport=MagicMock(),
        )
        bridge.bridge_state.is_active = True

        await bridge.end_bridge()

        # The RTCP transport is closed too (not just RTP).
        rtcp_a.close.assert_called_once()
        # The BYE (hang_up) is sent before the transport is closed.
        names = [c[0] for c in manager.mock_calls]
        assert names.index("hang_up") < names.index("rtp_a_close")

    @pytest.mark.asyncio
    async def test_bridge_calls_success(self):
        """Test bridge_calls sets up both legs and calls both endpoints."""
        mock_protocol = MagicMock()
        mock_protocol.outgoing_call.side_effect = [MagicMock(), MagicMock()]
        source = get_sip_endpoint(host="127.0.0.1", port=5060)
        destination_a = get_sip_endpoint(host="192.168.1.100", port=5060)
        destination_b = get_sip_endpoint(host="192.168.1.101", port=5060)

        bridge = CallBridge(
            sip_protocol=mock_protocol,
            source_endpoint=source,
            local_ip="127.0.0.1",
        )

        try:
            result = await bridge.bridge_calls(
                destination_a=destination_a, destination_b=destination_b
            )

            assert result is True
            assert bridge.bridge_state.is_active is True
            assert bridge.bridge_state.call_a is not None
            assert bridge.bridge_state.call_b is not None
            assert mock_protocol.outgoing_call.call_count == 2
        finally:
            await bridge.end_bridge()

    @pytest.mark.asyncio
    async def test_bridge_calls_closes_pending_sockets_on_failure(self):
        """Test a failure mid-setup closes sockets not yet owned by a transport."""
        mock_protocol = MagicMock()
        source = get_sip_endpoint(host="127.0.0.1", port=5060)
        destination_a = get_sip_endpoint(host="192.168.1.100", port=5060)
        destination_b = get_sip_endpoint(host="192.168.1.101", port=5060)

        bridge = CallBridge(
            sip_protocol=mock_protocol,
            source_endpoint=source,
            local_ip="127.0.0.1",
        )

        socks = [MagicMock(name=f"sock{i}") for i in range(4)]
        bridge._create_rtp_socket_pair = MagicMock(
            side_effect=[
                (socks[0], socks[1], 16000),
                (socks[2], socks[3], 16002),
            ]
        )

        calls = 0

        async def fake_create_datagram_endpoint(*args, **kwargs):
            nonlocal calls
            calls += 1
            # Fail on the second endpoint, after the first socket was handed over.
            if calls == 2:
                raise OSError("boom")
            return (MagicMock(), MagicMock())

        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_get_loop.return_value.create_datagram_endpoint = (
                fake_create_datagram_endpoint
            )
            result = await bridge.bridge_calls(
                destination_a=destination_a, destination_b=destination_b
            )

        assert result is False
        # socks[0] was handed to a transport before the failure: not closed here.
        socks[0].close.assert_not_called()
        # The three sockets still pending when the failure hit must be closed.
        socks[1].close.assert_called_once()
        socks[2].close.assert_called_once()
        socks[3].close.assert_called_once()
