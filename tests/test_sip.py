"""Test voip_utils SIP functionality."""

from unittest.mock import Mock

from voip_utils.sip import (
    CallInfo,
    SdpInfo,
    SipDatagramProtocol,
    SipEndpoint,
    SipMessage,
    get_header,
    get_sip_endpoint,
    parse_via_header,
)

_CRLF = "\r\n"


def test_parse_header_for_uri():
    endpoint = SipEndpoint('"Test Name" <sip:12345@example.com>')
    assert endpoint.description == "Test Name"
    assert endpoint.uri == "sip:12345@example.com"
    assert endpoint.username == "12345"
    assert endpoint.host == "example.com"
    assert endpoint.port == 5060


def test_parse_header_for_uri_no_name():
    endpoint = SipEndpoint("sip:12345@example.com")
    assert endpoint.description is None
    assert endpoint.uri == "sip:12345@example.com"


def test_parse_header_for_uri_sips():
    endpoint = SipEndpoint('"Test Name" <sips:12345@example.com>')
    assert endpoint.description == "Test Name"
    assert endpoint.uri == "sips:12345@example.com"


def test_parse_header_for_uri_no_space_name():
    endpoint = SipEndpoint("Test <sip:12345@example.com>")
    assert endpoint.description == "Test"
    assert endpoint.uri == "sip:12345@example.com"


def test_parse_header_for_uri_no_space_between_name():
    endpoint = SipEndpoint("Test<sip:12345@example.com>")
    assert endpoint.description == "Test"
    assert endpoint.uri == "sip:12345@example.com"


def test_parse_header_for_uri_no_space_between_quoted_name():
    endpoint = SipEndpoint('"Test Endpoint"<sip:12345@example.com>')
    assert endpoint.description == "Test Endpoint"
    assert endpoint.uri == "sip:12345@example.com"


def test_parse_header_for_uri_no_username():
    endpoint = SipEndpoint("Test <sip:example.com>")
    assert endpoint.description == "Test"
    assert endpoint.username is None
    assert endpoint.uri == "sip:example.com"


def test_parse_header_for_parameters():
    endpoint = SipEndpoint("Test <sip:example.com;transport=tcp;lr;method=INVITE>")
    assert endpoint.description == "Test"
    assert endpoint.uri == "sip:example.com;transport=tcp;lr;method=INVITE"
    assert endpoint.host == "example.com"
    assert endpoint.uri_parameters
    assert "transport" in endpoint.uri_parameters
    assert "lr" in endpoint.uri_parameters
    assert "method" in endpoint.uri_parameters
    assert endpoint.uri_parameters["transport"] == "tcp"
    assert not endpoint.uri_parameters["lr"]
    assert endpoint.uri_parameters["method"] == "INVITE"


def test_parse_header_for_uri_headers():
    endpoint = SipEndpoint("Test <sip:example.com?priority=urgent&subject=Hello>")
    assert endpoint.description == "Test"
    assert endpoint.uri == "sip:example.com?priority=urgent&subject=Hello"
    assert endpoint.host == "example.com"
    assert endpoint.uri_headers
    assert "priority" in endpoint.uri_headers
    assert "subject" in endpoint.uri_headers
    assert endpoint.uri_headers["priority"] == "urgent"
    assert endpoint.uri_headers["subject"] == "Hello"


def test_parse_header_for_parameters_and_headers():
    endpoint = SipEndpoint(
        "Test <sip:example.com;transport=tcp;lr;method=INVITE?priority=urgent&subject=Hello>"
    )
    assert endpoint.description == "Test"
    assert (
        endpoint.uri
        == "sip:example.com;transport=tcp;lr;method=INVITE?priority=urgent&subject=Hello"
    )
    assert endpoint.host == "example.com"
    assert endpoint.uri_parameters
    assert "transport" in endpoint.uri_parameters
    assert "lr" in endpoint.uri_parameters
    assert "method" in endpoint.uri_parameters
    assert endpoint.uri_parameters["transport"] == "tcp"
    assert not endpoint.uri_parameters["lr"]
    assert endpoint.uri_parameters["method"] == "INVITE"
    assert endpoint.uri_headers
    assert "priority" in endpoint.uri_headers
    assert "subject" in endpoint.uri_headers
    assert endpoint.uri_headers["priority"] == "urgent"
    assert endpoint.uri_headers["subject"] == "Hello"
    assert endpoint.base_uri == "sip:example.com"


def test_get_sip_endpoint():
    endpoint = get_sip_endpoint("example.com")
    assert endpoint.host == "example.com"
    assert endpoint.port == 5060
    assert endpoint.description is None
    assert endpoint.username is None
    assert endpoint.uri == "sip:example.com"


def test_get_sip_endpoint_with_username():
    endpoint = get_sip_endpoint("example.com", username="test")
    assert endpoint.host == "example.com"
    assert endpoint.port == 5060
    assert endpoint.description is None
    assert endpoint.username == "test"
    assert endpoint.uri == "sip:test@example.com"


def test_get_sip_endpoint_with_description():
    endpoint = get_sip_endpoint("example.com", description="Test Endpoint")
    assert endpoint.host == "example.com"
    assert endpoint.port == 5060
    assert endpoint.description == "Test Endpoint"
    assert endpoint.username is None
    assert endpoint.uri == "sip:example.com"
    assert endpoint.sip_header == '"Test Endpoint" <sip:example.com>'


def test_get_sip_endpoint_with_scheme():
    endpoint = get_sip_endpoint("example.com", scheme="sips")
    assert endpoint.host == "example.com"
    assert endpoint.port == 5060
    assert endpoint.description is None
    assert endpoint.username is None
    assert endpoint.uri == "sips:example.com"


def test_get_sip_endpoint_with_description_and_parameters():
    endpoint = get_sip_endpoint(
        "example.com",
        description="Test Endpoint",
        header_parameters={"tag": "decafc0ffee"},
    )
    assert endpoint.host == "example.com"
    assert endpoint.port == 5060
    assert endpoint.description == "Test Endpoint"
    assert endpoint.username is None
    assert endpoint.uri == "sip:example.com"
    assert endpoint.sip_header == '"Test Endpoint" <sip:example.com>;tag=decafc0ffee'


def test_parse_via_header():
    via_header_value = "SIP/2.0/UDP testhost:5061"
    result = parse_via_header(via_header_value)
    assert result
    host, port = result
    assert host == "testhost"
    assert port == 5061


def test_parse_via_header_default_port():
    via_header_value = "SIP/2.0/UDP testhost"
    result = parse_via_header(via_header_value)
    assert result
    host, port = result
    assert host == "testhost"
    assert port == 5060


def test_parse_via_header_with_parameters():
    via_header_value = "SIP/2.0/UDP testhost;branch=brnch12345"
    result = parse_via_header(via_header_value)
    assert result
    host, port = result
    assert host == "testhost"
    assert port == 5060


def test_parse_via_header_error():
    via_header_value = "some garbage text"
    result = parse_via_header(via_header_value)
    assert result is None


def test_parse_freepbx_options():
    options_lines = [
        "",
        "OPTIONS sip:10.5.1.2:5060 SIP/2.0"
        "Via: SIP/2.0/UDP 10.5.1.3:5060;rport;branch=z9hG4bKPj67dd8ad6-5b27-4860-b9fb-8bae195d6443"
        "From: <sip:HomeAssistant@10.5.1.3>;tag=bab3c78d-7659-466f-8326-61d6da0c5267"
        "To: <sip:10.5.1.2>"
        "Contact: <sip:999@10.5.1.3:5060>"
        "Call-ID: 9aa75329-b33d-4e27-b2e3-73ab30677942"
        "CSeq: 14010 OPTIONS"
        "Max-Forwards: 70"
        "User-Agent: FPBX-17.0.19.27(21.8.0)"
        "Content-Length:  0"
        "",
    ]
    options_text = _CRLF.join(options_lines) + _CRLF
    options_msg = SipMessage.parse_sip(options_text, False)
    assert options_msg is not None


def test_parse_with_body():
    invite_lines = [
        "",
        "INVITE sip:6002@192.168.0.18 SIP/2.0",
        "Via: SIP/2.0/UDP 192.168.0.18:5062",
        "From: sip:5000@192.168.0.18:5062",
        "Contact: sip:5000@192.168.0.18:5062",
        "To: sip:6002@192.168.0.18",
        "Call-ID: 5443482144267586",
        "CSeq: 50 INVITE",
        "User-Agent: test-agent 1.0",
        "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE",
        "Accept: application/sdp, application/dtmf-relay",
        "Content-Type: application/sdp",
        "Content-Length: 391",
        "",
        "v=0",
        "o=5000 5443482144267586 5443482144267586 IN IP4 192.168.0.18",
        "s=Talk",
        "c=IN IP4 192.168.0.18",
        "t=0 0",
        "m=audio 59756 RTP/AVP 123 96 101 103 104",
        "a=sendrecv",
        "a=rtpmap:96 opus/48000/2",
        "a=fmtp:96 useinbandfec=0",
        "a=rtpmap:123 opus/48000/2",
        "a=fmtp:123 maxplaybackrate=16000",
        "a=rtpmap:101 telephone-event/48000",
        "a=rtpmap:103 telephone-event/16000",
        "a=rtpmap:104 telephone-event/8000",
        "a=ptime:20",
    ]
    invite_text = _CRLF.join(invite_lines) + _CRLF
    invite_msg = SipMessage.parse_sip(invite_text, False)
    assert invite_msg is not None
    assert invite_msg.body is not None
    assert invite_msg.body.startswith("v=0")


class MockSipDatagramProtocol(SipDatagramProtocol):
    def on_call(self, call_info: CallInfo):
        pass


def test_cancel():
    protocol = MockSipDatagramProtocol(SdpInfo("username", 5, "session", "version"))
    source = get_sip_endpoint("testsource")
    destination = get_sip_endpoint("destination")
    invite_lines = [
        f"INVITE {destination.uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {source.host}:{source.port}",
        f"From: {source.sip_header}",
        f"Contact: {source.sip_header}",
        f"To: {destination.sip_header}",
        "Call-ID: 100",
        "CSeq: 50 INVITE",
        "User-Agent: test-agent 1.0",
        "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE",
        "Accept: application/sdp, application/dtmf-relay",
        "Content-Type: application/sdp",
        "Content-Length: 0",
        "",
    ]
    invite_text = _CRLF.join(invite_lines) + _CRLF
    invite_msg = SipMessage.parse_sip(invite_text, False)

    call_info = CallInfo(
        caller_endpoint=destination,
        local_endpoint=source,
        caller_rtp_port=12345,
        server_ip=source.host,
        headers=invite_msg.headers,
    )

    transport = Mock()
    protocol.connection_made(transport)
    protocol.cancel_call(call_info)

    transport.sendto.assert_called_once_with(
        b"CANCEL sip:destination SIP/2.0\r\nVia: SIP/2.0/UDP testsource:5060\r\nFrom: sip:testsource\r\nTo: sip:destination\r\nCall-ID: 100\r\nCSeq: 50 CANCEL\r\nUser-Agent: voip-utils 1.0\r\nContent-Length: 0\r\n\r\n",
        ("destination", 5060),
    )


def test_answer_to_add_tag():
    protocol = MockSipDatagramProtocol(SdpInfo("username", 5, "session", "version"))
    transport = Mock()
    source = get_sip_endpoint("testsource")
    destination = get_sip_endpoint("destination")

    invite_lines = [
        f"INVITE {destination.uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {source.host}:{source.port}",
        f"From: {source.sip_header}",
        f"Contact: {source.sip_header}",
        f"To: {destination.sip_header};tag=deadbeef",
        "Call-ID: 100",
        "CSeq: 50 INVITE",
        "User-Agent: test-agent 1.0",
        "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE",
        "Accept: application/sdp, application/dtmf-relay",
        "Content-Type: application/sdp",
        "Content-Length: 0",
        "",
    ]
    invite_text = _CRLF.join(invite_lines) + _CRLF
    invite_msg = SipMessage.parse_sip(invite_text, True)

    call_info = CallInfo(
        caller_endpoint=destination,
        local_endpoint=source,
        caller_rtp_port=12345,
        server_ip=source.host,
        headers=invite_msg.headers,
    )

    protocol.connection_made(transport)
    protocol.answer(call_info, 12345)

    transport.sendto.assert_called_once_with(
        b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP testsource:5060\r\nFrom: sip:testsource\r\nTo: sip:destination;tag=deadbeef\r\nCall-ID: 100\r\nContent-Type: application/sdp\r\nContent-Length: 174\r\nCSeq: 50 INVITE\r\nContact: sip:testsource\r\nUser-Agent: username 5 version\r\nAllow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n\r\nv=0\r\no=username 5 1 IN IP4 testsource\r\ns=session\r\nc=IN IP4 testsource\r\nt=0 0\r\nm=audio 12345 RTP/AVP 123\r\na=rtpmap:123 opus/48000/2\r\na=ptime:20\r\na=maxptime:150\r\na=sendrecv\r\n\r\n",
        ("destination", 5060),
    )


class TagBytesMatcher:
    def __init__(self, prefix: bytes, suffix: bytes, expected_length: int):
        self.prefix = prefix
        self.suffix = suffix
        self.expected_length = expected_length

    def __eq__(self, other):
        if not isinstance(other, bytes):
            return False
        if not other.startswith(self.prefix) or not other.endswith(self.suffix):
            return False
        middle = other[len(self.prefix) : -len(self.suffix) or None]
        return len(middle) == self.expected_length

    def __repr__(self):
        return f"<TagBytesMatcher(prefix={self.prefix}, expected_length={self.expected_length}, suffix={self.suffix}"


def test_answer_to_generated_tag():
    protocol = MockSipDatagramProtocol(SdpInfo("username", 5, "session", "version"))
    transport = Mock()
    source = get_sip_endpoint("testsource")
    destination = get_sip_endpoint("destination")

    invite_lines = [
        f"INVITE {destination.uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {source.host}:{source.port}",
        f"From: {source.sip_header}",
        f"Contact: {source.sip_header}",
        f"To: {destination.sip_header}",
        "Call-ID: 100",
        "CSeq: 50 INVITE",
        "User-Agent: test-agent 1.0",
        "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE",
        "Accept: application/sdp, application/dtmf-relay",
        "Content-Type: application/sdp",
        "Content-Length: 0",
        "",
    ]
    invite_text = _CRLF.join(invite_lines) + _CRLF
    invite_msg = SipMessage.parse_sip(invite_text, True)

    call_info = CallInfo(
        caller_endpoint=destination,
        local_endpoint=source,
        caller_rtp_port=12345,
        server_ip=source.host,
        headers=invite_msg.headers,
    )

    protocol.connection_made(transport)
    protocol.answer(call_info, 12345)

    transport.sendto.assert_called_once_with(
        TagBytesMatcher(
            b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP testsource:5060\r\nFrom: sip:testsource\r\nTo: sip:destination;tag=",
            b"\r\nCall-ID: 100\r\nContent-Type: application/sdp\r\nContent-Length: 174\r\nCSeq: 50 INVITE\r\nContact: sip:testsource\r\nUser-Agent: username 5 version\r\nAllow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n\r\nv=0\r\no=username 5 1 IN IP4 testsource\r\ns=session\r\nc=IN IP4 testsource\r\nt=0 0\r\nm=audio 12345 RTP/AVP 123\r\na=rtpmap:123 opus/48000/2\r\na=ptime:20\r\na=maxptime:150\r\na=sendrecv\r\n\r\n",
            16,
        ),
        ("destination", 5060),
    )


def test_answer_to_generated_tag_with_desc():
    protocol = MockSipDatagramProtocol(SdpInfo("username", 5, "session", "version"))
    transport = Mock()
    source = get_sip_endpoint("testsource")
    destination = get_sip_endpoint(host="destination", description="Test Endpoint")

    invite_lines = [
        f"INVITE {destination.uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {source.host}:{source.port}",
        f"From: {source.sip_header}",
        f"Contact: {source.sip_header}",
        f"To: {destination.sip_header}",
        "Call-ID: 100",
        "CSeq: 50 INVITE",
        "User-Agent: test-agent 1.0",
        "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE",
        "Accept: application/sdp, application/dtmf-relay",
        "Content-Type: application/sdp",
        "Content-Length: 0",
        "",
    ]
    invite_text = _CRLF.join(invite_lines) + _CRLF
    invite_msg = SipMessage.parse_sip(invite_text, True)

    call_info = CallInfo(
        caller_endpoint=destination,
        local_endpoint=source,
        caller_rtp_port=12345,
        server_ip=source.host,
        headers=invite_msg.headers,
    )

    protocol.connection_made(transport)
    protocol.answer(call_info, 12345)

    transport.sendto.assert_called_once_with(
        TagBytesMatcher(
            b'SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP testsource:5060\r\nFrom: sip:testsource\r\nTo: "Test Endpoint" <sip:destination>;tag=',
            b"\r\nCall-ID: 100\r\nContent-Type: application/sdp\r\nContent-Length: 174\r\nCSeq: 50 INVITE\r\nContact: sip:testsource\r\nUser-Agent: username 5 version\r\nAllow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n\r\nv=0\r\no=username 5 1 IN IP4 testsource\r\ns=session\r\nc=IN IP4 testsource\r\nt=0 0\r\nm=audio 12345 RTP/AVP 123\r\na=rtpmap:123 opus/48000/2\r\na=ptime:20\r\na=maxptime:150\r\na=sendrecv\r\n\r\n",
            16,
        ),
        ("destination", 5060),
    )


def test_cancel_via():
    protocol = MockSipDatagramProtocol(SdpInfo("username", 5, "session", "version"))
    source = get_sip_endpoint("testsource")
    destination = get_sip_endpoint("destination")
    invite_lines = [
        f"INVITE {destination.uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {source.host}:{source.port}",
        f"From: {source.sip_header}",
        f"Contact: {source.sip_header}",
        f"To: {destination.sip_header}",
        "Call-ID: 100",
        "CSeq: 50 INVITE",
        "User-Agent: test-agent 1.0",
        "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE",
        "Accept: application/sdp, application/dtmf-relay",
        "Content-Type: application/sdp",
        "Content-Length: 0",
        "",
    ]
    invite_text = _CRLF.join(invite_lines) + _CRLF
    invite_msg = SipMessage.parse_sip(invite_text, False)

    call_info = CallInfo(
        caller_endpoint=destination,
        local_endpoint=source,
        caller_rtp_port=12345,
        server_ip=source.host,
        headers=invite_msg.headers,
        via_host="viahost",
        via_port=5061,
    )

    transport = Mock()
    protocol.connection_made(transport)
    protocol.cancel_call(call_info)

    transport.sendto.assert_called_once_with(
        b"CANCEL sip:destination SIP/2.0\r\nVia: SIP/2.0/UDP testsource:5060\r\nFrom: sip:testsource\r\nTo: sip:destination\r\nCall-ID: 100\r\nCSeq: 50 CANCEL\r\nUser-Agent: voip-utils 1.0\r\nContent-Length: 0\r\n\r\n",
        ("viahost", 5061),
    )


def test_hang_up_ends_outgoing_call():
    """Hanging up sends a BYE, deregisters the call and notifies on_hangup.

    outgoing_call() records the INVITE headers with their original casing, so
    hang_up() has to look the Call-ID up case-insensitively.
    """
    # pylint: disable=protected-access
    protocol = MockSipDatagramProtocol(SdpInfo("username", 5, "session", "version"))
    protocol.on_hangup = Mock()
    transport = Mock()
    protocol.connection_made(transport)

    source = get_sip_endpoint("testsource")
    destination = get_sip_endpoint("destination")
    call_info = protocol.outgoing_call(source, destination, 12345)

    call_id = get_header(call_info.headers, "call-id")[1]
    assert protocol._get_call_rtp_port(call_id) == 12345

    transport.sendto.reset_mock()
    protocol.hang_up(call_info)

    bye_lines = [
        "BYE sip:destination SIP/2.0",
        "Via: SIP/2.0/UDP testsource:5060",
        "From: sip:testsource",
        "To: sip:destination",
        f"Call-ID: {call_id}",
        "CSeq: 51 BYE",
        "User-Agent: voip-utils 1.0",
        "Content-Length: 0",
        "",
    ]
    transport.sendto.assert_called_once_with(
        (_CRLF.join(bye_lines) + _CRLF).encode("utf-8"),
        ("destination", 5060),
    )
    assert protocol._get_call_rtp_port(call_id) is None
    protocol.on_hangup.assert_called_once_with(call_info)


class RecordingSipDatagramProtocol(SipDatagramProtocol):
    """Protocol that records the calls handed to it instead of answering them."""

    def __init__(self, sdp_info: SdpInfo):
        super().__init__(sdp_info)
        self.calls: list[CallInfo] = []

    def on_call(self, call_info: CallInfo):
        self.calls.append(call_info)


_PEER = ("192.168.1.50", 5060)
_LISTENER = ("192.168.1.10", 5060)


def _connected_protocol(sockname=("0.0.0.0", 5060)):
    """Return a protocol with a mock transport bound to the given address."""
    protocol = RecordingSipDatagramProtocol(
        SdpInfo("username", 5, "session", "version")
    )
    transport = Mock()
    transport.get_extra_info.return_value = sockname
    protocol.connection_made(transport)
    return protocol, transport


def _invite(via: str) -> bytes:
    """Build an INVITE carrying the given Via header value."""
    invite_lines = [
        f"INVITE sip:homeassistant@{_LISTENER[0]}:{_LISTENER[1]} SIP/2.0",
        f"Via: {via}",
        "From: sip:phone@192.168.1.50",
        "Contact: sip:phone@192.168.1.50",
        f"To: sip:homeassistant@{_LISTENER[0]}",
        "Call-ID: 100",
        "CSeq: 50 INVITE",
        "User-Agent: test-agent 1.0",
        "Content-Type: application/sdp",
        "Content-Length: 0",
        "",
    ]
    body_lines = [
        "v=0",
        "s=Talk",
        "t=0 0",
        "m=audio 5004 RTP/AVP 123",
        "a=rtpmap:123 opus/48000/2",
        "",
    ]
    return (_CRLF.join(invite_lines) + _CRLF + _CRLF.join(body_lines)).encode("utf-8")


def test_invite_records_the_transport_source():
    """The address a call arrived from is carried on CallInfo.

    Headers carry whatever the caller put in them, so this is the only field
    that records where the call actually came from.
    """
    protocol, _ = _connected_protocol()

    protocol.datagram_received(_invite(f"SIP/2.0/UDP {_PEER[0]}:{_PEER[1]}"), _PEER)

    assert len(protocol.calls) == 1
    assert protocol.calls[0].peer_address == _PEER


def test_answer_ignores_via_naming_another_host():
    """A Via pointing somewhere else does not redirect our response there.

    The transport source is authoritative for where a response goes.
    """
    protocol, transport = _connected_protocol()

    protocol.datagram_received(_invite("SIP/2.0/UDP 203.0.113.9:5060"), _PEER)
    transport.sendto.reset_mock()
    protocol.answer(protocol.calls[0], 12345)

    transport.sendto.assert_called_once()
    assert transport.sendto.call_args[0][1] == _PEER


def test_answer_ignores_via_naming_the_listener():
    """A Via naming us does not make us answer ourselves."""
    protocol, transport = _connected_protocol()

    protocol.datagram_received(
        _invite(f"SIP/2.0/UDP {_LISTENER[0]}:{_LISTENER[1]}"), _PEER
    )
    transport.sendto.reset_mock()
    protocol.answer(protocol.calls[0], 12345)

    transport.sendto.assert_called_once()
    assert transport.sendto.call_args[0][1] == _PEER


def test_via_hostname_never_reaches_sendto():
    """A Via host that is not an IP literal is discarded, not resolved.

    Passing a name to sendto() would resolve it on the event loop.
    """
    protocol, transport = _connected_protocol()

    protocol.datagram_received(_invite("SIP/2.0/UDP proxy.example.com:5060"), _PEER)
    transport.sendto.reset_mock()
    protocol.answer(protocol.calls[0], 12345)

    assert protocol.calls[0].via_host != "proxy.example.com"
    transport.sendto.assert_called_once()
    assert transport.sendto.call_args[0][1] == _PEER


def test_answer_honours_via_port_from_the_caller():
    """A Via whose host agrees with the source still chooses the port.

    This is the RFC 3261 "received" rule, and phones that send from an ephemeral
    port rely on it.
    """
    protocol, transport = _connected_protocol()

    protocol.datagram_received(_invite(f"SIP/2.0/UDP {_PEER[0]}:5070"), _PEER)
    transport.sendto.reset_mock()
    protocol.answer(protocol.calls[0], 12345)

    assert transport.sendto.call_args[0][1] == (_PEER[0], 5070)


def _ok_response(call_id: str) -> bytes:
    ok_lines = [
        "SIP/2.0 200 OK",
        f"Via: SIP/2.0/UDP {_PEER[0]}:{_PEER[1]}",
        "From: sip:homeassistant@192.168.1.10",
        "To: sip:phone@192.168.1.50",
        f"Call-ID: {call_id}",
        "CSeq: 50 INVITE",
        "Content-Type: application/sdp",
        "Content-Length: 0",
        "",
    ]
    body_lines = [
        "v=0",
        "c=IN IP4 192.168.1.50",
        "t=0 0",
        "m=audio 5004 RTP/AVP 123",
        "a=rtpmap:123 opus/48000/2",
        "",
    ]
    return (_CRLF.join(ok_lines) + _CRLF + _CRLF.join(body_lines)).encode("utf-8")


def test_ok_for_unknown_call_id_is_ignored():
    """An unsolicited 200 OK does not start a call.

    Only a response matching an INVITE we sent corresponds to a call.
    """
    protocol, transport = _connected_protocol()

    protocol.datagram_received(_ok_response("not-a-call-we-made"), _PEER)

    assert not protocol.calls
    transport.sendto.assert_not_called()


def test_ok_for_known_call_id_is_handled():
    """A 200 OK for a call we placed still goes through."""
    # pylint: disable=protected-access
    protocol, _ = _connected_protocol()
    protocol._register_outgoing_call("100", 12345)

    protocol.datagram_received(_ok_response("100"), _PEER)

    assert len(protocol.calls) == 1
    assert protocol.calls[0].peer_address == _PEER


def test_datagram_from_our_own_address_is_dropped():
    """A datagram whose source is our own listening address is not a call."""
    protocol, transport = _connected_protocol(sockname=_LISTENER)

    protocol.datagram_received(
        _invite(f"SIP/2.0/UDP {_LISTENER[0]}:{_LISTENER[1]}"), _LISTENER
    )

    assert not protocol.calls
    transport.sendto.assert_not_called()
