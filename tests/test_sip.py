"""Test voip_utils SIP functionality."""

from voip_utils.sip import CallInfo, SdpInfo, SipDatagramProtocol, SipEndpoint, SipMessage, get_sip_endpoint
from unittest.mock import Mock

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
        f"Call-ID: 100",
        "CSeq: 50 INVITE",
        f"User-Agent: test-agent 1.0",
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

    transport.sendto.assert_called_once_with(b'CANCEL sip:destination SIP/2.0\r\nVia: SIP/2.0/UDP testsource:5060\r\nFrom: sip:testsource\r\nTo: sip:destination\r\nCall-ID: 100\r\nCSeq: 50 CANCEL\r\nUser-Agent: voip-utils 1.0\r\nContent-Length: 0\r\n\r\n', ('destination', 5060))

