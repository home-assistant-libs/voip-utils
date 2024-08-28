"""Test voip_utils SIP functionality."""

from voip_utils.sip import SipEndpoint, get_sip_endpoint


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
