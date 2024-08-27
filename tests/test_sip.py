"""Test voip_utils SIP functionality."""

from voip_utils.sip import SipEndpoint


def test_parse_header_for_uri():
    endpoint = SipEndpoint(
        '"Test Name" <sip:12345@example.com>'
    )
    assert endpoint.description == "Test Name"
    assert endpoint.uri == "sip:12345@example.com"
    assert endpoint.username == "12345"
    assert endpoint.host == "example.com"
    assert endpoint.port == 5060


def test_parse_header_for_uri_no_name():
    endpoint = SipEndpoint(
        "sip:12345@example.com"
    )
    assert endpoint.description is None
    assert endpoint.uri == "sip:12345@example.com"


def test_parse_header_for_uri_sips():
    endpoint = SipEndpoint(
        '"Test Name" <sips:12345@example.com>'
    )
    assert endpoint.description == "Test Name"
    assert endpoint.uri == "sips:12345@example.com"


def test_parse_header_for_uri_no_space_name():
    endpoint = SipEndpoint(
        "Test <sip:12345@example.com>"
    )
    assert endpoint.description == "Test"
    assert endpoint.uri == "sip:12345@example.com"


def test_parse_header_for_uri_no_username():
    endpoint = SipEndpoint(
        "Test <sip:example.com>"
    )
    assert endpoint.description == "Test"
    assert endpoint.username is None
    assert endpoint.uri == "sip:example.com"
