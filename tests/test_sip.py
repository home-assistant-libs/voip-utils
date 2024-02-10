"""Test voip_utils SIP functionality."""
import pytest
from voip_utils.sip import SipDatagramProtocol

def test_parse_header_for_uri():
    endpoint, name = SipDatagramProtocol._parse_uri_header('"Test Name" <sip:12345@example.com>')
    assert name == "Test Name"
    assert endpoint == "sip:12345@example.com"

def test_parse_header_for_uri_no_name():
    endpoint, name = SipDatagramProtocol._parse_uri_header('sip:12345@example.com')
    assert name is None
    assert endpoint == "sip:12345@example.com"

def test_parse_header_for_uri_sips():
    endpoint, name = SipDatagramProtocol._parse_uri_header('"Test Name" <sips:12345@example.com>')
    assert name == "Test Name"
    assert endpoint == "sips:12345@example.com"

def test_parse_header_for_uri_no_space_name():
    endpoint, name = SipDatagramProtocol._parse_uri_header('Test <sip:12345@example.com>')
    assert name == "Test"
    assert endpoint == "sip:12345@example.com"
