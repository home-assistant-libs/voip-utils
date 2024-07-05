
"""Implementation of SIP (Session Initiation Protocol)."""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .const import OPUS_PAYLOAD_TYPE
from .error import VoipError
from .util import is_ipv4_address

SIP_PORT = 5060

_LOGGER = logging.getLogger(__name__)
_CRLF = "\r\n"


@dataclass
class SdpInfo:
    """Information for Session Description Protocol (SDP)."""

    username: str
    id: int
    session_name: str
    version: str
    server_address: str
    prefer_ipv6: bool = True


@dataclass
class CallInfo:
    """Information gathered from an INVITE message."""

    caller_ip: str
    caller_sip_port: int
    caller_rtp_port: int
    caller_uri: str | None
    caller_name: str | None
    server_ip: str
    headers: dict[str, str]
    opus_payload_type: int = OPUS_PAYLOAD_TYPE

    @property
    def caller_rtcp_port(self) -> int:
        """Real-time Transport Control Protocol (RTCP) port."""
        return self.caller_rtp_port + 1


class SipDatagramProtocol(asyncio.DatagramProtocol, ABC):
    """UDP server for the Session Initiation Protocol (SIP)."""

    def __init__(self, sdp_info: SdpInfo) -> None:
        """Set up SIP server."""
        self.sdp_info = sdp_info
        self.transport = None

    def connection_made(self, transport):
        """Server ready."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        """Handle INVITE SIP messages."""
        try:
            caller_ip, caller_sip_port = addr
            message = data.decode()
            method, ruri, headers, body = self._parse_sip(message)
            _LOGGER.debug(
                "Received datagram method=%s, ruri=%s, headers=%s, body=%s",
                method,
                ruri,
                headers,
                body,
            )

            if method:
                method = method.lower()

            if method != "invite":
                # Not an INVITE message
                return

            if not ruri:
                raise ValueError("Empty receiver URI")

            caller_uri = None
            caller_name = None
            # The Contact header should give us the URI used for sending SIP messages to the device
            if headers.get("contact") is not None:
                caller_uri, caller_name = self._parse_uri_header(headers.get("contact"))
            # We can try using the From header as a fallback
            elif headers.get("from") is not None:
                caller_uri, caller_name = self._parse_uri_header(headers.get("from"))
            # If all else fails try to generate a URI based on the IP and port from the address the message came from
            else:
                caller_uri = "sip:" + caller_ip + ":" + caller_sip_port
                caller_name = "Unknown"

            _LOGGER.debug(
                "Incoming call from ip=%s, port=%s, uri=%s, name=%s",
                caller_ip,
                caller_sip_port,
                caller_uri,
                caller_name,
            )

            # Extract caller's RTP port from SDP.
            # See: https://datatracker.ietf.org/doc/html/rfc2327
            caller_rtp_port: Optional[int] = None
            opus_payload_type = OPUS_PAYLOAD_TYPE
            body_lines = body.splitlines()
            for line in body_lines:
                line = line.strip()
                if line:
                    key, value = line.split("=", maxsplit=1)
                    if key == "m":
                        parts = value.split()
                        if parts[0] == "audio":
                            caller_rtp_port = int(parts[1])
                    elif key == "a" and value.startswith("rtpmap:"):
                        # a=rtpmap:123 opus/48000/2
                        codec_str = value.split(":", maxsplit=1)[1]
                        codec_parts = codec_str.split()
                        if (len(codec_parts) > 1) and (
                            codec_parts[1].lower().startswith("opus")
                        ):
                            opus_payload_type = int(codec_parts[0])
                            _LOGGER.debug(
                                "Detected OPUS payload type as %s", opus_payload_type
                            )

            if caller_rtp_port is None:
                raise VoipError("No caller RTP port")

            # Extract host from ruri
            # sip:user@[2001:db8::1]:1234 or sip:user@123.123.123.123:1234 or sip:user@hostname:1234
            re_splituri = re.compile(
                r"(?P<scheme>\w+):"  # Scheme
                + r"(?:(?P<user>[\w\.]+):?(?P<password>[\w\.]+)?@)?"  # User:Password
                + r"\[?(?P<host>"  # Begin group host
                + r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|"  # IPv4 address Host Or
                + r"(?:(?=.*:)(?:[0-9a-fA-F]{0,4}:){0,7}[0-9a-fA-F]{0,4})|"  # IPv6 address Host Or
                + r"(?:(?:[0-9A-Za-z]+\.)+[0-9A-Za-z]+)"  # Hostname string
                + r")\]?:?"  # End group host
                + r"(?P<port>\d{1,6})?"  # port
                + r"(?:\;(?P<params>[^\?]*))?"  # parameters
                + r"(?:\?(?P<headers>.*))?"  # headers
            )
            re_uri = re_splituri.search(ruri)
            if re_uri is None:
                raise ValueError("Receiver URI did not match expected pattern")

            server_ip = re_uri.group("host")
            self.sdp_info.server_address = server_ip

            self.on_call(
                CallInfo(
                    caller_ip=caller_ip,
                    caller_sip_port=caller_sip_port,
                    caller_rtp_port=caller_rtp_port,
                    caller_uri=caller_uri,
                    caller_name=caller_name,
                    server_ip=server_ip,
                    headers=headers,
                    opus_payload_type=opus_payload_type,
                )
            )
        except Exception:
            _LOGGER.exception("Unexpected error handling SIP INVITE")

    @abstractmethod
    def on_call(self, call_info: CallInfo):
        """Handle incoming calls."""

    def answer(
        self,
        call_info: CallInfo,
        server_rtp_port: int,
    ):
        if self.transport is None:
            return

        # Resolve server_address if it's a hostname
        if not (is_ipv4_address(self.sdp_info.server_address) or ":" in self.sdp_info.server_address):
            self.sdp_info.server_address = resolve_hostname(self.sdp_info.server_address, self.sdp_info.prefer_ipv6)

        address_type = "IP6" if ":" in self.sdp_info.server_address else "IP4"
        
        body_lines = [
            "v=0",
            f"o={self.sdp_info.username} {self.sdp_info.id} 1 IN {address_type} {self.sdp_info.server_address}",
            f"s={self.sdp_info.session_name}",
            f"c=IN {address_type} {self.sdp_info.server_address}",
            "t=0 0",
            f"m=audio {server_rtp_port} RTP/AVP {call_info.opus_payload_type}",
            f"a=rtpmap:{call_info.opus_payload_type} opus/48000/2",
            "a=ptime:20",
            "a=maxptime:150",
            "a=sendrecv",
            _CRLF,
        ]
        body = _CRLF.join(body_lines)

        response_headers = {
            "Via": call_info.headers["via"],
            "From": call_info.headers["from"],
            "To": call_info.headers["to"],
            "Call-ID": call_info.headers["call-id"],
            "Content-Type": "application/sdp",
            "Content-Length": len(body),
            "CSeq": call_info.headers["cseq"],
            "Contact": call_info.headers["contact"],
            "User-Agent": f"{self.sdp_info.username} {self.sdp_info.id} {self.sdp_info.version}",
            "Allow": "INVITE, ACK, BYE, CANCEL, OPTIONS",
        }
        response_lines = ["SIP/2.0 200 OK"]

        for key, value in response_headers.items():
            response_lines.append(f"{key}: {value}")

        response_lines.append(_CRLF)
        response_str = _CRLF.join(response_lines) + body
        response_bytes = response_str.encode()

        self.transport.sendto(
            response_bytes,
            (call_info.caller_ip, call_info.caller_sip_port),
        )
        _LOGGER.debug(
            "Sent OK to ip=%s, port=%s with rtp_port=%s",
            call_info.caller_ip,
            call_info.caller_sip_port,
            server_rtp_port,
        )

    def _parse_uri_header(
        self, header: str | None
    ) -> Tuple[Optional[str], Optional[str]]:
        """Parse SIP Contact/From Header and return endpoint URI and name."""
        uri: Optional[str] = None
        name: Optional[str] = None

        if header is None:
            return uri, name

        header_pattern = re.compile(
            r'\s*((?P<name>\b\w+\b|"[^"]+")\s+)?<?(?P<uri>sips?:[^>]+)>?.*'
        )
        header_match = header_pattern.match(header)
        if header_match is not None:
            name_token = header_match.group("name")
            if name_token is not None:
                name = name_token.strip('"')
            uri = header_match.group("uri")

        return uri, name

    def _parse_sip(
        self, message: str
    ) -> Tuple[Optional[str], Optional[str], Dict[str, str], str]:
        """Parse SIP message and return method, headers, and body."""
        lines = message.splitlines()

        method: Optional[str] = None
        ruri: Optional[str] = None
        headers: dict[str, str] = {}
        offset: int = 0

        # See: https://datatracker.ietf.org/doc/html/rfc3261
        for i, line in enumerate(lines):
            if line:
                offset += len(line) + len(_CRLF)

            if i == 0:
                line_parts = line.split()
                method = line_parts[0]
                ruri = line_parts[1]
            elif not line:
                break
            else:
                key, value = line.split(":", maxsplit=1)
                headers[key.lower()] = value.strip()

        body = message[offset:]

        return method, ruri, headers, body

def resolve_hostname(hostname: str, prefer_ipv6: bool) -> str:
    """Resolve hostname to an IP address, preferring IPv6 or IPv4 based on prefer_ipv6 flag."""
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for info in addr_info:
            family, _, _, _, sockaddr = info
            if prefer_ipv6 and family == socket.AF_INET6:
                return sockaddr[0]
            elif not prefer_ipv6 and family == socket.AF_INET:
                return sockaddr[0]
        return addr_info[0][-1][0]  # If no preferred address is found, use the first available address
    except socket.gaierror:
        raise VoipError(f"Hostname resolution failed for {hostname}")