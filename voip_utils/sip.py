"""Implementation of SIP (Session Initiation Protocol)."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
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


@dataclass
class SipEndpoint:
    """Information about a SIP endpoint."""

    sip_header: str
    uri: str = field(init=False)
    scheme: str = field(init=False)
    host: str = field(init=False)
    port: int = field(init=False)
    username: str | None = field(init=False)
    description: str | None = field(init=False)

    def __post_init__(self):
        header_pattern = re.compile(
            r'\s*((?P<description>\b\w+\b|"[^"]+")\s+)?<?(?P<uri>sips?:[^>]+)>?.*'
        )
        header_match = header_pattern.match(self.sip_header)
        if header_match is not None:
            description_token = header_match.group("description")
            if description_token is not None:
                self.description = description_token.strip('"')
            else:
                self.description = None
            self.uri = header_match.group("uri")
            uri_pattern = re.compile(
                r"(?P<scheme>sips?):(?:(?P<user>[^@]+)@)?(?P<host>[^:;?]+)(?::(?P<port>\d+))?"
            )
            uri_match = uri_pattern.match(self.uri)
            if uri_match is None:
                raise ValueError("Invalid SIP uri")
            self.scheme = uri_match.group("scheme")
            self.username = uri_match.group("user")
            self.host = uri_match.group("host")
            self.port = (
                int(uri_match.group("port")) if uri_match.group("port") else SIP_PORT
            )
        else:
            raise ValueError("Invalid SIP header")


@dataclass
class CallInfo:
    """Information gathered from an INVITE message."""

    caller_endpoint: SipEndpoint
    caller_rtp_port: int
    server_ip: str
    headers: dict[str, str]
    opus_payload_type: int = OPUS_PAYLOAD_TYPE

    @property
    def caller_rtcp_port(self) -> int:
        """Real-time Transport Control Protocol (RTCP) port."""
        return self.caller_rtp_port + 1

    @property
    def caller_ip(self) -> str:
        """Get IP address of caller."""
        return self.caller_endpoint.host

    @property
    def caller_sip_port(self) -> int:
        """SIP port of caller."""
        return self.caller_endpoint.port


@dataclass
class RtpInfo:
    """Information about the RTP transport used for the call audio."""

    rtp_ip: str | None
    rtp_port: int | None
    payload_type: int | None


def get_sip_endpoint(
    host: str,
    port: Optional[int] = None,
    scheme: Optional[str] = "sip",
    username: Optional[str] = None,
    description: Optional[str] = None,
) -> SipEndpoint:
    uri = f"{scheme}:"
    if username:
        uri += f"{username}@"
    uri += host
    if port:
        uri += f":{port}"
    if description:
        uri = f'"{description}" <{uri}>'
    return SipEndpoint(uri)


def get_rtp_info(body: str) -> RtpInfo:
    body_lines = body.splitlines()
    rtp_ip = None
    rtp_port = None
    opus_payload_type = None
    opus_payload_types_detected = []
    for line in body_lines:
        line = line.strip()
        if not line:
            continue

        key, _, value = line.partition("=")
        if key == "m":
            parts = value.split()
            if parts[0] == "audio":
                rtp_port = int(parts[1])
        elif key == "c":
            parts = value.split()
            if len(parts) > 2:
                rtp_ip = parts[2]
        elif key == "a" and value.startswith("rtpmap:"):
            # a=rtpmap:123 opus/48000/2
            codec_str = value.split(":", maxsplit=1)[1]
            codec_parts = codec_str.split()
            if (len(codec_parts) > 1) and (codec_parts[1].lower().startswith("opus")):
                opus_payload_types_detected.append(int(codec_parts[0]))
                _LOGGER.debug("Detected OPUS payload type as %s", opus_payload_type)

    if len(opus_payload_types_detected) > 0:
        opus_payload_type = opus_payload_types_detected[0]
        _LOGGER.debug("Using first detected payload type: %s", opus_payload_type)
    else:
        opus_payload_type = OPUS_PAYLOAD_TYPE
        _LOGGER.debug("Using default payload type: %s", opus_payload_type)

    return RtpInfo(rtp_ip=rtp_ip, rtp_port=rtp_port, payload_type=opus_payload_type)


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
            message = data.decode("utf-8")
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

            caller_endpoint = None
            # The From header should give us the URI used for sending SIP messages to the device
            if headers.get("from") is not None:
                caller_endpoint = SipEndpoint(headers.get("from", ""))
            # We can try using the Contact header as a fallback
            elif headers.get("contact") is not None:
                caller_endpoint = SipEndpoint(headers.get("contact", ""))
            # If all else fails try to generate a URI based on the IP and port from the address the message came from
            else:
                caller_endpoint = get_sip_endpoint(caller_ip, port=caller_sip_port)

            _LOGGER.debug("Incoming call from endpoint=%s", caller_endpoint)

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
            # sip:user@123.123.123.123:1234
            re_splituri = re.compile(
                r"(?P<scheme>\w+):"  # Scheme
                + r"(?:(?P<user>[\w\.]+):?(?P<password>[\w\.]+)?@)?"  # User:Password
                + r"\[?(?P<host>"  # Begin group host
                + r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|"  # IPv4 address Host Or
                + r"(?:(?:[0-9a-fA-F]{1,4}):){7}[0-9a-fA-F]{1,4}|"  # IPv6 address Host Or
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
            if not is_ipv4_address(server_ip):
                raise VoipError(f"Invalid IPv4 address in {ruri}")

            self.on_call(
                CallInfo(
                    caller_endpoint=caller_endpoint,
                    caller_rtp_port=caller_rtp_port,
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
        """Send OK message to caller with our IP and RTP port."""
        if self.transport is None:
            return

        # SDP = Session Description Protocol
        # See: https://datatracker.ietf.org/doc/html/rfc2327
        body_lines = [
            "v=0",
            f"o={self.sdp_info.username} {self.sdp_info.id} 1 IN IP4 {call_info.server_ip}",
            f"s={self.sdp_info.session_name}",
            f"c=IN IP4 {call_info.server_ip}",
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


class CallPhoneDatagramProtocol(asyncio.DatagramProtocol, ABC):
    def __init__(
        self,
        sdp_info: SdpInfo | None,
        source: SipEndpoint,
        dest: SipEndpoint,
        rtp_port: int,
    ) -> None:
        self.sdp_info = sdp_info
        self.transport = None
        self._closed_event = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        self._session_id = str(time.monotonic_ns())
        self._session_version = self._session_id
        self._call_id = self._session_id
        self._source_endpoint = source
        self._dest_endpoint = dest
        self._rtp_port = rtp_port

    def connection_made(self, transport):
        self.transport = transport

        sdp_lines = [
            "v=0",
            f"o={self._source_endpoint.username} {self._session_id} {self._session_version} IN IP4 {self._source_endpoint.host}",
            "s=Talk",
            f"c=IN IP4 {self._source_endpoint.host}",
            "t=0 0",
            f"m=audio {self._rtp_port} RTP/AVP 123 96 101 103 104",
            "a=sendrecv",
            "a=rtpmap:96 opus/48000/2",
            "a=fmtp:96 useinbandfec=0",
            "a=rtpmap:123 opus/48000/2",
            "a=fmtp:123 maxplaybackrate=16000",
            "a=rtpmap:101 telephone-event/48000",
            "a=rtpmap:103 telephone-event/16000",
            "a=rtpmap:104 telephone-event/8000",
            "a=ptime:20",
            "",
        ]
        sdp_text = _CRLF.join(sdp_lines)
        sdp_bytes = sdp_text.encode("utf-8")

        invite_lines = [
            f"INVITE {self._dest_endpoint.uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self._source_endpoint.host}:{self._source_endpoint.port}",
            f"From: {self._source_endpoint.sip_header}",
            f"Contact: {self._source_endpoint.sip_header}",
            f"To: {self._dest_endpoint.sip_header}",
            f"Call-ID: {self._call_id}",
            "CSeq: 50 INVITE",
            "User-Agent: test-agent 1.0",
            "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE",
            "Accept: application/sdp, application/dtmf-relay",
            "Content-Type: application/sdp",
            f"Content-Length: {len(sdp_bytes)}",
            "",
        ]
        invite_text = _CRLF.join(invite_lines) + _CRLF
        invite_bytes = invite_text.encode("utf-8")

        _LOGGER.debug(invite_bytes + sdp_bytes)

        self.transport.sendto(
            invite_bytes + sdp_bytes,
            (self._dest_endpoint.host, self._dest_endpoint.port),
        )

    def datagram_received(self, data: bytes, addr):
        response_text = data.decode("utf-8")
        response_lines = response_text.splitlines()
        _LOGGER.debug(response_lines)
        is_ok = False

        for i, line in enumerate(response_lines):
            line = line.strip()
            if not line:
                break
            if i > 0:
                continue
            _version, code, response_type = line.split(maxsplit=2)
            _LOGGER.debug(
                "Version=%s, Code=%s, response_type=%s",
                _version,
                code,
                response_type,
            )
            if (code == "200") and (response_type == "OK"):
                is_ok = True
            elif code == "401":
                _LOGGER.debug(
                    "Got 401 Unauthorized response, should attempt authentication here..."
                )
                # register_lines = [
                #    f"REGISTER {self._dest_endpoint.uri} SIP/2.0",
                #    f"Via: SIP/2.0/UDP {self._source_endpoint.host}:{self._source_endpoint.port}",
                #    f"From: {self._source_endpoint.sip_header}",
                #    f"Contact: {self._source_endpoint.sip_header}",
                #    f"To: {self._dest_endpoint.sip_header}",
                #    f"Call-ID: {self._call_id}",
                #    "CSeq: 51 REGISTER",
                #    "Authorization: ",
                #    "User-Agent: test-agent 1.0",
                #    "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE",
                #    "",
                # ]
            elif _version == "BYE":
                _LOGGER.debug("Received BYE message: %s", line)
                if self.transport is None:
                    _LOGGER.debug("Skipping message: %s", line)
                    continue

                # Acknowledge the BYE message, otherwise the phone will keep sending it
                (
                    protocol,
                    code,
                    reason,
                    headers,
                    body,
                ) = self._parse_sip_reply(response_text)
                _LOGGER.debug(
                    "Parsed response protocol=%s code=%s reason=%s headers=[%s] body=[%s]",
                    protocol,
                    code,
                    reason,
                    headers,
                    body,
                )
                rtp_info = get_rtp_info(body)
                remote_rtp_port = rtp_info.rtp_port
                opus_payload_type = rtp_info.payload_type
                via_header = headers["via"]
                from_header = headers["from"]
                to_header = headers["to"]
                callid_header = headers["call-id"]
                cseq_header = headers["cseq"]
                ok_lines = [
                    "SIP/2.0 200 OK",
                    f"Via: {via_header}",
                    f"From: {from_header}",
                    f"To: {to_header}",
                    f"Call-ID: {callid_header}",
                    f"CSeq: {cseq_header}",
                    "User-Agent: test-agent 1.0",
                    "Content-Length: 0",
                ]
                ok_text = _CRLF.join(ok_lines) + _CRLF
                ok_bytes = ok_text.encode("utf-8")
                # We should probably tell the associated RTP server to shutdown at this point, assuming we aren't reusing it for other calls
                _LOGGER.debug("Sending OK for BYE message: %s", ok_text)
                self.transport.sendto(
                    ok_bytes,
                    (self._dest_endpoint.host, self._dest_endpoint.port),
                )

                self.transport.close()
                self.transport = None

        if not is_ok:
            _LOGGER.debug("Received non-OK response [%s]", response_text)
            return

        _LOGGER.debug("Got OK message")
        if self.transport is None:
            _LOGGER.debug("No transport for exchanging SIP message")
            return

        protocol, code, reason, headers, body = self._parse_sip_reply(response_text)
        _LOGGER.debug(
            "Parsed response protocol=%s code=%s reason=%s headers=[%s] body=[%s]",
            protocol,
            code,
            reason,
            headers,
            body,
        )
        rtp_info = get_rtp_info(body)
        remote_rtp_port = rtp_info.rtp_port
        opus_payload_type = rtp_info.payload_type
        to_header = headers["to"]
        ack_lines = [
            f"ACK {self._dest_endpoint.uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self._source_endpoint.host}:{self._source_endpoint.port}",
            f"From: {self._source_endpoint.sip_header}",
            f"To: {to_header}",
            f"Call-ID: {self._call_id}",
            "CSeq: 50 ACK",
            "User-Agent: test-agent 1.0",
            "Content-Length: 0",
        ]
        ack_text = _CRLF.join(ack_lines) + _CRLF
        ack_bytes = ack_text.encode("utf-8")
        self.transport.sendto(
            ack_bytes, (self._dest_endpoint.host, self._dest_endpoint.port)
        )

        # The call been answered, proceed with desired action here
        self.on_call(
            CallInfo(
                caller_endpoint=self._dest_endpoint,
                caller_rtp_port=remote_rtp_port,
                server_ip=self._dest_endpoint.host,
                headers=headers,
                opus_payload_type=opus_payload_type,  # Should probably update this to eventually support more codecs
            )
        )

    @abstractmethod
    def on_call(self, call_info: CallInfo):
        """Handle outgoing calls."""

    @abstractmethod
    def call_cleanup(self):
        """Handle cleanup after ending call."""

    def hang_up(self):
        """Hang up the call when finished"""
        bye_lines = [
            f"BYE {self._dest_endpoint.uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self._source_endpoint.host}:{self._source_endpoint.port}",
            f"From: {self._source_endpoint.sip_header}",
            f"To: {self._dest_endpoint.sip_header}",
            f"Call-ID: {self._call_id}",
            "CSeq: 51 BYE",
            "User-Agent: test-agent 1.0",
            "Content-Length: 0",
            "",
        ]
        _LOGGER.debug("Hanging up...")
        bye_text = _CRLF.join(bye_lines) + _CRLF
        bye_bytes = bye_text.encode("utf-8")
        self.transport.sendto(
            bye_bytes, (self._dest_endpoint.host, self._dest_endpoint.port)
        )

        self.call_cleanup()

        self.transport.close()
        self.transport = None

    def connection_lost(self, exc):
        """Signal wait_closed when transport is completely closed."""
        _LOGGER.debug("Connection lost")
        self._closed_event.set()
        self.call_cleanup()

    async def wait_closed(self) -> None:
        """Wait for connection_lost to be called."""
        await self._closed_event.wait()

    def _parse_sip_reply(
        self, message: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Dict[str, str], str]:
        """Parse SIP message and return method, headers, and body."""
        lines = message.splitlines()

        protocol: Optional[str] = None
        code: Optional[str] = None
        reason: Optional[str] = None
        headers: dict[str, str] = {}
        offset: int = 0

        # See: https://datatracker.ietf.org/doc/html/rfc3261
        for i, line in enumerate(lines):
            if line:
                offset += len(line) + len(_CRLF)

            if i == 0:
                line_parts = line.split()
                protocol = line_parts[0]
                code = line_parts[1]
                reason = line_parts[2]
            elif not line:
                break
            else:
                key, value = line.split(":", maxsplit=1)
                headers[key.lower()] = value.strip()

        body = message[offset:]

        return protocol, code, reason, headers, body
