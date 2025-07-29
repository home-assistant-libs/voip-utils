"""Implementation of SIP (Session Initiation Protocol)."""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .const import OPUS_PAYLOAD_TYPE
from .error import VoipError
from .util import is_ipv4_address

SIP_PORT = 5060

_LOGGER = logging.getLogger(__name__)
_CRLF = "\r\n"

VOIP_UTILS_AGENT = "voip-utils"


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
    uri_parameters: dict[str, str] | None = field(init=False)
    uri_headers: dict[str, str] | None = field(init=False)
    header_parameters: dict[str, str] | None = field(init=False)

    def __post_init__(self):
        header_pattern = re.compile(
            r"""
           ^\s*
           (?:(?P<description>\b[^<\s"]+\b|"[^"]+")\s*)?
           (?:
            <(?P<uri_bracketed>sips?:[^>]+)>
            |
            (?P<uri_unbracketed>sips?:[^\s;]+)
           )
           \s*
           (?P<header_params>(?:;\s*[^=;]+(?:=[^;]*)?)*)
           .*$
        """,
            re.VERBOSE | re.IGNORECASE,
        )
        header_match = header_pattern.match(self.sip_header)
        if header_match is not None:
            description_token = header_match.group("description")
            if description_token is not None:
                self.description = description_token.strip('"')
            else:
                self.description = None
            self.uri = (
                header_match.group("uri_bracketed")
                if header_match.group("uri_bracketed")
                else header_match.group("uri_unbracketed")
            )
            uri_pattern = re.compile(
                r"(?P<scheme>sips?):(?:(?P<user>[^@]+)@)?(?P<host>[^:;?]+)(?::(?P<port>\d+))?(?P<params>(?:;[^;=?]+(?:=[^;?]*)?)*)?(?:\?(?P<headers>[^#]*))?"
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
            self.uri_parameters: dict[str, str] = {}
            if uri_match.group("params"):
                for param in uri_match.group("params").lstrip(";").split(";"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        self.uri_parameters[key.strip()] = value.strip()
                    elif param.strip():
                        self.uri_parameters[param.strip()] = ""
            self.uri_headers: dict[str, str] = {}
            if uri_match.group("headers"):
                for pair in uri_match.group("headers").split("&"):
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        self.uri_headers[key.strip()] = value.strip()
            self.header_parameters: dict[str, str] = {}
            if header_match.group("header_params"):
                for param in header_match.group("header_params").lstrip(";").split(";"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        self.header_parameters[key.strip()] = value.strip()
                    elif param.strip():
                        self.header_parameters[param.strip()] = ""

        else:
            raise ValueError("Invalid SIP header")

    @property
    def base_uri(self) -> str:
        user_part = f"{self.username}@" if self.username else ""
        port_part = f":{self.port}" if self.port != SIP_PORT else ""
        return f"{self.scheme}:{user_part}{self.host}{port_part}"


@dataclass
class SipMessage:
    """Data parsed from a SIP message."""

    protocol: str
    method: Optional[str]
    request_uri: Optional[str]
    code: Optional[str]
    reason: Optional[str]
    headers: dict[str, str]
    body: str

    @staticmethod
    def parse_sip(message: str, header_lowercase: bool = True) -> SipMessage:
        """Parse a SIP message into a SipMessage object."""
        lines = message.splitlines()

        method: Optional[str] = None
        request_uri: Optional[str] = None
        code: Optional[str] = None
        reason: Optional[str] = None
        headers: dict[str, str] = {}
        offset: int = 0

        first_line = True

        # See: https://datatracker.ietf.org/doc/html/rfc3261
        for line in lines:
            if first_line:
                if line:
                    offset += len(line) + len(_CRLF)
                    line_parts = line.split()
                    if line_parts[0].startswith("SIP"):
                        protocol = line_parts[0]
                        code = line_parts[1]
                        reason = line_parts[2]
                    else:
                        method = line_parts[0]
                        request_uri = line_parts[1]
                        protocol = line_parts[2]
                    first_line = False
                else:
                    offset += len(_CRLF)
            elif not line:
                offset += len(_CRLF)
                break
            else:
                offset += len(line) + len(_CRLF)
                key, value = line.split(":", maxsplit=1)
                headers[key.lower() if header_lowercase else key] = value.strip()

        body = message[offset:]
        return SipMessage(protocol, method, request_uri, code, reason, headers, body)


@dataclass
class CallInfo:
    """Information gathered from an INVITE message."""

    caller_endpoint: SipEndpoint
    local_endpoint: SipEndpoint
    caller_rtp_port: int
    server_ip: str
    headers: dict[str, str]
    opus_payload_type: int = OPUS_PAYLOAD_TYPE
    local_rtp_ip: str | None = None
    local_rtp_port: int | None = None
    contact_endpoint: SipEndpoint | None = None
    via_host: str | None = None
    via_port: int | None = None

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

    @property
    def contact_host(self) -> str | None:
        """Get host address of contact header."""
        return self.contact_endpoint.host if self.contact_endpoint is not None else None

    @property
    def contact_port(self) -> int | None:
        """SIP port of contact header."""
        return self.contact_endpoint.port if self.contact_endpoint is not None else None

    @property
    def local_rtcp_port(self) -> int | None:
        """Get the local RTCP port."""
        return self.local_rtp_port + 1 if self.local_rtp_port is not None else None


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
    uri_parameters: Optional[dict[str, str]] = None,
    uri_headers: Optional[dict[str, str]] = None,
    header_parameters: Optional[dict[str, str]] = None,
) -> SipEndpoint:
    uri = f"{scheme}:"
    if username:
        uri += f"{username}@"
    uri += host
    if port:
        uri += f":{port}"
    if uri_parameters:
        for key, value in uri_parameters.items():
            if value:
                uri += f";{key}={value}"
            else:
                uri += f";{key}"
    if uri_headers:
        parts = [f"{key}={value}" for key, value in uri_headers.items()]
        uri += "?" + "&".join(parts)
    if description:
        uri = f'"{description}" <{uri}>'
    if header_parameters:
        for key, value in header_parameters.items():
            if value:
                uri += f";{key}={value}"
            else:
                uri += f";{key}"
    return SipEndpoint(uri)


def parse_via_header(value: str) -> Optional[Tuple[str, int]]:
    """Parse the host and port from a Via header."""
    pattern = re.compile(r"SIP/2\.0/\w+\s+(?P<host>[^:;\s]+)(?::(?P<port>\d+))?")
    match = pattern.search(value)
    if not match:
        return None

    host = match.group("host")
    port_str = match.group("port")
    port = int(port_str) if port_str is not None else SIP_PORT
    return host, port


def get_response_host(call_info: CallInfo) -> str:
    if call_info.via_host:
        return call_info.via_host
    if call_info.contact_host:
        return call_info.contact_host

    return call_info.caller_ip


def get_response_port(call_info: CallInfo) -> int:
    if call_info.via_port:
        return call_info.via_port
    if call_info.contact_port:
        return call_info.contact_port

    return call_info.caller_sip_port


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


def get_header(headers: dict[str, str], name: str) -> tuple[str, str] | None:
    """Get a header entry using a case insensitive key comparison."""
    return next(((k, v) for k, v in headers.items() if k.lower() == name.lower()), None)


class SipDatagramProtocol(asyncio.DatagramProtocol, ABC):
    """UDP server for the Session Initiation Protocol (SIP)."""

    def __init__(self, sdp_info: SdpInfo) -> None:
        """Set up SIP server."""
        self.sdp_info = sdp_info
        self.transport = None
        self._outgoing_calls: dict[str, int] = {}

    def outgoing_call(
        self,
        source: SipEndpoint,
        destination: SipEndpoint,
        rtp_port: int,
        contact: Optional[SipEndpoint] = None,
    ) -> CallInfo:
        """Make an outgoing call from the given source endpoint to the destination and contact endpoint, using the rtp_port for the local RTP port of the call."""
        if self.transport is None:
            raise RuntimeError("No transport available for outgoing call.")

        session_id = str(time.monotonic_ns())
        session_version = session_id
        call_id = session_id
        self._register_outgoing_call(call_id, rtp_port)

        sdp_lines = [
            "v=0",
            f"o={source.username} {session_id} {session_version} IN IP4 {source.host}",
            "s=Talk",
            f"c=IN IP4 {source.host}",
            "t=0 0",
            f"m=audio {rtp_port} RTP/AVP 123 96 101 103 104",
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
            f"INVITE {destination.uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {source.host}:{source.port}",
            f"From: {source.sip_header}",
            f"Contact: {source.sip_header}",
            f"To: {destination.sip_header}",
            f"Call-ID: {call_id}",
            "CSeq: 50 INVITE",
            f"User-Agent: {VOIP_UTILS_AGENT} 1.0",
            "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE",
            "Accept: application/sdp, application/dtmf-relay",
            "Content-Type: application/sdp",
            f"Content-Length: {len(sdp_bytes)}",
            "",
        ]
        invite_text = _CRLF.join(invite_lines) + _CRLF
        invite_bytes = invite_text.encode("utf-8")

        msg_bytes = invite_bytes + sdp_bytes

        _LOGGER.debug(msg_bytes)

        self.transport.sendto(
            msg_bytes,
            (
                contact.host if contact and contact.host else destination.host,
                contact.port if contact and contact.port else destination.port,
            ),
        )

        invite_msg = SipMessage.parse_sip(invite_text, False)

        return CallInfo(
            caller_endpoint=destination,
            local_endpoint=source,
            caller_rtp_port=rtp_port,
            server_ip=source.host,
            headers=invite_msg.headers,
            contact_endpoint=contact,
        )

    def hang_up(self, call_info: CallInfo):
        """Hang up the call when finished"""
        if self.transport is None:
            raise RuntimeError("No transport available for sending hangup.")

        call_id = get_header(call_info.headers, "call-id")[1]
        bye_lines = [
            f"BYE {call_info.caller_endpoint.uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {call_info.local_endpoint.host}:{call_info.local_endpoint.port}",
            f"From: {call_info.local_endpoint.sip_header}",
            f"To: {call_info.caller_endpoint.sip_header}",
            f"Call-ID: {call_id}",
            "CSeq: 51 BYE",
            f"User-Agent: {VOIP_UTILS_AGENT} 1.0",
            "Content-Length: 0",
            "",
        ]
        _LOGGER.debug("Hanging up...")
        bye_text = _CRLF.join(bye_lines) + _CRLF
        bye_bytes = bye_text.encode("utf-8")
        response_host = get_response_host(call_info)
        response_port = get_response_port(call_info)
        self.transport.sendto(bye_bytes, (response_host, response_port))

        self._end_outgoing_call(call_info.headers["call-id"])
        self.on_hangup(call_info)

    def cancel_call(self, call_info: CallInfo):
        """Cancel an outgoing call while it's still ringing."""
        if self.transport is None:
            raise RuntimeError("No transport available for sending cancel.")

        required_headers = ("via", "from", "to", "call-id")

        cancel_headers = [
            f"{k}: {v}"
            for k, v in call_info.headers.items()
            if k.lower() in required_headers
        ]

        cseq_header, cseq_value = get_header(call_info.headers, "cseq")
        cseq_num = cseq_value.split()[0]

        cancel_lines = (
            [f"CANCEL {call_info.caller_endpoint.uri} SIP/2.0"]
            + cancel_headers
            + [
                f"{cseq_header}: {cseq_num} CANCEL",
                f"User-Agent: {VOIP_UTILS_AGENT} 1.0",
                "Content-Length: 0",
                "",
            ]
        )
        _LOGGER.debug("Canceling call...")
        cancel_text = _CRLF.join(cancel_lines) + _CRLF
        cancel_bytes = cancel_text.encode("utf-8")

        response_host = get_response_host(call_info)
        response_port = get_response_port(call_info)

        self.transport.sendto(
            cancel_bytes,
            (response_host, response_port),
        )

        self._end_outgoing_call(get_header(call_info.headers, "call-id")[1])
        self.on_hangup(call_info)

    def _register_outgoing_call(self, call_id: str, rtp_port: int):
        """Register the RTP port associated with an outgoing call."""
        self._outgoing_calls[call_id] = rtp_port

    def _get_call_rtp_port(self, call_id: str) -> int | None:
        """Get the RTP port associated with an outgoing call."""
        return self._outgoing_calls.get(call_id)

    def _end_outgoing_call(self, call_id: str):
        """Register the end of an outgoing call."""
        self._outgoing_calls.pop(call_id, None)

    def connection_made(self, transport):
        """Server ready."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        """Handle INVITE SIP messages."""
        try:
            if self.transport is None:
                _LOGGER.warning("No transport for exchanging SIP message")
                return

            caller_ip, caller_sip_port = addr
            message = data.decode("utf-8")
            smsg = SipMessage.parse_sip(message)
            _LOGGER.debug(
                "Received datagram protocol=[%s], method=[%s], ruri=[%s], code=[%s], reason=[%s], headers=[%s], body=[%s]",
                smsg.protocol,
                smsg.method,
                smsg.request_uri,
                smsg.code,
                smsg.reason,
                smsg.headers,
                smsg.body,
            )
            method = smsg.method
            if method is not None:
                method = method.lower()

            if method == "invite":
                # An invite message means someone called HA
                _LOGGER.debug("Received invite message")
                if not smsg.request_uri:
                    raise ValueError("Empty receiver URI")

                caller_endpoint = None
                # The From header should give us the URI used for identifying the device
                if smsg.headers.get("from") is not None:
                    caller_endpoint = SipEndpoint(smsg.headers.get("from", ""))
                # We can try using the Contact header as a fallback
                elif smsg.headers.get("contact") is not None:
                    caller_endpoint = SipEndpoint(smsg.headers.get("contact", ""))
                # If all else fails try to generate a URI based on the IP and port from the address the message came from
                else:
                    caller_endpoint = get_sip_endpoint(caller_ip, port=caller_sip_port)

                # We need to get the URI needed for initiating messages to the device from the Contact header
                if smsg.headers.get("contact") is not None:
                    contact_endpoint = SipEndpoint(smsg.headers.get("contact", ""))
                # If all else fails try to generate a URI based on the IP and port from the address the message came from
                else:
                    contact_endpoint = get_sip_endpoint(caller_ip, port=caller_sip_port)

                # We need to get the URI needed for sending replies to the device from the Via header
                if smsg.headers.get("via") is not None and (
                    via_result := parse_via_header(smsg.headers.get("via"))
                ):
                    via_host, via_port = via_result
                # If all else fails use the Contact header, which may have been generated based on the IP and port the message came from
                else:
                    via_host = contact_endpoint.host
                    via_port = contact_endpoint.port

                local_endpoint = None
                if smsg.headers.get("to") is not None:
                    local_endpoint = SipEndpoint(smsg.headers.get("to", ""))
                else:
                    local_ip, local_port = self.transport.get_extra_info("sockname")
                    local_endpoint = get_sip_endpoint(local_ip, port=local_port)

                _LOGGER.debug("Incoming call from endpoint=%s", caller_endpoint)

                # Extract caller's RTP port from SDP.
                # See: https://datatracker.ietf.org/doc/html/rfc2327
                caller_rtp_port: Optional[int] = None
                opus_payload_type = OPUS_PAYLOAD_TYPE
                body_lines = smsg.body.splitlines()
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
                                    "Detected OPUS payload type as %s",
                                    opus_payload_type,
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
                re_uri = re_splituri.search(smsg.request_uri)
                if re_uri is None:
                    raise ValueError("Receiver URI did not match expected pattern")

                server_ip = re_uri.group("host")
                if not is_ipv4_address(server_ip):
                    raise VoipError(f"Invalid IPv4 address in {smsg.request_uri}")

                self.on_call(
                    CallInfo(
                        caller_endpoint=caller_endpoint,
                        local_endpoint=local_endpoint,
                        caller_rtp_port=caller_rtp_port,
                        server_ip=server_ip,
                        headers=smsg.headers,
                        opus_payload_type=opus_payload_type,
                        contact_endpoint=contact_endpoint,
                        via_host=via_host,
                        via_port=via_port,
                    )
                )
            elif method is None:
                # Reply message means we must have received a response to someone we called
                # TODO: Verify that the call / sequence IDs match our outgoing INVITE
                _LOGGER.debug("Received response [%s]", message)
                is_ok = smsg.code == "200" and smsg.reason == "OK"
                if smsg.code == "487":
                    # A 487 Request Terminated will be sent in response to a Cancel message
                    _LOGGER.debug("Got 487 Request Terminated")
                    caller_endpoint = None
                    if smsg.headers.get("to") is not None:
                        caller_endpoint = SipEndpoint(smsg.headers.get("to", ""))
                    else:
                        caller_endpoint = get_sip_endpoint(
                            caller_ip, port=caller_sip_port
                        )
                    cseq_num = get_header(smsg.headers, "cseq")[1].split()[0]
                    ack_lines = [
                        f"ACK {caller_endpoint.uri} SIP/2.0",
                        f"Via: {smsg.headers['via']}",
                        f"From: {smsg.headers['from']}",
                        f"To: {smsg.headers['to']}",
                        f"Call-ID: {smsg.headers['call-id']}",
                        f"CSeq: {cseq_num} ACK",
                        f"User-Agent: {VOIP_UTILS_AGENT} 1.0",
                        "Content-Length: 0",
                    ]
                    ack_text = _CRLF.join(ack_lines) + _CRLF
                    ack_bytes = ack_text.encode("utf-8")
                    via_result = parse_via_header(smsg.headers["via"])
                    if via_result:
                        response_host, response_port = via_result
                    else:
                        response_host = caller_ip
                        response_port = caller_sip_port
                    self.transport.sendto(ack_bytes, (response_host, response_port))
                    return
                if not is_ok:
                    _LOGGER.debug("Received non-OK response [%s]", message)
                    return

                _LOGGER.debug("Got OK message")
                if not self._is_response_type(smsg, "invite"):
                    # This will happen if/when we hang up.
                    _LOGGER.debug("Got response for non-invite message")
                    return

                _LOGGER.debug("Got invite response")
                rtp_info = get_rtp_info(smsg.body)
                remote_rtp_ip = rtp_info.rtp_ip
                remote_rtp_port = rtp_info.rtp_port
                opus_payload_type = rtp_info.payload_type
                caller_endpoint = None
                if smsg.headers.get("to") is not None:
                    caller_endpoint = SipEndpoint(smsg.headers.get("to", ""))
                else:
                    caller_endpoint = get_sip_endpoint(caller_ip, port=caller_sip_port)
                # The From header should give us the URI used for identifying the device
                local_endpoint = None
                if smsg.headers.get("from") is not None:
                    local_endpoint = SipEndpoint(smsg.headers.get("from", ""))
                else:
                    local_endpoint = get_sip_endpoint(caller_ip, port=caller_sip_port)

                _LOGGER.debug("Outgoing call to endpoint=%s", caller_endpoint)
                ack_lines = [
                    f"ACK {caller_endpoint.uri} SIP/2.0",
                    f"Via: SIP/2.0/UDP {local_endpoint.host}:{local_endpoint.port}",
                    f"From: {local_endpoint.sip_header}",
                    f"To: {smsg.headers['to']}",
                    f"Call-ID: {smsg.headers['call-id']}",
                    "CSeq: 50 ACK",
                    f"User-Agent: {VOIP_UTILS_AGENT} 1.0",
                    "Content-Length: 0",
                ]
                ack_text = _CRLF.join(ack_lines) + _CRLF
                ack_bytes = ack_text.encode("utf-8")
                self.transport.sendto(ack_bytes, (caller_ip, caller_sip_port))

                # The call been answered, proceed with desired action here
                local_rtp_port = self._get_call_rtp_port(smsg.headers["call-id"])
                self.on_call(
                    CallInfo(
                        caller_endpoint=caller_endpoint,
                        local_endpoint=local_endpoint,
                        caller_rtp_port=remote_rtp_port,
                        server_ip=remote_rtp_ip,
                        headers=smsg.headers,
                        opus_payload_type=opus_payload_type,  # Should probably update this to eventually support more codecs
                        local_rtp_ip=local_endpoint.host,
                        local_rtp_port=local_rtp_port,
                    )
                )
            elif method == "bye":
                # Acknowlege the BYE message when the remote party hangs up
                _LOGGER.debug("Received BYE message: %s", message)
                if self.transport is None:
                    _LOGGER.debug("Skipping message: %s", message)
                    return

                # The From header should give us the URI used for sending SIP messages to the device
                if smsg.headers.get("from") is not None:
                    caller_endpoint = SipEndpoint(smsg.headers.get("from", ""))
                # We can try using the Contact header as a fallback
                elif smsg.headers.get("contact") is not None:
                    caller_endpoint = SipEndpoint(smsg.headers.get("contact", ""))
                # If all else fails try to generate a URI based on the IP and port from the address the message came from
                else:
                    caller_endpoint = get_sip_endpoint(caller_ip, port=caller_sip_port)

                # We need to get the URI needed for initiating messages to the device from the Contact header
                if smsg.headers.get("contact") is not None:
                    contact_endpoint = SipEndpoint(smsg.headers.get("contact", ""))
                # If all else fails try to generate a URI based on the IP and port from the address the message came from
                else:
                    contact_endpoint = get_sip_endpoint(caller_ip, port=caller_sip_port)

                # We need to get the URI needed for sending replies to the device from the Via header
                if smsg.headers.get("via") is not None and (
                    via_result := parse_via_header(smsg.headers.get("via"))
                ):
                    via_host, via_port = via_result
                # If all else fails use the Contact header, which may have been generated based on the IP and port the message came from
                else:
                    via_host = contact_endpoint.host
                    via_port = contact_endpoint.port

                local_endpoint = None
                if smsg.headers.get("to") is not None:
                    local_endpoint = SipEndpoint(smsg.headers.get("to", ""))
                else:
                    local_ip, local_port = self.transport.get_extra_info("sockname")
                    local_endpoint = get_sip_endpoint(local_ip, port=local_port)

                _LOGGER.debug("Incoming BYE from endpoint=%s", caller_endpoint)

                # Acknowledge the BYE message, otherwise the phone will keep sending it
                rtp_info = get_rtp_info(smsg.body)
                remote_rtp_ip = rtp_info.rtp_ip
                remote_rtp_port = rtp_info.rtp_port
                opus_payload_type = rtp_info.payload_type
                # We should remove the call from the outgoing calls dict now if it is there
                self._end_outgoing_call(smsg.headers["call-id"])
                ok_lines = [
                    "SIP/2.0 200 OK",
                    f"Via: {smsg.headers['via']}",
                    f"From: {smsg.headers['from']}",
                    f"To: {smsg.headers['to']}",
                    f"Call-ID: {smsg.headers['call-id']}",
                    f"CSeq: {smsg.headers['cseq']}",
                    f"User-Agent: {VOIP_UTILS_AGENT} 1.0",
                    "Content-Length: 0",
                ]
                ok_text = _CRLF.join(ok_lines) + _CRLF
                ok_bytes = ok_text.encode("utf-8")

                call_info = CallInfo(
                    caller_endpoint=caller_endpoint,
                    local_endpoint=local_endpoint,
                    caller_rtp_port=remote_rtp_port,
                    server_ip=remote_rtp_ip,
                    headers=smsg.headers,
                    contact_endpoint=contact_endpoint,
                    via_host=via_host,
                    via_port=via_port,
                )
                # We should probably tell the associated RTP server to shutdown at this point, assuming we aren't reusing it for other calls
                _LOGGER.debug("Sending OK for BYE message: %s", ok_text)
                response_host = get_response_host(call_info)
                response_port = get_response_port(call_info)
                self.transport.sendto(
                    ok_bytes,
                    (response_host, response_port),
                )
                # The transport might be used for incoming calls
                # as well, so we should leave it open.

                # Cleanup any necessary call state
                self.on_hangup(call_info)

        except Exception:
            _LOGGER.exception("Unexpected error handling SIP message")

    @abstractmethod
    def on_call(self, call_info: CallInfo):
        """Handle incoming calls."""

    def on_hangup(self, call_info: CallInfo):
        """Handle the end of a call."""

    def _is_response_type(self, msg: SipMessage, resp_type: str) -> bool:
        """Return whether or not the response message is for the given type."""
        return (
            msg is not None
            and "cseq" in msg.headers
            and resp_type.lower() in msg.headers["cseq"].lower()
        )

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

        to_header = SipEndpoint(call_info.headers["to"])
        # Check if the TO header already includes a tag
        if "tag" not in to_header.header_parameters:
            new_params = (
                to_header.header_parameters.copy()
                if to_header.header_parameters
                else {}
            )
            new_params["tag"] = secrets.token_hex(8)
            to_header = get_sip_endpoint(
                host=to_header.host,
                port=to_header.port if to_header.port != SIP_PORT else None,
                scheme=to_header.scheme,
                username=to_header.username,
                description=to_header.description,
                uri_parameters=to_header.uri_parameters,
                uri_headers=to_header.uri_headers,
                header_parameters=new_params,
            )

        response_headers = {
            "Via": call_info.headers["via"],
            "From": call_info.headers["from"],
            "To": to_header.sip_header,  # Append the tag if necessary
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

        response_host = get_response_host(call_info)
        response_port = get_response_port(call_info)

        self.transport.sendto(
            response_bytes,
            (response_host, response_port),
        )
        _LOGGER.debug(
            "Sent OK to ip=%s, port=%s with rtp_port=%s",
            response_host,
            response_port,
            server_rtp_port,
        )
