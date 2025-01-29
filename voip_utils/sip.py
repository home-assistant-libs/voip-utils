"""Implementation of SIP (Session Initiation Protocol)."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

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

    def __post_init__(self):
        header_pattern = re.compile(
            r'\s*((?P<description>\b\w+\b|"[^"]+")\s*)?<?(?P<uri>sips?:[^>]+)>?.*'
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
    def parse_sip(message: str) -> SipMessage:
        """Parse a SIP message into a SipMessage object."""
        lines = message.splitlines()

        method: Optional[str] = None
        request_uri: Optional[str] = None
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
                if line_parts[0].startswith("SIP"):
                    protocol = line_parts[0]
                    code = line_parts[1]
                    reason = line_parts[2]
                else:
                    method = line_parts[0]
                    request_uri = line_parts[1]
                    protocol = line_parts[2]
            elif not line:
                break
            else:
                key, value = line.split(":", maxsplit=1)
                headers[key.lower()] = value.strip()

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
        self._outgoing_calls: dict[str, int] = {}

    def outgoing_call(
        self, source: SipEndpoint, destination: SipEndpoint, rtp_port: int
    ) -> CallInfo:
        """Make an outgoing call from the given source endpoint to the destination endpoint, using the rtp_port for the local RTP port of the call."""
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
            (destination.host, destination.port),
        )

        return CallInfo(
            caller_endpoint=destination,
            local_endpoint=source,
            caller_rtp_port=rtp_port,
            server_ip=source.host,
            headers={"call-id": call_id},
        )

    def hang_up(self, call_info: CallInfo):
        """Hang up the call when finished"""
        if self.transport is None:
            raise RuntimeError("No transport available for sending hangup.")

        bye_lines = [
            f"BYE {call_info.caller_endpoint.uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {call_info.local_endpoint.host}:{call_info.local_endpoint.port}",
            f"From: {call_info.local_endpoint.sip_header}",
            f"To: {call_info.caller_endpoint.sip_header}",
            f"Call-ID: {call_info.headers['call-id']}",
            "CSeq: 51 BYE",
            f"User-Agent: {VOIP_UTILS_AGENT} 1.0",
            "Content-Length: 0",
            "",
        ]
        _LOGGER.debug("Hanging up...")
        bye_text = _CRLF.join(bye_lines) + _CRLF
        bye_bytes = bye_text.encode("utf-8")
        self.transport.sendto(
            bye_bytes, (call_info.caller_endpoint.host, call_info.caller_endpoint.port)
        )

        self._end_outgoing_call(call_info.headers["call-id"])
        self.on_hangup(call_info)

    def cancel_call(self, call_info: CallInfo):
        """Cancel an outgoing call while it's still ringing."""
        if self.transport is None:
            raise RuntimeError("No transport available for sending cancel.")

        cancel_lines = [
            f"CANCEL {call_info.caller_endpoint.uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {call_info.local_endpoint.host}:{call_info.local_endpoint.port}",
            f"From: {call_info.local_endpoint.sip_header}",
            f"To: {call_info.caller_endpoint.sip_header}",
            f"Call-ID: {call_info.headers['call-id']}",
            "CSeq: 51 CANCEL",
            f"User-Agent: {VOIP_UTILS_AGENT} 1.0",
            "Content-Length: 0",
            "",
        ]
        _LOGGER.debug("Canceling call...")
        cancel_text = _CRLF.join(cancel_lines) + _CRLF
        cancel_bytes = cancel_text.encode("utf-8")
        self.transport.sendto(
            cancel_bytes,
            (call_info.caller_endpoint.host, call_info.caller_endpoint.port),
        )

        self._end_outgoing_call(call_info.headers["call-id"])
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
                # The From header should give us the URI used for sending SIP messages to the device
                if smsg.headers.get("from") is not None:
                    caller_endpoint = SipEndpoint(smsg.headers.get("from", ""))
                # We can try using the Contact header as a fallback
                elif smsg.headers.get("contact") is not None:
                    caller_endpoint = SipEndpoint(smsg.headers.get("contact", ""))
                # If all else fails try to generate a URI based on the IP and port from the address the message came from
                else:
                    caller_endpoint = get_sip_endpoint(caller_ip, port=caller_sip_port)

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
                    )
                )
            elif method is None:
                # Reply message means we must have received a response to someone we called
                # TODO: Verify that the call / sequence IDs match our outgoing INVITE
                _LOGGER.debug("Received response [%s]", message)
                is_ok = smsg.code == "200" and smsg.reason == "OK"
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
                # The From header should give us the URI used for sending SIP messages to the device
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
                # We should probably tell the associated RTP server to shutdown at this point, assuming we aren't reusing it for other calls
                _LOGGER.debug("Sending OK for BYE message: %s", ok_text)
                self.transport.sendto(
                    ok_bytes,
                    (caller_ip, caller_sip_port),
                )
                # The transport might be used for incoming calls
                # as well, so we should leave it open.

                # Cleanup any necessary call state
                self.on_hangup(
                    CallInfo(
                        caller_endpoint=caller_endpoint,
                        local_endpoint=local_endpoint,
                        caller_rtp_port=remote_rtp_port,
                        server_ip=remote_rtp_ip,
                        headers=smsg.headers,
                    )
                )

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
