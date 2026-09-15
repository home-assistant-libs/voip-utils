# Changelog

## 0.5.0

- Address SIP responses, ACKs and BYEs using the transport source; `Via` supplies the response port only when its host agrees with that source, per the RFC 3261 "received" rule
- Ignore responses whose `Call-ID` does not match an INVITE we sent
- Stop carrying a `Via` host that is not an IPv4 literal into `sendto()`, where it would be resolved on the event loop
- Drop datagrams whose source is our own listening address
- Bound the free RTP/RTCP port search, and close the socket opened on each failed attempt; exhaustion now fails one call rather than looping on the event loop
- Stop answering our own outgoing calls, which made two voip-utils endpoints trade 200 OK and ACK for the length of a call
- Seed the outgoing RTP destination from the answered SDP, so a callee that only listens still receives audio
- Require the answered SDP address to be an IPv4 literal
- `CallInfo` gains `peer_address`, the source address of the datagram a received call arrived on
- `CallInfo.caller_ip` becomes `caller_uri_host`, since it is the host of the caller's URI rather than an address; `caller_ip` remains as an alias

## 0.4.3

- Clear queues on disconnect

## 0.4.2

- Remove upper limit on python version

## 0.4.1

- Move RTP audio output processing to separate task to maintain consistent schedule with silence sent when there is no active audio

## 0.4.0

- Update to opuslib-next

## 0.3.5

- Cleanup RTP/RTCP servers on hangup

## 0.3.4

- Add tag parameter to To header if missing
- Use header values for response host and port

## 0.3.3

- Handle empty lines at start of message

## 0.3.2

- Compliant cancel message

## 0.3.1

- Add cancel_call to stop ringing

## 0.3.0

- Add support for outgoing calls (@jaminh)

## 0.2.2

- Always set `addr`

## 0.2.1

- Use Python port of deprecated `audioop` module

## 0.2.0

- Add outgoing call feature

## 0.0.8

- Close RTP socket to free port

## 0.0.7

- Ensure payload type matches everywhere

## 0.0.6

- Detect OPUS payload type
- Update receiver URI parsing

## 0.0.5

- Initial release
