"""Tests for rtp_audio."""

import struct

from voip_utils.rtp_audio import RtpOpusOutput


def _parse_rtp_header(packet: bytes) -> tuple[int, int, int, int, int]:
    """Parse RTP header: (flags, payload_type, seq_num, timestamp, ssrc)."""
    return struct.unpack(">BBHLL", packet[:12])


def test_rtp_opus_output_ssrc_persistence():
    """Verify SSRC remains constant throughout the session across resets and is_end."""
    output = RtpOpusOutput()
    initial_ssrc = output._rtp_ssrc

    # 1. Check silence frame SSRC
    silence_packet = output.silence_frame()
    _, _, seq1, ts1, ssrc1 = _parse_rtp_header(silence_packet)
    assert ssrc1 == initial_ssrc

    # 2. Process audio with is_end=True
    dummy_audio = bytes(output.opus_bytes_per_frame * 2)  # 2 frames
    packets = list(
        output.process_audio(
            dummy_audio,
            rate=output.opus_rate,
            width=output.opus_width,
            channels=output.opus_channels,
            is_end=True,
        )
    )
    assert len(packets) == 2

    for p in packets:
        _, _, _, _, ssrc = _parse_rtp_header(p)
        assert ssrc == initial_ssrc

    # 3. Explicit reset() must not change SSRC or sequence/timestamp clock
    output.reset()
    assert output._rtp_ssrc == initial_ssrc

    # 4. Subsequent silence frame must still have the same SSRC
    next_silence = output.silence_frame()
    _, _, seq_after, ts_after, ssrc_after = _parse_rtp_header(next_silence)
    assert ssrc_after == initial_ssrc
    assert seq_after == (seq1 + 3) & 0xFFFF
    assert ts_after == (ts1 + 3 * output.opus_frame_size) & 0xFFFFFFFF
