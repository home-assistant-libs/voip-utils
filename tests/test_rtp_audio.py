"""Tests for rtp_audio."""

# pylint: disable=protected-access

import math
import struct

import opuslib_next as opuslib
import pytest

from voip_utils.rtp_audio import RtpOpusInput, RtpOpusOutput


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


def _stereo_bit(packet: bytes) -> int:
    """Get the stereo flag from the TOC byte of an OPUS packet in RTP."""
    return (packet[12] >> 2) & 1


def _tone(seconds: float, channels: int, rate: int = 48000) -> bytes:
    """Make 16-bit audio of a 440Hz tone."""
    samples = []
    for i in range(int(rate * seconds)):
        sample = int(10000 * math.sin(2 * math.pi * 440 * i / rate))
        samples.extend([sample] * channels)
    return struct.pack(f"<{len(samples)}h", *samples)


@pytest.mark.parametrize(("channels", "stereo_bit"), [(1, 0), (2, 1)])
def test_rtp_opus_output_encoder_channels(channels, stereo_bit):
    """Encoded packets really carry the configured channel count."""
    output = RtpOpusOutput()
    output.set_channels(channels)

    packets = [output.silence_frame()] + list(
        output.process_audio(_tone(0.1, 1, 16000), 16000, 2, 1)
    )

    assert len(packets) > 1
    for packet in packets:
        assert _stereo_bit(packet) == stereo_bit
        assert opuslib.api.decoder.packet_get_nb_channels(packet[12:]) == channels


def test_rtp_opus_output_default_is_stereo():
    """Without a request for anything else the encoder stays stereo."""
    output = RtpOpusOutput()

    assert output.opus_channels == 2
    assert output.opus_bytes_per_frame == 960 * 2 * 2
    assert _stereo_bit(output.silence_frame()) == 1


@pytest.mark.parametrize("input_channels", [1, 2])
@pytest.mark.parametrize("output_channels", [1, 2])
def test_rtp_opus_output_converts_channels(input_channels, output_channels):
    """Any input layout makes full frames of audible audio for either encoder."""
    output = RtpOpusOutput()
    output.set_channels(output_channels)

    packets = list(
        output.process_audio(_tone(0.2, input_channels), 48000, 2, input_channels)
    )

    # 0.2 seconds of 20ms frames: the input was not read as the wrong layout
    assert len(packets) == 10

    rtp_input = RtpOpusInput()
    decoded = b"".join(rtp_input.process_packet(p, 48000, 2, 1) for p in packets)
    samples = struct.unpack(f"<{len(decoded) // 2}h", decoded)
    assert max(samples[len(samples) // 2 :]) > 5000


def test_rtp_opus_output_set_channels_keeps_rtp_stream():
    """Changing channels drops buffered audio but not the RTP stream state."""
    output = RtpOpusOutput()
    assert not list(output.process_audio(bytes(100), 48000, 2, 2))
    _, _, seq, timestamp, ssrc = _parse_rtp_header(output.silence_frame())

    output.set_channels(1)

    assert output._audio_buffer == b""
    _, _, next_seq, next_timestamp, next_ssrc = _parse_rtp_header(
        output.silence_frame()
    )
    assert next_ssrc == ssrc
    assert next_seq == seq + 1
    assert next_timestamp == timestamp + output.opus_frame_size


def test_rtp_opus_output_rejects_other_channel_counts():
    """Anything but mono and stereo is refused."""
    with pytest.raises(ValueError):
        RtpOpusOutput().set_channels(3)
