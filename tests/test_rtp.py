"""Test voip_utils RTP functionality."""

import os
from unittest.mock import Mock

from voip_utils.rtp_audio import RtpOpusOutput


def test_opus_output():
    rtpout = RtpOpusOutput()
    assert rtpout.opus_rate == 48000
    assert rtpout.opus_width == 2
    assert rtpout.opus_channels == 2
    assert rtpout.opus_frame_size == 960


def test_sequence_number_wrap_silence():
    rtpout = RtpOpusOutput()
    rtpout._rtp_sequence_num = 65535
    rtpout.silence_frame()
    assert rtpout._rtp_sequence_num == 0


def test_sequence_number_wrap_audio():
    rtpout = RtpOpusOutput()
    rtpout._rtp_sequence_num = 65535
    rtpiter = rtpout.process_audio(os.urandom(3840), 48000, 2, 2)
    next(rtpiter)
    next(rtpiter, None)
    assert rtpout._rtp_sequence_num == 0
