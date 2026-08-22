"""pcap read/write round-trips, and the parsing edge cases that bite in real
captures."""

import struct

import pytest

from netflow.pcap import Packet, PcapReader, write_pcap


def test_write_then_read_roundtrips():
    packets = [Packet(1.5, b"hello", 5), Packet(2.25, b"world!!", 7)]
    parsed = list(PcapReader(write_pcap(packets)))

    assert len(parsed) == 2
    assert parsed[0].data == b"hello"
    assert parsed[1].data == b"world!!"
    assert abs(parsed[0].timestamp - 1.5) < 1e-6
    assert abs(parsed[1].timestamp - 2.25) < 1e-6


def test_reads_big_endian():
    """Captures are written in host byte order; the reader must honour the
    magic number, not assume little-endian."""
    le = write_pcap([Packet(1.0, b"abc", 3)])
    # Hand-build the big-endian equivalent.
    be = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 65535, 0, 1)
    be += struct.pack(">IIII", 1, 0, 3, 3) + b"abc"
    parsed = list(PcapReader(be))
    assert parsed[0].data == b"abc"


def test_rejects_unknown_magic():
    with pytest.raises(ValueError, match="magic"):
        PcapReader(b"\x00" * 24)


def test_rejects_truncated_header():
    with pytest.raises(ValueError, match="too short"):
        PcapReader(b"\x00" * 10)


def test_stops_cleanly_at_a_truncated_record():
    """A capture cut off mid-record must not raise — it just yields what's
    complete."""
    good = write_pcap([Packet(1.0, b"abc", 3)])
    truncated = good + struct.pack("<IIII", 2, 0, 100, 100) + b"only-a-few"
    parsed = list(PcapReader(truncated))
    assert len(parsed) == 1  # the complete packet, not the truncated one


def test_nanosecond_resolution():
    ns = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 65535, 0, 1)
    ns += struct.pack("<IIII", 5, 500_000_000, 1, 1) + b"x"
    parsed = list(PcapReader(ns))
    assert abs(parsed[0].timestamp - 5.5) < 1e-9
