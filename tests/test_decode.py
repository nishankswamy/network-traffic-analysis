"""Header decoding, including the variable-length-header traps."""

import socket
import struct

import pytest

from netflow.decode import ACK, SYN, decode
from tests.conftest import make_tcp_frame, make_udp_frame


def test_decode_tcp():
    d = decode(make_tcp_frame("10.0.0.1", "8.8.8.8", 1234, 443, SYN, b"data"))
    assert d.protocol == "tcp"
    assert d.src_ip == "10.0.0.1"
    assert d.dst_ip == "8.8.8.8"
    assert d.src_port == 1234
    assert d.dst_port == 443
    assert d.payload == b"data"
    assert d.tcp_flags & SYN


def test_decode_udp():
    d = decode(make_udp_frame("10.0.0.1", "8.8.8.8", 5353, 53, b"query"))
    assert d.protocol == "udp"
    assert d.dst_port == 53
    assert d.payload == b"query"


def test_honours_ipv4_options():
    """An IPv4 header with options (IHL > 5) must not read the payload at the
    default offset — the classic packet-parsing bug."""
    payload = b"PAYLOAD"
    options = b"\x00\x00\x00\x00"  # 4 bytes of options -> IHL = 6
    eth = b"\x11" * 12 + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH", 0x46, 0, 24 + 20 + len(payload), 0, 0, 64, 6, 0)
    ip += socket.inet_aton("1.1.1.1") + socket.inet_aton("2.2.2.2") + options
    tcp = struct.pack("!HHIIBBHHH", 1, 2, 0, 0, (5 << 4), ACK, 0, 0, 0)
    d = decode(eth + ip + tcp + payload)
    assert d.payload == payload


def test_ignores_non_ip():
    arp = b"\x11" * 12 + struct.pack("!H", 0x0806) + b"\x00" * 28
    assert decode(arp) is None


def test_ignores_truncated_frame():
    assert decode(b"\x00" * 10) is None
