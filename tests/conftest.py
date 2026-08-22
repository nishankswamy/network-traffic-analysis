import socket
import struct

import pytest

from netflow.decode import ACK, SYN
from netflow.pcap import Packet


def make_tcp_frame(src, dst, sport, dport, flags=0, payload=b"", seq=1000):
    eth = b"\x11" * 12 + struct.pack("!H", 0x0800)
    total = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0)
    ip += socket.inet_aton(src) + socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, (5 << 4), flags, 0, 0, 0)
    return eth + ip + tcp + payload


def make_udp_frame(src, dst, sport, dport, payload=b""):
    eth = b"\x11" * 12 + struct.pack("!H", 0x0800)
    total = 20 + 8 + len(payload)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 17, 0)
    ip += socket.inet_aton(src) + socket.inet_aton(dst)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return eth + ip + udp + payload


@pytest.fixture
def tcp_frame():
    return make_tcp_frame


@pytest.fixture
def udp_frame():
    return make_udp_frame
