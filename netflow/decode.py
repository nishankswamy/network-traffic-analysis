"""Decode Ethernet / IPv4 / IPv6 / TCP / UDP headers from raw packet bytes.

Each layer is a fixed or self-describing header followed by the next layer's
bytes. The work is knowing the offsets and the two fields that make it not quite
fixed-length: IPv4's IHL (the header can carry options, so its length is a field,
not a constant) and TCP's data offset (same reason). Reading the payload at a
hard-coded offset instead of honouring these is the most common packet-parsing
bug, and it silently corrupts everything above it.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

ETH_HEADER = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
PROTO_TCP = 6
PROTO_UDP = 17


@dataclass
class Decoded:
    src_ip: str
    dst_ip: str
    protocol: str          # "tcp" | "udp"
    src_port: int
    dst_port: int
    payload: bytes
    tcp_flags: int = 0
    seq: int = 0

    @property
    def five_tuple(self) -> tuple:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)


def decode(frame: bytes) -> Decoded | None:
    """Ethernet frame -> Decoded, or None if it's not IP/TCP/UDP or is truncated.

    Returns None rather than raising: a real capture is full of ARP, LLDP,
    truncated frames and protocols we don't care about, and one odd frame must
    never stop the analysis."""
    if len(frame) < ETH_HEADER:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]

    if ethertype == ETHERTYPE_IPV4:
        return _decode_ipv4(frame[ETH_HEADER:])
    if ethertype == ETHERTYPE_IPV6:
        return _decode_ipv6(frame[ETH_HEADER:])
    return None


def _decode_ipv4(packet: bytes) -> Decoded | None:
    if len(packet) < 20:
        return None
    version_ihl = packet[0]
    ihl = (version_ihl & 0x0F) * 4  # header length in bytes — variable!
    if ihl < 20 or len(packet) < ihl:
        return None

    protocol = packet[9]
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])
    return _decode_transport(protocol, src_ip, dst_ip, packet[ihl:])


def _decode_ipv6(packet: bytes) -> Decoded | None:
    if len(packet) < 40:  # IPv6 header is a fixed 40 bytes (no options here)
        return None
    next_header = packet[6]
    src_ip = socket.inet_ntop(socket.AF_INET6, packet[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, packet[24:40])
    return _decode_transport(next_header, src_ip, dst_ip, packet[40:])


def _decode_transport(protocol: int, src_ip: str, dst_ip: str, segment: bytes) -> Decoded | None:
    if protocol == PROTO_TCP:
        if len(segment) < 20:
            return None
        src_port, dst_port, seq = struct.unpack("!HHI", segment[:8])
        data_offset = (segment[12] >> 4) * 4  # TCP header length — variable!
        if data_offset < 20 or len(segment) < data_offset:
            return None
        flags = segment[13]
        return Decoded(src_ip, dst_ip, "tcp", src_port, dst_port,
                       segment[data_offset:], tcp_flags=flags, seq=seq)

    if protocol == PROTO_UDP:
        if len(segment) < 8:
            return None
        src_port, dst_port, length, _ = struct.unpack("!HHHH", segment[:8])
        return Decoded(src_ip, dst_ip, "udp", src_port, dst_port, segment[8:])

    return None


# TCP flag bits, for flow reconstruction.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
