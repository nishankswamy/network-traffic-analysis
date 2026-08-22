"""pcap file parsing, by hand.

pcap is the on-disk format tcpdump and Wireshark write. Parsing it yourself —
rather than reaching for scapy — is the point of the exercise: the format is a
24-byte global header followed by per-packet records, and knowing that structure
is what lets you reason about capture truncation, endianness, and link types
when a real capture misbehaves.

    [ global header, 24 bytes ]
    [ record header, 16 bytes ][ packet bytes ]
    [ record header, 16 bytes ][ packet bytes ]
    ...

The magic number in the global header encodes byte order (captures are written
in the host's endianness) and timestamp resolution (micro- vs nanosecond). Get
the endianness wrong and every length reads as garbage — so it's read first and
everything else follows from it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# Little- and big-endian magic numbers, microsecond and nanosecond variants.
_MAGIC = {
    0xA1B2C3D4: ("<", "us"),
    0xD4C3B2A1: (">", "us"),
    0xA1B23C4D: ("<", "ns"),
    0x4D3CB2A1: (">", "ns"),
}


@dataclass
class Packet:
    timestamp: float      # seconds since epoch
    data: bytes           # the captured bytes (may be truncated — see caplen)
    original_length: int  # length on the wire, before capture truncation


class PcapReader:
    def __init__(self, blob: bytes) -> None:
        if len(blob) < 24:
            raise ValueError("too short to be a pcap file")

        (magic,) = struct.unpack("<I", blob[:4])
        if magic not in _MAGIC:
            raise ValueError(f"unknown pcap magic {magic:#010x}")
        self.endian, self.ts_resolution = _MAGIC[magic]

        # Global header: magic, version, tz, sigfigs, snaplen, link-type.
        _, self.v_major, self.v_minor, _, _, self.snaplen, self.link_type = struct.unpack(
            self.endian + "IHHiIII", blob[:24]
        )
        self._blob = blob
        self._offset = 24

    def __iter__(self):
        return self

    def __next__(self) -> Packet:
        blob = self._blob
        if self._offset + 16 > len(blob):
            raise StopIteration

        ts_sec, ts_frac, caplen, orig_len = struct.unpack(
            self.endian + "IIII", blob[self._offset : self._offset + 16]
        )

        # A capture cut off mid-record (the process was killed, the disk filled)
        # leaves a header promising more bytes than exist. Stop cleanly rather
        # than yield a silently-truncated packet.
        if self._offset + 16 + caplen > len(blob):
            raise StopIteration

        self._offset += 16
        # caplen is what was actually saved; it can be less than orig_len when
        # the capture used a snaplen. Reading orig_len bytes here would walk off
        # the end of the record — a classic pcap-parsing bug.
        data = blob[self._offset : self._offset + caplen]
        self._offset += caplen

        divisor = 1e9 if self.ts_resolution == "ns" else 1e6
        return Packet(
            timestamp=ts_sec + ts_frac / divisor,
            data=data,
            original_length=orig_len,
        )


def write_pcap(packets: list[Packet], link_type: int = 1) -> bytes:
    """Write a little-endian microsecond pcap. Used by the traffic generator so
    the parser round-trips against real bytes, not just against itself."""
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 65535, 0, link_type)
    for p in packets:
        sec = int(p.timestamp)
        usec = int(round((p.timestamp - sec) * 1e6))
        if usec == 1_000_000:  # rounding can tip a fraction over a full second
            sec, usec = sec + 1, 0
        out += struct.pack("<IIII", sec, usec, len(p.data), p.original_length or len(p.data))
        out += p.data
    return bytes(out)
