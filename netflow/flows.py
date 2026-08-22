"""Flow reconstruction: group packets into bidirectional conversations.

A flow is one conversation between two endpoints. Packets arrive interleaved
across many flows, in both directions, so reconstruction means keying each
packet to its flow and merging the two directions.

The key insight is **canonicalisation**. A packet from A→B and its reply B→A
belong to the same flow, but their 5-tuples are reversed. Canonicalising the key
(sort the two endpoints) makes both directions hash to the same flow — without
it you'd get two half-flows and every bidirectional metric would be wrong.

The output is a flow record: endpoints, packet and byte counts per direction,
start/end time, duration. That record is what every detector on Days 15-16
consumes — nobody works on raw packets again.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .decode import ACK, FIN, RST, SYN, Decoded


def canonical_key(d: Decoded) -> tuple:
    """A direction-independent flow key. Sorting the two (ip, port) endpoints
    means A→B and B→A produce the same key."""
    a = (d.src_ip, d.src_port)
    b = (d.dst_ip, d.dst_port)
    lo, hi = sorted([a, b])
    return (lo, hi, d.protocol)


@dataclass
class Flow:
    endpoint_a: tuple            # (ip, port) — the lexically smaller endpoint
    endpoint_b: tuple
    protocol: str
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    start_time: float = float("inf")
    end_time: float = float("-inf")
    timestamps: list = field(default_factory=list)  # for beaconing analysis
    saw_syn: bool = False
    saw_fin: bool = False
    saw_rst: bool = False

    @property
    def total_packets(self) -> int:
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def total_bytes(self) -> int:
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    @property
    def is_established(self) -> bool:
        """A TCP flow that completed a handshake. A SYN with no reply is a scan,
        not a conversation — this tells them apart."""
        return self.saw_syn and self.packets_a_to_b > 0 and self.packets_b_to_a > 0


class FlowTable:
    def __init__(self) -> None:
        self._flows: dict[tuple, Flow] = {}

    def add(self, decoded: Decoded, timestamp: float, wire_length: int) -> None:
        key = canonical_key(decoded)
        flow = self._flows.get(key)
        if flow is None:
            (a, b, proto) = key
            flow = Flow(endpoint_a=a, endpoint_b=b, protocol=proto)
            self._flows[key] = flow

        # Direction: is this packet going a->b or b->a?
        source = (decoded.src_ip, decoded.src_port)
        if source == flow.endpoint_a:
            flow.packets_a_to_b += 1
            flow.bytes_a_to_b += wire_length
        else:
            flow.packets_b_to_a += 1
            flow.bytes_b_to_a += wire_length

        flow.start_time = min(flow.start_time, timestamp)
        flow.end_time = max(flow.end_time, timestamp)
        flow.timestamps.append(timestamp)

        if decoded.protocol == "tcp":
            if decoded.tcp_flags & SYN:
                flow.saw_syn = True
            if decoded.tcp_flags & FIN:
                flow.saw_fin = True
            if decoded.tcp_flags & RST:
                flow.saw_rst = True

    def flows(self) -> list[Flow]:
        return sorted(self._flows.values(), key=lambda f: f.start_time)

    def __len__(self) -> int:
        return len(self._flows)


def reconstruct(packets, decoder=None) -> FlowTable:
    """Feed (Packet) objects through the decoder into a flow table."""
    from .decode import decode as default_decode

    decode = decoder or default_decode
    table = FlowTable()
    for pkt in packets:
        decoded = decode(pkt.data)
        if decoded is not None:
            table.add(decoded, pkt.timestamp, pkt.original_length or len(pkt.data))
    return table
