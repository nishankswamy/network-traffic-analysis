"""TCP stream reassembly — rebuilding the byte stream from segments.

A flow record counts packets and bytes, but a *detection* often needs the actual
application bytes: a TLS ClientHello, an HTTP request line, a DNS-over-TCP message.
Those don't arrive as one packet. TCP is a byte stream sliced into segments that
can arrive out of order, be retransmitted, or overlap — so reading "the first
payload" (what the flow parser did) misses a ClientHello split across two segments,
which is exactly what a large cipher list or many extensions causes in practice.

Reassembly orders segments by sequence number and stitches them into a contiguous
stream, which is what Wireshark's "Follow TCP Stream" and every IDS does. The
subtle parts, all handled here:

- **Out-of-order:** segments are keyed by sequence number, not arrival order.
- **Retransmissions:** a segment covering already-seen bytes is a duplicate; keep
  the first copy, ignore the rest (the standard policy — first-wins avoids the
  overlap-rewriting attacks that bit older IDSes).
- **Gaps:** if a segment is missing, the stream is only contiguous up to the gap;
  emit what's contiguous rather than guessing across the hole.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Segment:
    seq: int          # TCP sequence number of the first byte
    data: bytes


class TCPReassembler:
    """Reassembles one direction of one TCP connection.

    Feed it segments in any order; ask for the contiguous stream so far. The
    initial sequence number is learned from the first segment, so callers don't
    need the SYN."""

    def __init__(self) -> None:
        self._segments: dict[int, bytes] = {}   # seq -> data (first-wins)
        self._base: int | None = None

    def add(self, seq: int, data: bytes) -> None:
        if not data:
            return
        # The base is the lowest sequence number seen, not the first one added —
        # segments arrive out of order, so "first added" would pick the wrong
        # start and drop everything before it.
        if self._base is None or seq < self._base:
            self._base = seq
        # First-wins on overlap: only record bytes at sequence numbers not yet
        # seen. A retransmission of the same range is ignored.
        if seq not in self._segments:
            self._segments[seq] = data

    def contiguous(self) -> bytes:
        """The byte stream from the base up to the first gap. Bytes past a
        missing segment are withheld — you don't parse across a hole."""
        if self._base is None:
            return b""

        out = bytearray()
        expected = self._base
        # Walk segments in sequence order, appending only where they continue
        # the contiguous run.
        for seq in sorted(self._segments):
            data = self._segments[seq]
            if seq > expected:
                break                 # a gap — stop at the first hole
            end = seq + len(data)
            if end <= expected:
                continue              # entirely old bytes (a retransmit)
            # Append only the new tail, in case this segment partially overlaps.
            overlap = expected - seq
            out += data[overlap:]
            expected = end
        return bytes(out)

    @property
    def has_gap(self) -> bool:
        """True if there's a hole before the highest byte seen — the stream is
        incomplete and a parser should wait or give up."""
        if self._base is None:
            return False
        stream = self.contiguous()
        highest = max((seq + len(d) for seq, d in self._segments.items()), default=self._base)
        return (self._base + len(stream)) < highest


def reassemble(segments: list[Segment]) -> bytes:
    """Convenience: reassemble a list of segments into the contiguous stream."""
    r = TCPReassembler()
    for s in segments:
        r.add(s.seq, s.data)
    return r.contiguous()
