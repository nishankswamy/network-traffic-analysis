"""TCP stream reassembly — the cases real captures throw at you."""

from netflow.reassembly import Segment, TCPReassembler, reassemble


def test_in_order_segments():
    r = TCPReassembler()
    r.add(0, b"hello ")
    r.add(6, b"world")
    assert r.contiguous() == b"hello world"


def test_out_of_order_segments_are_reordered():
    """Segments keyed by sequence number, not arrival order."""
    r = TCPReassembler()
    r.add(12, b"there")     # arrives first
    r.add(0, b"hello ")     # base, arrives second
    r.add(6, b"world ")     # middle, arrives last
    assert r.contiguous() == b"hello world there"
    assert not r.has_gap


def test_retransmission_is_deduplicated():
    r = TCPReassembler()
    r.add(0, b"hello")
    r.add(0, b"hello")      # exact retransmit
    assert r.contiguous() == b"hello"


def test_partial_overlap_keeps_first_and_appends_new_tail():
    """First-wins on overlap, then append only the genuinely new bytes."""
    r = TCPReassembler()
    r.add(0, b"hello")          # bytes 0-4
    r.add(3, b"loWORLD")        # overlaps 3-4 ('lo'), new tail 'WORLD'
    assert r.contiguous() == b"helloWORLD"


def test_gap_withholds_bytes_past_the_hole():
    r = TCPReassembler()
    r.add(0, b"hello")
    r.add(100, b"world")       # big gap
    assert r.contiguous() == b"hello"   # nothing past the hole
    assert r.has_gap


def test_gap_then_filled_becomes_contiguous():
    r = TCPReassembler()
    r.add(0, b"AAA")
    r.add(6, b"CCC")           # gap at 3-5
    assert r.contiguous() == b"AAA"
    assert r.has_gap
    r.add(3, b"BBB")           # fill it
    assert r.contiguous() == b"AAABBBCCC"
    assert not r.has_gap


def test_empty_segments_ignored():
    r = TCPReassembler()
    r.add(0, b"")
    assert r.contiguous() == b""


def test_reassemble_helper():
    segs = [Segment(6, b"world"), Segment(0, b"hello ")]
    assert reassemble(segs) == b"hello world"


def test_clienthello_split_across_segments():
    """The motivating case: a TLS ClientHello too large for one segment. Reading
    the first payload alone would miss it; reassembly recovers it whole."""
    from netflow.tls import parse_client_hello
    import struct

    # build a real-ish ClientHello (reuse the tls test's builder inline)
    ciphers = [0x1301, 0x1302]
    extensions = [0x0000, 0x0010]
    body = struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00"
    body += struct.pack("!H", len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack("!H", c)
    body += b"\x01\x00"
    ext_bytes = b"".join(struct.pack("!HH", e, 0) for e in extensions)
    body += struct.pack("!H", len(ext_bytes)) + ext_bytes
    handshake = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body
    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake

    # split it across two TCP segments
    r = TCPReassembler()
    r.add(1000, record[:10])
    r.add(1000 + 10, record[10:])
    reassembled = r.contiguous()

    assert reassembled == record
    hello = parse_client_hello(reassembled)
    assert hello is not None
    assert hello.cipher_suites == ciphers   # parsed from the stitched stream
