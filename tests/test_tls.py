"""TLS fingerprinting: JA3 is order-sensitive, JA4-lite is order-robust — the
whole reason JA4 was created."""

import struct

from netflow.tls import ClientHello, ja3, ja4_lite, parse_client_hello


def build_client_hello(ciphers, extensions):
    """Minimal but real ClientHello bytes."""
    body = struct.pack("!H", 0x0303)  # version TLS 1.2
    body += b"\x00" * 32              # random
    body += b"\x00"                   # session id len
    body += struct.pack("!H", len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack("!H", c)
    body += b"\x01\x00"               # compression methods
    ext_bytes = b""
    for e in extensions:
        ext_bytes += struct.pack("!HH", e, 0)
    body += struct.pack("!H", len(ext_bytes)) + ext_bytes

    handshake = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body
    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake
    return record


def test_parses_ciphers_and_extensions():
    hello = parse_client_hello(build_client_hello([0x1301, 0x1302], [0x0000, 0x0010]))
    assert hello.cipher_suites == [0x1301, 0x1302]
    assert 0x0000 in hello.extensions
    assert hello.has_sni  # extension 0x0000 is SNI


def test_ja3_is_stable_for_identical_hellos():
    a = parse_client_hello(build_client_hello([0x1301, 0x1302], [0x0000, 0x0010]))
    b = parse_client_hello(build_client_hello([0x1301, 0x1302], [0x0000, 0x0010]))
    assert ja3(a) == ja3(b)


def test_ja3_changes_when_extension_order_changes():
    """JA3's weakness: shuffling extension order changes the fingerprint, which
    is how Chrome's randomisation defeated it."""
    a = parse_client_hello(build_client_hello([0x1301], [0x0000, 0x0010, 0x000a]))
    b = parse_client_hello(build_client_hello([0x1301], [0x000a, 0x0010, 0x0000]))
    assert ja3(a) != ja3(b)


def test_ja4_is_stable_across_extension_order():
    """JA4's fix: sorting before hashing means order randomisation doesn't
    change the fingerprint."""
    a = parse_client_hello(build_client_hello([0x1301, 0x1302], [0x0000, 0x0010, 0x000a]))
    b = parse_client_hello(build_client_hello([0x1302, 0x1301], [0x000a, 0x0000, 0x0010]))
    assert ja4_lite(a) == ja4_lite(b)


def test_grease_is_stripped():
    """GREASE values are random per-connection; both fingerprints must ignore
    them or they'd change every handshake."""
    plain = parse_client_hello(build_client_hello([0x1301], [0x0000]))
    greased = parse_client_hello(build_client_hello([0x0A0A, 0x1301], [0x1A1A, 0x0000]))
    assert ja3(plain) == ja3(greased)
    assert ja4_lite(plain) == ja4_lite(greased)


def test_rejects_non_client_hello():
    assert parse_client_hello(b"\x17\x03\x03\x00\x05hello") is None  # application data
