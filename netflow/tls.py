"""TLS ClientHello parsing and JA3 fingerprinting.

A TLS handshake begins with a ClientHello sent in the clear, before any
encryption. It lists the client's supported cipher suites, extensions, elliptic
curves and point formats — and different client software (a browser, curl, a
malware family) lists them in a characteristic order. JA3 hashes that list into
a fingerprint that identifies the *client software* without decrypting a single
byte of the session.

That's the power and the privacy problem in one sentence: you can tell Chrome
from a Python script from a Cobalt Strike beacon on an encrypted connection. JA3
was later partly defeated by TLS extension randomisation (Chrome shuffles its
extension order now), which is exactly why JA4 was designed to be robust to it —
it sorts the extensions before hashing. Both are implemented here so the
difference is concrete.

    JA3  = md5(version,ciphers,extensions,curves,point_formats)   order-sensitive
    JA4  = sorted, and includes SNI presence + ALPN               order-robust
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

# GREASE values (RFC 8701): reserved codepoints clients inject to keep the
# ecosystem tolerant of unknown values. They're random per-connection, so both
# JA3 and JA4 must strip them or the fingerprint changes every handshake.
_GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

_HANDSHAKE = 22
_CLIENT_HELLO = 1
_EXT_SNI = 0x0000
_EXT_ALPN = 0x0010
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_EC_POINT_FORMATS = 0x000B


@dataclass
class ClientHello:
    version: int
    cipher_suites: list[int]
    extensions: list[int]
    curves: list[int]
    point_formats: list[int]
    has_sni: bool


def parse_client_hello(payload: bytes) -> ClientHello | None:
    """Parse a TLS record carrying a ClientHello. Returns None if the bytes
    aren't one — the caller feeds it every TCP payload and lets it filter."""
    try:
        return _parse(payload)
    except (struct.error, IndexError):
        return None  # truncated or malformed; not our packet


def _parse(payload: bytes) -> ClientHello | None:
    if len(payload) < 6 or payload[0] != _HANDSHAKE:
        return None
    # TLS record header (5) then handshake header (4).
    if payload[5] != _CLIENT_HELLO:
        return None

    pos = 9
    client_version = struct.unpack("!H", payload[pos:pos + 2])[0]
    pos += 2
    pos += 32  # random
    session_id_len = payload[pos]
    pos += 1 + session_id_len

    cipher_len = struct.unpack("!H", payload[pos:pos + 2])[0]
    pos += 2
    ciphers = [struct.unpack("!H", payload[pos + i:pos + i + 2])[0]
               for i in range(0, cipher_len, 2)]
    pos += cipher_len

    compression_len = payload[pos]
    pos += 1 + compression_len

    extensions, curves, point_formats, has_sni = [], [], [], False
    if pos + 2 <= len(payload):
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            body = payload[pos:pos + ext_len]
            pos += ext_len
            extensions.append(ext_type)
            if ext_type == _EXT_SNI:
                has_sni = True
            elif ext_type == _EXT_SUPPORTED_GROUPS and len(body) >= 2:
                n = struct.unpack("!H", body[:2])[0]
                curves = [struct.unpack("!H", body[2 + i:4 + i])[0] for i in range(0, n, 2)]
            elif ext_type == _EXT_EC_POINT_FORMATS and len(body) >= 1:
                point_formats = list(body[1:1 + body[0]])

    return ClientHello(client_version, ciphers, extensions, curves, point_formats, has_sni)


def _strip_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in _GREASE]


def ja3(hello: ClientHello) -> str:
    """Classic JA3: MD5 of the comma-joined, dash-separated fields in the order
    the client sent them. Order-sensitive by design — which is its weakness."""
    parts = [
        str(hello.version),
        "-".join(map(str, _strip_grease(hello.cipher_suites))),
        "-".join(map(str, _strip_grease(hello.extensions))),
        "-".join(map(str, _strip_grease(hello.curves))),
        "-".join(map(str, _strip_grease(hello.point_formats))),
    ]
    return hashlib.md5(",".join(parts).encode()).hexdigest()


def ja4_lite(hello: ClientHello) -> str:
    """A JA4-style fingerprint: extensions and ciphers are SORTED before
    hashing, so extension-order randomisation (which broke JA3) doesn't change
    it. Not the full JA4 spec — the salient design choice, made concrete."""
    ciphers = "-".join(f"{c:04x}" for c in sorted(_strip_grease(hello.cipher_suites)))
    exts = "-".join(f"{e:04x}" for e in sorted(_strip_grease(hello.extensions)))
    sni = "d" if hello.has_sni else "i"  # (d)omain present / (i)p only
    digest = hashlib.sha256(f"{ciphers}|{exts}".encode()).hexdigest()[:12]
    return f"t{hello.version:04x}{sni}_{digest}"
