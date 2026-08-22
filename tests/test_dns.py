"""DNS tunnelling detection: entropy separates encoded names from real ones."""

import base64
import os

from netflow.dns import (
    DomainStats,
    group_by_domain,
    parse_dns_query,
    shannon_entropy,
)


def test_entropy_distinguishes_encoded_from_words():
    encoded = base64.b32encode(os.urandom(20)).decode().rstrip("=")
    assert shannon_entropy(encoded) > 4.0    # near-random
    assert shannon_entropy("www") < 2.0      # real label
    assert shannon_entropy("mail") < 2.5


def test_empty_string_has_zero_entropy():
    assert shannon_entropy("") == 0.0


def test_parses_a_dns_query_name():
    # DNS query for www.example.com
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    query += b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    assert parse_dns_query(query) == "www.example.com"


def test_rejects_non_query():
    assert parse_dns_query(b"\x00\x00") is None


def test_tunnel_scores_high():
    stats = DomainStats("evil.com")
    for _ in range(30):
        sub = base64.b32encode(os.urandom(16)).decode().rstrip("=").lower()
        stats.observe(f"{sub}.evil.com")
    assert stats.tunnel_score() > 0.7


def test_normal_domain_scores_low():
    stats = DomainStats("google.com")
    for sub in ["www", "mail", "maps", "www", "drive", "www", "mail", "www"]:
        stats.observe(f"{sub}.google.com")
    assert stats.tunnel_score() < 0.3


def test_too_few_queries_scores_zero():
    """A handful of odd queries isn't a tunnel — needs volume to judge."""
    stats = DomainStats("example.com")
    stats.observe("weird-xyzabc.example.com")
    assert stats.tunnel_score() == 0.0


def test_group_by_domain():
    names = ["a.evil.com", "b.evil.com", "www.google.com"]
    grouped = group_by_domain(names)
    assert "evil.com" in grouped
    assert "google.com" in grouped
    assert grouped["evil.com"].query_count == 2
