"""DNS tunnelling detection.

DNS tunnelling smuggles data through DNS queries: an attacker encodes bytes into
subdomain labels of a domain they control, and the recursive resolver dutifully
forwards them out of the network — through a channel almost no firewall blocks,
because breaking DNS breaks everything.

The signal is that tunnelled queries don't look like human DNS. They are:
  - long (data packed into the name),
  - high-entropy (encoded bytes look random, not like English words),
  - frequent to one domain (a tunnel is chatty),
  - and often NXDOMAIN (each unique-encoded name is a cache miss).

No single one of these is conclusive — a CDN uses long high-entropy hostnames
too — so the detector scores a domain on the combination, and Day 16 measures
what that costs in false positives against legitimately weird-looking domains.
"""

from __future__ import annotations

import math
import struct
from collections import defaultdict
from dataclasses import dataclass, field


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character. Encoded/random text approaches log2(alphabet
    size) (~4-6 bits); English words sit lower (~3-4). The gap is the signal."""
    if not text:
        return 0.0
    counts = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parse_dns_query(payload: bytes) -> str | None:
    """Extract the queried name from a DNS query packet. Returns None if it's
    not a parseable query."""
    if len(payload) < 12:
        return None
    try:
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount < 1:
            return None
        pos = 12
        labels = []
        while pos < len(payload):
            length = payload[pos]
            pos += 1
            if length == 0:
                break
            if length & 0xC0:  # compression pointer — not in a query's question
                return None
            labels.append(payload[pos:pos + length].decode("ascii", "replace"))
            pos += length
        return ".".join(labels) if labels else None
    except (struct.error, IndexError):
        return None


@dataclass
class DomainStats:
    domain: str
    query_count: int = 0
    unique_subdomains: set = field(default_factory=set)
    subdomain_lengths: list = field(default_factory=list)
    subdomain_entropies: list = field(default_factory=list)

    def observe(self, qname: str) -> None:
        self.query_count += 1
        sub = qname[: -(len(self.domain) + 1)] if qname.endswith(self.domain) else qname
        self.unique_subdomains.add(sub)
        self.subdomain_lengths.append(len(sub))
        self.subdomain_entropies.append(shannon_entropy(sub.replace(".", "")))

    def tunnel_score(self) -> float:
        """0-1 suspicion score combining the tunnelling signals.

        Deliberately a weighted blend, not a hard rule: any single signal has a
        benign explanation, so the score only gets high when several coincide.
        The weights are tuned on Day 16 against the false-positive traffic."""
        if self.query_count < 5:
            return 0.0  # too little to judge

        avg_len = sum(self.subdomain_lengths) / len(self.subdomain_lengths)
        avg_entropy = sum(self.subdomain_entropies) / len(self.subdomain_entropies)
        unique_ratio = len(self.unique_subdomains) / self.query_count

        length_signal = min(1.0, avg_len / 40)       # tunnels pack long names
        entropy_signal = min(1.0, max(0.0, (avg_entropy - 3.0) / 1.5))  # >3 bits/char
        churn_signal = unique_ratio                   # every query a new name

        return 0.4 * entropy_signal + 0.35 * length_signal + 0.25 * churn_signal


def group_by_domain(qnames: list[str], registrable_depth: int = 2) -> dict:
    """Group query names under their registrable domain (last N labels).

    Approximation of the public-suffix list: real code would use the PSL to know
    that `co.uk` is a suffix, but last-two-labels covers the common case and
    keeps the detector dependency-free."""
    stats: dict[str, DomainStats] = {}
    for qname in qnames:
        labels = qname.split(".")
        if len(labels) < registrable_depth:
            continue
        domain = ".".join(labels[-registrable_depth:])
        if domain not in stats:
            stats[domain] = DomainStats(domain)
        stats[domain].observe(qname)
    return stats
