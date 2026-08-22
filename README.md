# Network Traffic Analysis

Parse pcap by hand, reconstruct flows, fingerprint TLS clients (JA3/JA4), and
detect DNS tunnelling and C2 beaconing — all defensive, all measured against the
legitimate traffic that trips each detector up.

Days 14–16 of a 30-day challenge, all three done.

```bash
pip install -r requirements.txt
python evaluate_main.py    # the beaconing false-positive finding
pytest                     # 39 tests
```

## The finding

**A beaconing detector that flags NTP is worse than useless — and timing alone
cannot avoid it.** C2 malware beacons on a regular interval; so do NTP, software
update checks, and telemetry heartbeats. They are *identically* periodic.

Measured on 243 synthetic flows (200 human, 15 NTP, 20 update checks, 8 real
beacons):

| detector | beacons caught | false positives | precision |
|---|---|---|---|
| timing only (coefficient of variation) | 8/8 | **35** | 19% |
| + drop service ports + small consistent payloads | 8/8 | **0** | 100% |

The naive detector catches every beacon *and* every NTP client and update
checker — 35 false positives for 8 real detections, a queue an analyst mutes by
lunchtime. The false positives are exactly the legitimately-periodic traffic, and
`test_legitimate_periodic_traffic_is_flagged` pins that as documented behaviour,
not a bug.

The refinement recovers full precision with two cheap discriminators: drop known
periodic-service ports (NTP is 123, DNS is 53), and require the small, consistent
payloads a beacon has and a 1 KB update check doesn't.

**But the honest limit stands:** a beacon deliberately configured to look like
benign HTTPS — port 443, tuned payload sizes, a little jitter — is
indistinguishable from legitimate periodic HTTPS *by network features alone*.
Catching that needs destination reputation (is 45.13.x.x known-bad?), which is
data this layer doesn't have. Timing gets you the lazy beacons; the careful ones
need threat intel.

## What's built, and why by hand

### pcap parsing (`pcap.py`)

pcap is a 24-byte global header then per-packet records. Parsing it directly —
not via scapy — is the point: you learn that the magic number encodes both byte
order *and* timestamp resolution, that `caplen` (saved bytes) differs from
`orig_len` (wire length) under a snaplen, and that a capture killed mid-record
leaves a header promising bytes that aren't there. The reader stops cleanly on
that truncation rather than yielding a corrupt packet — `test_stops_cleanly_at_a_truncated_record`.

### Header decoding (`decode.py`)

Ethernet → IPv4/IPv6 → TCP/UDP. The two traps, both tested: IPv4's IHL and TCP's
data-offset are *lengths*, not constants (options make the header longer), and
reading the payload at a hard-coded offset silently corrupts everything above it.

### Flow reconstruction (`flows.py`)

The A→B and B→A halves of a conversation have reversed 5-tuples. **Canonicalising
the key** (sort the two endpoints) makes both directions hash to one flow —
without it every bidirectional metric is half-counted. The flow record
(endpoints, per-direction packet/byte counts, duration, TCP flags) is what every
detector consumes; nobody touches raw packets again. It also distinguishes an
established conversation from a lone SYN, which is a scan.

### TLS fingerprinting (`tls.py`)

A ClientHello is sent in the clear before encryption, listing cipher suites and
extensions in a client-characteristic order. **JA3 hashes that list to identify
the client software without decrypting anything** — you can tell Chrome from curl
from a Cobalt Strike beacon on an encrypted session.

The project implements JA3 *and* a JA4-style fingerprint to make one thing
concrete: JA3 is order-sensitive, so Chrome's later extension-order randomisation
broke it (`test_ja3_changes_when_extension_order_changes`). JA4 sorts before
hashing, so the same randomisation doesn't change it
(`test_ja4_is_stable_across_extension_order`). Both strip GREASE values, which are
random per-connection and would otherwise change the fingerprint every handshake.

### DNS tunnelling (`dns.py`)

Tunnelling smuggles data through DNS queries no firewall blocks. The signal is
that tunnelled names don't look human: long, high-entropy (encoded bytes ≈ 4–6
bits/char vs ≈ 3 for English), every query a unique subdomain. None is conclusive
alone — a CDN uses long high-entropy hostnames too — so the detector scores the
*combination*. Measured: a base32 tunnel scores 0.91, real domains 0.06–0.08.

## Depth questions

**JA3 identifies client software without decryption. What does that imply for
privacy, and why did JA4 replace it?**
It means a passive observer — an ISP, a network operator, an adversary on-path —
can fingerprint the *application* you're using on an encrypted connection without
breaking the encryption. That's a real privacy exposure, and it's also why it's
useful defensively. JA4 replaced JA3 not for privacy but for robustness: browsers
began randomising TLS extension order specifically to frustrate fingerprinting,
which changed the order-sensitive JA3 hash every connection. JA4 sorts the fields
first, so it survives the randomisation and stays a stable identifier.

**Your beaconing detector flags NTP and update checks. How would you separate
"periodic" from "suspicious" without an allowlist?**
You mostly can't, on timing alone — that's the finding. The discriminators that
help are destination and payload, not timing: a beacon to a never-before-seen IP
sending fixed-size small requests looks different from NTP to a known pool server.
So you combine periodicity with destination novelty/reputation and payload
consistency. An allowlist of service ports handles the easy 80%; the residual —
a beacon mimicking HTTPS telemetry — genuinely needs threat intelligence, because
by network features it *is* benign periodic HTTPS.

**Entropy flags DNS tunnelling. What legitimate traffic also has high-entropy
subdomains, and how many false positives does that cost?**
CDNs and cloud services: `d1a2b3c4e5.cloudfront.net`, hashed cache keys, per-object
storage hostnames — all long and high-entropy. That's why the detector doesn't
threshold on entropy alone but combines it with query volume to one domain and
unique-subdomain churn; a CDN has high entropy but you don't send it hundreds of
unique never-repeated names. It cuts the false positives but wouldn't eliminate
them — a busy S3-heavy host would still need an allowlist.

**What can you infer about an encrypted session from packet sizes and timings
alone?**
A surprising amount. Packet-size sequences leak which page you loaded (traffic
analysis / website fingerprinting), typing rhythm in an interactive SSH session
leaks keystroke timing, and request/response size patterns distinguish a
file upload from a video stream from a chat. The content is encrypted; the
*shape* of the conversation is not, and the shape is often enough.

## Layout

```
netflow/
  pcap.py        pcap read/write, by hand
  decode.py      Ethernet / IP / TCP / UDP header decoding
  flows.py       bidirectional flow reconstruction
  tls.py         ClientHello parsing, JA3 + JA4-lite
  dns.py         DNS tunnelling detection (entropy + volume + churn)
  beaconing.py   periodicity detection via coefficient of variation
  generate.py    synthetic traffic incl. benign-periodic (the hard part)
evaluate_main.py the beaconing false-positive measurement
tests/           39 tests
```

## What I'd do differently

<!-- Fill this in. -->

## Known gaps

- No TCP stream reassembly. Flows count packets and bytes but don't rebuild the
  byte stream, so a ClientHello split across segments would be missed. Real tools
  reassemble; this reads the first payload.
- The registrable-domain grouping is last-two-labels, not the public suffix list,
  so it mis-groups `foo.co.uk`.
- Beaconing uses coefficient of variation only. FFT / autocorrelation would catch
  multi-modal beacons (two interleaved intervals) that CV smears together.
- Synthetic traffic. Real captures have retransmits, reordering, and NAT that this
  doesn't model — the false-positive *lesson* holds, the exact numbers wouldn't.
- No destination reputation, which the finding shows is the missing ingredient for
  the beacons timing can't catch.
