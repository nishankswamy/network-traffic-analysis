"""Measure beaconing detection against the traffic that actually trips it up.

    python evaluate_main.py

The naive timing-only detector, then the refined one, scored on the same
labelled traffic — so the false-positive cost of confusing NTP with C2 is a
number, and so is the improvement from fixing it.
"""

from __future__ import annotations

import numpy as np

from netflow.beaconing import analyse_timing
from netflow.generate import TrafficGenerator


def payload_consistency(sizes: list[int]) -> float:
    """CV of payload sizes. A beacon sends near-identical requests (low CV); an
    update check or NTP is also consistent — so this alone isn't enough either,
    but combined with a non-service port it separates C2 from NTP."""
    if len(sizes) < 2:
        return 1.0
    mean = np.mean(sizes)
    return (np.std(sizes) / mean) if mean else 1.0


SERVICE_PORTS = {123, 53}  # NTP, DNS — legitimately periodic by design


def score_timing_only(flow) -> bool:
    """Flag anything rigidly periodic. This is the naive detector."""
    return analyse_timing(flow.timestamps).is_beacon


def score_refined(flow) -> bool:
    """Timing + two cheap discriminators:
      - drop known periodic-service ports (NTP/DNS) — timing can't separate them
      - require consistent small payloads, which beacons have and update checks
        (large) mostly don't
    This is what timing alone cannot do, made explicit."""
    verdict = analyse_timing(flow.timestamps)
    if not verdict.is_beacon:
        return False
    if getattr(flow, "dst_port", 0) in SERVICE_PORTS:
        return False
    sizes = getattr(flow, "payload_sizes", [])
    if sizes and (np.mean(sizes) > 600 or payload_consistency(sizes) > 0.3):
        return False
    return True


def evaluate(name: str, flows, scorer) -> None:
    tp = fp = fn = 0
    fp_by_type = {}
    for f in flows:
        flagged = scorer(f)
        is_c2 = f.behaviour == "beacon"
        if flagged and is_c2:
            tp += 1
        elif flagged and not is_c2:
            fp += 1
            fp_by_type[f.behaviour] = fp_by_type.get(f.behaviour, 0) + 1
        elif not flagged and is_c2:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    print(f"{name}")
    print(f"  caught {tp}/{tp + fn} beacons (recall {recall:.0%}), "
          f"{fp} false positives (precision {precision:.0%})")
    if fp_by_type:
        print(f"  false positives came from: {fp_by_type}")
    print()


def main() -> None:
    flows = TrafficGenerator().build_default()
    from collections import Counter
    counts = Counter(f.behaviour for f in flows)
    print(f"Traffic: {len(flows)} flows — {dict(counts)}\n")

    print("=" * 60)
    print("Timing-only detector (coefficient of variation)")
    print("=" * 60)
    evaluate("naive", flows, score_timing_only)

    print("=" * 60)
    print("Refined: drop service ports + require small consistent payloads")
    print("=" * 60)
    evaluate("refined", flows, score_refined)

    print("The finding")
    print("-" * 11)
    print("""
  A timing-only beaconing detector flags every NTP client and every
  update checker, because they are as periodic as any C2. In this traffic
  that's dozens of false positives for 8 real beacons — a precision an
  analyst would mute within a day.

  Timing alone cannot fix it: a beacon deliberately configured to look like
  NTP (port 123, 64s interval) is, by timing, NTP. The refinement drops
  known periodic-service ports and requires the small, consistent payloads a
  beacon has and an update check doesn't. That recovers precision — but the
  honest limit stands: a beacon on port 443 with tuned payloads and jitter
  is indistinguishable from benign periodic HTTPS by network features alone.
  Catching that needs destination reputation, which is data this layer
  doesn't have.
""")


if __name__ == "__main__":
    main()
