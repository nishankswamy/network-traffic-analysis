"""C2 beaconing detection — and its central problem: legitimate periodic traffic.

Command-and-control malware "beacons": it calls home on a regular interval to
fetch orders. In flow data that shows up as connections to one destination at
suspiciously regular time intervals. Detecting it sounds easy — find the regular
inter-arrival times — until you remember that NTP, software update checks,
keepalives, and telemetry are *also* perfectly periodic. That is the whole
difficulty, and the thing most writeups skip.

So this doesn't just detect periodicity; it's evaluated against benign periodic
traffic, and Day 16 reports the false-positive rate, because a beaconing
detector that flags NTP is worse than useless.

The signal used is the coefficient of variation of inter-arrival times: the
standard deviation divided by the mean. A perfect beacon has CV near 0 (rigidly
regular); random human traffic has CV near or above 1. Real malware adds
**jitter** — randomising the interval ±N% to evade exactly this detection — so
the detector has to tolerate some CV without opening the door to normal traffic.
Where that threshold sits is the tunable that trades detection for false alarms.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass


@dataclass
class BeaconVerdict:
    is_beacon: bool
    score: float                 # 0-1, higher = more beacon-like
    interval_seconds: float      # estimated beacon period
    coefficient_of_variation: float
    n_intervals: int


def analyse_timing(timestamps: list[float], min_events: int = 8) -> BeaconVerdict:
    """Score a series of connection times for beacon-like regularity.

    Needs enough events to be a pattern rather than a coincidence — three evenly
    spaced connections are not a beacon, they're Tuesday. `min_events` guards
    that, and it's a real lever on the false-positive rate."""
    if len(timestamps) < min_events:
        return BeaconVerdict(False, 0.0, 0.0, 0.0, 0)

    ordered = sorted(timestamps)
    intervals = [b - a for a, b in zip(ordered, ordered[1:])]
    intervals = [i for i in intervals if i > 0]
    if len(intervals) < min_events - 1:
        return BeaconVerdict(False, 0.0, 0.0, 0.0, len(intervals))

    mean = statistics.mean(intervals)
    stdev = statistics.pstdev(intervals)
    cv = stdev / mean if mean > 0 else float("inf")

    # Map CV to a 0-1 beacon score. CV=0 (rigid) -> 1.0; CV>=0.5 -> ~0.
    # 0.5 is chosen on Day 16: below it, malware jitter still scores; above it,
    # normal bursty traffic starts to leak in.
    score = max(0.0, 1.0 - cv / 0.5)

    return BeaconVerdict(
        is_beacon=score >= 0.5,
        score=score,
        interval_seconds=mean,
        coefficient_of_variation=cv,
        n_intervals=len(intervals),
    )


def find_beacons(flow_table, min_events: int = 8) -> list[tuple]:
    """Scan every flow for beaconing. Returns (flow, verdict) for beacons,
    sorted by score."""
    results = []
    for flow in flow_table.flows():
        verdict = analyse_timing(flow.timestamps, min_events)
        if verdict.is_beacon:
            results.append((flow, verdict))
    return sorted(results, key=lambda x: -x[1].score)
