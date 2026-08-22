"""Beaconing detection, and the false-positive problem it exists to expose."""

import numpy as np
import pytest

from netflow.beaconing import analyse_timing


def periodic(interval, count, jitter=0.0, seed=0):
    rng = np.random.default_rng(seed)
    gaps = rng.uniform(interval * (1 - jitter), interval * (1 + jitter), count - 1) if jitter \
        else np.full(count - 1, interval)
    return list(np.cumsum(np.concatenate([[0], gaps])))


def test_rigid_beacon_is_detected():
    v = analyse_timing(periodic(60, 30))
    assert v.is_beacon
    assert v.score > 0.9
    assert abs(v.interval_seconds - 60) < 1


def test_jittered_beacon_still_detected():
    v = analyse_timing(periodic(60, 30, jitter=0.1))
    assert v.is_beacon


def test_random_traffic_is_not_a_beacon():
    rng = np.random.default_rng(0)
    times = list(np.cumsum(rng.exponential(30, 30)))
    assert not analyse_timing(times).is_beacon


def test_legitimate_periodic_traffic_is_flagged():
    """The core problem, pinned as a test: NTP is as periodic as any C2, so a
    timing-only detector cannot tell them apart. This test PASSING is the
    finding — it documents the limitation, not a bug."""
    ntp = periodic(64, 30, jitter=0.01)
    assert analyse_timing(ntp).is_beacon  # a false positive, by design


def test_too_few_events_is_not_a_beacon():
    """Three evenly spaced connections are coincidence, not a beacon."""
    assert not analyse_timing([0, 60, 120]).is_beacon


def test_needs_positive_intervals():
    assert not analyse_timing([5.0] * 10).is_beacon  # all identical timestamps
