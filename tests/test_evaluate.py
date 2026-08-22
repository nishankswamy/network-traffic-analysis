"""The end-to-end beaconing evaluation and its finding."""

import numpy as np

from netflow.generate import TrafficGenerator


def _score_naive(flow):
    from netflow.beaconing import analyse_timing
    return analyse_timing(flow.timestamps).is_beacon


def _score_refined(flow):
    from netflow.beaconing import analyse_timing
    v = analyse_timing(flow.timestamps)
    if not v.is_beacon:
        return False
    if flow.dst_port in {123, 53}:
        return False
    sizes = flow.payload_sizes
    if sizes and (np.mean(sizes) > 600 or (np.std(sizes) / np.mean(sizes)) > 0.3):
        return False
    return True


def _precision_recall(flows, scorer):
    tp = fp = fn = 0
    for f in flows:
        flagged = scorer(f)
        if flagged and f.behaviour == "beacon":
            tp += 1
        elif flagged:
            fp += 1
        elif f.behaviour == "beacon":
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return precision, recall


def test_naive_detector_has_low_precision():
    """Timing-only flags all the legitimate periodic traffic."""
    flows = TrafficGenerator().build_default()
    precision, recall = _precision_recall(flows, _score_naive)
    assert recall == 1.0        # it catches every beacon
    assert precision < 0.3      # but drowns in NTP/update false positives


def test_refined_detector_recovers_precision():
    """Dropping service ports and requiring small consistent payloads removes
    the false positives without losing a beacon."""
    flows = TrafficGenerator().build_default()
    precision, recall = _precision_recall(flows, _score_refined)
    assert recall == 1.0
    assert precision > 0.9


def test_false_positives_are_the_periodic_services():
    """Confirms the false positives are exactly NTP and update checks — the
    legitimately periodic traffic, not random noise."""
    flows = TrafficGenerator().build_default()
    fp_types = {f.behaviour for f in flows if _score_naive(f) and f.behaviour != "beacon"}
    assert fp_types <= {"ntp", "update_check"}
    assert "ntp" in fp_types
