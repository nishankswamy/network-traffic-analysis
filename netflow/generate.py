"""Synthetic network traffic with labelled behaviours.

Every flow carries a `behaviour` label so detection can be scored. The critical
design choice is including **benign periodic** traffic — NTP, update checks,
telemetry heartbeats — because the whole point of Day 16 is measuring how often
a beaconing detector confuses those with C2. A generator that only produced
"beacon" and "random human" would make the detector look perfect and teach
nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np


@dataclass
class SyntheticFlow:
    dst_ip: str
    dst_port: int
    timestamps: list
    behaviour: str  # "human" | "beacon" | "ntp" | "update_check" | "tunnel_dns"
    payload_sizes: list = field(default_factory=list)


class TrafficGenerator:
    def __init__(self, seed: int = 14) -> None:
        self.rng = np.random.default_rng(seed)
        self.flows: list[SyntheticFlow] = []

    def _times(self, start, interval_fn, count):
        gaps = interval_fn(count - 1)
        return list(np.cumsum(np.concatenate([[start], gaps])))

    def human_browsing(self, n_flows: int, duration: float = 3600) -> None:
        for i in range(n_flows):
            count = self.rng.integers(8, 40)
            start = self.rng.uniform(0, duration / 2)
            # Bursty, heavy-tailed gaps — nothing regular.
            ts = self._times(start, lambda k: self.rng.exponential(20, k), count)
            self.flows.append(SyntheticFlow(
                f"93.184.{self.rng.integers(1,255)}.{self.rng.integers(1,255)}",
                443, ts, "human",
                payload_sizes=list(self.rng.integers(200, 4000, count)),
            ))

    def ntp(self, n_flows: int, count: int = 30) -> None:
        for _ in range(n_flows):
            # Rigidly periodic, ~64s — legitimate, and a false positive waiting
            # to happen for any timing-only detector.
            ts = self._times(self.rng.uniform(0, 100),
                             lambda k: self.rng.normal(64, 0.5, k), count)
            self.flows.append(SyntheticFlow("129.6.15.28", 123, ts, "ntp",
                                            payload_sizes=[48] * count))

    def update_check(self, n_flows: int, count: int = 12) -> None:
        for _ in range(n_flows):
            # Every ~5 min, mild jitter — also legitimately periodic.
            ts = self._times(self.rng.uniform(0, 300),
                             lambda k: self.rng.normal(300, 8, k), count)
            self.flows.append(SyntheticFlow(
                f"104.16.{self.rng.integers(1,255)}.{self.rng.integers(1,255)}",
                443, ts, "update_check", payload_sizes=[1200] * count))

    def c2_beacon(self, n_flows: int, count: int = 30, jitter: float = 0.1) -> None:
        for _ in range(n_flows):
            interval = self.rng.uniform(30, 120)
            # Malware beacon with configurable jitter (±jitter fraction).
            ts = self._times(self.rng.uniform(0, 60),
                             lambda k: self.rng.uniform(interval * (1 - jitter),
                                                        interval * (1 + jitter), k), count)
            self.flows.append(SyntheticFlow(
                f"45.13.{self.rng.integers(1,4)}.{self.rng.integers(1,255)}",
                443, ts, "beacon",
                # Beacons send near-identical small payloads — a second signal.
                payload_sizes=list(self.rng.integers(180, 220, count)),
            ))

    def build_default(self) -> list[SyntheticFlow]:
        self.human_browsing(200)
        self.ntp(15)
        self.update_check(20)
        self.c2_beacon(8)
        return self.flows


def to_flow_table(synthetic: list[SyntheticFlow]):
    """Adapt SyntheticFlow into something the beaconing detector consumes."""
    from .flows import Flow, FlowTable

    table = FlowTable()
    for sf in synthetic:
        flow = Flow(endpoint_a=("10.0.0.5", 40000), endpoint_b=(sf.dst_ip, sf.dst_port),
                    protocol="udp" if sf.dst_port == 123 else "tcp")
        flow.timestamps = list(sf.timestamps)
        flow.packets_a_to_b = len(sf.timestamps)
        flow.start_time = min(sf.timestamps)
        flow.end_time = max(sf.timestamps)
        flow._behaviour = sf.behaviour  # label for evaluation
        flow._payload_sizes = sf.payload_sizes
        flow._dst_port = sf.dst_port
        table._flows[(flow.endpoint_a, flow.endpoint_b, flow.protocol, id(sf))] = flow
    return table


if __name__ == "__main__":
    flows = TrafficGenerator().build_default()
    from collections import Counter
    print(Counter(f.behaviour for f in flows))
