"""Flow reconstruction: the two directions of a conversation must merge into
one flow."""

from netflow.decode import ACK, FIN, SYN, decode
from netflow.flows import FlowTable, canonical_key, reconstruct
from netflow.pcap import Packet
from tests.conftest import make_tcp_frame


def test_both_directions_merge_into_one_flow():
    a = decode(make_tcp_frame("10.0.0.5", "1.2.3.4", 5000, 443, SYN))
    b = decode(make_tcp_frame("1.2.3.4", "10.0.0.5", 443, 5000, SYN | ACK))
    assert canonical_key(a) == canonical_key(b)

    table = FlowTable()
    table.add(a, 1.0, 60)
    table.add(b, 1.1, 60)
    assert len(table) == 1


def test_directional_counts():
    table = FlowTable()
    table.add(decode(make_tcp_frame("10.0.0.5", "1.2.3.4", 5000, 443, SYN)), 1.0, 60)
    table.add(decode(make_tcp_frame("10.0.0.5", "1.2.3.4", 5000, 443, ACK, b"req")), 1.1, 100)
    table.add(decode(make_tcp_frame("1.2.3.4", "10.0.0.5", 443, 5000, ACK, b"response")), 1.2, 200)

    # Canonicalisation sorts endpoints, so the server (1.2.3.4:443) is
    # endpoint_a and the client (10.0.0.5:5000) is endpoint_b. Direction counts
    # follow that, not argument order — which is the point of canonicalisation.
    flow = table.flows()[0]
    assert flow.endpoint_a == ("1.2.3.4", 443)
    assert flow.packets_b_to_a == 2   # the two client packets
    assert flow.packets_a_to_b == 1   # the one server response
    assert flow.bytes_b_to_a == 160
    assert flow.bytes_a_to_b == 200
    assert flow.total_bytes == 360


def test_established_vs_scan():
    """A SYN with a reply is a conversation; a lone SYN is a scan."""
    established = FlowTable()
    established.add(decode(make_tcp_frame("10.0.0.5", "1.2.3.4", 5000, 443, SYN)), 1.0, 60)
    established.add(decode(make_tcp_frame("1.2.3.4", "10.0.0.5", 443, 5000, SYN | ACK)), 1.1, 60)
    assert established.flows()[0].is_established

    scan = FlowTable()
    scan.add(decode(make_tcp_frame("10.0.0.5", "1.2.3.4", 5000, 443, SYN)), 1.0, 60)
    assert not scan.flows()[0].is_established


def test_separate_conversations_stay_separate():
    table = FlowTable()
    table.add(decode(make_tcp_frame("10.0.0.5", "1.1.1.1", 5000, 443, SYN)), 1.0, 60)
    table.add(decode(make_tcp_frame("10.0.0.5", "2.2.2.2", 5001, 443, SYN)), 1.0, 60)
    assert len(table) == 2


def test_reconstruct_from_packets():
    packets = [
        Packet(1.0, make_tcp_frame("10.0.0.5", "1.2.3.4", 5000, 443, SYN), 60),
        Packet(1.1, make_tcp_frame("1.2.3.4", "10.0.0.5", 443, 5000, SYN | ACK), 60),
        Packet(5.0, make_tcp_frame("1.2.3.4", "10.0.0.5", 443, 5000, FIN), 60),
    ]
    flow = reconstruct(packets).flows()[0]
    assert flow.total_packets == 3
    assert flow.duration == 4.0
    assert flow.saw_fin
