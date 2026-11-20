import struct
import unittest

from network_sniffer.capture import Packet
from network_sniffer.dissect import analyze_packet
from network_sniffer.tcp_flow import FlowSnapshot, TcpTracker, reassemble

from test_dissect import ethernet, ipv4, ipv6


def segment(
    sequence: int, *, acknowledgment: int = 0, flags: int = 0x10, payload: bytes = b"", reverse: bool = False,
    port: int = 49152, version: int = 4, snaplen: int | None = None, fragment: int = 0, padding: bytes = b"",
) -> Packet:
    ports = (80, port) if reverse else (port, 80)
    tcp = struct.pack("!HHIIHHHH", *ports, sequence, acknowledgment, 0x5000 | flags, 4096, 0, 0) + payload
    if version == 4:
        header = ipv4(6, tcp, flags=fragment)
        if reverse:
            header = header[:12] + header[16:20] + header[12:16] + header[20:]
        frame = ethernet(0x0800, header) + padding
    else:
        options = bytes((6, 0, 1, 4, 0, 0, 0, 0))
        header = ipv6(60, options + tcp)
        if reverse:
            header = header[:8] + header[24:40] + header[8:24] + header[40:]
        frame = ethernet(0x86DD, header) + padding
    return Packet(0, 1, len(frame), frame[:snaplen])


def load(tracker: TcpTracker, *packets: Packet, start: int = 1) -> None:
    for number, packet in enumerate(packets, start=start):
        tracker.observe(number, packet, analyze_packet(packet))


def data_of(flow: FlowSnapshot, direction: int) -> bytes:
    return b"".join(bytes(span.data) for span in reassemble(flow, direction).spans if span.data is not None)


class TcpFlowTests(unittest.TestCase):
    def test_duplex_concurrent_ipv4_and_ipv6_connections(self):
        tracker = TcpTracker()
        load(
            tracker,
            segment(100, payload=b"v4 request"), segment(50, port=50000, payload=b"other v4"),
            segment(80, version=6, payload=b"v6 request"), segment(70, reverse=True, payload=b"v4 reply"),
            segment(90, reverse=True, version=6, payload=b"v6 reply"),
        )
        self.assertEqual([tracker.flow_for_packet(number) for number in range(1, 6)], [1, 2, 3, 1, 3])
        first = tracker.snapshot(1)
        third = tracker.snapshot(3)
        self.assertEqual([str(endpoint) for endpoint in first.endpoints], ["192.0.2.10:49152", "198.51.100.20:80"])
        self.assertEqual([str(endpoint) for endpoint in third.endpoints], ["[2001:db8::1]:49152", "[2001:db8::2]:80"])
        self.assertEqual((data_of(first, 0), data_of(first, 1)), (b"v4 request", b"v4 reply"))
        self.assertEqual((data_of(third, 0), data_of(third, 1)), (b"v6 request", b"v6 reply"))
        self.assertEqual((third.directions[0].packets, third.directions[0].payload_bytes), (1, 10))

    def test_handshake_fin_and_tuple_reuse_with_retransmitted_syn(self):
        tracker = TcpTracker()
        opening = segment(100, flags=0x02)
        load(tracker, opening, opening, segment(200, reverse=True, flags=0x12, acknowledgment=101))
        self.assertEqual(tracker.snapshot(1).state, "Handshake")
        load(tracker, segment(101, acknowledgment=201), start=4)
        self.assertEqual(tracker.snapshot(1).state, "Established")
        load(tracker, segment(101, flags=0x11, acknowledgment=201), start=5)
        self.assertEqual(tracker.snapshot(1).state, "Closing")
        load(
            tracker,
            segment(201, reverse=True, acknowledgment=102),
            segment(201, reverse=True, flags=0x11, acknowledgment=102),
            segment(102, acknowledgment=202), start=6,
        )
        self.assertEqual(tracker.snapshot(1).state, "Closed")
        load(tracker, segment(500, flags=0x02), segment(0, reverse=True, flags=0x14, acknowledgment=501), start=9)
        first, second = tracker.snapshot(1), tracker.snapshot(2)
        self.assertEqual([tracker.flow_for_packet(i) for i in range(1, 11)], [1] * 8 + [2, 2])
        self.assertEqual([item.fin_packet for item in first.directions], [5, 7])
        self.assertTrue(first.start_seen)
        self.assertEqual((second.state, second.rst_packet), ("Reset", 10))

    def test_syn_ack_captured_before_initial_syn(self):
        tracker = TcpTracker()
        load(
            tracker,
            segment(200, reverse=True, flags=0x12, acknowledgment=101),
            segment(100, flags=0x02), segment(101, acknowledgment=201),
        )
        flow = tracker.snapshot(1)
        self.assertEqual((flow.state, flow.start_seen), ("Established", True))
        self.assertEqual([packet.number for packet in flow.packets], [1, 2, 3])

    def test_reuse_without_observed_close_gets_another_flow(self):
        tracker = TcpTracker()
        load(tracker, segment(100, payload=b"old"), segment(900, flags=0x02), segment(901, payload=b"new"))
        self.assertEqual(tracker.snapshot(1).state, "Superseded")
        self.assertEqual(data_of(tracker.snapshot(1), 0), b"old")
        self.assertEqual(data_of(tracker.snapshot(2), 0), b"new")

    def test_out_of_order_retransmission_and_conflicting_overlap(self):
        tracker = TcpTracker()
        load(
            tracker, segment(100, flags=0x02), segment(106, payload=b"FGH"),
            segment(101, payload=b"abcdefg"), segment(101, payload=b"abcdefg"), segment(109, payload=b"i"),
        )
        flow = tracker.snapshot(1)
        result = reassemble(flow, 0)
        self.assertEqual(data_of(flow, 0), b"abcdeFGHi")
        self.assertEqual((result.captured_bytes, result.missing_bytes, result.overlapping_bytes), (9, 0, 9))

    def test_wraparound_and_syn_data(self):
        tracker = TcpTracker()
        load(
            tracker, segment(0xFFFFFFFD, flags=0x02, payload=b"a"), segment(0, payload=b"cd"),
            segment(0xFFFFFFFF, payload=b"b"), segment(700, acknowledgment=500),
        )
        flow = tracker.snapshot(1)
        self.assertEqual(data_of(flow, 0), b"abcd")
        self.assertEqual((reassemble(flow, 0).missing_bytes, reassemble(flow, 0).captured_bytes), (0, 4))

    def test_capture_gap_and_snaplen_truncation(self):
        tracker = TcpTracker()
        load(
            tracker, segment(100, flags=0x02), segment(101, payload=b"12345", snaplen=56),
            segment(109, payload=b"AB"), segment(113, flags=0x11),
        )
        flow = tracker.snapshot(1)
        self.assertTrue(flow.packets[1].partial)
        self.assertEqual(flow.packets[1].expected_payload, 5)
        result = reassemble(flow, 0)
        self.assertEqual([(span.offset, span.length) for span in result.spans if span.data is None], [(2, 6), (10, 2)])
        self.assertEqual((data_of(flow, 0), result.missing_bytes), (b"12AB", 8))

    def test_midstream_capture_with_earlier_data_arriving_later(self):
        tracker = TcpTracker()
        load(tracker, segment(210, payload=b"cd"), segment(208, payload=b"ab"))
        flow = tracker.snapshot(1)
        self.assertEqual((flow.state, flow.start_seen), ("Midstream", False))
        self.assertEqual(data_of(flow, 0), b"abcd")

    def test_partial_headers_ip_fragments_and_link_padding(self):
        tracker = TcpTracker()
        load(
            tracker, segment(10, flags=0x02, snaplen=38), segment(20, payload=b"part", fragment=0x2000),
            segment(30, payload=b"later IP fragment", fragment=1), segment(24, padding=b"padding"),
        )
        flow = tracker.snapshot(1)
        self.assertTrue(flow.packets[0].partial)
        self.assertIsNone(flow.packets[0].sequence)
        self.assertIsNone(flow.packets[1].expected_payload)
        self.assertIsNone(tracker.flow_for_packet(3))
        self.assertEqual(data_of(flow, 0), b"part")

    def test_live_limits_keep_counts_and_mark_evicted_payload(self):
        tracker = TcpTracker(flow_limit=2, packet_limit=2, byte_limit=256)
        load(tracker, segment(100, payload=b"ab"), segment(102, payload=b"cd"), segment(104, payload=b"ef"))
        flow = tracker.snapshot(1)
        self.assertEqual((len(flow.packets), flow.omitted_packets), (2, 1))
        self.assertEqual((flow.directions[0].packets, flow.directions[0].payload_bytes), (3, 6))
        self.assertEqual((data_of(flow, 0), reassemble(flow, 0).missing_bytes), (b"cdef", 2))
        self.assertIsNone(tracker.flow_for_packet(1))
        load(tracker, segment(9, port=50000), segment(9, port=50001), start=4)
        self.assertIsNone(tracker.snapshot(1))
