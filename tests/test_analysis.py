import struct
import unittest
from dataclasses import replace

from network_sniffer.application import parse_dns, scan_http, scan_tcp_dns, scan_tls
from network_sniffer.capture import Packet
from network_sniffer.dissect import analyze_packet
from network_sniffer.display_filter import compile_display_filter
from network_sniffer.flow_analysis import application_messages, tcp_metrics
from network_sniffer.tcp_flow import TcpTracker, reassemble
from network_sniffer.traffic_stats import TrafficStats

from test_dissect import ethernet, ipv4, udp
from test_tcp_flow import load, segment


_DNS_QUERY = struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x04test\x00\x00\x01\x00\x01"
_DNS_REPLY = (
    struct.pack("!6H", 0x1234, 0x8180, 1, 1, 0, 0) + _DNS_QUERY[12:]
    + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((192, 0, 2, 55))
)


def tls_vector(data: bytes, width: int = 2) -> bytes:
    return len(data).to_bytes(width, "big") + data


def tls_extension(kind: int, data: bytes) -> bytes:
    return struct.pack("!H", kind) + tls_vector(data)


def tls_record(data: bytes) -> bytes:
    return b"\x16\x03\x03" + tls_vector(data)


class ApplicationAnalysisTests(unittest.TestCase):
    def test_udp_dns_query_response_offsets_and_filtering(self):
        frame = ethernet(0x0800, ipv4(17, udp(_DNS_REPLY)))
        packet = Packet(0, 1, len(frame), frame)
        analysis = analyze_packet(packet)
        self.assertEqual([layer.name for layer in analysis.layers], ["Ethernet", "IPv4", "UDP", "DNS"])
        dns = analysis.layers[-1]
        fields = {item.key: item for item in dns.fields}
        self.assertEqual((fields["dns.id"].value, fields["dns.id"].offset), (0x1234, 42))
        self.assertEqual(fields["dns.qname"].value, "example.test")
        self.assertEqual(fields["dns.rr.name"].length, 2)
        self.assertEqual(fields["dns.rr.data"].value, "192.0.2.55")
        self.assertTrue(compile_display_filter("udp and dns and dns.response == 1").matches(packet, analysis))
        self.assertFalse(analysis.issues)

    def test_dns_compression_and_incomplete_stream_frames(self):
        bad = _DNS_QUERY[:12] + b"\xc0\x0c\x00\x01\x00\x01"
        self.assertIn("Invalid DNS compression", parse_dns(bad).note)
        self.assertIsNone(parse_dns(b"\x00"))
        dns_stream = tls_vector(_DNS_QUERY) + tls_vector(_DNS_REPLY) + tls_vector(_DNS_QUERY)[:-1]
        messages = scan_tcp_dns(dns_stream)
        self.assertEqual([item.title for item in messages], ["DNS Query", "DNS Response", "DNS over TCP"])
        self.assertIn("Incomplete", messages[-1].note)

    def test_http_messages_after_fixed_length_and_chunked_bodies(self):
        request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc"
        followup = b"GET /next HTTP/1.1\r\n\r\n"
        self.assertEqual([item.title for item in scan_http(request + followup)], ["HTTP POST /upload", "HTTP GET /next"])
        response = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3;id=x\r\nabc\r\n0\r\nX-Trailer: ok\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
        )
        self.assertEqual([item.title for item in scan_http(response)], ["HTTP 200 OK", "HTTP 204 No Content"])
        incomplete = scan_http(request[:-2])[0]
        self.assertEqual(incomplete.note, "Incomplete HTTP body")
        unsafe_header = scan_http(b"GET / HTTP/1.1\r\nHost: a\x1b[0m\r\n\r\n")[0]
        self.assertEqual(unsafe_header.fields[-1].text, "a\\x1b[0m")

    def test_tls_visible_metadata_across_tls_records(self):
        sni = tls_extension(0, tls_vector(b"\x00" + tls_vector(b"example.test")))
        versions = tls_extension(43, bytes.fromhex("04 0304 0303"))
        alpn = tls_extension(16, tls_vector(tls_vector(b"h2", 1) + tls_vector(b"http/1.1", 1)))
        body = bytes.fromhex("0303") + bytes(32) + b"\x00" + tls_vector(bytes.fromhex("1301")) + b"\x01\x00"
        hello = b"\x01" + tls_vector(body + tls_vector(sni + versions + alpn), 3)
        captured = tls_record(hello[:13]) + tls_record(hello[13:])
        client, = scan_tls(captured)
        fields = {item.key: item.text for item in client.fields}
        self.assertEqual((client.title, fields["tls.sni"], fields["tls.versions"]),
                         ("TLS ClientHello", "example.test", "TLS 1.3, TLS 1.2"))
        self.assertEqual(fields["tls.alpn"], "h2, http/1.1")
        server_body = bytes.fromhex("0303") + bytes(32) + bytes.fromhex("00 1301 00")
        server = tls_record(b"\x02" + tls_vector(server_body + tls_vector(tls_extension(43, bytes.fromhex("0304"))), 3))
        server_hello, = scan_tls(server)
        self.assertEqual({item.key: item.text for item in server_hello.fields}["tls.versions"], "TLS 1.3")
        self.assertIn("not observed", scan_tls(captured[:-1])[0].note)

    def test_reassembled_tcp_application_does_not_cross_a_gap(self):
        tracker = TcpTracker()
        load(tracker, segment(100, flags=2), segment(101, payload=b"GET / HTTP/1.1\r\nHost:"),
             segment(126, payload=b" example.test\r\n\r\n"))
        flow = tracker.snapshot(1)
        messages, note = application_messages(reassemble(flow, 0), dns=False)
        self.assertEqual(messages[0].note, "Incomplete HTTP headers or header limit reached")
        self.assertIn("gap", note)

        tracker = TcpTracker()
        data = tls_vector(_DNS_QUERY)
        load(tracker, segment(500, flags=2, port=53), segment(512, payload=data[11:], port=53),
             segment(501, payload=data[:11], port=53))
        messages, note = application_messages(reassemble(tracker.snapshot(1), 0), dns=True)
        self.assertEqual(messages[0].title, "DNS Query")
        self.assertIsNone(note)


class StatisticsTests(unittest.TestCase):
    def test_protocol_endpoint_udp_and_tcp_session_counts(self):
        tracker = TcpTracker()
        traffic = TrafficStats()
        dns = ethernet(0x0800, ipv4(17, udp(_DNS_QUERY)))
        dns_packet = Packet(0, 1, len(dns), dns)
        tcp = segment(111, payload=b"payload", snaplen=56)
        for number, packet in enumerate((dns_packet, tcp), start=1):
            analysis = analyze_packet(packet)
            traffic.observe(packet, analysis)
            tracker.observe(number, packet, analysis)
        report = traffic.snapshot()
        self.assertEqual((report.total.packets, report.total.frame_bytes, report.total.captured_bytes), (2, len(dns) + 61, len(dns) + 56))
        protocols = dict(report.protocols)
        self.assertEqual({name: count.packets for name, count in protocols.items()},
                         {"Ethernet": 2, "IPv4": 2, "TCP": 1, "UDP": 1, "DNS": 1})
        self.assertEqual([item.sent.packets for item in report.endpoints], [2, 0])
        self.assertEqual([item.received.packets for item in report.endpoints], [0, 2])
        self.assertEqual(report.udp_sessions[0].traffic.frame_bytes, len(dns))
        self.assertEqual((tracker.flow_infos()[0].packet_count, tracker.flow_infos()[0].frame_bytes), (1, 61))

    def test_bounded_detail_tables_preserve_capture_totals(self):
        traffic = TrafficStats(endpoint_limit=1, udp_limit=1)
        first = ethernet(0x0800, ipv4(17, udp()))
        second = bytearray(first)
        second[34:36] = bytes.fromhex("002a")
        for frame in (first, bytes(second)):
            packet = Packet(0, 1, len(frame), frame)
            traffic.observe(packet, analyze_packet(packet))
        report = traffic.snapshot()
        self.assertEqual((report.total.packets, len(report.endpoints), len(report.udp_sessions)), (2, 1, 1))
        self.assertEqual((report.endpoint_evictions, report.udp_evictions), (3, 1))

    def test_rtt_excludes_retransmission_and_gap_ambiguity(self):
        tracker = TcpTracker()
        frames = [
            (segment(100, flags=2), 10_000),
            (segment(200, flags=0x12, reverse=True, acknowledgment=101), 30_000),
            (segment(101, acknowledgment=201), 45_000),
            (segment(101, payload=b"abc", acknowledgment=201), 60_000),
            (segment(101, payload=b"abc", acknowledgment=201), 80_000),
            (segment(201, reverse=True, acknowledgment=104), 100_000),
            (segment(104, payload=b"def", acknowledgment=201), 130_000),
            (segment(201, reverse=True, acknowledgment=107), 160_000),
            (segment(109, payload=b"ghi", acknowledgment=201), 180_000),
            (segment(201, reverse=True, acknowledgment=112), 220_000),
        ]
        load(tracker, *(replace(packet, timestamp_us=timestamp) for packet, timestamp in frames))
        forward, reverse = tcp_metrics(tracker.snapshot(1))
        self.assertEqual((forward.retransmissions, forward.rtt_samples), (1, 2))
        self.assertEqual((forward.minimum_us, forward.mean_us, forward.maximum_us), (20_000, 25_000, 30_000))
        self.assertEqual((reverse.rtt_samples, reverse.mean_us), (1, 15_000))
