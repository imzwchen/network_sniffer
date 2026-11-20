import struct
import unittest
from ipaddress import ip_address

from network_sniffer.capture import Packet
from network_sniffer.dissect import PacketAnalysis, ProtocolField, analyze_packet


_SOURCE_MAC = bytes.fromhex("02 00 00 00 00 01")
_TARGET_MAC = bytes.fromhex("02 00 00 00 00 02")
_SOURCE_IP4 = ip_address("192.0.2.10")
_TARGET_IP4 = ip_address("198.51.100.20")
_SOURCE_IP6 = ip_address("2001:db8::1")
_TARGET_IP6 = ip_address("2001:db8::2")


def ethernet(ether_type: int, payload: bytes) -> bytes:
    return _TARGET_MAC + _SOURCE_MAC + struct.pack("!H", ether_type) + payload


def ipv4(
    protocol: int, payload: bytes, *, flags: int = 0, options: bytes = b"", length: int | None = None,
) -> bytes:
    header_size = 20 + len(options)
    length = length if length is not None else header_size + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x40 | (header_size // 4), 0, length, 0x1234, flags, 64,
        protocol, 0, _SOURCE_IP4.packed, _TARGET_IP4.packed,
    )
    return header + options + payload


def ipv6(protocol: int, payload: bytes) -> bytes:
    return struct.pack(
        "!IHBB16s16s", 0x6AB12345, len(payload), protocol, 32, _SOURCE_IP6.packed, _TARGET_IP6.packed,
    ) + payload


def udp(payload: bytes = b"", *, length: int | None = None) -> bytes:
    return struct.pack("!HHHH", 5353, 53, length if length is not None else 8 + len(payload), 0) + payload


def analyze(frame: bytes, link: int = 1, original: int | None = None) -> PacketAnalysis:
    return analyze_packet(Packet(0, link, len(frame) if original is None else original, frame))


def fields(analysis: PacketAnalysis) -> dict[str, ProtocolField]:
    return {field.key: field for layer in analysis.layers for field in layer.fields}


class PacketAnalysisTests(unittest.TestCase):
    def test_ethernet_ipv4_and_tcp_options_produce_absolute_fields(self):
        tcp = struct.pack("!HHIIHHHH", 49152, 443, 10, 20, 0x6012, 8192, 0, 0) + b"\x02\x04\x05\xb4"
        frame = ethernet(0x0800, ipv4(6, tcp, options=b"\x01\x01\x00\x00"))
        analysis = analyze(frame)
        parsed = fields(analysis)
        self.assertEqual([(layer.name, layer.offset, layer.length) for layer in analysis.layers], [
            ("Ethernet", 0, 14), ("IPv4", 14, 24), ("TCP", 38, 24),
        ])
        self.assertEqual(parsed["eth.src"].value, "02:00:00:00:00:01")
        self.assertEqual(parsed["ipv4.src"].value, _SOURCE_IP4)
        self.assertEqual(parsed["ipv4.dst"].offset, 30)
        self.assertEqual(parsed["ipv4.options"].offset, 34)
        self.assertEqual(parsed["tcp.dst_port"].value, 443)
        self.assertEqual(parsed["tcp.flags"].value, 0x12)
        self.assertEqual(parsed["tcp.flags"].offset, 50)
        self.assertIn("SYN, ACK", parsed["tcp.flags"].display)
        self.assertEqual(parsed["tcp.options"].offset, 58)
        self.assertFalse(analysis.issues)

    def test_stacked_vlan_ipv6_and_udp(self):
        tags = struct.pack("!HHHH", 0xB025, 0x8100, 0x0099, 0x86DD)
        analysis = analyze(ethernet(0x88A8, tags + ipv6(17, udp(b"abc"))))
        outer, inner = analysis.layers[1:3]
        self.assertEqual((outer.name, inner.name), ("VLAN", "VLAN"))
        self.assertEqual([field.value for field in outer.fields], [5, 1, 37, 0x8100])
        self.assertEqual((inner.offset, inner.fields[2].value), (18, 153))
        parsed = fields(analysis)
        self.assertEqual(parsed["ipv6.traffic_class"].value, 0xAB)
        self.assertEqual(parsed["ipv6.flow_label"].value, 0x12345)
        self.assertEqual(parsed["ipv6.dst"].value, _TARGET_IP6)
        self.assertEqual(parsed["udp.dst_port"].offset, 64)
        self.assertEqual(parsed["udp.length"].value, 11)
        self.assertFalse(analysis.issues)

    def test_linux_cooked_capture_v1_and_v2(self):
        address = _SOURCE_MAC.ljust(8, b"\x00")
        sll = struct.pack("!HHH8sH", 4, 1, 6, address, 0x0800)
        sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 7, 1, 4, 6, address)
        for link, header, name in [(113, sll, "SLL"), (276, sll2, "SLL2")]:
            with self.subTest(link=link):
                analysis = analyze(header + ipv4(17, udp()), link)
                parsed = fields(analysis)
                self.assertEqual(analysis.layers[0].name, name)
                self.assertEqual(analysis.layers[1].offset, len(header))
                self.assertEqual(parsed[f"{name.lower()}.packet_type"].value, 4)
                self.assertEqual(parsed[f"{name.lower()}.address"].value, "02:00:00:00:00:01")
                self.assertEqual(parsed["udp.src_port"].value, 5353)
                self.assertFalse(analysis.issues)
        self.assertEqual(fields(analysis)["sll2.ifindex"].value, 7)

    def test_arp_variable_address_layout(self):
        payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        payload += _SOURCE_MAC + _SOURCE_IP4.packed + bytes(6) + _TARGET_IP4.packed
        analysis = analyze(ethernet(0x0806, payload))
        parsed = fields(analysis)
        self.assertEqual(analysis.protocol, "ARP")
        self.assertEqual(analysis.layers[1].length, 28)
        self.assertEqual(parsed["arp.operation"].value, 1)
        self.assertEqual(parsed["arp.sender_ip"].value, _SOURCE_IP4)
        self.assertEqual(parsed["arp.target_ip"].value, _TARGET_IP4)
        self.assertEqual(parsed["arp.target_ip"].offset, 38)

    def test_ipv6_extension_chain_finds_transport(self):
        hop_by_hop = bytes([43, 0, 1, 4, 0, 0, 0, 0])
        routing = bytes([60, 0, 2, 0, 0, 0, 0, 0])
        options = bytes([51, 0, 1, 4, 0, 0, 0, 0])
        authentication = struct.pack("!BBHIII", 17, 2, 0, 42, 10, 0)
        analysis = analyze(ethernet(0x86DD, ipv6(0, hop_by_hop + routing + options + authentication + udp())))
        self.assertEqual([layer.offset for layer in analysis.layers], [0, 14, 54, 62, 70, 78, 94])
        self.assertEqual(analysis.protocol, "UDP")
        self.assertEqual(fields(analysis)["ipv6.ext51.spi"].value, 42)
        self.assertFalse(analysis.issues)

    def test_non_initial_fragments_stop_before_transport(self):
        fragment = struct.pack("!BBHI", 17, 0, 0x0018, 123)
        for frame, expected_layer, field_key in [
            (ethernet(0x0800, ipv4(17, udp(), flags=3)), "IPv4", "ipv4.fragment_offset"),
            (ethernet(0x86DD, ipv6(44, fragment + udp())), "IPv6 Fragment", "ipv6.ext44.fragment_offset"),
        ]:
            with self.subTest(last_layer=expected_layer):
                analysis = analyze(frame)
                parsed = fields(analysis)
                self.assertEqual(analysis.layers[-1].name, expected_layer)
                self.assertEqual(parsed[field_key].value, 24)
                self.assertNotIn("udp.src_port", parsed)
                self.assertEqual([issue.kind for issue in analysis.issues], ["Fragment"])

    def test_first_fragments_can_have_an_incomplete_datagram(self):
        datagram = udp(b"12345678", length=40)
        ipv6_fragment = struct.pack("!BBHI", 17, 0, 1, 123)
        for frame in (
            ethernet(0x0800, ipv4(17, datagram, flags=0x2000)),
            ethernet(0x86DD, ipv6(44, ipv6_fragment + datagram)),
        ):
            with self.subTest(ether_type=frame[12:14].hex()):
                analysis = analyze(frame)
                self.assertEqual(analysis.protocol, "UDP")
                self.assertEqual(fields(analysis)["udp.length"].value, 40)
                self.assertEqual([issue.kind for issue in analysis.issues], ["Fragment"])

    def test_icmp_echo_fields_for_both_versions(self):
        for name, ether_type, message_type, make_ip, protocol in [
            ("icmp", 0x0800, 8, ipv4, 1), ("icmpv6", 0x86DD, 128, ipv6, 58),
        ]:
            with self.subTest(protocol=name):
                message = struct.pack("!BBHHH", message_type, 0, 0, 1234, 7)
                parsed = fields(analyze(ethernet(ether_type, make_ip(protocol, message))))
                self.assertIn("Echo Request", parsed[f"{name}.type"].display)
                self.assertEqual(parsed[f"{name}.id"].value, 1234)
                self.assertEqual(parsed[f"{name}.sequence"].value, 7)

    def test_snapshot_truncation_preserves_complete_fields(self):
        frame = ethernet(0x0800, ipv4(17, udp(b"payload")))
        analysis = analyze(frame[:36], original=len(frame))
        parsed = fields(analysis)
        self.assertEqual(parsed["ipv4.dst"].value, _TARGET_IP4)
        self.assertEqual(parsed["udp.src_port"].value, 5353)
        self.assertNotIn("udp.dst_port", parsed)
        self.assertTrue(all(issue.kind == "Truncated" for issue in analysis.issues))

    def test_ip_length_prevents_decoding_ethernet_padding_as_transport(self):
        frame = ethernet(0x0800, ipv4(17, udp(), length=20))
        analysis = analyze(frame)
        self.assertEqual(analysis.protocol, "IPv4")
        self.assertNotIn("udp.src_port", fields(analysis))
        self.assertEqual(analysis.issues[-1].kind, "Malformed")

        frame = ethernet(0x0800, ipv4(17, udp(), options=b"\x01" * 4, length=20))
        analysis = analyze(frame)
        self.assertNotIn("ipv4.options", fields(analysis))
        self.assertEqual(analysis.issues[-1].kind, "Malformed")

    def test_unsupported_headers_keep_the_parsed_prefix(self):
        for frame, link, expected, protocol in [
            (b"\x01\x02", 999, "Link type 999", "Unknown"),
            (ethernet(0x88CC, b"\x01\x02"), 1, "EtherType 0x88cc", "Ethernet"),
            (ethernet(0x0800, ipv4(253, b"\x01\x02")), 1, "protocol 253", "IPv4"),
        ]:
            with self.subTest(expected=expected):
                analysis = analyze(frame, link)
                self.assertEqual(analysis.protocol, protocol)
                self.assertEqual(analysis.issues[0].kind, "Unsupported")
                self.assertIn(expected, analysis.issues[0].message)

    def test_every_snapshot_prefix_stays_within_captured_bytes(self):
        frames = [
            ethernet(0x8100, struct.pack("!HH", 122, 0x0800) + ipv4(17, udp(b"payload"))),
            ethernet(0x86DD, ipv6(0, bytes([17, 0, 0, 0, 0, 0, 0, 0]) + udp())),
        ]
        for frame in frames:
            for size in range(len(frame)):
                with self.subTest(ether_type=frame[12:14].hex(), caplen=size):
                    analysis = analyze(frame[:size], original=len(frame))
                    self.assertEqual(analysis.issues[0].kind, "Truncated")
                    for field in fields(analysis).values():
                        self.assertLessEqual(field.offset + field.length, size)
