import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from network_sniffer.capture import CaptureError, Packet, open_capture
from network_sniffer.dissect import analyze_packet
from network_sniffer.display_filter import DisplayFilterError, compile_display_filter

from test_dissect import ethernet, ipv4, ipv6, udp


_SAMPLE = Path(__file__).resolve().parents[1] / "sample.pcap"


class FilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open_capture(_SAMPLE) as packets:
            base = list(packets)
        extra = [
            ethernet(0x86DD, ipv6(17, udp())),
            ethernet(0x86DD, ipv6(58, struct.pack("!BBHHH", 128, 0, 0, 1, 1))),
        ]
        cls.packets = base + [Packet(1_700_000_001_000_000, 1, len(frame), frame) for frame in extra]

    def _display_matches(self, expression: str) -> list[int]:
        rule = compile_display_filter(expression)
        return [
            index for index, packet in enumerate(self.packets, start=1)
            if rule.matches(packet, analyze_packet(packet))
        ]

    def test_bpf_and_display_selection_across_protocols(self):
        # A fixed Ethernet savefile lets both filters examine the same frames.
        with TemporaryDirectory() as directory:
            sample = Path(directory) / "mixed.pcap"
            with sample.open("wb") as output:
                output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
                for packet in self.packets:
                    seconds, usec = divmod(packet.timestamp_us, 1_000_000)
                    output.write(struct.pack("<IIII", seconds, usec, packet.captured_length, packet.original_length))
                    output.write(packet.data)

            for bpf, display, indexes in (
                ("tcp", "tcp", [1]), ("udp", "udp", [2, 4]), ("ip", "ipv4", [1, 2, 3]),
                ("ip6", "ipv6", [4, 5]), ("icmp", "icmp", [3]), ("icmp6", "icmpv6", [5]),
                ("(tcp or udp) and not ip6", "(tcp or udp) and not ipv6", [1, 2]),
                ("ip6 and udp and dst port 53", "ipv6 and udp and dst.port == 53", [4]),
            ):
                with self.subTest(bpf=bpf, display=display):
                    with open_capture(sample, capture_filter=bpf) as packets:
                        self.assertEqual(list(packets), [self.packets[index - 1] for index in indexes])
                    self.assertEqual(self._display_matches(display), indexes)
            with open_capture(sample) as packets:
                self.assertEqual(list(packets), self.packets)

    def test_display_precedence_and_parentheses(self):
        self.assertEqual(self._display_matches("tcp or udp and ipv6"), [1, 4])
        self.assertEqual(self._display_matches("(tcp or udp) and ipv6"), [4])
        self.assertEqual(self._display_matches("not tcp and ipv4"), [2, 3])
        self.assertEqual(self._display_matches("NOT (tcp AND ipv4)"), [2, 3, 4, 5])
        self.assertEqual(self._display_matches("not not icmpv6"), [5])

    def test_display_address_and_numeric_comparisons(self):
        self.assertEqual(self._display_matches("dst.ip == 2001:db8::2 and dst.port <= 53"), [4])
        self.assertEqual(self._display_matches("src.ip == 192.0.2.10 and tcp.flags == 0x002"), [1])
        self.assertEqual(self._display_matches("udp and dst.port >= 0053"), [2, 4])
        self.assertEqual(self._display_matches("frame.len == 90 and frame.caplen < 90"), [3])
        self.assertEqual(self._display_matches("tcp.port == 80"), [1])
        self.assertEqual(self._display_matches("tcp.port != 80"), [])

    def test_missing_field_stays_unknown_through_negation_and_logic(self):
        self.assertEqual(self._display_matches("dst.port != 80"), [2, 4])
        self.assertEqual(self._display_matches("not dst.port == 80"), [2, 4])
        self.assertEqual(self._display_matches("icmp or dst.port == 53"), [3, 4])
        self.assertEqual(self._display_matches("not (udp and tcp.dst_port == 443)"), [1, 3, 5])

        frame = ethernet(0x0800, ipv4(17, udp(), flags=1))
        fragment = Packet(0, 1, len(frame), frame)
        analysis = analyze_packet(fragment)
        self.assertTrue(compile_display_filter("ipv4 and ipv4.fragment_offset == 8").matches(fragment, analysis))
        self.assertFalse(compile_display_filter("not dst.port == 53").matches(fragment, analysis))

    def test_invalid_expressions_report_one_based_columns(self):
        for expression, column in (
            ("bogus", 1), ("tcp and", 8), ("(udp", 5), ("tcp udp", 5),
            ("dst.port = 53", 10), ("dst.port == nope", 13), ("src.ip == 299.1.1.1", 11),
            ("ipv6.dst == 127.0.0.1", 13), ("src.ip > 127.0.0.1", 8),
            ("(" * 33 + "tcp" + ")" * 33, 33),
        ):
            with self.subTest(expression=expression):
                with self.assertRaises(DisplayFilterError) as error:
                    compile_display_filter(expression)
                self.assertEqual(error.exception.column, column)

    def test_invalid_bpf_is_reported_and_no_rule_is_left_installed(self):
        with self.assertRaisesRegex(CaptureError, "could not compile BPF capture filter"):
            with open_capture(_SAMPLE, capture_filter="tcp and ("):
                self.fail("invalid BPF must fail before a reader is yielded")
        with open_capture(_SAMPLE) as packets:
            self.assertEqual(list(packets), self.packets[:3])
