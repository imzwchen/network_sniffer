from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address

from .application import parse_dns
from .capture import Packet


_VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
_IPV6_EXTENSIONS = {
    0: "Hop-by-Hop Options",
    43: "Routing",
    44: "Fragment",
    51: "Authentication",
    60: "Destination Options",
}
_MAX_HEADER_DEPTH = 64
_TCP_FLAGS = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "AE")
_ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect", 8: "Echo Request",
    11: "Time Exceeded", 12: "Parameter Problem",
}
_ICMPV6_TYPES = {
    1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded", 4: "Parameter Problem",
    128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation", 134: "Router Advertisement",
    135: "Neighbor Solicitation", 136: "Neighbor Advertisement", 137: "Redirect",
}
_SUMMARY_PROTOCOLS = {"IPv4", "IPv6", "ARP", "TCP", "UDP", "ICMP", "ICMPv6", "DNS"}

FieldValue = int | str | bytes | IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class ProtocolField:
    key: str
    label: str
    value: FieldValue
    offset: int
    length: int
    display: str


@dataclass(frozen=True, slots=True)
class ProtocolLayer:
    name: str
    offset: int
    length: int
    fields: tuple[ProtocolField, ...]


@dataclass(frozen=True, slots=True)
class ParseIssue:
    kind: str
    message: str
    offset: int


@dataclass(frozen=True, slots=True)
class PacketAnalysis:
    layers: tuple[ProtocolLayer, ...]
    issues: tuple[ParseIssue, ...]

    @property
    def protocol(self) -> str:
        for layer in reversed(self.layers):
            if layer.length and layer.name in _SUMMARY_PROTOCOLS:
                return layer.name
        return next((layer.name for layer in reversed(self.layers) if layer.length), "Unknown")


class _Header:
    """Read fields only from the captured portion of this header."""

    def __init__(self, data: bytes, name: str, key: str, offset: int, size: int, bound: int) -> None:
        self.data = data
        self.name = name
        self.key = key
        self.offset = offset
        self.end = min(len(data), bound, offset + size)
        self.fields: list[ProtocolField] = []

    def _part(self, offset: int, length: int) -> bytes | None:
        start = self.offset + offset
        if length > 0 and start + length <= self.end:
            return self.data[start : start + length]
        return None

    def _field(self, key: str, label: str, value: FieldValue, offset: int, length: int, display: str) -> None:
        self.fields.append(ProtocolField(f"{self.key}.{key}", label, value, self.offset + offset, length, display))

    def number(
        self, key: str, label: str, offset: int, length: int = 1, *,
        mask: int = -1, shift: int = 0, unit: int = 1, fmt: str = "d",
        display: Callable[[int], str] | None = None,
    ) -> int | None:
        part = self._part(offset, length)
        if part is None:
            return None
        value = ((int.from_bytes(part, "big") >> shift) & mask) * unit
        text = format(value, fmt) if display is None else display(value)
        self._field(key, label, value, offset, length, text)
        return value

    def address(
        self, key: str, label: str, offset: int, length: int, *,
        convert: Callable[[bytes], FieldValue] = ip_address,
    ) -> None:
        part = self._part(offset, length)
        if part is not None:
            value = convert(part)
            text = value.hex(" ") if isinstance(value, bytes) else str(value)
            self._field(key, label, value, offset, length, text)

    def raw(self, key: str, label: str, offset: int, length: int) -> None:
        self.address(key, label, offset, length, convert=bytes)

    def finish(self) -> ProtocolLayer:
        return ProtocolLayer(self.name, self.offset, max(0, self.end - self.offset), tuple(self.fields))


def _mac(data: bytes) -> str:
    return data.hex(":")


def format_tcp_flags(value: int) -> str:
    flags = ", ".join(name for bit, name in enumerate(_TCP_FLAGS) if value & (1 << bit))
    return f"{value:#05x} ({flags})" if flags else f"{value:#05x}"


def _icmp_type(value: int, names: dict[int, str]) -> str:
    name = names.get(value)
    return f"{value} ({name})" if name is not None else str(value)


class _Dissector:
    def __init__(self, packet: Packet) -> None:
        self.packet = packet
        self.data = packet.data
        self.layers: list[ProtocolLayer] = []
        self.issues: list[ParseIssue] = []

    def _issue(self, kind: str, message: str, offset: int) -> None:
        self.issues.append(ParseIssue(kind, message, offset))

    def _require(self, name: str, offset: int, size: int, bound: int, *, fragment: bool = False) -> bool:
        if offset + size > bound:
            kind = "Fragment" if fragment else "Malformed"
            self._issue(kind, f"{name} needs {size} bytes, with {max(0, bound - offset)} in its enclosing data", offset)
            return False
        if offset + size > len(self.data):
            self._issue("Truncated", f"{name} needs {size} bytes, with {max(0, len(self.data) - offset)} captured", offset)
            return False
        return True

    def _header(self, name: str, key: str, offset: int, size: int, bound: int) -> _Header:
        return _Header(self.data, name, key, offset, size, bound)

    def _byte(self, offset: int, bound: int) -> int | None:
        return self.data[offset] if offset < min(bound, len(self.data)) else None

    def dissect(self) -> PacketAnalysis:
        captured, original = len(self.data), self.packet.original_length
        if captured < original:
            self._issue("Truncated", f"Captured {captured} of {original} frame bytes", captured)
        elif captured > original:
            self._issue("Malformed", f"Captured length {captured} exceeds original length {original}", original)

        bound = max(original, captured)
        if self.packet.link_type == 1:  # DLT_EN10MB
            self._ethernet(bound)
        elif self.packet.link_type in (113, 276):  # DLT_LINUX_SLL and DLT_LINUX_SLL2
            self._cooked(bound, self.packet.link_type == 276)
        else:
            self._issue("Unsupported", f"Link type {self.packet.link_type}", 0)
        return PacketAnalysis(tuple(self.layers), tuple(self.issues))

    def _ethernet(self, bound: int) -> None:
        header = self._header("Ethernet", "eth", 0, 14, bound)
        header.address("dst", "Destination MAC", 0, 6, convert=_mac)
        header.address("src", "Source MAC", 6, 6, convert=_mac)
        ether_type = header.number("type", "Type or length", 12, 2, fmt="#06x")
        self.layers.append(header.finish())
        if not self._require("Ethernet header", 0, 14, bound) or ether_type is None:
            return
        if ether_type <= 1500:
            self._issue("Unsupported", f"IEEE 802.3 LLC payload ({ether_type} bytes)", 14)
            return
        self._network(ether_type, 14, bound)

    def _cooked(self, bound: int, version_two: bool) -> None:
        name, key, size = ("SLL2", "sll2", 20) if version_two else ("SLL", "sll", 16)
        header = self._header(name, key, 0, size, bound)
        if version_two:
            ether_type = header.number("type", "Protocol type", 0, 2, fmt="#06x")
            header.number("ifindex", "Interface index", 4, 4)
            header.number("hardware_type", "Hardware type", 8, 2)
            header.number("packet_type", "Packet type", 10)
            address_length = header.number("address_length", "Address length", 11)
            address_offset = 12
        else:
            header.number("packet_type", "Packet type", 0, 2)
            header.number("hardware_type", "Hardware type", 2, 2)
            address_length = header.number("address_length", "Address length", 4, 2)
            address_offset = 6
            ether_type = header.number("type", "Protocol type", 14, 2, fmt="#06x")
        header.address("address", "Link address", address_offset, min(8, address_length or 0), convert=_mac)
        self.layers.append(header.finish())
        if self._require(f"{name} header", 0, size, bound) and ether_type is not None:
            self._network(ether_type, size, bound)

    def _network(self, ether_type: int, offset: int, bound: int) -> None:
        while ether_type in _VLAN_TYPES:
            if len(self.layers) >= _MAX_HEADER_DEPTH:
                self._issue("Unsupported", "Header nesting limit reached", offset)
                return
            header = self._header("VLAN", "vlan", offset, 4, bound)
            header.number("priority", "Priority", 0, 2, shift=13, mask=7)
            header.number("dei", "Drop eligible", 0, 2, shift=12, mask=1)
            header.number("id", "VLAN ID", 0, 2, mask=0xFFF)
            next_type = header.number("type", "Encapsulated type", 2, 2, fmt="#06x")
            self.layers.append(header.finish())
            if not self._require("VLAN header", offset, 4, bound) or next_type is None:
                return
            ether_type, offset = next_type, offset + 4

        if ether_type == 0x0800:
            self._ipv4(offset, bound)
        elif ether_type == 0x0806:
            self._arp(offset, bound)
        elif ether_type == 0x86DD:
            self._ipv6(offset, bound)
        else:
            self._issue("Unsupported", f"EtherType {ether_type:#06x}", offset)

    def _arp(self, offset: int, bound: int) -> None:
        hlen = self._byte(offset + 4, bound)
        plen = self._byte(offset + 5, bound)
        size = 8 + 2 * ((hlen or 0) + (plen or 0))
        header = self._header("ARP", "arp", offset, size, bound)
        hardware = header.number("hardware_type", "Hardware type", 0, 2)
        protocol = header.number("protocol_type", "Protocol type", 2, 2, fmt="#06x")
        header.number("hardware_length", "Hardware address length", 4)
        header.number("protocol_length", "Protocol address length", 5)
        header.number("operation", "Operation", 6, 2)
        if hlen is not None and plen is not None:
            hardware_address = _mac if hardware == 1 and hlen == 6 else bytes
            protocol_address = ip_address if (protocol, plen) in ((0x0800, 4), (0x86DD, 16)) else bytes
            header.address("sender_mac", "Sender hardware address", 8, hlen, convert=hardware_address)
            header.address("sender_ip", "Sender protocol address", 8 + hlen, plen, convert=protocol_address)
            target = 8 + hlen + plen
            header.address("target_mac", "Target hardware address", target, hlen, convert=hardware_address)
            header.address("target_ip", "Target protocol address", target + hlen, plen, convert=protocol_address)
        self.layers.append(header.finish())
        self._require("ARP message", offset, size, bound)

    def _ipv4(self, offset: int, bound: int) -> None:
        first = self._byte(offset, bound) or 0
        size = max(20, (first & 15) * 4)
        length_bytes = self.data[offset + 2 : min(bound, offset + 4)]
        declared = int.from_bytes(length_bytes, "big") if len(length_bytes) == 2 else size
        header = self._header("IPv4", "ipv4", offset, min(size, max(20, declared)), bound)
        version = header.number("version", "Version", 0, shift=4)
        ihl = header.number("header_length", "Header length (bytes)", 0, mask=15, unit=4)
        header.number("dscp", "DSCP", 1, shift=2)
        header.number("ecn", "ECN", 1, mask=3)
        total = header.number("length", "Total length", 2, 2)
        header.number("id", "Identification", 4, 2, fmt="#06x")
        header.number("df", "Don't fragment", 6, 2, shift=14, mask=1)
        more = header.number("mf", "More fragments", 6, 2, shift=13, mask=1)
        displacement = header.number("fragment_offset", "Fragment offset (bytes)", 6, 2, mask=0x1FFF, unit=8)
        header.number("ttl", "Time to live", 8)
        protocol = header.number("protocol", "Protocol", 9)
        header.number("checksum", "Header checksum", 10, 2, fmt="#06x")
        header.address("src", "Source address", 12, 4)
        header.address("dst", "Destination address", 16, 4)
        header.raw("options", "Options", 20, size - 20)
        self.layers.append(header.finish())
        if not self._require("IPv4 header", offset, 20, bound):
            return
        if version != 4 or ihl is None or ihl < 20 or total is None or total < size:
            self._issue("Malformed", "Invalid IPv4 version or header/total length", offset)
            return
        if not self._require("IPv4 header with options", offset, size, bound):
            return
        network_end = self._payload_end("IPv4 total length", offset, total, bound)
        if more or displacement:
            self._fragment("IPv4", offset, displacement or 0, bool(more))
        if displacement == 0 and protocol is not None:
            self._transport(protocol, offset + size, network_end, ipv6=False, fragment=bool(more))

    def _payload_end(self, name: str, offset: int, size: int, bound: int) -> int:
        if offset + size > bound:
            self._issue("Malformed", f"{name} exceeds the enclosing packet", offset)
        return min(offset + size, bound)

    def _ipv6(self, offset: int, bound: int) -> None:
        header = self._header("IPv6", "ipv6", offset, 40, bound)
        version = header.number("version", "Version", 0, shift=4)
        header.number("traffic_class", "Traffic class", 0, 2, shift=4, mask=0xFF)
        header.number("flow_label", "Flow label", 1, 3, mask=0xFFFFF, fmt="#07x")
        length = header.number("payload_length", "Payload length", 4, 2)
        protocol = header.number("next_header", "Next header", 6)
        header.number("hop_limit", "Hop limit", 7)
        header.address("src", "Source address", 8, 16)
        header.address("dst", "Destination address", 24, 16)
        self.layers.append(header.finish())
        if not self._require("IPv6 header", offset, 40, bound):
            return
        if version != 6 or length is None or protocol is None:
            self._issue("Malformed", "Invalid IPv6 header", offset)
            return
        if length == 0 and protocol == 0:
            self._issue("Unsupported", "IPv6 jumbogram or missing Hop-by-Hop payload", offset + 40)
            return

        network_end = self._payload_end("IPv6 payload length", offset + 40, length, bound)
        offset += 40
        fragmented = False
        while protocol in _IPV6_EXTENSIONS:
            if len(self.layers) >= _MAX_HEADER_DEPTH:
                self._issue("Unsupported", "Header nesting limit reached", offset)
                return
            extension = self._ipv6_extension(protocol, offset, network_end, fragmented)
            if extension is None:
                return
            protocol, offset, fragmented = extension
        if protocol != 59:  # No Next Header
            self._transport(protocol, offset, network_end, ipv6=True, fragment=fragmented)

    def _ipv6_extension(
        self, protocol: int, offset: int, bound: int, fragmented: bool,
    ) -> tuple[int, int, bool] | None:
        extension_name = _IPV6_EXTENSIONS[protocol]
        size_byte = self._byte(offset + 1, bound)
        if protocol == 44:
            size = 8
        elif protocol == 51:
            size = ((size_byte or 0) + 2) * 4
        else:
            size = ((size_byte or 0) + 1) * 8
        header = self._header(f"IPv6 {extension_name}", f"ipv6.ext{protocol}", offset, size, bound)
        next_protocol = header.number("next_header", "Next header", 0)
        displacement, more = None, None
        if protocol == 44:
            displacement = header.number("fragment_offset", "Fragment offset (bytes)", 2, 2, mask=0xFFF8)
            more = header.number("mf", "More fragments", 2, 2, mask=1)
            header.number("id", "Identification", 4, 4, fmt="#010x")
        else:
            header.number("length", "Header length field", 1)
            if protocol == 43:
                header.number("routing_type", "Routing type", 2)
                header.number("segments_left", "Segments left", 3)
            elif protocol == 51:
                header.number("spi", "Security parameters index", 4, 4, fmt="#010x")
                header.number("sequence", "Sequence number", 8, 4)
            else:
                header.raw("options", "Options", 2, size - 2)
        self.layers.append(header.finish())
        if protocol == 51 and size_byte is not None and size < 12:
            self._issue("Malformed", "IPv6 Authentication header is shorter than 12 bytes", offset)
            return None
        if not self._require(header.name, offset, size, bound, fragment=fragmented) or next_protocol is None:
            return None
        if more or displacement:
            self._fragment("IPv6", offset, displacement or 0, bool(more))
        if displacement:
            return None
        return next_protocol, offset + size, fragmented or bool(more)

    def _fragment(self, name: str, offset: int, displacement: int, more: bool) -> None:
        ending = ", more fragments follow" if more else ""
        self._issue("Fragment", f"{name} fragment at payload offset {displacement} bytes{ending}", offset)

    def _transport(self, protocol: int, offset: int, bound: int, *, ipv6: bool, fragment: bool) -> None:
        if protocol == 6:
            self._tcp(offset, bound, fragment)
        elif protocol == 17:
            self._udp(offset, bound, fragment)
        elif protocol == (58 if ipv6 else 1):
            self._icmp(offset, bound, ipv6, fragment)
        else:
            label = "IPv6 next header" if ipv6 else "IPv4 protocol"
            self._issue("Unsupported", f"{label} {protocol}", offset)

    def _tcp(self, offset: int, bound: int, fragment: bool) -> None:
        data_offset = self._byte(offset + 12, bound)
        size = max(20, ((data_offset or 0) >> 4) * 4)
        header = self._header("TCP", "tcp", offset, size, bound)
        header.number("src_port", "Source port", 0, 2)
        header.number("dst_port", "Destination port", 2, 2)
        header.number("seq", "Sequence number", 4, 4)
        header.number("ack", "Acknowledgment number", 8, 4)
        length = header.number("header_length", "Header length (bytes)", 12, shift=4, unit=4)
        header.number("flags", "Flags", 12, 2, mask=0x1FF, display=format_tcp_flags)
        header.number("window", "Window", 14, 2)
        header.number("checksum", "Checksum", 16, 2, fmt="#06x")
        header.number("urgent", "Urgent pointer", 18, 2)
        header.raw("options", "Options", 20, size - 20)
        self.layers.append(header.finish())
        if length is not None and length < 20:
            self._issue("Malformed", "TCP header length is shorter than 20 bytes", offset)
        self._require("TCP header", offset, size, bound, fragment=fragment)

    def _udp(self, offset: int, bound: int, fragment: bool) -> None:
        header = self._header("UDP", "udp", offset, 8, bound)
        source = header.number("src_port", "Source port", 0, 2)
        destination = header.number("dst_port", "Destination port", 2, 2)
        length = header.number("length", "Length", 4, 2)
        header.number("checksum", "Checksum", 6, 2, fmt="#06x")
        self.layers.append(header.finish())
        if length is not None and (length < 8 or (not fragment and offset + length > bound)):
            self._issue("Malformed", f"UDP length {length} is outside its IP payload", offset + 4)
        if not self._require("UDP header", offset, 8, bound, fragment=fragment):
            return
        if not fragment and length is not None and 53 in (source, destination) and 20 <= length <= bound - offset:
            start, end = offset + 8, min(offset + length, len(self.data))
            message = parse_dns(self.data[start:end])
            if message is not None:
                fields = tuple(
                    ProtocolField(item.key, item.label, item.value, start + item.offset, item.length, item.text)
                    for item in message.fields
                )
                self.layers.append(ProtocolLayer("DNS", start, end - start, fields))
                if message.note:
                    kind = "Truncated" if end < offset + length else "Malformed"
                    if message.note == "DNS record display limit reached":
                        kind = "Limited"
                    self._issue(kind, message.note, start)

    def _icmp(self, offset: int, bound: int, ipv6: bool, fragment: bool) -> None:
        names = _ICMPV6_TYPES if ipv6 else _ICMP_TYPES
        name, key = ("ICMPv6", "icmpv6") if ipv6 else ("ICMP", "icmp")
        kind = self._byte(offset, bound)
        echo = kind in ((128, 129) if ipv6 else (0, 8))
        size = 8 if echo or (ipv6 and kind in (2, 4)) else 4
        header = self._header(name, key, offset, size, bound)
        header.number("type", "Type", 0, display=lambda value: _icmp_type(value, names))
        header.number("code", "Code", 1)
        header.number("checksum", "Checksum", 2, 2, fmt="#06x")
        if echo:
            header.number("id", "Echo identifier", 4, 2)
            header.number("sequence", "Echo sequence", 6, 2)
        elif ipv6 and kind == 2:
            header.number("mtu", "MTU", 4, 4)
        elif ipv6 and kind == 4:
            header.number("pointer", "Pointer", 4, 4)
        self.layers.append(header.finish())
        self._require(f"{name} header", offset, size, bound, fragment=fragment)


def analyze_packet(packet: Packet) -> PacketAnalysis:
    """Dissect captured bytes and retain every field that fits its enclosing header."""
    return _Dissector(packet).dissect()
