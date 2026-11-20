from collections import OrderedDict
from dataclasses import dataclass, field, replace
from heapq import heappop, heappush
from ipaddress import IPv4Address, IPv6Address
from itertools import pairwise
from threading import Lock

from .capture import Packet
from .dissect import PacketAnalysis


_FIN, _SYN, _RST, _ACK = 0x01, 0x02, 0x04, 0x10
_SEQUENCE_MASK = 0xFFFFFFFF
_HALF_SEQUENCE_SPACE = 1 << 31
_EMPTY_PAYLOAD = memoryview(b"")


@dataclass(frozen=True, slots=True)
class Endpoint:
    address: IPv4Address | IPv6Address
    port: int

    def __str__(self) -> str:
        if self.address.version == 6:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"


def connection_endpoints(first: Endpoint, second: Endpoint) -> tuple[Endpoint, Endpoint]:
    left = (first.address.version, int(first.address), first.port)
    right = (second.address.version, int(second.address), second.port)
    return (first, second) if left <= right else (second, first)


@dataclass(frozen=True, slots=True)
class FlowPacket:
    number: int
    timestamp_us: int
    direction: int
    sequence: int | None
    acknowledgment: int | None
    flags: int
    original_length: int
    retained_bytes: int
    payload: memoryview
    expected_payload: int | None
    partial: bool
    payload_start: int | None = None


@dataclass(frozen=True, slots=True)
class DirectionSummary:
    packets: int
    frame_bytes: int
    payload_bytes: int
    syn_packet: int | None
    fin_packet: int | None
    start: int | None
    end: int | None


@dataclass(frozen=True, slots=True)
class FlowSnapshot:
    number: int
    endpoints: tuple[Endpoint, Endpoint]
    state: str
    start_seen: bool
    directions: tuple[DirectionSummary, DirectionSummary]
    rst_packet: int | None
    packets: tuple[FlowPacket, ...]
    omitted_packets: int


@dataclass(frozen=True, slots=True)
class FlowInfo:
    number: int
    endpoints: tuple[Endpoint, Endpoint]
    state: str
    first_us: int
    last_us: int
    initiator: Endpoint | None
    packet_count: int
    frame_bytes: int = 0


@dataclass(frozen=True, slots=True)
class PayloadSpan:
    offset: int
    length: int
    data: memoryview | None


@dataclass(frozen=True, slots=True)
class ReassembledPayload:
    spans: tuple[PayloadSpan, ...]
    captured_bytes: int
    missing_bytes: int
    overlapping_bytes: int


def _extract_tcp(
    number: int, packet: Packet, analysis: PacketAnalysis,
) -> tuple[tuple[Endpoint, Endpoint], FlowPacket] | None:
    if analysis.protocol != "TCP":
        return None
    tcp = analysis.layers[-1]
    ip = next(layer for layer in analysis.layers if layer.name in ("IPv4", "IPv6"))
    fields = {item.key: item.value for layer in (ip, tcp) for item in layer.fields}
    prefix = ip.name.lower()
    source, destination = fields.get(f"{prefix}.src"), fields.get(f"{prefix}.dst")
    source_port, destination_port = fields.get("tcp.src_port"), fields.get("tcp.dst_port")
    if not (
        isinstance(source, (IPv4Address, IPv6Address)) and isinstance(destination, (IPv4Address, IPv6Address))
        and isinstance(source_port, int) and isinstance(destination_port, int)
    ):
        return None

    sender = Endpoint(source, source_port)
    receiver = Endpoint(destination, destination_port)
    key = connection_endpoints(sender, receiver)
    length = fields.get("ipv4.length") if ip.name == "IPv4" else fields.get("ipv6.payload_length")
    header_length = fields.get("tcp.header_length")
    fragmented = any(issue.kind == "Fragment" for issue in analysis.issues)
    payload = _EMPTY_PAYLOAD
    expected_payload = None
    if isinstance(length, int) and isinstance(header_length, int) and header_length >= 20:
        ip_end = ip.offset + length + (40 if ip.name == "IPv6" else 0)
        start = tcp.offset + header_length
        if start <= ip_end <= packet.original_length:
            if not fragmented:
                expected_payload = ip_end - start
            if start < min(ip_end, packet.captured_length):
                payload = memoryview(packet.data)[start:ip_end]

    sequence = fields.get("tcp.seq")
    acknowledgment = fields.get("tcp.ack")
    flags = fields.get("tcp.flags")
    return key, FlowPacket(
        number, packet.timestamp_us, 0 if sender == key[0] else 1,
        sequence if isinstance(sequence, int) else None,
        acknowledgment if isinstance(acknowledgment, int) else None,
        flags if isinstance(flags, int) else 0,
        packet.original_length, packet.captured_length if payload else 0, payload, expected_payload,
        expected_payload is None or len(payload) < expected_payload or tcp.length < (header_length or 20),
    )


def unwrap_sequence(sequence: int, reference: int) -> int:
    distance = (sequence - reference + _HALF_SEQUENCE_SPACE) & _SEQUENCE_MASK
    return reference + distance - _HALF_SEQUENCE_SPACE


def _covers(acknowledgment: int | None, sequence: int | None) -> bool:
    return (
        acknowledgment is not None and sequence is not None
        and ((acknowledgment - sequence) & _SEQUENCE_MASK) < _HALF_SEQUENCE_SPACE
    )


@dataclass(slots=True)
class _Direction:
    packets: int = 0
    frame_bytes: int = 0
    payload_bytes: int = 0
    syn_packet: int | None = None
    syn_sequence: int | None = None
    fin_packet: int | None = None
    fin_next: int | None = None
    last_ack: int | None = None
    reference: int | None = None
    origin: int | None = None
    first_payload: int | None = None
    end: int | None = None

    def add(self, packet: FlowPacket) -> FlowPacket:
        self.packets += 1
        self.frame_bytes += packet.original_length
        self.payload_bytes += len(packet.payload)
        if packet.flags & _ACK and packet.acknowledgment is not None:
            if self.last_ack is None or _covers(packet.acknowledgment, self.last_ack):
                self.last_ack = packet.acknowledgment
        if packet.sequence is None:
            return packet

        sequence = packet.sequence if self.reference is None else unwrap_sequence(packet.sequence, self.reference)
        syn = bool(packet.flags & _SYN)
        start = sequence + syn
        size = len(packet.payload) if packet.expected_payload is None else packet.expected_payload
        end = start + size
        if syn and self.syn_packet is None:
            self.syn_packet = packet.number
            self.syn_sequence = packet.sequence
            self.origin = start
        if size:
            self.first_payload = start if self.first_payload is None else min(self.first_payload, start)
        fin = bool(packet.flags & _FIN)
        if fin:
            if self.fin_packet is None:
                self.fin_packet = packet.number
            if self.fin_next is None and packet.expected_payload is not None:
                self.fin_next = end + 1
        if syn or size or (fin and packet.expected_payload is not None):
            self.end = end if self.end is None else max(self.end, end)
            next_sequence = end + (fin and packet.expected_payload is not None)
            self.reference = next_sequence if self.reference is None else max(self.reference, next_sequence)
        return replace(packet, payload_start=start)

    def snapshot(self) -> DirectionSummary:
        return DirectionSummary(
            self.packets, self.frame_bytes, self.payload_bytes, self.syn_packet, self.fin_packet,
            self.origin if self.origin is not None else self.first_payload, self.end,
        )


@dataclass(slots=True)
class _Flow:
    number: int
    endpoints: tuple[Endpoint, Endpoint]
    first_us: int
    last_us: int
    directions: tuple[_Direction, _Direction] = field(default_factory=lambda: (_Direction(), _Direction()))
    packets: dict[int, FlowPacket] = field(default_factory=dict)
    start_seen: bool = False
    initiator: Endpoint | None = None
    rst_packet: int | None = None
    superseded: bool = False

    @property
    def state(self) -> str:
        a, b = self.directions
        if self.rst_packet is not None:
            return "Reset"
        if _covers(a.last_ack, b.fin_next) and _covers(b.last_ack, a.fin_next):
            return "Closed"
        if self.superseded:
            return "Superseded"
        if a.fin_packet is not None or b.fin_packet is not None:
            return "Closing"
        if a.syn_sequence is not None and b.syn_sequence is not None:
            if _covers(a.last_ack, b.syn_sequence + 1) and _covers(b.last_ack, a.syn_sequence + 1):
                return "Established"
        return "Handshake" if a.syn_packet is not None or b.syn_packet is not None else "Midstream"

    def is_new_connection(self, packet: FlowPacket) -> bool:
        if not packet.flags & _SYN or packet.sequence is None:
            return False
        sender, peer = self.directions[packet.direction], self.directions[1 - packet.direction]
        if self.state in ("Closed", "Reset") and not packet.flags & _ACK:
            return True
        if sender.syn_sequence is not None:
            return sender.syn_sequence != packet.sequence
        if peer.syn_sequence is None:
            return True
        if packet.flags & _ACK:
            return not _covers(packet.acknowledgment, peer.syn_sequence + 1)
        return peer.last_ack is not None and not _covers(peer.last_ack, packet.sequence + 1)

    def add(self, packet: FlowPacket) -> None:
        self.packets[packet.number] = self.directions[packet.direction].add(packet)
        self.first_us = min(self.first_us, packet.timestamp_us)
        self.last_us = max(self.last_us, packet.timestamp_us)
        if packet.flags & _SYN and not packet.flags & _ACK:
            self.start_seen = True
            if self.initiator is None:
                self.initiator = self.endpoints[packet.direction]
        if packet.flags & _RST and self.rst_packet is None:
            self.rst_packet = packet.number

    def snapshot(self) -> FlowSnapshot:
        directions = (self.directions[0].snapshot(), self.directions[1].snapshot())
        omitted = sum(direction.packets for direction in directions) - len(self.packets)
        return FlowSnapshot(
            self.number, self.endpoints, self.state, self.start_seen, directions, self.rst_packet,
            tuple(self.packets.values()), omitted,
        )

    def info(self) -> FlowInfo:
        return FlowInfo(
            self.number, self.endpoints, self.state, self.first_us, self.last_us, self.initiator,
            self.directions[0].packets + self.directions[1].packets,
            self.directions[0].frame_bytes + self.directions[1].frame_bytes,
        )


class TcpTracker:
    """Index packets and connection generations in capture order."""

    def __init__(
        self, *, flow_limit: int | None = None, packet_limit: int | None = None, byte_limit: int | None = None,
    ) -> None:
        self._lock = Lock()
        self._flow_limit = flow_limit
        self._packet_limit = packet_limit
        self._byte_limit = byte_limit
        self._next_id = 1
        self._retained_bytes = 0
        self._flows: OrderedDict[int, _Flow] = OrderedDict()
        self._current: dict[tuple[Endpoint, Endpoint], _Flow] = {}
        self._packet_flows: OrderedDict[int, _Flow] = OrderedDict()

    def observe(self, number: int, packet: Packet, analysis: PacketAnalysis) -> None:
        parsed = _extract_tcp(number, packet, analysis)
        if parsed is None:
            return
        key, segment = parsed
        with self._lock:
            flow = self._current.get(key)
            if flow is None or flow.is_new_connection(segment):
                if flow is not None:
                    flow.superseded = True
                flow = _Flow(self._next_id, key, segment.timestamp_us, segment.timestamp_us)
                self._next_id += 1
                self._flows[flow.number] = flow
                self._current[key] = flow
            flow.add(segment)
            self._flows.move_to_end(flow.number)
            self._packet_flows[number] = flow
            self._retained_bytes += segment.retained_bytes
            self._prune()

    def _prune(self) -> None:
        if self._flow_limit is not None and len(self._flows) > self._flow_limit:
            _, oldest = self._flows.popitem(last=False)
            if self._current.get(oldest.endpoints) is oldest:
                del self._current[oldest.endpoints]
            for number, packet in oldest.packets.items():
                del self._packet_flows[number]
                self._retained_bytes -= packet.retained_bytes

        while (
            (self._packet_limit is not None and len(self._packet_flows) > self._packet_limit)
            or (self._byte_limit is not None and self._retained_bytes > self._byte_limit)
        ):
            number, flow = self._packet_flows.popitem(last=False)
            self._retained_bytes -= flow.packets.pop(number).retained_bytes

    def flow_for_packet(self, number: int) -> int | None:
        with self._lock:
            flow = self._packet_flows.get(number)
            return flow.number if flow is not None else None

    def snapshot(self, number: int) -> FlowSnapshot | None:
        with self._lock:
            flow = self._flows.get(number)
            return flow.snapshot() if flow is not None else None

    def flow_infos(self) -> tuple[FlowInfo, ...]:
        with self._lock:
            return tuple(flow.info() for flow in self._flows.values())


def reassemble(flow: FlowSnapshot, direction: int) -> ReassembledPayload:
    summary = flow.directions[direction]
    origin, limit = summary.start, summary.end
    if origin is None or limit is None or origin >= limit:
        return ReassembledPayload((), 0, 0, 0)

    # Sweep the observed intervals in sequence order. The lowest capture number wins an overlap.
    intervals: list[tuple[int, int, int, memoryview]] = []
    boundaries = {origin, limit}
    observed_bytes = 0
    for packet in flow.packets:
        if packet.direction != direction or packet.payload_start is None or not packet.payload:
            continue
        start = max(origin, packet.payload_start)
        end = min(limit, packet.payload_start + len(packet.payload))
        if start < end:
            boundaries.update((start, end))
            intervals.append((start, end, packet.number, packet.payload[start - packet.payload_start : end - packet.payload_start]))
            observed_bytes += end - start

    intervals.sort()
    active: list[tuple[int, int, int, memoryview]] = []
    spans = []
    covered = 0
    next_interval = 0
    for start, end in pairwise(sorted(boundaries)):
        while next_interval < len(intervals) and intervals[next_interval][0] == start:
            first, last, number, payload = intervals[next_interval]
            heappush(active, (number, last, first, payload))
            next_interval += 1
        while active and active[0][1] <= start:
            heappop(active)
        length = end - start
        data = None
        if active:
            _, _, first, payload = active[0]
            data = payload[start - first : end - first]
            covered += length
        spans.append(PayloadSpan(start - origin, length, data))
    return ReassembledPayload(tuple(spans), covered, limit - origin - covered, observed_bytes - covered)
