from bisect import bisect_left
from dataclasses import dataclass
from heapq import heappop, heappush

from .application import ApplicationMessage, scan_http, scan_tcp_dns, scan_tls
from .tcp_flow import FlowPacket, FlowSnapshot, ReassembledPayload, unwrap_sequence


_FIN, _SYN, _RST, _ACK = 0x01, 0x02, 0x04, 0x10
_PREVIEW_BYTES = 128 * 1024
_PENDING_LIMIT = 1024


@dataclass(frozen=True, slots=True)
class TcpMetrics:
    retransmissions: int
    rtt_samples: int
    minimum_us: int | None
    mean_us: float | None
    maximum_us: int | None


@dataclass(slots=True)
class _SentSegment:
    start: int
    time_us: int
    ambiguous: bool = False


class _DirectionMetrics:
    def __init__(self) -> None:
        self.covered: list[tuple[int, int]] = []
        self.pending: dict[int, _SentSegment] = {}
        self.pending_ends: list[int] = []
        self.last_ack: int | None = None
        self.retransmissions = 0
        self.samples = 0
        self.total_us = 0
        self.minimum_us: int | None = None
        self.maximum_us: int | None = None

    def _add_range(self, start: int, end: int) -> bool:
        ranges = self.covered
        left, right = start, end
        index = bisect_left(ranges, (start,))
        if index and ranges[index - 1][1] >= start:
            index -= 1
        stop = index
        overlaps = False
        while stop < len(ranges) and ranges[stop][0] <= right:
            first, last = ranges[stop]
            overlaps |= first < end and start < last
            left, right = min(left, first), max(right, last)
            stop += 1
        ranges[index:stop] = [(left, right)]
        return overlaps

    def send(self, packet: FlowPacket) -> None:
        if packet.payload_start is None or packet.flags & _RST:
            return
        start = packet.payload_start - bool(packet.flags & _SYN)
        size = packet.expected_payload if packet.expected_payload is not None else len(packet.payload)
        end = packet.payload_start + size + bool(packet.flags & _FIN and packet.expected_payload is not None)
        if end <= start:
            return
        overlaps = self._add_range(start, end)
        if overlaps:
            self.retransmissions += 1
            for limit, segment in self.pending.items():
                if segment.start < end and start < limit:
                    segment.ambiguous = True
        if overlaps or packet.partial or (self.last_ack is not None and end <= self.last_ack):
            return
        self.pending[end] = _SentSegment(start, packet.timestamp_us)
        heappush(self.pending_ends, end)
        if len(self.pending_ends) > _PENDING_LIMIT:
            self.pending.pop(heappop(self.pending_ends))

    def acknowledge(self, sequence: int, timestamp_us: int) -> None:
        if not self.covered:
            return
        highest = self.covered[-1][1]
        acknowledgment = unwrap_sequence(sequence, highest)
        if self.last_ack is not None and acknowledgment <= self.last_ack:
            return
        segment = self.pending.get(acknowledgment)
        unambiguous = (
            segment is not None and not segment.ambiguous
            and (self.last_ack >= segment.start if self.last_ack is not None else self.pending_ends[0] == acknowledgment)
        )
        if segment is not None and unambiguous:
            start = segment.start if self.last_ack is None else self.last_ack
            index = bisect_left(self.covered, (acknowledgment,)) - 1
            left, right = self.covered[index] if index >= 0 else (0, 0)
            delta = timestamp_us - segment.time_us
            if delta > 0 and left <= start and acknowledgment <= right:
                self.samples += 1
                self.total_us += delta
                self.minimum_us = delta if self.minimum_us is None else min(self.minimum_us, delta)
                self.maximum_us = delta if self.maximum_us is None else max(self.maximum_us, delta)
        self.last_ack = acknowledgment
        while self.pending_ends and self.pending_ends[0] <= acknowledgment:
            self.pending.pop(heappop(self.pending_ends))

    def summary(self) -> TcpMetrics:
        mean = self.total_us / self.samples if self.samples else None
        return TcpMetrics(self.retransmissions, self.samples, self.minimum_us, mean, self.maximum_us)


def tcp_metrics(flow: FlowSnapshot) -> tuple[TcpMetrics, TcpMetrics]:
    directions = (_DirectionMetrics(), _DirectionMetrics())
    for packet in flow.packets:
        if packet.flags & _ACK and not packet.flags & _RST and packet.acknowledgment is not None:
            directions[1 - packet.direction].acknowledge(packet.acknowledgment, packet.timestamp_us)
        directions[packet.direction].send(packet)
    return directions[0].summary(), directions[1].summary()


def application_messages(
    payload: ReassembledPayload, *, dns: bool,
) -> tuple[tuple[ApplicationMessage, ...], str | None]:
    prefix = bytearray()
    note = None
    for span in payload.spans:
        if span.data is None:
            note = f"Application parsing ends at payload gap @{span.offset:08x}"
            break
        remaining = _PREVIEW_BYTES - len(prefix)
        prefix.extend(span.data[:remaining])
        if span.length > remaining:
            note = "Application preview limited to 128 KiB"
            break
    if not prefix:
        return (), note
    data = bytes(prefix)
    if dns:
        return scan_tcp_dns(data), note
    return scan_tls(data) or scan_http(data), note
