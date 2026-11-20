from collections import OrderedDict
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from threading import Lock

from .capture import Packet
from .dissect import FieldValue, PacketAnalysis
from .tcp_flow import Endpoint, connection_endpoints


IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class TrafficCount:
    packets: int = 0
    frame_bytes: int = 0
    captured_bytes: int = 0


@dataclass(slots=True)
class _Counter:
    packets: int = 0
    frame_bytes: int = 0
    captured_bytes: int = 0

    def add(self, packet: Packet) -> None:
        self.packets += 1
        self.frame_bytes += packet.original_length
        self.captured_bytes += packet.captured_length

    def snapshot(self) -> TrafficCount:
        return TrafficCount(self.packets, self.frame_bytes, self.captured_bytes)


@dataclass(slots=True)
class _EndpointCounters:
    sent: _Counter = field(default_factory=_Counter)
    received: _Counter = field(default_factory=_Counter)


@dataclass(frozen=True, slots=True)
class EndpointCount:
    address: IPAddress
    sent: TrafficCount
    received: TrafficCount


@dataclass(frozen=True, slots=True)
class UdpSessionCount:
    endpoints: tuple[Endpoint, Endpoint]
    traffic: TrafficCount


@dataclass(frozen=True, slots=True)
class TrafficReport:
    total: TrafficCount
    protocols: tuple[tuple[str, TrafficCount], ...]
    endpoints: tuple[EndpointCount, ...]
    udp_sessions: tuple[UdpSessionCount, ...]
    endpoint_evictions: int
    udp_evictions: int


class TrafficStats:
    """Count packets before the display queue. Detail tables use bounded LRU retention."""

    def __init__(self, *, endpoint_limit: int = 4096, udp_limit: int = 2048) -> None:
        self._lock = Lock()
        self._total = _Counter()
        self._protocols: dict[str, _Counter] = {}
        self._endpoints: OrderedDict[IPAddress, _EndpointCounters] = OrderedDict()
        self._udp: OrderedDict[tuple[Endpoint, Endpoint], _Counter] = OrderedDict()
        self._endpoint_limit = endpoint_limit
        self._udp_limit = udp_limit
        self._endpoint_evictions = 0
        self._udp_evictions = 0

    def observe(self, packet: Packet, analysis: PacketAnalysis) -> None:
        protocols = {layer.name for layer in analysis.layers if layer.length}
        ip = next((layer for layer in analysis.layers if layer.name in ("IPv4", "IPv6")), None)
        if ip is None:
            ip = next((layer for layer in analysis.layers if layer.name == "ARP"), None)
        source = destination = None
        if ip is not None:
            source = next((item.value for item in ip.fields if item.key.endswith((".src", ".sender_ip"))), None)
            destination = next((item.value for item in ip.fields if item.key.endswith((".dst", ".target_ip"))), None)
        udp = next((layer for layer in analysis.layers if layer.name == "UDP"), None)

        with self._lock:
            self._total.add(packet)
            for protocol in protocols or {"Unknown"}:
                counter = self._protocols.get(protocol)
                if counter is None:
                    counter = self._protocols[protocol] = _Counter()
                counter.add(packet)

            if isinstance(source, (IPv4Address, IPv6Address)):
                self._observe_endpoint(source).sent.add(packet)
            if isinstance(destination, (IPv4Address, IPv6Address)):
                self._observe_endpoint(destination).received.add(packet)

            if (
                udp is not None and isinstance(source, (IPv4Address, IPv6Address))
                and isinstance(destination, (IPv4Address, IPv6Address))
            ):
                self._observe_udp(source, destination, {item.key: item.value for item in udp.fields}, packet)

    def _observe_endpoint(self, address: IPAddress) -> _EndpointCounters:
        counter = self._endpoints.get(address)
        if counter is None:
            counter = self._endpoints[address] = _EndpointCounters()
        else:
            self._endpoints.move_to_end(address)
        if len(self._endpoints) > self._endpoint_limit:
            self._endpoints.popitem(last=False)
            self._endpoint_evictions += 1
        return counter

    def _observe_udp(self, source: IPAddress, destination: IPAddress, fields: dict[str, FieldValue], packet: Packet) -> None:
        src, dst = fields.get("udp.src_port"), fields.get("udp.dst_port")
        if not isinstance(src, int) or not isinstance(dst, int):
            return
        key = connection_endpoints(Endpoint(source, src), Endpoint(destination, dst))
        counter = self._udp.get(key)
        if counter is None:
            counter = self._udp[key] = _Counter()
        else:
            self._udp.move_to_end(key)
        counter.add(packet)
        if len(self._udp) > self._udp_limit:
            self._udp.popitem(last=False)
            self._udp_evictions += 1

    def snapshot(self) -> TrafficReport:
        with self._lock:
            return TrafficReport(
                self._total.snapshot(), tuple((name, count.snapshot()) for name, count in self._protocols.items()),
                tuple(EndpointCount(address, counts.sent.snapshot(), counts.received.snapshot())
                      for address, counts in self._endpoints.items()),
                tuple(UdpSessionCount(key, count.snapshot()) for key, count in self._udp.items()),
                self._endpoint_evictions, self._udp_evictions,
            )
