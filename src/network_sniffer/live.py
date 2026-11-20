from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Condition, Thread
from time import monotonic

from .capture import CaptureError, Packet, _PcapReader, _PcapWriter, open_live, save_capture
from .dissect import analyze_packet
from .process_tracker import ProcessMonitor
from .tcp_flow import TcpTracker
from .traffic_stats import TrafficStats


_QUEUE_SIZE = 256
_BATCH_SIZE = 64
_IDLE_WAIT = 0.02
_STATS_INTERVAL = 0.25


@dataclass(frozen=True, slots=True)
class LiveStatus:
    state: str
    received: int
    pcap_drops: int | None
    queue_drops: int


@dataclass(frozen=True, slots=True)
class CapturedPacket:
    number: int
    packet: Packet


class LiveCapture:
    """Own live libpcap handles and the optional savefile on a background thread."""

    def __init__(
        self, interface: str, snaplen: int, output_path: Path | None, *, capture_filter: str | None = None,
        pids: tuple[int, ...] = (),
    ) -> None:
        self.interface = interface
        self.snaplen = snaplen
        self.output_path = output_path
        self.capture_filter = capture_filter
        self.status = LiveStatus("Starting", 0, None, 0)
        self.error: Exception | None = None
        self.flows = TcpTracker(flow_limit=1024, packet_limit=4096, byte_limit=16 * 1024 * 1024)
        self.stats = TrafficStats()
        self.process = ProcessMonitor(pids, self.flows) if pids else None
        self._packets: Queue[CapturedPacket] = Queue(maxsize=_QUEUE_SIZE)
        self._received = 0
        self._queue_drops = 0
        self._control = Condition()
        self._enabled = True
        self._closing = False
        self._thread = Thread(target=self._run, name="libpcap capture")

    def __enter__(self) -> "LiveCapture":
        if self.process is not None:
            self.process.start()
        try:
            self._thread.start()
        except BaseException:
            if self.process is not None:
                self.process.close()
            raise
        return self

    def __exit__(self, *exc_info: object) -> None:
        with self._control:
            self._closing = True
            self._control.notify()
        try:
            self._thread.join()
        finally:
            if self.process is not None:
                self.process.close()

    def toggle(self) -> None:
        with self._control:
            self._enabled = not self._enabled
            self._control.notify()

    def take_pending(self) -> Iterator[Packet]:
        for record in self.take_records():
            yield record.packet

    def take_records(self) -> Iterator[CapturedPacket]:
        for _ in range(_QUEUE_SIZE):
            try:
                yield self._packets.get_nowait()
            except Empty:
                return

    def _publish(self, state: str, pcap_drops: int | None) -> None:
        self.status = LiveStatus(state, self._received, pcap_drops, self._queue_drops)

    def _run(self) -> None:
        try:
            self._run_sessions()
        except StopIteration:
            self.error = CaptureError(f"capture on {self.interface!r} ended unexpectedly")
        except Exception as error:
            self.error = error

    def _run_sessions(self) -> None:
        previous_drops: int | None = 0
        with ExitStack() as savefile:
            output = None
            while True:
                with self._control:
                    self._control.wait_for(lambda: self._enabled or self._closing)
                    if self._closing:
                        return

                self._publish("Starting", previous_drops)
                with open_live(self.interface, self.snaplen, capture_filter=self.capture_filter) as reader:
                    if self.output_path is not None and output is None:
                        output = savefile.enter_context(save_capture(reader, self.output_path))
                    if output is not None and output.savefile_format != reader.savefile_format:
                        raise CaptureError("the capture format changed after restarting the interface")
                    self._publish("Capturing", _sum_drops(previous_drops, reader.dropped()))
                    previous_drops = self._collect(reader, output, previous_drops)
                self._publish("Stopped", previous_drops)

    def _collect(
        self, reader: _PcapReader, output: _PcapWriter | None, previous_drops: int | None
    ) -> int | None:
        refresh_at = monotonic() + _STATS_INTERVAL
        while True:
            with self._control:
                if self._closing or not self._enabled:
                    break

            for _ in range(_BATCH_SIZE):
                packet = reader.read(output)
                if packet is None:
                    break
                self._received += 1
                analysis = analyze_packet(packet)
                self.flows.observe(self._received, packet, analysis)
                self.stats.observe(packet, analysis)
                try:
                    self._packets.put_nowait(CapturedPacket(self._received, packet))
                except Full:
                    self._queue_drops += 1

            now = monotonic()
            if now >= refresh_at:
                if output is not None:
                    output.flush()
                self._publish("Capturing", _sum_drops(previous_drops, reader.dropped()))
                refresh_at = now + _STATS_INTERVAL
            if packet is None:
                with self._control:
                    self._control.wait_for(lambda: self._closing or not self._enabled, _IDLE_WAIT)

        if output is not None:
            output.flush()
        return _sum_drops(previous_drops, reader.dropped())


def _sum_drops(previous: int | None, current: int | None) -> int | None:
    if previous is None or current is None:
        return None
    return previous + current
