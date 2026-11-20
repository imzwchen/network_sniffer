import curses
from dataclasses import dataclass, field
from time import monotonic

from .dissect import format_tcp_flags
from .flow_analysis import application_messages, tcp_metrics
from .process_tracker import FlowOwner
from .tcp_flow import FlowSnapshot, ReassembledPayload, reassemble
from .tui_theme import Drawing


_COMPACT_BODY_ROW = 8
_DIRECTIONS = ("A>B", "B>A")
_DIRECTION_ROLES = ("accent", "secondary")
_FLOW_TABS = ("Packets", "A>B payload", "B>A payload", "Analysis")


@dataclass(slots=True)
class FlowView:
    flow_number: int
    tab: int = 0
    top: int = 0
    _page: int = 1
    _last_top: int = 0
    _body_row: int = _COMPACT_BODY_ROW
    _payloads: dict[int, ReassembledPayload] = field(default_factory=dict)
    _revision: tuple[int, int] | None = None
    _analysis_lines: list[tuple[str, str]] | None = None
    _analysis_refresh_at: float = 0.0

    def handle_key(self, key: int) -> None:
        if ord("1") <= key < ord("1") + len(_FLOW_TABS):
            self.tab = key - ord("1")
            self.top = 0
        elif key == ord("\t"):
            self.tab = (self.tab + 1) % len(_FLOW_TABS)
            self.top = 0
        else:
            step = {
                curses.KEY_UP: -1, curses.KEY_DOWN: 1,
                curses.KEY_PPAGE: -self._page, curses.KEY_NPAGE: self._page,
            }.get(key)
            if step is not None:
                self.top = min(max(0, self.top + step), self._last_top)

    def draw(
        self, drawing: Drawing, flow: FlowSnapshot | None, *, live: bool,
        owners: tuple[FlowOwner, ...] | None = None,
    ) -> None:
        height, width = drawing.height, drawing.width
        if width <= 0:
            return
        show_tabs = height >= 14 and width >= 48
        self._body_row = _COMPACT_BODY_ROW + int(show_tabs)
        shortcuts = [("Esc", "back"), ("Tab", "view"), ("Up/Down", "scroll")]
        if live:
            shortcuts.append(("s", "start/stop"))
        if height < self._body_row + 2 or width < 19:
            drawing.title("Enlarge the terminal")
            if height > 1:
                drawing.footer(shortcuts[:1])
            return
        drawing.footer(shortcuts)
        if flow is None:
            drawing.title(f"TCP flow #{self.flow_number}")
            drawing.text(2, "History expired", "warning")
            self._payloads.clear()
            self._analysis_lines = None
            return

        start = "" if flow.start_seen else " | Start not observed"
        drawing.title(f"TCP flow #{flow.number}", flow.state, start)
        drawing.text(1, f"A  {flow.endpoints[0]}", _DIRECTION_ROLES[0])
        drawing.text(2, f"B  {flow.endpoints[1]}", _DIRECTION_ROLES[1])
        events = []
        for index, direction in enumerate(flow.directions):
            label = _DIRECTIONS[index]
            totals = f"{label}  {direction.packets} packets | {direction.payload_bytes} captured payload B"
            drawing.text(3 + index, totals + f" | {direction.frame_bytes} frame B")
            if direction.syn_packet is not None:
                events.append(f"SYN {label} #{direction.syn_packet}")
            if direction.fin_packet is not None:
                events.append(f"FIN {label} #{direction.fin_packet}")
        if flow.rst_packet is not None:
            events.append(f"RST #{flow.rst_packet}")
        if events:
            drawing.text(5, " | ".join(events), "warning" if flow.rst_packet is not None else "muted")
        status = []
        if owners is not None:
            labels = [f"PID {owner.pid} ({owner.source})" for owner in owners]
            status.append("Owners " + ", ".join(dict.fromkeys(labels)) if labels else "Owner unknown")
        if flow.omitted_packets:
            status.append(f"Live history omitted {flow.omitted_packets} older packets")
        if status:
            drawing.text(6, " | ".join(status), "warning" if flow.omitted_packets or owners == () else "muted")

        if show_tabs:
            drawing.tabs(7, _FLOW_TABS, self.tab)
        self._page = height - self._body_row - 1
        if self.tab == 0:
            self._draw_packets(drawing, flow)
        elif self.tab == 3:
            self._draw_analysis(drawing, flow, live)
        else:
            self._draw_payload(drawing, flow)

    def _set_length(self, rows: int) -> None:
        self._last_top = max(0, rows - self._page)
        self.top = min(self.top, self._last_top)

    def _draw_packets(self, drawing: Drawing, flow: FlowSnapshot) -> None:
        columns = "   No  Dir      Time (s)        Seq        Ack  Data B  Flags"
        drawing.bar(self._body_row - 1, columns)
        self._set_length(len(flow.packets))
        if not flow.packets:
            drawing.text(self._body_row, "No packets retained for this flow.", "muted")
            return
        first = flow.packets[0].timestamp_us
        for row, packet in enumerate(flow.packets[self.top : self.top + self._page], start=self._body_row):
            relative_time = (packet.timestamp_us - first) / 1_000_000
            sequence = "-" if packet.sequence is None else str(packet.sequence)
            ack = "-" if packet.acknowledgment is None else str(packet.acknowledgment)
            partial = " [partial]" if packet.partial else ""
            line = (
                f"{packet.number:5}  {_DIRECTIONS[packet.direction]}  {relative_time:12.6f} "
                f"{sequence:>10} {ack:>10} {len(packet.payload):7}  {format_tcp_flags(packet.flags)}{partial}"
            )
            role = "warning" if packet.partial else "alternate" if row % 2 else "body"
            drawing.bar(row, line, role)

    def _update_revision(self, flow: FlowSnapshot) -> None:
        revision = (sum(item.packets for item in flow.directions), flow.omitted_packets)
        if revision != self._revision:
            self._revision = revision
            self._payloads.clear()
            self._analysis_lines = None

    def _payload(self, flow: FlowSnapshot, direction: int) -> ReassembledPayload:
        if direction not in self._payloads:
            self._payloads[direction] = reassemble(flow, direction)
        return self._payloads[direction]

    def _draw_analysis(self, drawing: Drawing, flow: FlowSnapshot, live: bool) -> None:
        now = monotonic()
        if self._analysis_lines is None or not live or now >= self._analysis_refresh_at:
            self._update_revision(flow)
        if self._analysis_lines is None:
            lines = []
            for direction, metrics in enumerate(tcp_metrics(flow)):
                label = _DIRECTIONS[direction]
                lines.append((f"{label} probable retransmissions {metrics.retransmissions}",
                              "warning" if metrics.retransmissions else _DIRECTION_ROLES[direction]))
                if metrics.rtt_samples:
                    estimate = (
                        f"  RTT estimate {metrics.rtt_samples} samples | min {metrics.minimum_us / 1000:.3f} ms"
                        f" | mean {metrics.mean_us / 1000:.3f} ms | max {metrics.maximum_us / 1000:.3f} ms"
                    )
                    lines.append((estimate, "body"))
                else:
                    lines.append(("  RTT estimate unavailable (no unambiguous ACK sample)", "muted"))

            dns = any(endpoint.port == 53 for endpoint in flow.endpoints)
            for direction, label in enumerate(_DIRECTIONS):
                messages, note = application_messages(self._payload(flow, direction), dns=dns)
                if not messages:
                    lines.append((f"{label} no recognized application message", "muted"))
                for message in messages:
                    lines.append((f"{label} {message.title}", "section"))
                    lines.extend((f"  {item.label} = {item.text}", "body") for item in message.fields)
                    if message.note:
                        lines.append((f"  {message.note}", "warning"))
                if note:
                    lines.append((f"  {note}", "warning"))
            self._analysis_lines = lines
            self._analysis_refresh_at = now + 0.25
        heading = "Flow analysis | TCP and application messages"
        drawing.bar(self._body_row - 1, heading)
        self._set_length(len(self._analysis_lines))
        for row, (line, role) in enumerate(self._analysis_lines[self.top : self.top + self._page], start=self._body_row):
            if role == "section":
                drawing.bar(row, line)
            else:
                drawing.text(row, line, role)

    def _draw_payload(self, drawing: Drawing, flow: FlowSnapshot) -> None:
        direction = self.tab - 1
        self._update_revision(flow)
        result = self._payload(flow, direction)
        title = (
            f"{_DIRECTIONS[direction]} payload | {result.captured_bytes} unique B | "
            f"{result.missing_bytes} gap B | {result.overlapping_bytes} overlap B"
        )
        drawing.bar(self._body_row - 1, title)
        if not result.spans:
            self._set_length(0)
            drawing.text(self._body_row, "No payload bytes observed in this direction.", "muted")
            return

        stride = min(16, (drawing.width - 11) // 4)
        span_rows = [1 if item.data is None else (item.length + stride - 1) // stride for item in result.spans]
        self._set_length(sum(span_rows))
        skip, row = self.top, self._body_row
        for span, count in zip(result.spans, span_rows):
            if skip >= count:
                skip -= count
                continue
            for line in range(skip, min(count, skip + self._body_row + self._page - row)):
                if span.data is None:
                    drawing.text(row, f"{span.offset:08x}  [gap {span.length} bytes]", "warning")
                else:
                    start = line * stride
                    drawing.hex_row(row, span.offset + start, span.data[start : start + stride], stride)
                row += 1
            if row >= self._body_row + self._page:
                break
            skip = 0
