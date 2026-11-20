import curses
from bisect import bisect_left
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum
from functools import lru_cache

from .capture import Packet
from .dissect import FieldValue, PacketAnalysis, analyze_packet
from .display_filter import DisplayFilter, DisplayFilterError, compile_display_filter
from .flow_view import FlowView
from .live import LiveCapture
from .process_view import ProcessView
from .tcp_flow import TcpTracker
from .traffic_stats import TrafficStats
from .traffic_view import TrafficView
from .tui_theme import Drawing, Theme, protocol_role


_BODY_ROW = 6
_LIVE_HISTORY_SIZE = 512
_LIVE_REFRESH_MS = 80


class _View(IntEnum):
    PACKETS = 0
    TREE = 1
    HEX = 2


_VIEW_NAMES = ("Packets", "Protocol tree", "Hex")
_PACKET_TABS = ("List", "Tree", "Hex")


@dataclass(slots=True)
class _FilterEditor:
    text: str
    cursor: int
    error: str | None = None

    def handle_key(self, key: int) -> None:
        if key == curses.KEY_LEFT:
            self.cursor = max(0, self.cursor - 1)
        elif key == curses.KEY_RIGHT:
            self.cursor = min(len(self.text), self.cursor + 1)
        elif key == curses.KEY_HOME:
            self.cursor = 0
        elif key == curses.KEY_END:
            self.cursor = len(self.text)
        elif key == 21:  # Ctrl+U
            self.text, self.cursor, self.error = "", 0, None
        elif key in (curses.KEY_BACKSPACE, 127, 8) and self.cursor:
            self.text = self.text[: self.cursor - 1] + self.text[self.cursor :]
            self.cursor -= 1
            self.error = None
        elif key == curses.KEY_DC and self.cursor < len(self.text):
            self.text = self.text[: self.cursor] + self.text[self.cursor + 1 :]
            self.error = None
        elif 32 <= key < 127:
            self.text = self.text[: self.cursor] + chr(key) + self.text[self.cursor :]
            self.cursor += 1
            self.error = None


def show_capture(packets: Sequence[Packet], filename: str, *, capture_filter: str | None = None) -> None:
    curses.wrapper(_browse, packets, filename, capture_filter=capture_filter)


def show_live_capture(capture: LiveCapture) -> None:
    curses.wrapper(_browse, (), capture.interface, capture, capture_filter=capture.capture_filter)


def _browse(
    screen: curses.window, packets: Sequence[Packet], name: str, live: LiveCapture | None = None, *,
    capture_filter: str | None = None,
) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass  # Cursor visibility is unavailable on some terminals.
    theme = Theme.create()
    screen.bkgd(" ", theme["body"])

    index = 0
    first_byte = 0
    first_tree_row = 0
    first_packet_index = 0
    view = _View.HEX
    analyze = lru_cache(maxsize=128)(analyze_packet)
    display_filter: DisplayFilter | None = None
    editor: _FilterEditor | None = None
    matches: list[int] = []
    follow = live is not None
    history: deque[Packet] = deque(maxlen=_LIVE_HISTORY_SIZE)
    history_numbers: deque[int] = deque(maxlen=_LIVE_HISTORY_SIZE)
    numbers: Sequence[int] = range(1, len(packets) + 1)
    flows = live.flows if live is not None else None
    stats = live.stats if live is not None else None
    flow_view: FlowView | None = None
    traffic_view: TrafficView | None = None
    process = live.process if live is not None else None
    process_view = ProcessView() if process is not None else None
    notice = ""
    if live is not None:
        screen.timeout(_LIVE_REFRESH_MS)
        packets = history
        numbers = history_numbers

    while True:
        drawing = Drawing(screen, theme)
        if live is not None:
            if live.error is not None:
                raise live.error
            for pending in live.take_records():
                if len(history) == _LIVE_HISTORY_SIZE:
                    first_packet_index += 1
                history.append(pending.packet)
                history_numbers.append(pending.number)
                if display_filter is not None and display_filter.matches(pending.packet, analyze(pending.packet)):
                    matches.append(first_packet_index + len(history) - 1)
            if matches and matches[0] < first_packet_index:
                del matches[:bisect_left(matches, first_packet_index)]

        if traffic_view is not None and stats is not None and flows is not None:
            screen.erase()
            traffic_view.draw(drawing, stats, flows, live.status if live is not None else None)
            screen.refresh()
            key = screen.getch()
            if key == ord("q"):
                return
            if key in (27, ord("v")):
                traffic_view = None
            elif live is not None and key == ord("s"):
                live.toggle()
            else:
                traffic_view.handle_key(key)
            continue

        if flow_view is not None and flows is not None:
            screen.erase()
            owners = None
            if process is not None:
                owners = next((item.owners for item in process.report.flows if item.flow.number == flow_view.flow_number), ())
            flow_view.draw(drawing, flows.snapshot(flow_view.flow_number), live=live is not None, owners=owners)
            screen.refresh()
            key = screen.getch()
            if key == ord("q"):
                return
            if key in (27, 10, 13, curses.KEY_ENTER):
                flow_view = None
            elif live is not None and key == ord("s"):
                live.toggle()
            else:
                flow_view.handle_key(key)
            continue

        if process_view is not None and process is not None and live is not None:
            screen.erase()
            process_view.draw(drawing, process.report, live.status.state)
            screen.refresh()
            key = screen.getch()
            if key == ord("q"):
                return
            if key in (27, ord("p")):
                process_view = None
            elif key == ord("v"):
                traffic_view = TrafficView()
            elif key == ord("s"):
                live.toggle()
            else:
                flow_number = process_view.handle_key(key)
                if flow_number is not None:
                    flow_view = FlowView(flow_number)
            continue

        visible = matches if display_filter is not None else range(first_packet_index, first_packet_index + len(packets))
        selected = 0
        if visible:
            last = len(visible) - 1
            selected = last if follow else min(bisect_left(visible, index), last)
            next_index = visible[selected]
            if next_index != index:
                index, first_byte, first_tree_row = next_index, 0, 0

        height, width = drawing.height, drawing.width
        screen.erase()
        can_show_packet = height >= _BODY_ROW + 2 and width >= 19

        if can_show_packet:
            shortcuts = [("Tab", "view"), ("Enter", "flow"), ("/", "filter"), ("v", "stats")]
            suffix = f" | BPF {ascii(capture_filter)}" if capture_filter is not None else ""
            if live is None:
                drawing.title(f"Capture {ascii(name)}", suffix=suffix)
                drawing.tabs(5, _PACKET_TABS, view)
            else:
                status = live.status
                drawing.title(f"Live {ascii(name)}", status.state, suffix)
                pcap_drops = "n/a" if status.pcap_drops is None else str(status.pcap_drops)
                counters = (
                    f"Captured {status.received} | pcap drops {pcap_drops}"
                    f" | queue drops {status.queue_drops}"
                )
                counter_style = "warning" if status.queue_drops or status.pcap_drops else "muted"
                if width >= len(counters) + 26:
                    drawing.tabs(5, _PACKET_TABS, view)
                    drawing.text(5, counters, counter_style, x=width - len(counters))
                else:
                    drawing.text(5, counters, counter_style)
                shortcuts.append(("s", "start/stop"))
                if process is not None:
                    shortcuts.append(("p", "PID"))
                else:
                    shortcuts.append(("f", "latest"))
            if editor is not None:
                _draw_filter_editor(drawing, editor)
            else:
                drawing.footer(shortcuts)
                if display_filter is not None:
                    filter_status = f"Display filter [{len(visible)}/{len(packets)}] {display_filter.expression}"
                    drawing.bar(height - 2, filter_status, "filter")
        elif width > 0:
            drawing.title("Enlarge the terminal")
            if height > 1:
                drawing.footer(())

        filter_row = int(display_filter is not None or editor is not None)
        page_height = height - _BODY_ROW - 1 - filter_row
        row_width = min(16, (width - 11) // 4) if can_show_packet else 1
        packet = packets[index - first_packet_index] if can_show_packet and visible else None
        if packet is not None:
            analysis = analyze(packet)
            number = numbers[index - first_packet_index]
            packet_count = max(live.status.received, numbers[-1]) if live is not None else len(packets)
            _draw_packet_header(drawing, packet, number, packet_count)
            mode = f"Link type {packet.link_type} | {analysis.protocol} | {_VIEW_NAMES[view]}"
            drawing.text(4, notice or mode, "warning" if notice else protocol_role(analysis.protocol))
            if page_height > 0:
                if view == _View.PACKETS:
                    list_width = width
                    if width >= 115 and page_height >= 10:
                        list_width = width * 56 // 100
                        _draw_packet_preview(drawing, packet, analysis, list_width, page_height)
                    _draw_packet_list(drawing, packets, numbers, analyze, visible, selected, first_packet_index, list_width, page_height)
                elif view == _View.TREE:
                    lines = _protocol_lines(analysis)
                    last_top_row = max(0, len(lines) - page_height)
                    top_row = min(first_tree_row, last_top_row)
                    for row, (line, role) in enumerate(lines[top_row : top_row + page_height], start=_BODY_ROW):
                        if role == "section":
                            drawing.bar(row, line)
                        else:
                            drawing.text(row, line, role)
                else:
                    row_count = (packet.captured_length + row_width - 1) // row_width
                    last_top_row = max(0, row_count - page_height)
                    top_row = min(first_byte // row_width, last_top_row)
                    _draw_hex(drawing, packet.data, row_width, top_row, page_height)
        elif can_show_packet:
            if display_filter is not None:
                message = "No packets match the display filter."
            elif live is None and capture_filter is not None:
                message = "No packets match the BPF filter."
            else:
                message = "No packets in this capture." if live is None else "No packets captured yet."
            drawing.text(2, message, "muted")
            drawing.text(4, _VIEW_NAMES[view], "accent")

        screen.refresh()
        key = screen.getch()
        if key != -1:
            notice = ""
        if editor is not None:
            if key == 27:  # Escape
                editor = None
            elif key in (10, 13, curses.KEY_ENTER):
                try:
                    candidate = compile_display_filter(editor.text) if editor.text.strip() else None
                except DisplayFilterError as error:
                    editor.error = str(error)
                    editor.cursor = min(len(editor.text), error.column - 1)
                    continue
                display_filter = candidate
                matches = [] if candidate is None else [
                    first_packet_index + position for position, retained in enumerate(packets)
                    if candidate.matches(retained, analyze(retained))
                ]
                editor = None
            else:
                editor.handle_key(key)
            continue

        if key == ord("/"):
            expression = display_filter.expression if display_filter is not None else ""
            editor = _FilterEditor(expression, len(expression))
            continue
        if key == ord("q"):
            return
        if key == ord("v"):
            if stats is None:
                if can_show_packet:
                    drawing.bar(4, "Indexing traffic statistics...", "filter")
                    screen.refresh()
                stats = TrafficStats()
                index_flows = flows is None
                if flows is None:
                    flows = TcpTracker()
                for position, retained in enumerate(packets, start=1):
                    decoded = analyze(retained)
                    stats.observe(retained, decoded)
                    if index_flows:
                        flows.observe(position, retained, decoded)
            traffic_view = TrafficView()
            continue
        if key == ord("p") and process is not None:
            process_view = ProcessView()
            continue
        if live is not None and key == ord("s"):
            live.toggle()
            continue
        if live is not None and key == ord("f"):
            follow = True
            continue
        if key == ord("\t"):
            view = _View((view + 1) % len(_VIEW_NAMES))
            continue
        if ord("1") <= key <= ord("3"):
            view = _View(key - ord("1"))
            continue
        if packet is None:
            continue
        if key in (10, 13, curses.KEY_ENTER):
            if analysis.protocol != "TCP":
                notice = "Select a TCP packet to open its flow."
                continue
            if flows is None:
                drawing.bar(4, "Indexing TCP flows...", "filter")
                screen.refresh()
                flows = TcpTracker()
                for position, retained in enumerate(packets, start=1):
                    flows.observe(position, retained, analyze(retained))
            flow_number = flows.flow_for_packet(number)
            if flow_number is None:
                notice = "TCP flow unavailable for this packet."
            else:
                follow = False
                flow_view = FlowView(flow_number)
            continue

        page_step = max(1, page_height - 1) if view == _View.PACKETS else page_height
        scroll = {
            curses.KEY_UP: -1,
            curses.KEY_DOWN: 1,
            curses.KEY_PPAGE: -page_step,
            curses.KEY_NPAGE: page_step,
        }.get(key)
        if key in (curses.KEY_LEFT, curses.KEY_RIGHT):
            step = -1 if key == curses.KEY_LEFT else 1
        else:
            step = scroll if view == _View.PACKETS else None

        if step is not None:
            follow = False
            next_index = visible[min(max(selected + step, 0), len(visible) - 1)]
            if next_index != index:
                index, first_byte, first_tree_row = next_index, 0, 0
        elif scroll is not None and page_height > 0:
            follow = False
            target = min(max(0, top_row + scroll), last_top_row)
            if view == _View.TREE:
                first_tree_row = target
            else:
                first_byte = target * row_width


def _draw_filter_editor(drawing: Drawing, editor: _FilterEditor) -> None:
    prompt = "Display filter> "
    height, width = drawing.height, drawing.width
    help_text = editor.error or "Enter apply | Esc cancel | Ctrl+U clear"
    drawing.bar(height - 2, help_text, "error" if editor.error is not None else "section")
    available = width - len(prompt)
    start = max(0, editor.cursor - available + 1)
    drawing.bar(height - 1, editor.text[start : start + available], "input", x=len(prompt))
    drawing.bar(height - 1, prompt, "filter", width=len(prompt))
    character = editor.text[editor.cursor : editor.cursor + 1] or " "
    drawing.text(height - 1, character, "active", x=len(prompt) + editor.cursor - start)


def _draw_packet_header(drawing: Drawing, packet: Packet, number: int, count: int) -> None:
    drawing.text(1, f"Packet {number}/{count}", "accent")
    drawing.text(2, _format_timestamp(packet.timestamp_us), "muted")
    lengths = f"Captured {packet.captured_length} B / original {packet.original_length} B"
    drawing.text(3, lengths, "warning" if packet.captured_length < packet.original_length else "body")


def _draw_hex(
    drawing: Drawing, data: bytes, bytes_per_row: int, top_row: int, page_height: int,
) -> None:
    if not data:
        drawing.text(_BODY_ROW, "Packet has no captured bytes.", "muted")
        return

    start = top_row * bytes_per_row
    stop = min(start + page_height * bytes_per_row, len(data))
    for row, offset in enumerate(range(start, stop, bytes_per_row), start=_BODY_ROW):
        chunk = data[offset : offset + bytes_per_row]
        drawing.hex_row(row, offset, chunk, bytes_per_row)


def _protocol_lines(analysis: PacketAnalysis) -> list[tuple[str, str]]:
    lines = [
        (f"! {issue.kind} @{issue.offset:04x}  {issue.message}", "error" if issue.kind == "Malformed" else "warning")
        for issue in analysis.issues
    ]
    for layer in analysis.layers:
        lines.append((f"{layer.offset:04x}+{layer.length:<2} {layer.name}", "section"))
        lines.extend(
            (f"  {field.offset:04x}+{field.length:<2} {field.label} = {field.display}", "body")
            for field in layer.fields
        )
    return lines


def _draw_packet_list(
    drawing: Drawing, packets: Sequence[Packet], numbers: Sequence[int],
    analyze: Callable[[Packet], PacketAnalysis],
    visible: Sequence[int], selected: int, first_index: int, width: int, page_height: int,
) -> None:
    first_row = _BODY_ROW
    if page_height > 1:
        drawing.bar(first_row, "   No  Proto     Bytes  Source > Destination", width=width)
        first_row += 1
        page_height -= 1

    top = min(max(0, selected - page_height // 2), max(0, len(visible) - page_height))
    for row, position in enumerate(range(top, min(top + page_height, len(visible))), start=first_row):
        index = visible[position]
        packet = packets[index - first_index]
        analysis = analyze(packet)
        addresses = _packet_endpoints(analysis)
        focused = position == selected
        prefix = "!" if analysis.issues else ">" if focused else " "
        leading = f"{prefix}{numbers[index - first_index]:>4}  "
        line = f"{leading}{analysis.protocol:<8} {packet.original_length:>6}  {addresses}"
        role = "selected" if focused else "alternate" if position % 2 else "body"
        drawing.bar(row, line, role, width=width)
        if not focused:
            if analysis.issues:
                drawing.text(row, "!", "warning")
            drawing.text(row, analysis.protocol, protocol_role(analysis.protocol), x=len(leading), width=width - len(leading))


def _draw_packet_preview(
    drawing: Drawing, packet: Packet, analysis: PacketAnalysis, separator: int, page_height: int,
) -> None:
    x = separator + 2
    width = drawing.width - x
    drawing.screen.vline(_BODY_ROW, separator, curses.ACS_VLINE, page_height, drawing.theme["divider"])
    drawing.bar(_BODY_ROW, " Selected packet", x=x, width=width)
    stack = " > ".join(layer.name for layer in analysis.layers) or "Unknown link type"
    drawing.text(_BODY_ROW + 1, stack, protocol_role(analysis.protocol), x=x)
    drawing.text(_BODY_ROW + 2, _packet_endpoints(analysis), x=x)
    if analysis.issues:
        issue = analysis.issues[0]
        drawing.text(_BODY_ROW + 3, f"! {issue.kind} | {issue.message}", "warning", x=x)
    drawing.bar(_BODY_ROW + 4, " Raw bytes", x=x, width=width)
    size = min(16, (width - 11) // 4)
    for row, offset in enumerate(range(0, min(packet.captured_length, size * (page_height - 5)), size), start=_BODY_ROW + 5):
        drawing.hex_row(row, offset, packet.data[offset : offset + size], size, x=x, width=width)


def _packet_endpoints(analysis: PacketAnalysis) -> str:
    fields = {field.key: field.value for layer in analysis.layers for field in layer.fields}
    for prefix, left, right in (
        ("ipv4", "src", "dst"), ("ipv6", "src", "dst"),
        ("arp", "sender_ip", "target_ip"), ("eth", "src", "dst"),
    ):
        source = fields.get(f"{prefix}.{left}")
        destination = fields.get(f"{prefix}.{right}")
        if source is not None or destination is not None:
            transport = "tcp" if "tcp.src_port" in fields else "udp"
            source_text = _format_endpoint(source, fields.get(f"{transport}.src_port"))
            destination_text = _format_endpoint(destination, fields.get(f"{transport}.dst_port"))
            return f"{source_text} > {destination_text}"
    return "-"


def _format_endpoint(address: FieldValue | None, port: FieldValue | None) -> str:
    if address is None:
        return "-"
    text = address.hex(":") if isinstance(address, bytes) else str(address)
    if port is None:
        return text
    return f"[{text}]:{port}" if ":" in text else f"{text}:{port}"


def _format_timestamp(timestamp_us: int) -> str:
    seconds, microseconds = divmod(timestamp_us, 1_000_000)
    try:
        date = datetime.fromtimestamp(seconds, UTC)
    except (ValueError, OverflowError, OSError):
        return f"{seconds}.{microseconds:06d} since Unix epoch"
    return f"{date:%Y-%m-%d %H:%M:%S}.{microseconds:06d} UTC"
