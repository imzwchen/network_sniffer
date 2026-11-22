import curses
from dataclasses import dataclass, field
from time import monotonic

from .live import LiveStatus
from .tcp_flow import TcpTracker
from .traffic_stats import TrafficReport, TrafficStats
from .tui_theme import Drawing, cell_width, state_role


_TABS = ("Protocols", "Endpoints", "Sessions")
_COMPACT_BODY_ROW = 5


@dataclass(slots=True)
class TrafficView:
    tab: int = 0
    top: int = 0
    _page: int = 1
    _last_top: int = 0
    _report: TrafficReport | None = None
    _lines: list[str] = field(default_factory=list)
    _lines_tab: int | None = None
    _refresh_at: float = 0.0

    def handle_key(self, key: int) -> None:
        if ord("1") <= key <= ord("3"):
            self.tab = key - ord("1")
            self.top = 0
        elif key == ord("\t"):
            self.tab = (self.tab + 1) % len(_TABS)
            self.top = 0
        else:
            step = {
                curses.KEY_UP: -1, curses.KEY_DOWN: 1,
                curses.KEY_PPAGE: -self._page, curses.KEY_NPAGE: self._page,
            }.get(key)
            if step is not None:
                self.top = min(max(0, self.top + step), self._last_top)

    def draw(self, drawing: Drawing, stats: TrafficStats, flows: TcpTracker, live_status: LiveStatus | None) -> None:
        t = drawing.t
        height, width = drawing.height, drawing.width
        show_tabs = height >= 12 and width >= 38
        body_row = _COMPACT_BODY_ROW + int(show_tabs)
        if height < body_row + 2 or width < 19:
            if width > 0:
                drawing.title(t("Enlarge the terminal"))
                if height > 1:
                    drawing.footer((("Esc", "back"),))
            return
        now = monotonic()
        if self._report is None or (live_status is not None and now >= self._refresh_at):
            self._report = stats.snapshot()
            self._refresh_at = now + 0.25
            self._lines_tab = None
        report = self._report
        if self._lines_tab != self.tab:
            self._lines = _table_lines(report, flows, self.tab)
            self._lines_tab = self.tab

        drawing.title(f"{t('Traffic statistics')} | {t(_TABS[self.tab])}")
        total = report.total
        totals = t(
            "Total {packets} packets | {frames} frame B | {captured} captured B",
            packets=total.packets, frames=total.frame_bytes, captured=total.captured_bytes,
        )
        drawing.text(1, totals, "accent")
        if live_status is not None:
            state = live_status.state
            state_label = t(state)
            drawing.text(2, state_label, state_role(state))
            pcap_drops = t("n/a") if live_status.pcap_drops is None else live_status.pcap_drops
            drops = t(" | pcap drops {pcap} | queue drops {queue}", pcap=pcap_drops, queue=live_status.queue_drops)
            role = "warning" if live_status.pcap_drops or live_status.queue_drops else "muted"
            drawing.text(2, drops, role, x=cell_width(state_label))
        if self.tab == 0:
            hint = t("Each frame can count in several protocol layers.")
            columns_text = "     Packets       Frame B    Captured B  Protocol"
        elif self.tab == 1:
            hint = t(
                "{count} IP addresses | {evictions} older entries evicted",
                count=len(report.endpoints), evictions=report.endpoint_evictions,
            )
            columns_text = "    Sent pkt        Sent B      Recv pkt        Recv B  IP address"
        else:
            hint = t("Retained TCP flows and UDP pairs | {evictions} older UDP entries evicted", evictions=report.udp_evictions)
            columns_text = "     Packets       Frame B  Session"
        if show_tabs:
            drawing.tabs(3, _TABS, self.tab)
        drawing.text(body_row - 2, hint, "muted")
        drawing.bar(body_row - 1, t(columns_text))
        shortcuts = [("Esc", "back"), ("Tab", "view"), ("Up/Down", "scroll")]
        if live_status is not None:
            shortcuts.append(("s", "start/stop"))
        drawing.footer(shortcuts)
        self._page = height - body_row - 1
        self._last_top = max(0, len(self._lines) - self._page)
        self.top = min(self.top, self._last_top)
        if not self._lines:
            drawing.text(body_row, t("No entries yet."), "muted")
        for row, line in enumerate(self._lines[self.top : self.top + self._page], start=body_row):
            drawing.bar(row, line, "alternate" if row % 2 else "body")


def _table_lines(report: TrafficReport, flows: TcpTracker, tab: int) -> list[str]:
    if tab == 0:
        protocols = sorted(report.protocols, key=lambda item: (-item[1].packets, item[0]))
        return [
            f"{count.packets:12} {count.frame_bytes:13} {count.captured_bytes:13}  {name}"
            for name, count in protocols
        ]
    if tab == 1:
        endpoints = sorted(report.endpoints, key=lambda item: (-(item.sent.frame_bytes + item.received.frame_bytes), str(item.address)))
        return [
            f"{item.sent.packets:12} {item.sent.frame_bytes:13} {item.received.packets:13} "
            f"{item.received.frame_bytes:13}  {item.address}"
            for item in endpoints
        ]
    sessions = [
        (item.packet_count, item.frame_bytes, f"TCP #{item.number} {item.endpoints[0]} <> {item.endpoints[1]}")
        for item in flows.flow_infos()
    ]
    sessions.extend(
        (item.traffic.packets, item.traffic.frame_bytes, f"UDP {item.endpoints[0]} <> {item.endpoints[1]}")
        for item in report.udp_sessions
    )
    sessions.sort(key=lambda item: (-item[1], item[2]))
    return [f"{packets:12} {frame_bytes:13}  {name}" for packets, frame_bytes, name in sessions]
