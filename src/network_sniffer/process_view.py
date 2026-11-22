import curses
from bisect import bisect_left
from dataclasses import dataclass, field

from .process_tracker import ProcessReport
from .tui_theme import Drawing, pad_cells, state_role


@dataclass(slots=True)
class ProcessView:
    selected: int = 0
    show_unknown: bool = False
    _visible: list[int] = field(default_factory=list)
    _page: int = 1

    def draw(self, drawing: Drawing, report: ProcessReport, capture_state: str) -> None:
        t = drawing.t
        height, width = drawing.height, drawing.width
        if height < 8 or width < 19:
            self._visible = []
            if width > 0:
                drawing.title(t("Enlarge the terminal"))
                if height > 1:
                    drawing.footer((("Esc", "back"),))
            return
        drawing.title(t("Process TCP flows"), capture_state)
        event_status = "".join(char for char in report.events if " " <= char <= "~")
        role = "success" if event_status == "Kernel events active" else "warning" if "unavailable" in event_status or "loss" in event_status else "muted"
        drawing.text(1, t.detail(event_status), role)
        row = 2
        for pid, status in report.targets[: height - 6]:
            readable = "".join(char for char in status if " " <= char <= "~")
            if readable.startswith("Snapshot"):
                role = "body"
            else:
                role = "error" if readable.startswith(("Permission denied", "Socket query failed")) else "warning"
            drawing.text(row, f"PID {pid} | {t.detail(readable)}", role)
            row += 1

        unknown = sum(not item.owners for item in report.flows)
        visible = report.flows if self.show_unknown else tuple(item for item in report.flows if item.owners)
        self._visible = [item.flow.number for item in visible]
        self._page = height - row - 3
        summary = t("{known} attributed | {unknown} unknown", known=len(report.flows) - unknown, unknown=unknown)
        drawing.text(row, summary, "accent")
        drawing.bar(row + 1, t(" Flow  State        PID(s)         Endpoints"))
        row += 2
        toggle = "hide unknown" if self.show_unknown else "show unknown"
        drawing.footer((("Esc", "packets"), ("Enter", "open"), ("u", toggle), ("v", "stats"), ("s", "start/stop")))
        if not visible:
            drawing.text(row, t("No matching TCP flows yet."), "muted")
            return
        position = min(bisect_left(self._visible, self.selected), len(visible) - 1)
        self.selected = self._visible[position]
        top = min(max(0, position - self._page // 2), max(0, len(visible) - self._page))
        for line, item in enumerate(visible[top : top + self._page], start=row):
            pids = ",".join(str(pid) for pid in sorted({owner.pid for owner in item.owners})) or t("Unknown")
            flow = item.flow
            focused = flow.number == self.selected
            leading = f"{'>' if focused else ' '}{flow.number:4}  "
            state = t(flow.state)
            text = f"{leading}{pad_cells(state, 11)}  {pad_cells(pids, max(13, len(pids)))}  {flow.endpoints[0]} <> {flow.endpoints[1]}"
            role = "selected" if focused else "alternate" if line % 2 else "body"
            drawing.bar(line, text, role)
            if not focused:
                drawing.text(line, state, state_role(flow.state), x=len(leading))

    def handle_key(self, key: int) -> int | None:
        if key == ord("u"):
            self.show_unknown = not self.show_unknown
            return None
        if not self._visible:
            return None
        if key in (10, 13, curses.KEY_ENTER):
            return self.selected
        step = {
            curses.KEY_UP: -1, curses.KEY_DOWN: 1,
            curses.KEY_PPAGE: -self._page, curses.KEY_NPAGE: self._page,
        }.get(key)
        if step is not None:
            index = bisect_left(self._visible, self.selected)
            self.selected = self._visible[max(0, min(index + step, len(self._visible) - 1))]
        return None
