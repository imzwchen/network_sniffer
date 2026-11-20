import curses
import os
from collections.abc import Sequence
from dataclasses import dataclass


# xterm palette, with an eight-color equivalent for standard terminals.
_COLORS = {
    "body": (253, 233, -1, -1),
    "alternate": (253, 234, -1, -1),
    "title": (231, 24, curses.COLOR_WHITE, curses.COLOR_BLUE),
    "identity": (233, 81, curses.COLOR_BLACK, curses.COLOR_CYAN),
    "section": (117, 236, curses.COLOR_CYAN, -1),
    "inactive": (252, 235, -1, -1),
    "active": (233, 81, curses.COLOR_BLACK, curses.COLOR_CYAN),
    "selected": (231, 24, curses.COLOR_BLACK, curses.COLOR_CYAN),
    "footer": (250, 236, -1, -1),
    "key": (159, 236, curses.COLOR_CYAN, -1),
    "accent": (81, 233, curses.COLOR_CYAN, -1),
    "secondary": (183, 233, curses.COLOR_MAGENTA, -1),
    "muted": (248, 233, -1, -1),
    "divider": (244, 233, curses.COLOR_CYAN, -1),
    "success": (120, 233, curses.COLOR_GREEN, -1),
    "warning": (222, 233, curses.COLOR_YELLOW, -1),
    "error": (217, 233, curses.COLOR_RED, -1),
    "title_success": (157, 24, curses.COLOR_WHITE, curses.COLOR_BLUE),
    "title_warning": (229, 24, curses.COLOR_YELLOW, curses.COLOR_BLUE),
    "title_error": (224, 24, curses.COLOR_WHITE, curses.COLOR_BLUE),
    "filter": (159, 237, curses.COLOR_CYAN, -1),
    "input": (231, 237, -1, -1),
    "tcp": (81, 233, curses.COLOR_CYAN, -1),
    "udp": (120, 233, curses.COLOR_GREEN, -1),
    "icmp": (222, 233, curses.COLOR_YELLOW, -1),
    "dns": (183, 233, curses.COLOR_MAGENTA, -1),
}
_BOLD_STYLES = {
    "title", "identity", "section", "active", "selected", "key", "accent", "warning", "error",
    "title_success", "title_warning", "title_error",
}
_REVERSED_STYLES = {
    "title", "identity", "section", "active", "selected", "footer", "key", "title_success", "title_warning", "title_error",
}


@dataclass(frozen=True, slots=True)
class Theme:
    attributes: dict[str, int]

    @classmethod
    def create(cls) -> "Theme":
        fallback = {
            name: (curses.A_BOLD if name in _BOLD_STYLES else 0)
            | (curses.A_REVERSE if name in _REVERSED_STYLES else 0)
            for name in _COLORS
        }
        if os.environ.get("NO_COLOR") or not curses.has_colors():
            return cls(fallback)
        try:
            curses.start_color()
            try:
                curses.use_default_colors()
                default_fg = default_bg = -1
            except curses.error:
                default_fg, default_bg = curses.COLOR_WHITE, curses.COLOR_BLACK
            extended = curses.COLORS >= 256
            for pair, (name, palette) in enumerate(_COLORS.items(), start=1):
                if pair >= curses.COLOR_PAIRS:
                    break
                fg, bg = palette[:2] if extended else palette[2:]
                curses.init_pair(pair, default_fg if fg < 0 else fg, default_bg if bg < 0 else bg)
                fallback[name] = curses.color_pair(pair) | (curses.A_BOLD if name in _BOLD_STYLES else 0)
        except curses.error:
            pass  # Keep the monochrome attributes for unavailable colors.
        return cls(fallback)

    def __getitem__(self, role: str) -> int:
        return self.attributes[role]


def protocol_role(name: str) -> str:
    return {"TCP": "tcp", "UDP": "udp", "DNS": "dns", "ICMP": "icmp", "ICMPv6": "icmp"}.get(name, "accent")


def state_role(state: str) -> str:
    if state in ("Capturing", "Established"):
        return "success"
    if state == "Reset":
        return "error"
    if state in ("Starting", "Handshake", "Closing", "Midstream", "Superseded"):
        return "warning"
    return "muted"


class Drawing:
    """A frame's dimensions and the shared styles used by every curses view."""

    def __init__(self, screen: curses.window, theme: Theme) -> None:
        self.screen = screen
        self.theme = theme
        self.height, columns = screen.getmaxyx()
        self.width = columns - 1  # Leave the lower-right cell untouched.

    def text(self, row: int, text: str, role: str = "body", *, x: int = 0, width: int | None = None) -> None:
        available = self.width - x if width is None else min(width, self.width - x)
        if 0 <= row < self.height and available > 0 and text:
            self.screen.addnstr(row, x, text, available, self.theme[role])

    def bar(self, row: int, text: str, role: str = "section", *, x: int = 0, width: int | None = None) -> None:
        available = self.width - x if width is None else min(width, self.width - x)
        if available > 0:
            self.text(row, text[:available].ljust(available), role, x=x, width=available)

    def title(self, text: str, state: str | None = None, suffix: str = "") -> None:
        self.bar(0, "", "title")
        x = 1
        if self.width >= 62:
            self.text(0, " SNIFFER ", "identity")
            x = 10
        self.text(0, text + (" | " if state is not None else ""), "title", x=x)
        x += len(text) + (3 if state is not None else 0)
        if state is not None:
            role = state_role(state)
            self.text(0, state, "title" if role == "muted" else f"title_{role}", x=x)
            x += len(state)
        self.text(0, suffix, "title", x=x)

    def tabs(self, row: int, names: Sequence[str], selected: int) -> None:
        x = 0
        for index, name in enumerate(names):
            label = f" {index + 1} {name} "
            self.text(row, label, "active" if index == selected else "inactive", x=x)
            x += len(label) + 1

    def footer(self, shortcuts: Sequence[tuple[str, str]]) -> None:
        row = self.height - 1
        self.bar(row, "", "footer")
        quit_x = max(0, self.width - 8)
        self.text(row, "q", "key", x=quit_x)
        self.text(row, " quit", "footer", x=quit_x + 1)
        x = 1
        for key, desc in shortcuts:
            span = len(key) + len(desc) + 1
            if x + span > quit_x - 1:
                continue
            self.text(row, key, "key", x=x)
            self.text(row, f" {desc}", "footer", x=x + len(key))
            x += span + 3

    def hex_row(
        self, row: int, offset: int, data: bytes | memoryview, size: int, *, x: int = 0, width: int | None = None,
    ) -> None:
        right = self.width if width is None else x + width
        prefix = f"{offset:08x}  "
        self.text(row, prefix, "muted", x=x, width=right - x)
        x += len(prefix)
        hexadecimal = data.hex(" ").ljust(size * 3 - 1) + "  "
        self.text(row, hexadecimal, x=x, width=right - x)
        x += len(hexadecimal)
        ascii_text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data)
        self.text(row, ascii_text, "success", x=x, width=right - x)
