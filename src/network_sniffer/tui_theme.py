import curses
import os
from collections.abc import Sequence
from dataclasses import dataclass
from unicodedata import combining, east_asian_width

from .tui_i18n import Language


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


def _character_width(char: str) -> int:
    if combining(char):
        return 0
    return 2 if east_asian_width(char) in ("W", "F") else 1


def cell_width(text: str) -> int:
    return len(text) if text.isascii() else sum(map(_character_width, text))


def _fit_cells(text: str, width: int) -> tuple[str, int]:
    if text.isascii():
        return text[:width], min(len(text), width)
    used = 0
    for index, char in enumerate(text):
        advance = _character_width(char)
        if used + advance > width:
            return text[:index], used
        used += advance
    return text, used


def pad_cells(text: str, width: int) -> str:
    clipped, used = _fit_cells(text, width)
    return clipped + " " * (width - used)


class Drawing:
    """A frame's dimensions and the shared styles used by every curses view."""

    def __init__(self, screen: curses.window, theme: Theme, language: Language) -> None:
        self.screen = screen
        self.theme = theme
        self.t = language
        self.height, columns = screen.getmaxyx()
        self.width = columns - 1  # Leave the lower-right cell untouched.

    def text(self, row: int, text: str, role: str = "body", *, x: int = 0, width: int | None = None) -> None:
        available = self.width - x if width is None else min(width, self.width - x)
        if 0 <= row < self.height and available > 0 and text:
            clipped, _ = _fit_cells(text, available)
            if clipped:
                self.screen.addstr(row, x, clipped, self.theme[role])

    def bar(self, row: int, text: str, role: str = "section", *, x: int = 0, width: int | None = None) -> None:
        available = self.width - x if width is None else min(width, self.width - x)
        if available > 0:
            self.text(row, pad_cells(text, available), role, x=x, width=available)

    def title(self, text: str, state: str | None = None, suffix: str = "") -> None:
        self.bar(0, "", "title")
        x = 1
        if self.width >= 62:
            identity = f" {self.t('SNIFFER')} "
            self.text(0, identity, "identity")
            x = cell_width(identity) + 1
        self.text(0, text + (" | " if state is not None else ""), "title", x=x)
        x += cell_width(text) + (3 if state is not None else 0)
        if state is not None:
            role = state_role(state)
            label = self.t(state)
            self.text(0, label, "title" if role == "muted" else f"title_{role}", x=x)
            x += cell_width(label)
        self.text(0, suffix, "title", x=x)

    def tabs(self, row: int, names: Sequence[str], selected: int) -> None:
        x = 0
        for index, name in enumerate(names):
            label = f" {index + 1} {self.t(name)} "
            self.text(row, label, "active" if index == selected else "inactive", x=x)
            x += cell_width(label) + 1

    def footer(self, shortcuts: Sequence[tuple[str, str]]) -> None:
        row = self.height - 1
        self.bar(row, "", "footer")
        quit_label = " " + self.t("quit")
        quit_x = max(0, self.width - cell_width(quit_label) - 3)
        self.text(row, "q", "key", x=quit_x)
        self.text(row, quit_label, "footer", x=quit_x + 1)
        switch_label = " English" if self.t.code == "zh" else " 中文"
        switch_x = quit_x - cell_width(switch_label) - 4
        right = quit_x
        if switch_x > 0:
            self.text(row, "l", "key", x=switch_x)
            self.text(row, switch_label, "footer", x=switch_x + 1)
            right = switch_x
        x = 1
        for key, desc in shortcuts:
            key, desc = self.t(key), self.t(desc)
            key_width = cell_width(key)
            span = key_width + cell_width(desc) + 1
            if x + span > right - 1:
                continue
            self.text(row, key, "key", x=x)
            self.text(row, f" {desc}", "footer", x=x + key_width)
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
