import argparse
import curses
import sys
from pathlib import Path

from .capture import CaptureError, list_interfaces, open_capture
from .live import LiveCapture
from .tui import show_capture, show_live_capture


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture and browse network packets in a terminal.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-D", "--list-interfaces", action="store_true", help="list capture interfaces")
    mode.add_argument("-i", "--interface", metavar="NAME", help="capture live on this interface")
    mode.add_argument("-r", "--read", type=Path, metavar="FILE", help="capture file to open")
    parser.add_argument(
        "-s", "--snaplen", type=int, metavar="BYTES", help="maximum live bytes per packet (default 65535)"
    )
    parser.add_argument("-w", "--write", type=Path, metavar="FILE", help="save live packets to a new .pcap")
    parser.add_argument(
        "--capture-filter", metavar="BPF", help="libpcap filter for live capture or offline reading",
    )
    parser.add_argument("--pid", type=int, action="append", metavar="PID", help="track a local process's TCP flows (repeatable)")
    options = parser.parse_args()

    if options.interface is None and (options.snaplen is not None or options.write is not None):
        parser.error("--snaplen and --write require --interface")
    if options.snaplen is not None and not 1 <= options.snaplen <= 262144:
        parser.error("--snaplen must be between 1 and 262144 bytes")
    if options.list_interfaces and options.capture_filter is not None:
        parser.error("--capture-filter requires --interface or --read")
    if options.pid and options.interface is None:
        parser.error("--pid requires --interface")
    if options.pid and any(not 0 < pid <= 0x7FFFFFFF for pid in options.pid):
        parser.error("--pid requires a positive Linux process ID")

    try:
        if options.list_interfaces:
            for name, description in list_interfaces():
                print(f"{name}\t{description}" if description else name)
            return 0

        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise CaptureError("the viewer requires an interactive terminal")

        if options.read is not None:
            with open_capture(options.read, capture_filter=options.capture_filter) as source:
                packets = list(source)
            show_capture(packets, options.read.name, capture_filter=options.capture_filter)
        else:
            with LiveCapture(
                options.interface, options.snaplen or 65535, options.write, capture_filter=options.capture_filter,
                pids=tuple(dict.fromkeys(options.pid or ())),
            ) as capture:
                show_live_capture(capture)
            if capture.error is not None:
                raise capture.error
    except (CaptureError, OSError, curses.error) as error:
        print(f"{parser.prog}: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0
