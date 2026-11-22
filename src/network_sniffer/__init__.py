import argparse
import curses
import os
import sys
from pathlib import Path

from .capture import CaptureError, list_interfaces, open_capture
from .live import LiveCapture
from .tui import select_interface, show_capture, show_live_capture
from .tui_i18n import Language


def main(*, elevate_live: bool = False) -> int:
    parser = argparse.ArgumentParser(prog="network-sniffer", description="Capture and browse network packets in a terminal.")
    mode = parser.add_mutually_exclusive_group(required=not elevate_live)
    mode.add_argument("-D", "--list-interfaces", action="store_true", help="list capture interfaces")
    interface_help = "capture live on this interface"
    if elevate_live:
        interface_help += " (omit to choose in the TUI)"
    mode.add_argument("-i", "--interface", metavar="NAME", help=interface_help)
    mode.add_argument("-r", "--read", type=Path, metavar="FILE", help="capture file to open")
    parser.add_argument(
        "-s", "--snaplen", type=int, metavar="BYTES", help="maximum live bytes per packet (default 65535)"
    )
    parser.add_argument("-w", "--write", type=Path, metavar="FILE", help="save live packets, replacing an existing .pcap")
    parser.add_argument(
        "--capture-filter", metavar="BPF", help="libpcap filter for live capture or offline reading",
    )
    parser.add_argument("--pid", type=int, action="append", metavar="PID", help="track a local process's TCP flows (repeatable)")
    parser.add_argument("--lang", choices=("en", "zh"), default="en", help="TUI language (default en)")
    options = parser.parse_args()

    live_mode = options.read is None and not options.list_interfaces
    if not live_mode and (options.snaplen is not None or options.write is not None):
        parser.error("--snaplen and --write require live capture")
    if options.snaplen is not None and not 1 <= options.snaplen <= 262144:
        parser.error("--snaplen must be between 1 and 262144 bytes")
    if options.list_interfaces and options.capture_filter is not None:
        parser.error("--capture-filter requires --interface or --read")
    if options.pid and not live_mode:
        parser.error("--pid requires live capture")
    if options.pid and any(not 0 < pid <= 0x7FFFFFFF for pid in options.pid):
        parser.error("--pid requires a positive Linux process ID")

    try:
        if options.list_interfaces:
            for name, description in list_interfaces():
                print(f"{name}\t{description}" if description else name)
            return 0

        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise CaptureError("the viewer requires an interactive terminal")

        language = Language(options.lang)
        if options.read is not None:
            with open_capture(options.read, capture_filter=options.capture_filter) as source:
                packets = list(source)
            show_capture(packets, options.read.name, language, capture_filter=options.capture_filter)
        else:
            interface = options.interface
            arguments = sys.argv[1:]
            if interface is None:
                interfaces = list_interfaces()
                if not interfaces:
                    raise CaptureError("no capture interfaces found")
                interface = select_interface(interfaces, language)
                if interface is None:
                    return 0
                arguments = [f"--interface={interface}", *arguments]

            if elevate_live and os.geteuid() != 0:
                executable = Path(sys.executable).with_name("network-sniffer")
                if language.code != options.lang:
                    arguments = [*arguments, "--lang", language.code]
                os.execvp("sudo", ["sudo", "--", str(executable), *arguments])

            with LiveCapture(
                interface, options.snaplen or 65535, options.write, capture_filter=options.capture_filter,
                pids=tuple(dict.fromkeys(options.pid or ())),
            ) as capture:
                show_live_capture(capture, language)
            if capture.error is not None:
                raise capture.error
    except (CaptureError, OSError, curses.error) as error:
        print(f"{parser.prog}: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0
