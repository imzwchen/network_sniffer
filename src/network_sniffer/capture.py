from __future__ import annotations

import ctypes
import os
from collections.abc import Generator, Iterator
from contextlib import ExitStack, closing, contextmanager
from ctypes.util import find_library
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory


class CaptureError(Exception):
    """An error from the libpcap capture backend."""


@dataclass(frozen=True, slots=True)
class Packet:
    timestamp_us: int
    link_type: int
    original_length: int
    data: bytes

    @property
    def captured_length(self) -> int:
        return len(self.data)


class _Timeval(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_long)]


class _PacketHeader(ctypes.Structure):
    _fields_ = [
        ("timestamp", _Timeval),
        ("captured_length", ctypes.c_uint32),
        ("original_length", ctypes.c_uint32),
    ]


_HeaderPointer = ctypes.POINTER(_PacketHeader)


class _Device(ctypes.Structure):
    pass


_DevicePointer = ctypes.POINTER(_Device)
_Device._fields_ = [
    ("next", _DevicePointer),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint32),
]


class _CaptureStats(ctypes.Structure):
    _fields_ = [
        ("received", ctypes.c_uint),
        ("dropped", ctypes.c_uint),
        ("interface_dropped", ctypes.c_uint),
    ]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("instruction_count", ctypes.c_uint), ("instructions", ctypes.c_void_p)]


_ERROR_BUFFER_SIZE = 256  # PCAP_ERRBUF_SIZE
_NETMASK_UNKNOWN = 0xFFFFFFFF  # PCAP_NETMASK_UNKNOWN


def _load_libpcap() -> ctypes.CDLL:
    try:
        library = ctypes.CDLL(find_library("pcap") or "libpcap.so.0.8")
    except OSError as error:
        raise CaptureError(f"could not load libpcap: {error}") from error

    handle, integer, string = ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p
    error_buffer = ctypes.POINTER(ctypes.c_char)
    net_address = ctypes.POINTER(ctypes.c_uint32)
    program = ctypes.POINTER(_BpfProgram)
    signatures = (
        ("pcap_findalldevs", integer, ctypes.POINTER(_DevicePointer), error_buffer),
        ("pcap_freealldevs", None, _DevicePointer),
        ("pcap_open_offline", handle, string, error_buffer),
        ("pcap_open_live", handle, string, integer, integer, integer, error_buffer),
        ("pcap_lookupnet", integer, string, net_address, net_address, error_buffer),
        ("pcap_compile", integer, handle, program, string, integer, ctypes.c_uint32),
        ("pcap_setfilter", integer, handle, program),
        ("pcap_freecode", None, program),
        ("pcap_setnonblock", integer, handle, integer, error_buffer),
        ("pcap_datalink", integer, handle),
        ("pcap_datalink_ext", integer, handle),
        ("pcap_snapshot", integer, handle),
        ("pcap_stats", integer, handle, ctypes.POINTER(_CaptureStats)),
        ("pcap_next_ex", integer, handle, ctypes.POINTER(_HeaderPointer), ctypes.POINTER(handle)),
        ("pcap_geterr", string, handle),
        ("pcap_close", None, handle),
        ("pcap_dump_open", handle, handle, string),
        ("pcap_dump", None, handle, _HeaderPointer, handle),
        ("pcap_dump_file", handle, handle),
        ("pcap_dump_flush", integer, handle),
        ("pcap_dump_close", None, handle),
    )
    for name, result_type, *argument_types in signatures:
        function = getattr(library, name)
        function.argtypes = argument_types
        function.restype = result_type
    return library


def list_interfaces() -> list[tuple[str, str | None]]:
    library = _load_libpcap()
    devices = _DevicePointer()
    error_buffer = ctypes.create_string_buffer(_ERROR_BUFFER_SIZE)
    if library.pcap_findalldevs(ctypes.byref(devices), error_buffer) != 0:
        raise CaptureError(f"could not list interfaces: {error_buffer.value.decode(errors='replace')}")

    interfaces = []
    try:
        current = devices
        while current:
            device = current.contents
            description = device.description.decode(errors="replace") if device.description else None
            interfaces.append((os.fsdecode(device.name), description))
            current = device.next
    finally:
        library.pcap_freealldevs(devices)
    return interfaces


def _install_capture_filter(
    library: ctypes.CDLL, handle: int, expression: str, netmask: int = _NETMASK_UNKNOWN,
) -> None:
    if "\x00" in expression:
        raise CaptureError("a BPF capture filter cannot contain a null byte")
    program = _BpfProgram()
    pointer = ctypes.byref(program)
    if library.pcap_compile(handle, pointer, os.fsencode(expression), 1, netmask) != 0:
        message = library.pcap_geterr(handle).decode(errors="replace")
        raise CaptureError(f"could not compile BPF capture filter {expression!r}: {message}")
    try:
        if library.pcap_setfilter(handle, pointer) != 0:
            message = library.pcap_geterr(handle).decode(errors="replace")
            raise CaptureError(f"could not apply BPF capture filter {expression!r}: {message}")
    finally:
        library.pcap_freecode(pointer)


class _PcapReader:
    def __init__(self, library: ctypes.CDLL, handle: int) -> None:
        self.library = library
        self.handle = handle
        self.link_type = library.pcap_datalink(handle)
        self._header = _HeaderPointer()
        self._data = ctypes.c_void_p()

    @property
    def savefile_format(self) -> tuple[int, int, int]:
        return (
            self.link_type,
            self.library.pcap_datalink_ext(self.handle),
            self.library.pcap_snapshot(self.handle),
        )

    def dropped(self) -> int | None:
        stats = _CaptureStats()
        if self.library.pcap_stats(self.handle, ctypes.byref(stats)) != 0:
            return None
        return stats.dropped

    def read(self, output: _PcapWriter | None = None) -> Packet | None:
        result = self.library.pcap_next_ex(
            self.handle, ctypes.byref(self._header), ctypes.byref(self._data)
        )
        if result == 0:
            return None  # No packet is ready on a non-blocking live handle.
        if result == -2:
            raise StopIteration
        if result == -1:
            message = self.library.pcap_geterr(self.handle).decode(errors="replace")
            raise CaptureError(f"could not read packet: {message}")
        if result != 1:
            raise CaptureError(f"unexpected libpcap result while reading a packet ({result})")

        if output is not None:
            output.write(self._header, self._data)
        header = self._header.contents
        timestamp_us = header.timestamp.seconds * 1_000_000 + header.timestamp.microseconds
        # libpcap can reuse the packet buffer on the next read.
        data = ctypes.string_at(self._data, header.captured_length)
        return Packet(timestamp_us, self.link_type, header.original_length, data)


def _offline_packets(reader: _PcapReader) -> Generator[Packet, None, None]:
    while True:
        try:
            packet = reader.read()
        except StopIteration:
            return
        if packet is not None:
            yield packet


@contextmanager
def open_capture(path: Path, *, capture_filter: str | None = None) -> Iterator[Iterator[Packet]]:
    """Read a libpcap savefile while its handle is open."""
    library = _load_libpcap()
    error_buffer = ctypes.create_string_buffer(_ERROR_BUFFER_SIZE)
    handle = library.pcap_open_offline(os.fsencode(path.absolute()), error_buffer)
    if not handle:
        message = error_buffer.value.decode(errors="replace")
        raise CaptureError(f"could not open {str(path)!r}: {message}")

    try:
        if capture_filter is not None:
            _install_capture_filter(library, handle, capture_filter)
        with closing(_offline_packets(_PcapReader(library, handle))) as packets:
            yield packets
    finally:
        library.pcap_close(handle)


@contextmanager
def open_live(
    interface: str, snaplen: int, *, capture_filter: str | None = None,
) -> Iterator[_PcapReader]:
    error_buffer = ctypes.create_string_buffer(_ERROR_BUFFER_SIZE)
    library = _load_libpcap()
    # Capture this host's traffic without requesting promiscuous mode.
    device = os.fsencode(interface)
    handle = library.pcap_open_live(device, snaplen, 0, 25, error_buffer)
    if not handle:
        message = error_buffer.value.decode(errors="replace")
        raise CaptureError(f"could not capture on {interface!r}: {message}")
    try:
        if capture_filter is not None:
            subnet, netmask = ctypes.c_uint32(), ctypes.c_uint32(_NETMASK_UNKNOWN)
            result = library.pcap_lookupnet(device, ctypes.byref(subnet), ctypes.byref(netmask), error_buffer)
            _install_capture_filter(
                library, handle, capture_filter, netmask.value if result == 0 else _NETMASK_UNKNOWN,
            )
        if library.pcap_setnonblock(handle, 1, error_buffer) != 0:
            message = error_buffer.value.decode(errors="replace")
            raise CaptureError(f"could not enable non-blocking capture on {interface!r}: {message}")
        yield _PcapReader(library, handle)
    finally:
        library.pcap_close(handle)


class _PcapWriter:
    def __init__(self, reader: _PcapReader, dumper: int, path: Path) -> None:
        self.savefile_format = reader.savefile_format
        self._library = reader.library
        self._dumper = dumper
        self._path = path
        self._stream = self._library.pcap_dump_file(dumper)
        self._ferror = ctypes.CDLL(None).ferror
        self._ferror.argtypes = (ctypes.c_void_p,)
        self._ferror.restype = ctypes.c_int

    def write(self, header: _HeaderPointer, data: ctypes.c_void_p) -> None:
        self._library.pcap_dump(self._dumper, header, data)

    def flush(self) -> None:
        if self._library.pcap_dump_flush(self._dumper) != 0 or self._ferror(self._stream):
            raise CaptureError(f"could not write capture file {str(self._path)!r}")


@contextmanager
def save_capture(reader: _PcapReader, path: Path) -> Iterator[_PcapWriter]:
    with ExitStack() as cleanup:
        with TemporaryDirectory(prefix=".network-sniffer-", dir=path.parent) as directory:
            staged = Path(directory) / "capture.pcap"
            os.close(os.open(staged, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            dumper = reader.library.pcap_dump_open(reader.handle, os.fsencode(staged))
            if not dumper:
                message = reader.library.pcap_geterr(reader.handle).decode(errors="replace")
                raise CaptureError(f"could not save capture to {str(path)!r}: {message}")
            cleanup.callback(reader.library.pcap_dump_close, dumper)

            writer = _PcapWriter(reader, dumper, path)
            # Publish the new file only after libpcap has written a valid header.
            writer.flush()
            os.replace(staged, path)

        yield writer
        writer.flush()
