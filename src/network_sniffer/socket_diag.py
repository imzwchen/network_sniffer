import errno
import os
import re
import socket
import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from .tcp_flow import Endpoint


_PROC = Path("/proc")
_SOCKET_LINK = re.compile(r"socket:\[(\d+)\]")
_NETLINK_SOCK_DIAG = 4
_SOCK_DIAG_BY_FAMILY = 20
_NLMSG_ERROR = 2
_NLMSG_DONE = 3
_NLM_F_REQUEST = 1
_NLM_F_DUMP = 0x300
_NLM_F_DUMP_INTR = 0x10
_NL_HEADER = struct.Struct("=IHHII")
_DIAG_REQUEST = struct.Struct("=BBBBI40xII")
_DIAG_MESSAGE_SIZE = 72


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    start_ticks: int
    network_namespace: int


@dataclass(frozen=True, slots=True)
class TcpSocket:
    inode: int
    cookie: tuple[int, int]
    local: Endpoint
    remote: Endpoint
    state: int


def _process_stat(pid: int) -> tuple[str, int]:
    stat = (_PROC / str(pid) / "stat").read_text(errors="replace")
    fields = stat.rpartition(")")[2].split()  # Fields 3 onward, even when comm contains a ')'.
    if len(fields) < 20:
        raise OSError(errno.EIO, f"Invalid stat record for PID {pid}")
    return fields[0], int(fields[19])


def read_process_identity(pid: int) -> ProcessIdentity:
    state, start_ticks = _process_stat(pid)
    if state in {"X", "Z"}:
        raise ProcessLookupError(errno.ESRCH, f"PID {pid} exited")
    namespace = (_PROC / str(pid) / "ns" / "net").stat().st_ino
    new_state, new_start = _process_stat(pid)
    if new_start != start_ticks or new_state in {"X", "Z"}:
        raise ProcessLookupError(errno.ESRCH, f"PID {pid} changed while reading its identity")
    return ProcessIdentity(pid, start_ticks, namespace)


def process_socket_inodes(pid: int) -> set[int]:
    sockets = set()
    with os.scandir(_PROC / str(pid) / "fd") as descriptors:
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor.path)
            except FileNotFoundError:
                continue  # The process closed this descriptor during the scan.
            match = _SOCKET_LINK.fullmatch(target)
            if match is not None:
                sockets.add(int(match[1]))
    return sockets


def normalize_address(address: IPv4Address | IPv6Address) -> IPv4Address | IPv6Address:
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _decode_socket(message: bytes) -> TcpSocket | None:
    if len(message) < _DIAG_MESSAGE_SIZE:
        raise OSError(errno.EPROTO, "Short NETLINK_SOCK_DIAG TCP message")
    family, state = message[0], message[1]
    local_port, remote_port = struct.unpack_from("!HH", message, 4)
    inode = struct.unpack_from("=I", message, 68)[0]
    if not inode or not local_port or not remote_port or state == 10:  # TCP_LISTEN
        return None
    if family == socket.AF_INET:
        local = IPv4Address(message[8:12])
        remote = IPv4Address(message[24:28])
    elif family == socket.AF_INET6:
        local = normalize_address(IPv6Address(message[8:24]))
        remote = normalize_address(IPv6Address(message[24:40]))
    else:
        return None
    cookie = struct.unpack_from("=II", message, 44)
    return TcpSocket(inode, cookie, Endpoint(local, local_port), Endpoint(remote, remote_port), state)


def _dump_family(channel: socket.socket, family: int, sequence: int) -> dict[int, TcpSocket]:
    request = _DIAG_REQUEST.pack(family, socket.IPPROTO_TCP, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    header = _NL_HEADER.pack(_NL_HEADER.size + len(request), _SOCK_DIAG_BY_FAMILY, _NLM_F_REQUEST | _NLM_F_DUMP, sequence, 0)
    channel.sendto(header + request, (0, 0))
    sockets: dict[int, TcpSocket] = {}
    while True:
        data, _, flags, sender = channel.recvmsg(65536)
        if flags & socket.MSG_TRUNC:
            raise OSError(errno.EMSGSIZE, "Truncated NETLINK_SOCK_DIAG reply")
        if sender[0] != 0:
            continue
        offset = 0
        while offset + _NL_HEADER.size <= len(data):
            length, kind, message_flags, reply_sequence, _ = _NL_HEADER.unpack_from(data, offset)
            if not _NL_HEADER.size <= length <= len(data) - offset:
                raise OSError(errno.EPROTO, "Invalid NETLINK_SOCK_DIAG message length")
            payload = data[offset + _NL_HEADER.size : offset + length]
            offset += (length + 3) & ~3
            if reply_sequence != sequence:
                continue
            if message_flags & _NLM_F_DUMP_INTR:
                raise OSError(errno.EINTR, "NETLINK_SOCK_DIAG dump was interrupted")
            if kind in (_NLMSG_ERROR, _NLMSG_DONE):
                if len(payload) >= 4:
                    code = -struct.unpack_from("=i", payload)[0]
                    if code:
                        raise OSError(code, f"NETLINK_SOCK_DIAG: {os.strerror(code)}")
                if kind == _NLMSG_DONE:
                    return sockets
            elif kind == _SOCK_DIAG_BY_FAMILY:
                record = _decode_socket(payload)
                if record is not None:
                    sockets[record.inode] = record


def tcp_sockets_by_inode() -> dict[int, TcpSocket]:
    """Read connected IPv4 and IPv6 TCP sockets in the calling network namespace."""
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_SOCK_DIAG) as channel:
        channel.bind((0, 0))
        channel.settimeout(0.5)
        sockets = _dump_family(channel, socket.AF_INET, 1)
        try:
            sockets.update(_dump_family(channel, socket.AF_INET6, 2))
        except OSError as error:
            if error.errno not in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.ENOENT):
                raise
        return sockets
