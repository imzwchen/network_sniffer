import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from ipaddress import ip_address

from .socket_diag import ProcessIdentity, normalize_address
from .tcp_flow import Endpoint


@dataclass(frozen=True, slots=True)
class TcpOpenEvent:
    kind: str
    pid: int
    namespace: int
    local: Endpoint
    remote: Endpoint
    started_us: int
    completed_us: int


_PROBE_TEMPLATE = r"""
kprobe:FUNCTION
/ PID_FILTER /
{
    @KIND_socket[tid] = SOCKET_ARG;
    @KIND_start[tid] = nsecs;
}

kretprobe:FUNCTION
/ @KIND_socket[tid] /
{
    $socket = (struct socket *)@KIND_socket[tid];
    $start = @KIND_start[tid];
    delete(@KIND_socket[tid]);
    delete(@KIND_start[tid]);
    if (RESULT_OK) {
        $sk = $socket->sk;
        if ((uint64)$sk != 0 && $sk->sk_protocol == 6 && $sk->__sk_common.skc_dport != 0) {
            $net = $sk->__sk_common.skc_net.net->ns.inum;
            $ports = ((uint32)$sk->__sk_common.skc_num << 16) | REMOTE_PORT;
            if ($sk->__sk_common.skc_family == 2) {
                printf("NS_TCP KIND %d %llu %llu %u %s %s %u\n", pid, $start, nsecs, $net,
                       ntop(2, $sk->__sk_common.skc_rcv_saddr), ntop(2, $sk->__sk_common.skc_daddr), $ports);
            }
            if ($sk->__sk_common.skc_family == 10) {
                printf("NS_TCP KIND %d %llu %llu %u %s %s %u\n", pid, $start, nsecs, $net,
                       ntop(10, $sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8),
                       ntop(10, $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8), $ports);
            }
        }
    }
}
"""


def tcp_probe_source(targets: tuple[ProcessIdentity, ...]) -> str:
    tick_ns = 1_000_000_000 // os.sysconf("SC_CLK_TCK")
    generation = f"((struct task_struct *)curtask)->group_leader->start_boottime / {tick_ns}"
    pid_filter = " || ".join(f"(pid == {target.pid} && {generation} == {target.start_ticks})" for target in targets)
    remote = "(uint16)$sk->__sk_common.skc_dport"
    if sys.byteorder == "little":
        remote = f"bswap({remote})"
    probes = []
    for kind, function, argument, result in (
        ("connect", "inet_stream_connect", "arg0", "(int32)retval == 0 || (int32)retval == -115"),
        ("accept", "inet_accept", "arg1", "(int32)retval == 0"),
    ):
        probes.append(
            _PROBE_TEMPLATE.replace("FUNCTION", function).replace("KIND", kind)
            .replace("SOCKET_ARG", argument).replace("RESULT_OK", result)
            .replace("REMOTE_PORT", remote).replace("PID_FILTER", pid_filter)
        )
    probes.append('interval:ms:250 { if (!@started) { @started = 1; printf("NS_READY\\n"); } }\n')
    return "\n".join(probes)


def parse_tcp_event(line: str, epoch_offset_us: int) -> TcpOpenEvent | None:
    parts = line.split()
    if len(parts) != 9 or parts[0] != "NS_TCP" or parts[1] not in ("connect", "accept"):
        return None
    _, kind, pid, started, completed, namespace, source, destination, ports = parts
    try:
        first, last = int(started), int(completed)
        process_id, netns, packed_ports = int(pid), int(namespace), int(ports)
        local_port, remote_port = divmod(packed_ports, 65536)
        local = Endpoint(normalize_address(ip_address(source)), local_port)
        remote = Endpoint(normalize_address(ip_address(destination)), remote_port)
    except ValueError:
        return None
    if not (0 <= first <= last and 0 < local_port < 65536 and remote_port > 0):
        return None
    return TcpOpenEvent(
        kind, process_id, netns, local, remote, epoch_offset_us + first // 1000, epoch_offset_us + last // 1000,
    )


class TcpEventReader:
    """Read optional eBPF connect and accept events without blocking the snapshot worker."""

    def __init__(self, targets: tuple[ProcessIdentity, ...]) -> None:
        self._process: subprocess.Popen[bytes] | None = None
        self._buffer = b""
        self._last_error = ""
        self._ready = False
        self._loss = False
        self._epoch_offset_us = (time.time_ns() - time.monotonic_ns()) // 1000
        if not targets:
            self.status = "Events unavailable (no readable target in capture namespace)"
            return
        program = shutil.which("bpftrace")
        if program is None:
            self.status = "Events unavailable (bpftrace missing)"
            return
        try:
            self._process = subprocess.Popen(
                [program, "-q", "-B", "line", "-e", tcp_probe_source(targets)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            assert self._process.stdout is not None
            os.set_blocking(self._process.stdout.fileno(), False)
            self.status = "Starting kernel events"
        except OSError as error:
            self.status = f"Events unavailable ({error.strerror or type(error).__name__})"
            self.close()

    def drain(self) -> list[TcpOpenEvent]:
        process = self._process
        if process is None:
            return []
        assert process.stdout is not None
        events = []
        for _ in range(8):
            try:
                data = os.read(process.stdout.fileno(), 65536)
            except BlockingIOError:
                break
            except OSError as error:
                self.status = f"Events unavailable ({error.strerror or type(error).__name__})"
                self.close()
                return events
            if not data:
                break
            lines = (self._buffer + data).split(b"\n")
            self._buffer = lines.pop()[-4096:]
            for raw in lines:
                line = raw.decode(errors="replace").strip()
                if line == "NS_READY":
                    self._ready = True
                elif event := parse_tcp_event(line, self._epoch_offset_us):
                    self._ready = True
                    events.append(event)
                elif line and not line.startswith("NS_TCP "):
                    if line.startswith("ERROR:") or not self._last_error:
                        self._last_error = "".join(c for c in line if " " <= c <= "~")[:160]
                    if "lost" in line.lower():
                        self._loss = True
        if process.poll() is not None:
            self.status = f"Events unavailable ({self._last_error or 'bpftrace exited'})"
            self.close()
        elif self._ready:
            self.status = "Kernel events active" + (" (loss reported)" if self._loss else "")
        return events

    def close(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.stdout is not None:
            process.stdout.close()
