import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from threading import Event, Thread

from .process_events import TcpEventReader, TcpOpenEvent
from .socket_diag import ProcessIdentity, TcpSocket, process_socket_inodes, read_process_identity, tcp_sockets_by_inode
from .tcp_flow import Endpoint, FlowInfo, TcpTracker, connection_endpoints


_REFRESH_SECONDS = 0.15
_SNAPSHOT_GRACE_US = 400_000
_EVENT_GRACE_US = 5_000
_HISTORY_LIMIT = 4096


@dataclass(frozen=True, slots=True)
class FlowOwner:
    pid: int
    local: Endpoint
    source: str


@dataclass(frozen=True, slots=True)
class OwnershipObservation:
    owner: FlowOwner
    remote: Endpoint
    first_us: int
    last_us: int

    @classmethod
    def from_event(cls, event: TcpOpenEvent) -> "OwnershipObservation":
        first = event.started_us if event.kind == "connect" else event.completed_us
        return cls(FlowOwner(event.pid, event.local, event.kind), event.remote, first, event.completed_us)


@dataclass(frozen=True, slots=True)
class ProcessFlow:
    flow: FlowInfo
    owners: tuple[FlowOwner, ...]


@dataclass(frozen=True, slots=True)
class ProcessReport:
    targets: tuple[tuple[int, str], ...]
    events: str
    flows: tuple[ProcessFlow, ...] = ()


def flow_ownership(
    flows: tuple[FlowInfo, ...], observations: tuple[OwnershipObservation, ...],
) -> tuple[ProcessFlow, ...]:
    by_endpoints: dict[tuple[Endpoint, Endpoint], list[FlowInfo]] = defaultdict(list)
    for flow in flows:
        by_endpoints[flow.endpoints].append(flow)
    for group in by_endpoints.values():
        group.sort(key=lambda flow: (flow.first_us, flow.number))

    matches: dict[int, dict[tuple[int, Endpoint], FlowOwner]] = defaultdict(dict)
    for evidence in observations:
        owner = evidence.owner
        candidates = by_endpoints.get(connection_endpoints(owner.local, evidence.remote), ())
        if owner.source == "connect":
            # A connect probe gives the interval in which the initial SYN was sent.
            openings = [
                flow for flow in candidates
                if flow.initiator == owner.local and flow.last_us >= evidence.first_us - _EVENT_GRACE_US
                and evidence.first_us - _EVENT_GRACE_US <= flow.first_us <= evidence.last_us + _EVENT_GRACE_US
            ]
            if openings:
                flow = min(openings, key=lambda item: (
                    item.first_us < evidence.first_us, abs(item.first_us - evidence.first_us),
                ))
                matches[flow.number][(owner.pid, owner.local)] = owner
                continue

        for index, flow in enumerate(candidates):
            if owner.source == "accept" and flow.initiator == owner.local:
                continue
            if owner.source == "connect" and flow.initiator is not None:
                continue
            grace = (
                _SNAPSHOT_GRACE_US if owner.source == "snapshot" and flow.state in ("Midstream", "Handshake", "Established", "Closing")
                else (_EVENT_GRACE_US if owner.source != "snapshot" else 0)
            )
            last = flow.last_us + grace
            if index + 1 < len(candidates):
                last = min(last, candidates[index + 1].first_us - 1)
            if evidence.first_us <= last and evidence.last_us >= flow.first_us:
                owners = matches[flow.number]
                previous = owners.get((owner.pid, owner.local))
                if previous is None or previous.source == "snapshot":
                    owners[(owner.pid, owner.local)] = owner

    return tuple(
        ProcessFlow(flow, tuple(sorted(matches[flow.number].values(), key=lambda owner: (owner.pid, str(owner.local)))))
        for flow in sorted(flows, key=lambda item: item.number)
    )


_SocketKey = tuple[int, int, tuple[int, int], Endpoint, Endpoint]


class ProcessMonitor:
    """Collect socket ownership for selected processes without blocking capture."""

    def __init__(self, pids: tuple[int, ...], flows: TcpTracker) -> None:
        self.pids = pids
        self._flows = flows
        self.report = ProcessReport(tuple((pid, "Inspecting") for pid in pids), "Checking event support")
        self._namespace = os.stat("/proc/self/ns/net").st_ino
        self._targets: dict[int, ProcessIdentity] = {}
        self._retired: dict[int, str] = {}
        self._active: dict[_SocketKey, OwnershipObservation] = {}
        self._history: deque[OwnershipObservation] = deque(maxlen=_HISTORY_LIMIT)
        self._closing = Event()
        self._worker = Thread(target=self._run, name="TCP process ownership")

    def start(self) -> None:
        self._worker.start()

    def close(self) -> None:
        self._closing.set()
        self._worker.join()

    def _identity(self, pid: int) -> tuple[ProcessIdentity | None, str]:
        if pid in self._retired:
            return None, self._retired[pid]
        try:
            current = read_process_identity(pid)
        except (ProcessLookupError, FileNotFoundError):
            status = "Exited" if pid in self._targets else "PID not found"
            self._retired[pid] = status
            return None, status
        except PermissionError:
            return None, "Permission denied"
        except OSError as error:
            return None, error.strerror or str(error)
        previous = self._targets.setdefault(pid, current)
        if current.start_ticks != previous.start_ticks:
            self._retired[pid] = "PID reused"
            return None, "PID reused"
        if current.network_namespace != self._namespace:
            return None, "Different network namespace"
        return current, ""

    def _snapshot(self) -> tuple[tuple[int, str], ...]:
        statuses: dict[int, str] = {}
        descriptors: dict[int, set[int]] = {}
        for pid in self.pids:
            identity, failure = self._identity(pid)
            if identity is None:
                statuses[pid] = failure
                continue
            try:
                descriptors[pid] = process_socket_inodes(pid)
            except (ProcessLookupError, FileNotFoundError):
                self._retired[pid] = statuses[pid] = "Exited"
            except PermissionError:
                statuses[pid] = "Permission denied reading fd"
            except OSError as error:
                statuses[pid] = error.strerror or str(error)

        observed_us = time.time_ns() // 1000
        try:
            records = tcp_sockets_by_inode() if any(descriptors.values()) else {}
        except OSError as error:
            records = None
            diagnostic = error.strerror or str(error)
        active = {}
        for pid, inodes in descriptors.items():
            current, failure = self._identity(pid)
            if current is None:
                statuses[pid] = failure
                continue
            if records is None:
                statuses[pid] = f"Socket query failed ({diagnostic})"
                continue
            sockets = [records[inode] for inode in inodes if inode in records]
            statuses[pid] = f"Snapshot {len(sockets)} TCP socket(s)"
            for sock in sockets:
                key = _socket_key(pid, sock)
                previous = self._active.get(key)
                if previous is None:
                    owner = FlowOwner(pid, sock.local, "snapshot")
                    observation = OwnershipObservation(owner, sock.remote, observed_us, observed_us)
                else:
                    observation = replace(previous, last_us=observed_us)
                active[key] = observation
        self._history.extend(observation for key, observation in self._active.items() if key not in active)
        self._active = active
        return tuple((pid, statuses[pid]) for pid in self.pids)

    def _run(self) -> None:
        statuses = self._snapshot()
        targets = tuple(item for item in self._targets.values() if item.network_namespace == self._namespace)
        events = TcpEventReader(targets)
        try:
            while not self._closing.is_set():
                for event in events.drain():
                    if event.namespace == self._namespace and event.pid in self._targets:
                        self._history.append(OwnershipObservation.from_event(event))
                observations = tuple(self._history) + tuple(self._active.values())
                flows = flow_ownership(self._flows.flow_infos(), observations)
                self.report = ProcessReport(statuses, events.status, flows)
                if self._closing.wait(_REFRESH_SECONDS):
                    break
                statuses = self._snapshot()
        finally:
            events.close()


def _socket_key(pid: int, sock: TcpSocket) -> _SocketKey:
    return pid, sock.inode, sock.cookie, sock.local, sock.remote
