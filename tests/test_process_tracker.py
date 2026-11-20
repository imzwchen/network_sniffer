import os
import socket
import struct
import subprocess
import sys
import unittest
from ipaddress import ip_address
from unittest.mock import patch

from network_sniffer.process_events import parse_tcp_event, tcp_probe_source
from network_sniffer.process_tracker import FlowOwner, OwnershipObservation, ProcessMonitor, flow_ownership
from network_sniffer.socket_diag import ProcessIdentity, _decode_socket, process_socket_inodes
from network_sniffer.socket_diag import read_process_identity, tcp_sockets_by_inode
from network_sniffer.tcp_flow import Endpoint, FlowInfo, TcpTracker, connection_endpoints


_CLIENT = Endpoint(ip_address("127.0.0.1"), 49152)
_SERVER = Endpoint(ip_address("127.0.0.1"), 9000)
_PAIR = connection_endpoints(_CLIENT, _SERVER)


def flow(number: int, first: int, last: int, state: str = "Closed") -> FlowInfo:
    return FlowInfo(number, _PAIR, state, first, last, _CLIENT, 6)


class ProcessAttributionTests(unittest.TestCase):
    def test_snapshot_attributes_shared_sockets_and_ignores_other_connections(self):
        a = FlowOwner(101, _CLIENT, "snapshot")
        b = FlowOwner(202, _CLIENT, "snapshot")
        c = FlowOwner(303, _SERVER, "snapshot")
        other_server = Endpoint(_SERVER.address, 9001)
        other = FlowInfo(2, connection_endpoints(_CLIENT, other_server), "Closed", 100, 200, _CLIENT, 4)
        results = flow_ownership((flow(1, 100, 200), other), (
            OwnershipObservation(a, _SERVER, 120, 120),
            OwnershipObservation(b, _SERVER, 130, 140),
            OwnershipObservation(c, _CLIENT, 140, 160),
        ))
        self.assertEqual(results[0].owners, (a, b, c))
        self.assertEqual(results[1].owners, ())

    def test_temporal_attribution_does_not_reuse_prior_owner(self):
        old = FlowOwner(101, _CLIENT, "snapshot")
        new = FlowOwner(202, _CLIENT, "snapshot")
        results = flow_ownership((flow(1, 100_000, 120_000, "Superseded"), flow(2, 140_000, 200_000)), (
            OwnershipObservation(old, _SERVER, 110_000, 115_000),
            OwnershipObservation(new, _SERVER, 150_000, 155_000),
        ))
        self.assertEqual([entry.owners for entry in results], [(old,), (new,)])
        reused_later = flow_ownership((flow(1, 100_000, 120_000, "Superseded"),), (
            OwnershipObservation(new, _SERVER, 155_000, 155_000),
        ))
        self.assertEqual(reused_later[0].owners, ())

    def test_connect_and_accept_attribute_a_flow_between_snapshots(self):
        epoch = 1_000_000
        client_ports = _CLIENT.port * 65536 + _SERVER.port
        server_ports = _SERVER.port * 65536 + _CLIENT.port
        connect = parse_tcp_event(f"NS_TCP connect 101 19000 22000 7 ::ffff:127.0.0.1 127.0.0.1 {client_ports}", epoch)
        accept = parse_tcp_event(f"NS_TCP accept 202 1000 28000 7 127.0.0.1 127.0.0.1 {server_ports}", epoch)
        self.assertEqual((connect.local, connect.namespace, connect.started_us), (_CLIENT, 7, epoch + 19))
        old, short = flow(1, epoch - 100_000, epoch - 10_000), flow(2, epoch + 20, epoch + 38)
        observed = tuple(OwnershipObservation.from_event(event) for event in (connect, accept))
        results = flow_ownership((old, short), observed)
        self.assertEqual(results[0].owners, ())
        self.assertEqual(results[1].owners, (FlowOwner(101, _CLIENT, "connect"), FlowOwner(202, _SERVER, "accept")))
        self.assertIsNone(parse_tcp_event("NS_TCP connect 101 invalid", epoch))

    def test_event_evidence_remains_stronger_than_snapshot(self):
        early = FlowOwner(101, _CLIENT, "connect")
        later = FlowOwner(101, _CLIENT, "snapshot")
        ownership = flow_ownership((flow(1, 1_000_000, 1_100_000),), (
            OwnershipObservation(early, _SERVER, 999_999, 1_000_001),
            OwnershipObservation(later, _SERVER, 1_001_000, 1_020_000),
        ))
        self.assertEqual(ownership[0].owners, (early,))

    def test_pid_exit_reuse_and_permissions(self):
        monitor = ProcessMonitor((101, 202, 303, 404), TcpTracker())
        namespace = monitor._namespace
        monitor._targets[101] = ProcessIdentity(101, 10, namespace)
        monitor._targets[202] = ProcessIdentity(202, 20, namespace)
        with patch("network_sniffer.process_tracker.read_process_identity", side_effect=(
            FileNotFoundError(), ProcessIdentity(202, 21, namespace), PermissionError(),
            ProcessIdentity(404, 40, namespace + 1),
        )):
            self.assertEqual(dict(monitor._snapshot()), {
                101: "Exited", 202: "PID reused", 303: "Permission denied", 404: "Different network namespace",
            })
        with patch("network_sniffer.process_tracker.read_process_identity") as reading:
            self.assertEqual(monitor._identity(202), (None, "PID reused"))
            reading.assert_not_called()

    def test_probe_targets_the_selected_process_generation(self):
        source = tcp_probe_source((ProcessIdentity(17, 100, 7), ProcessIdentity(22, 400, 7)))
        self.assertIn("pid == 17", source)
        self.assertIn("pid == 22", source)
        self.assertIn("start_boottime", source)
        self.assertIn("== 400", source)
        self.assertIn("kretprobe:inet_stream_connect", source)
        self.assertIn("kretprobe:inet_accept", source)


class SocketDiagnosticsTests(unittest.TestCase):
    def test_ipv4_mapped_ipv6_and_native_byte_orders(self):
        message = bytearray(72)
        message[:2] = bytes((socket.AF_INET6, 1))
        struct.pack_into("!HH", message, 4, _CLIENT.port, _SERVER.port)
        message[8:24] = ip_address("::ffff:127.0.0.1").packed
        message[24:40] = ip_address("::ffff:127.0.0.1").packed
        struct.pack_into("=II", message, 44, 456, 789)
        struct.pack_into("=I", message, 68, 123)
        decoded = _decode_socket(bytes(message))
        self.assertEqual((decoded.inode, decoded.cookie, decoded.local, decoded.remote), (123, (456, 789), _CLIENT, _SERVER))
        with self.assertRaises(OSError):
            _decode_socket(bytes(message[:64]))

    def test_native_diagnostics_find_ipv4_and_ipv6_connections(self):
        for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            with self.subTest(address=address):
                with socket.socket(family) as listener, socket.socket(family) as client:
                    listener.bind((address, 0))
                    listener.listen()
                    client.connect(listener.getsockname())
                    with listener.accept()[0] as peer:
                        client_inode = os.fstat(client.fileno()).st_ino
                        peer_inode = os.fstat(peer.fileno()).st_ino
                        inodes = process_socket_inodes(os.getpid())
                        records = tcp_sockets_by_inode()
                        self.assertTrue({client_inode, peer_inode} <= inodes)
                        self.assertEqual(records[client_inode].local, records[peer_inode].remote)
                        self.assertEqual(records[client_inode].remote, records[peer_inode].local)
                        self.assertEqual(records[client_inode].local.address, ip_address(address))

    def test_native_shared_connection_inode_belongs_to_two_processes(self):
        with socket.socket() as listener, socket.socket() as client:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            client.connect(listener.getsockname())
            with listener.accept()[0]:
                inode = os.fstat(client.fileno()).st_ino
                with subprocess.Popen(
                    [sys.executable, "-c", "input()"], stdin=subprocess.PIPE, pass_fds=(client.fileno(),),
                ) as child:
                    try:
                        self.assertEqual(read_process_identity(child.pid).pid, child.pid)
                        self.assertIn(inode, process_socket_inodes(child.pid) & process_socket_inodes(os.getpid()))
                        self.assertIn(inode, tcp_sockets_by_inode())
                    finally:
                        child.communicate(b"\n", timeout=3)
