import socket
from types import SimpleNamespace

from endpoint.collectors.network_monitor import NetworkMonitor


def fake_connection(pid, status):
    return SimpleNamespace(
        pid=pid,
        type=socket.SOCK_STREAM,
        laddr=("127.0.0.1", 50000),
        raddr=("127.0.0.1", 8003),
        status=status,
    )


def test_tcp_state_change_same_identity():
    monitor = NetworkMonitor(
        network_detection_mode="OFF"
    )

    established = fake_connection(
        1234, "ESTABLISHED"
    )

    closing = fake_connection(
        1234, "CLOSE_WAIT"
    )

    assert (
        monitor.make_connection_key(established)
        == monitor.make_connection_key(closing)
    )


def test_pid_loss_same_identity():
    monitor = NetworkMonitor(
        network_detection_mode="OFF"
    )

    established = fake_connection(
        1234, "ESTABLISHED"
    )

    time_wait = fake_connection(
        0, "TIME_WAIT"
    )

    assert (
        monitor.make_connection_key(established)
        == monitor.make_connection_key(time_wait)
    )


def test_closing_connections_skip_detection():
    monitor = NetworkMonitor(
        network_detection_mode="SHADOW"
    )

    class TrackerSpy:
        called = False

        def analyze(self, connection):
            self.called = True
            return []

    spy = TrackerSpy()
    monitor.network_behavior_tracker = spy

    findings = monitor.analyze_network_connection({
        "pid": 1234,
        "process_name": "example.exe",
        "remote_ip": "198.51.100.10",
        "remote_port": 443,
        "status": "TIME_WAIT",
    })

    assert findings == []
    assert spy.called is False