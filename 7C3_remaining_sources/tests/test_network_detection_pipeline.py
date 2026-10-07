"""Safe, in-memory network detection regression tests.

No sockets, production telemetry, database writes, or incident creation.
"""
from types import SimpleNamespace

from detection.network.network_behavior_tracker import NetworkBehaviorTracker
from endpoint.collectors.network_monitor import NetworkMonitor


def connection(port, pid=4321, status="ESTABLISHED", target="203.0.113.25"):
    return {
        "pid": pid, "process_name": "unit_test_process.exe",
        "protocol": "TCP", "local_ip": "192.0.2.10",
        "local_port": 50000 + int(port), "remote_ip": target,
        "remote_port": port, "status": status,
    }


def test_port_scan_detection_in_memory():
    tracker = NetworkBehaviorTracker(
        connection_burst_threshold=100,
        port_scan_threshold=5,
        dos_connection_threshold=100,
        beacon_min_connections=100,
        alert_cooldown_seconds=0,
    )
    findings = []
    for i, port in enumerate((21, 22, 23, 80, 443, 445)):
        findings.extend(tracker.analyze(connection(port), current_time=1700100000 + i))
    assert "PORT_SCAN_BEHAVIOR" in {f["detection_type"] for f in findings}


def test_pid_zero_and_teardown_not_used_as_attack_evidence():
    tracker = NetworkBehaviorTracker(connection_burst_threshold=1, port_scan_threshold=1)
    assert tracker.analyze(connection(443, pid=0), current_time=1700100000) == []
    assert tracker.analyze(connection(443, status="TIME_WAIT"), current_time=1700100001) == []


def test_shadow_mode_never_emits_alerts_or_writes_detections():
    monitor = object.__new__(NetworkMonitor)
    monitor.network_detection_mode = "SHADOW"
    monitor.network_behavior_tracker = NetworkBehaviorTracker(
        connection_burst_threshold=100,
        port_scan_threshold=3,
        dos_connection_threshold=100,
        beacon_min_connections=100,
        alert_cooldown_seconds=0,
    )

    class ForbiddenTelemetry:
        def emit(self, **_):
            raise AssertionError("SHADOW must never emit an attack event")

    monitor.telemetry = ForbiddenTelemetry()
    monitor.persist_network_detection = lambda **_: (_ for _ in ()).throw(
        AssertionError("SHADOW must never persist a detection")
    )
    findings = []
    for port in (21, 22, 23):
        findings.extend(monitor.analyze_network_connection(connection(port)))
    assert any(f["detection_type"] == "PORT_SCAN_BEHAVIOR" for f in findings)


def test_emit_mode_uses_alert_event_id_for_detection_without_real_storage():
    monitor = object.__new__(NetworkMonitor)
    monitor.network_detection_mode = "EMIT"
    monitor.network_behavior_tracker = NetworkBehaviorTracker(
        connection_burst_threshold=100, port_scan_threshold=2,
        dos_connection_threshold=100, beacon_min_connections=100,
        alert_cooldown_seconds=0,
    )
    emitted, saved = [], []

    class FakeTelemetry:
        def emit(self, **kwargs):
            emitted.append(kwargs)
            return SimpleNamespace(event_id="isolated-test-alert")

    monitor.telemetry = FakeTelemetry()
    monitor.persist_network_detection = lambda **kwargs: saved.append(kwargs) or True
    for port in (80, 443):
        monitor.analyze_network_connection(connection(port), source_event_id="source-unit-test")
    assert len(emitted) == 1
    assert emitted[0]["event_type"] == "network_behavior_alert"
    assert emitted[0]["metadata"]["source_event_id"] == "source-unit-test"
    assert len(saved) == 1
    assert saved[0]["event_id"] == "isolated-test-alert"
