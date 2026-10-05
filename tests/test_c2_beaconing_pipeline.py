"""Isolated periodicity detector tests; no simulated live security records.

The detector is heuristic: periodic connections alone do not prove C2.
"""
from detection.network.network_behavior_tracker import NetworkBehaviorTracker
from endpoint.collectors.network_monitor import NetworkMonitor


def sample(pid=7000, status="ESTABLISHED"):
    return {
        "pid": pid, "process_name": "test_beacon.exe", "protocol": "TCP",
        "local_ip": "192.0.2.10", "local_port": 53000,
        "remote_ip": "203.0.113.200", "remote_port": 443,
        "status": status,
    }


def tracker():
    return NetworkBehaviorTracker(
        connection_burst_threshold=100,
        port_scan_threshold=100,
        dos_connection_threshold=100,
        beacon_min_connections=5,
        beacon_history_seconds=300,
        beacon_min_interval_seconds=5,
        beacon_max_interval_seconds=60,
        beacon_max_coefficient_variation=0.15,
        alert_cooldown_seconds=0,
    )


def test_regular_connections_trigger_beaconing_heuristic():
    engine = tracker()
    findings = []
    for i in range(6):
        findings.extend(engine.analyze(sample(), current_time=1700100000 + i * 10))
    matching = [f for f in findings if f["detection_type"] == "SUSPICIOUS_BEACONING"]
    assert matching
    assert matching[-1]["detection_method"] == "RULE_BASED_PERIODICITY_ANALYSIS"
    assert "legitimate" in matching[-1]["interpretation"].lower()


def test_irregular_intervals_do_not_trigger_beaconing():
    engine = tracker()
    findings = []
    for offset in (0, 6, 17, 48, 54, 95):
        findings.extend(engine.analyze(sample(), current_time=1700100000 + offset))
    assert "SUSPICIOUS_BEACONING" not in {f["detection_type"] for f in findings}


def test_monitor_shadow_path_does_not_emit_or_persist():
    monitor = object.__new__(NetworkMonitor)
    monitor.network_detection_mode = "SHADOW"
    monitor.network_behavior_tracker = tracker()

    class ForbiddenTelemetry:
        def emit(self, **_):
            raise AssertionError("SHADOW must not write alerts")

    monitor.telemetry = ForbiddenTelemetry()
    monitor.persist_network_detection = lambda **_: (_ for _ in ()).throw(
        AssertionError("SHADOW must not write detections")
    )
    findings = []
    times = iter(1700100000 + i * 10 for i in range(6))
    monitor.network_behavior_tracker.now_timestamp = lambda: next(times)
    for _ in range(6):
        findings.extend(monitor.analyze_network_connection(sample()))
    assert any(f["detection_type"] == "SUSPICIOUS_BEACONING" for f in findings)
