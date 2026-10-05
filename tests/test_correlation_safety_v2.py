"""In-memory correlation regression tests. Never touch live incident storage."""
from datetime import datetime, timezone
import pytest
from detection.fusion.event_correlator import EventCorrelator


def event(identifier, kind, severity="INFO", *, pid=1234, device="device-a",
          when="2026-10-04T12:00:00+00:00", metadata=None):
    return {
        "event_id": identifier, "event_type": kind, "severity": severity,
        "timestamp": when, "device_id": device, "process": {"pid": pid},
        "network": {}, "file": {}, "registry": {}, "metadata": metadata or {},
    }


def test_same_device_process_file_corroborate():
    c = EventCorrelator()
    c.add_event(event("p", "process_fusion_detection", "HIGH"))
    output = c.add_event(event("f", "file_modified"))
    assert output["correlated"] is True
    assert output["related_event_count"] == 1


def test_different_device_same_pid_no_correlation():
    c = EventCorrelator()
    c.add_event(event("p", "process_fusion_detection", "HIGH", device="alpha"))
    output = c.add_event(event("f", "file_modified", "HIGH", device="beta"))
    assert output["related_event_count"] == 0
    assert output["correlated"] is False


def test_info_only_passive_telemetry_never_incident():
    c = EventCorrelator()
    c.add_event(event("p", "process_start"))
    result = c.add_event(event("f", "file_modified"))
    assert result["correlated"] is False


def test_shadow_findings_cannot_correlate():
    c = EventCorrelator()
    c.add_event(event("p", "process_fusion_detection", "HIGH"))
    result = c.add_event(event("f", "file_modified", "HIGH", metadata={"operating_mode": "SHADOW_VALIDATION"}))
    assert result["related_event_count"] == 0
    assert result["correlated"] is False


def test_simulation_events_not_authoritative():
    c = EventCorrelator()
    c.add_event(event("p", "process_fusion_detection", "HIGH"))
    result = c.add_event(event("f", "file_modified", "HIGH", metadata={"simulation_mode": True}))
    assert result["correlated"] is False


def test_real_iso_timestamps_used_not_ingestion_time():
    c = EventCorrelator(correlation_window_seconds=120)
    c.add_event(event("p", "process_fusion_detection", "HIGH", when="2026-10-01T12:00:00Z"))
    result = c.add_event(event("f", "file_modified", "HIGH", when="2026-10-04T12:00:00Z"))
    assert result["correlated"] is False
    assert result["related_event_count"] == 0


def test_invalid_timestamp_does_not_become_current_time():
    c = EventCorrelator()
    c.add_event(event("p", "process_fusion_detection", "HIGH", when="invalid"))
    result = c.add_event(event("f", "file_modified", "HIGH"))
    assert result["related_event_count"] == 0


def test_same_event_id_cannot_corroborate_itself():
    c = EventCorrelator()
    c.add_event(event("id", "process_fusion_detection", "HIGH"))
    result = c.add_event(event("id", "file_modified", "HIGH"))
    assert result["related_event_count"] == 0
    assert result["correlated"] is False


def test_pid_zero_unrelated():
    c = EventCorrelator()
    c.add_event(event("p", "process_fusion_detection", "HIGH", pid=0))
    result = c.add_event(event("f", "file_modified", "HIGH", pid=0))
    assert result["correlated"] is False


def test_incident_manager_never_persists_info_only(monkeypatch):
    import detection.fusion.correlation_manager as module
    saved = []
    class MemoryStore:
        def save_incident(self, incident): saved.append(incident)
    monkeypatch.setattr(module, "IncidentStore", MemoryStore)
    manager = module.CorrelationManager()
    manager.process_event(event("one", "process_start"))
    output = manager.process_event(event("two", "file_modified"))
    assert output["incident_created"] is False
    assert saved == []


def test_incident_manager_real_corroboration_persists_in_mock(monkeypatch):
    import detection.fusion.correlation_manager as module
    saved = []
    class MemoryStore:
        def save_incident(self, incident): saved.append(incident)
    monkeypatch.setattr(module, "IncidentStore", MemoryStore)
    manager = module.CorrelationManager()
    manager.process_event(event("one", "process_fusion_detection", "HIGH"))
    output = manager.process_event(event("two", "file_modified", "MEDIUM"))
    assert output["incident_created"] is True
    assert len(saved) == 1
    assert set(saved[0]["event_ids"]) == {"one", "two"}
