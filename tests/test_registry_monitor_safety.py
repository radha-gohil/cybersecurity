"""Isolated registry tests: no real Windows registry, telemetry, or SOC DB access."""
import importlib.util
import pathlib
import sys
import types
from unittest.mock import MagicMock

import pytest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "endpoint/collectors/registry_monitor.py"


@pytest.fixture
def registry_module(monkeypatch):
    winreg = types.ModuleType("winreg")
    winreg.HKEY_CURRENT_USER = 1
    winreg.KEY_READ = 0x20019
    winreg.OpenKey = MagicMock()
    winreg.EnumValue = MagicMock()
    telemetry_package = types.ModuleType("endpoint.agent.telemetry_manager")
    telemetry_package.shared_telemetry_manager = MagicMock()
    logger_package = types.ModuleType("endpoint.utils.logger")
    logger_package.get_logger = lambda _: MagicMock()
    for name, module in {
        "winreg": winreg,
        "endpoint.agent.telemetry_manager": telemetry_package,
        "endpoint.utils.logger": logger_package,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    spec = importlib.util.spec_from_file_location("registry_monitor_under_test", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(name="Sample", value="C:\\Program Files\\example.exe", kind=1):
    return {f"HKEY_CURRENT_USER\\Run\\{name}": {
        "name": name, "value": value, "type": kind,
        "registry_path": "HKEY_CURRENT_USER\\Run",
    }}


def test_invalid_poll_interval(registry_module):
    with pytest.raises(ValueError):
        registry_module.RegistryMonitor(0)


def test_first_snapshot_only_sets_baseline(registry_module):
    monitor = registry_module.RegistryMonitor()
    monitor.get_current_snapshot = lambda: record()
    assert monitor.check_changes() is True
    assert monitor.telemetry.emit.call_count == 0
    assert monitor.known_values == record()


def test_unavailable_snapshot_does_not_generate_deletions(registry_module):
    monitor = registry_module.RegistryMonitor()
    monitor.known_values = record()
    monitor._baseline_ready = True
    monitor.get_current_snapshot = lambda: None
    assert monitor.check_changes() is False
    assert monitor.known_values == record()
    monitor.telemetry.emit.assert_not_called()


def test_create_modify_delete_and_unknown_attribution(registry_module):
    monitor = registry_module.RegistryMonitor()
    snapshots = [record(), record(value="changed.exe"), {}, record()]
    monitor.get_current_snapshot = lambda: snapshots.pop(0)
    for _ in range(4):
        monitor.check_changes()
    calls = monitor.telemetry.emit.call_args_list
    assert [c.kwargs["event_type"] for c in calls] == [
        "registry_modify", "registry_delete", "registry_create"]
    assert all(c.kwargs["severity"] == "INFO" for c in calls)
    assert all(c.kwargs["metadata"]["attribution_status"] == "UNKNOWN" for c in calls)


def test_value_type_change_is_modification(registry_module):
    monitor = registry_module.RegistryMonitor()
    snapshots = [record(kind=1), record(kind=2)]
    monitor.get_current_snapshot = lambda: snapshots.pop(0)
    monitor.check_changes()
    monitor.check_changes()
    call = monitor.telemetry.emit.call_args
    assert call.kwargs["event_type"] == "registry_modify"
    assert call.kwargs["metadata"]["previous_type"] == 1
    assert call.kwargs["metadata"]["new_type"] == 2


def test_permission_error_returns_unknown_not_empty(registry_module):
    m = registry_module
    m.winreg.OpenKey.side_effect = PermissionError("denied")
    assert m.RegistryMonitor().read_registry_key(1, "HKCU", "Run") is None


def test_missing_key_is_empty(registry_module):
    m = registry_module
    m.winreg.OpenKey.side_effect = FileNotFoundError("missing")
    assert m.RegistryMonitor().read_registry_key(1, "HKCU", "Run") == {}


def test_unexpected_enum_error_returns_unknown(registry_module):
    m = registry_module
    m.winreg.OpenKey.return_value.__enter__.return_value = object()
    m.winreg.EnumValue.side_effect = PermissionError("enumeration failed")
    assert m.RegistryMonitor().read_registry_key(1, "HKCU", "Run") is None


def test_partial_snapshot_returns_unavailable(registry_module):
    monitor = registry_module.RegistryMonitor()
    monitor.read_registry_key = MagicMock(side_effect=[record(), None])
    assert monitor.get_current_snapshot() is None
