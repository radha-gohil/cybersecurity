"""Isolated FileMonitor regression tests: never touch the live SOC database."""
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.fixture
def env():
    source = Path(__file__).resolve().parents[1] / "endpoint/collectors/file_monitor.py"
    module_ast = ast.parse(source.read_text(encoding="utf-8"))
    classes = [n for n in module_ast.body if isinstance(n, ast.ClassDef)
               and n.name in {"SentinelFileEventHandler", "FileMonitor"}]
    # Reuse exact real class bodies without importing telemetry services or opening SQLite.
    ns = {
        "FileSystemEventHandler": object,
        "StaticFileAnalyzer": Mock,
        "MalwarePredictor": Mock,
        "RansomwareBehaviorDetector": Mock,
        "shared_telemetry_manager": Mock(),
        "save_detection": Mock(),
        "time": SimpleNamespace(time=lambda: 1234.0),
        "Path": Path,
        "Observer": Mock,
        "FILE_MONITOR_PATH": "unused",
        "logger": Mock(),
    }
    ns["shared_telemetry_manager"].emit.return_value = SimpleNamespace(event_id="isolated-test-event")
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(source), "exec"), ns)
    return ns


def prepare(env, *, enabled=False, prediction=None):
    handler = env["SentinelFileEventHandler"](malware_detection_enabled=enabled)
    handler.get_file_info = Mock(return_value={
        "name": "sample.exe", "path": "sample.exe", "extension": ".exe",
        "exists": True, "size": 123,
    })
    handler.analyze_file = Mock(return_value={
        "is_pe": True, "sha256": "hash-for-test", "severity": "INFO",
        "risk_score": 0,
    })
    handler.analyze_ransomware_behavior = Mock(return_value=[])
    handler.predict_malware = Mock(return_value=prediction or {})
    return handler


def test_malware_is_deferred_by_default(env):
    handler = prepare(env)
    result = handler.save_file_event("file_create", "sample.exe")
    handler.predict_malware.assert_not_called()
    env["save_detection"].assert_not_called()
    assert result["malware_detection"] is None
    assert env["shared_telemetry_manager"].emit.call_args.kwargs["metadata"]["malware_ml_enabled"] is False


def test_benign_ml_prediction_does_not_create_detection(env):
    handler = prepare(env, enabled=True, prediction={
        "valid": True, "prediction": 0, "malware_probability": 0.03,
        "benign_probability": 0.97, "severity": "INFO", "confidence": 0.97,
    })
    result = handler.save_file_event("file_create", "sample.exe")
    handler.predict_malware.assert_called_once_with("sample.exe")
    assert result["malware_detection"] is None
    env["save_detection"].assert_not_called()


def test_invalid_model_result_creates_no_detection(env):
    handler = prepare(env, enabled=True, prediction={"valid": False, "prediction": None})
    handler.save_file_event("file_create", "sample.exe")
    env["save_detection"].assert_not_called()


def test_malicious_model_result_uses_real_event_id_contract_in_mock(env):
    handler = prepare(env, enabled=True, prediction={
        "valid": True, "prediction": 1, "malware_probability": 0.98,
        "benign_probability": 0.02, "severity": "HIGH", "confidence": 0.98,
    })
    result = handler.save_file_event("file_create", "sample.exe")
    assert result["malware_detection"]["prediction"] == 1
    assert env["save_detection"].call_args.args[0] == "isolated-test-event"


def test_delete_event_retains_telemetry_without_model(env):
    handler = prepare(env, enabled=True)
    handler.get_file_info.return_value["exists"] = False
    handler.save_file_event("file_delete", "gone.exe")
    handler.predict_malware.assert_not_called()
    assert env["shared_telemetry_manager"].emit.call_args.kwargs["event_type"] == "file_delete"
