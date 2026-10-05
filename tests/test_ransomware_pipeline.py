"""Isolated FileMonitor-to-detector tests; never use live telemetry or SQLite."""
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from detection.behavior.ransomware_behavior_detector import RansomwareBehaviorDetector


@pytest.fixture
def isolated():
    source = Path(__file__).resolve().parents[1] / 'endpoint/collectors/file_monitor.py'
    tree = ast.parse(source.read_text(encoding='utf-8'))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name in {'SentinelFileEventHandler', 'FileMonitor'}]
    emitted = SimpleNamespace(event_id='isolated-event-id')
    telemetry = Mock()
    telemetry.emit.return_value = emitted
    db_save = Mock()
    ns = {'FileSystemEventHandler': object, 'StaticFileAnalyzer': Mock,
          'MalwarePredictor': Mock, 'RansomwareBehaviorDetector': RansomwareBehaviorDetector,
          'shared_telemetry_manager': telemetry, 'save_detection': db_save,
          'Path': Path, 'Observer': Mock, 'FILE_MONITOR_PATH': 'unused',
          'logger': Mock(), 'time': SimpleNamespace(time=lambda: 1_000)}
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(source), 'exec'), ns)
    handler = ns['SentinelFileEventHandler']()
    handler.get_file_info = Mock(return_value={'exists': False, 'path':'C:/sandbox/a.txt',
                                               'name':'a.txt', 'extension':'.txt','size':None})
    handler.analyze_file = Mock(return_value={})
    return handler, telemetry, db_save


def test_shadow_default_preserves_telemetry_but_no_attack_rows(isolated):
    handler, telemetry, save = isolated
    handler.ransomware_detector = RansomwareBehaviorDetector(
        modification_threshold=2, alert_cooldown_seconds=0)
    last = None
    for i in range(3):
        last = handler.save_file_event('file_modify', f'C:/sandbox/doc{i}.txt')
    assert last['ransomware_detections']
    assert telemetry.emit.call_count == 3
    assert telemetry.emit.call_args.kwargs['metadata']['ransomware_detection_mode'] == 'SHADOW'
    assert telemetry.emit.call_args.kwargs['severity'] == 'INFO'
    save.assert_not_called()


def test_explicit_emit_persists_to_real_event_id_only_in_mock(isolated):
    handler, telemetry, save = isolated
    handler.ransomware_detection_mode = 'EMIT'
    handler.ransomware_detector = RansomwareBehaviorDetector(
        modification_threshold=2, alert_cooldown_seconds=0)
    for i in range(2):
        handler.save_file_event('file_modify', f'C:/sandbox/doc{i}.txt')
    assert save.called
    assert save.call_args.args[0] == 'isolated-event-id'
    assert save.call_args.args[1]['attribution_status'] == 'UNKNOWN'
    assert telemetry.emit.call_args.kwargs['severity'] == 'LOW'


def test_off_mode_never_runs_detector(isolated):
    handler, telemetry, save = isolated
    handler.ransomware_detection_mode = 'OFF'
    handler.ransomware_detector.analyze = Mock(side_effect=AssertionError('Unexpected call'))
    result = handler.save_file_event('file_modify', 'C:/sandbox/doc.txt')
    assert result['ransomware_detections'] == []
    save.assert_not_called()


def test_malware_still_deferred(isolated):
    handler, telemetry, save = isolated
    assert handler.malware_predictor is None
    handler.save_file_event('file_create', 'C:/sandbox/doc.exe')
    save.assert_not_called()
