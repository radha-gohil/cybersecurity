"""No files, live telemetry, model loading or external services required."""
import pytest
from detection.behavior.ransomware_behavior_detector import RansomwareBehaviorDetector


def detector():
    return RansomwareBehaviorDetector(modification_threshold=3, rename_threshold=3,
                                      extension_change_threshold=3,
                                      alert_cooldown_seconds=30)


def file_event(n, pid=None, folder='work'):
    return {'event_type': 'file_modify', 'process_id': pid,
            'file_path': f'C:/sandbox/{folder}/doc{n}.txt'}


def rename_event(n, pid=None, folder='work'):
    return {'event_type': 'file_rename', 'process_id': pid,
            'file_path': f'C:/sandbox/{folder}/doc{n}.locked',
            'old_path': f'C:/sandbox/{folder}/doc{n}.txt',
            'new_path': f'C:/sandbox/{folder}/doc{n}.locked'}


def test_unknown_process_reports_low_evidence_not_high_ransomware():
    d = detector()
    found = []
    for i in range(4):
        found += d.analyze(file_event(i), current_time=100+i)
        found += d.analyze(rename_event(i), current_time=110+i)
    assert {'FILE_MODIFICATION_BURST', 'MASS_FILE_RENAME', 'EXTENSION_CHANGE_BURST'} <= {
        x['detection_type'] for x in found}
    assert all(x['severity'] == 'LOW' for x in found)
    assert not any(x['detection_type'] == 'POSSIBLE_RANSOMWARE_BEHAVIOR' for x in found)
    assert all(x['attribution_status'] == 'UNKNOWN' for x in found)


def test_unknown_process_scoped_by_directory():
    d = detector()
    findings = []
    for i in range(2):
        findings.extend(d.analyze(file_event(i, folder='one'), 100+i))
        findings.extend(d.analyze(file_event(i, folder='two'), 100+i))
    assert findings == []


def test_single_rename_behavior_cannot_manufacture_combined_result():
    d = detector()
    found = []
    for i in range(4):
        found.extend(d.analyze(rename_event(i, pid=1001), 100+i))
    kinds = {x['detection_type'] for x in found}
    assert 'MASS_FILE_RENAME' in kinds and 'EXTENSION_CHANGE_BURST' in kinds
    assert 'POSSIBLE_RANSOMWARE_BEHAVIOR' not in kinds


def test_independent_modification_plus_extension_corrob_in_same_pid():
    d = detector()
    found = []
    for i in range(4):
        found.extend(d.analyze(file_event(i, pid=1001), 100+i))
    for i in range(4):
        found.extend(d.analyze(rename_event(i, pid=1001), 110+i))
    combined = [x for x in found if x['detection_type'] == 'POSSIBLE_RANSOMWARE_BEHAVIOR']
    assert len(combined) == 1
    assert combined[0]['severity'] == 'HIGH'
    assert combined[0]['process_id'] == 1001
    assert 'FILE_MODIFICATION_BURST' in combined[0]['signals']


def test_different_processes_do_not_combine():
    d = detector()
    results = []
    for i in range(4):
        results += d.analyze(file_event(i, pid=1001), 100+i)
        results += d.analyze(rename_event(i, pid=2002), 110+i)
    assert not any(x['detection_type'] == 'POSSIBLE_RANSOMWARE_BEHAVIOR' for x in results)


def test_unknown_pid_zero_not_trusted():
    d = detector()
    results = []
    for i in range(4):
        results.extend(d.analyze(file_event(i, pid=0), 100+i))
    assert any(x['attribution_status'] == 'UNKNOWN' for x in results)


def test_duplicate_modifications_not_counted_as_distinct_files():
    d = detector()
    results = []
    for i in range(8):
        results.extend(d.analyze(file_event(0, pid=1001), 100+i))
    assert not results


def test_invalid_timestamp_and_missing_path_fail_closed():
    d = detector()
    assert d.analyze(file_event(0), current_time=float('nan')) == []
    assert d.analyze({'event_type':'file_modify'}, 100) == []


def test_bad_settings_rejected():
    with pytest.raises(ValueError):
        RansomwareBehaviorDetector(modification_threshold=0)
