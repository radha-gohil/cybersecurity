SENTINEL-X Network Detection (Phase 1) — isolated replacement bundle

Replace only these files in repository:
 endpoint/collectors/network_monitor.py
 detection/network/network_behavior_tracker.py
 tests/test_network_detection_pipeline.py
 tests/test_c2_beaconing_pipeline.py

Changes:
 * Validate process identity before attributing network behavior to it.
 * Exclude invalid/PID0 and TCP-closing records from direct tracker inference.
 * Preserve network telemetry, connection tuple identity, and OFF/SHADOW/EMIT semantics.
 * Replace out-of-date standalone scripts (behavior_tracker attribute and dict-return assumptions)
   with pytest-discoverable tests. New tests use in-memory evidence and stubbed storage/telemetry.
 * NO changes to network detection thresholds or live alert mode.

On user's Windows environment:
 python -m py_compile endpoint/collectors/network_monitor.py detection/network/network_behavior_tracker.py
 python -m pytest tests/test_network_detection_pipeline.py tests/test_c2_beaconing_pipeline.py -v
 python -m pytest tests -q

Caution: The focused sandbox tests only assert behavior of uploaded modules, with external imports stubbed.
 They do not validate runtime network threat accuracy, real traffic rates, or downstream SOC integration.
 Other network modules (network_attack_detector.py, network_rule_engine.py, network_event_factory.py,
 network_severity_mapper.py) were not uploaded and remain to be reviewed if they are active in live runtime.
