# SENTINEL-X ransomware behavioral validation update

## Replacements (all complete files)
- detection/behavior/ransomware_behavior_detector.py
- endpoint/collectors/file_monitor.py
- tests/test_ransomware_behavior_detector.py
- tests/test_ransomware_pipeline.py

## Why
- Prior pipeline scripts executed their `main()` only, so pytest did not collect them.
- Their synthetic metadata was sent through real FileMonitor telemetry (unsafe for production SOC data).
- Rename and extension changes from the same operation could combine into a HIGH ransomware alert.
- Watchdog often provides no source PID. Prior history grouped every unknown process together.

## Behavior
- Default Ransomware mode: SHADOW (findings visible in return/metadata, no attack detection rows or ransomware-derived event severity).
- EMIT requires explicit selection and is for later, controlled validation; malware ML inference remains deferred by default.
- Unknown PID: scope file history by directory; only LOW individual heuristic signals, never combined ransomware escalation.
- Known PID: only independent modification and rename/extension signals within a lookback window allow HIGH heuristic combination. This is **not** verified attribution or proof of encryption.
- No file contents are modified by tests; no real telemetry, SQLite or external APIs are called by the tests.
- No malware training models or telemetry manager were modified.

## Windows install
Run in project root and activate `.venv`, after committing or backing up your files.
```
Expand-Archive -Path .\sentinelx_ransomware_phase_update.zip -DestinationPath . -Force
python -m py_compile detection/behavior/ransomware_behavior_detector.py endpoint/collectors/file_monitor.py
python -m pytest tests/test_ransomware_behavior_detector.py tests/test_ransomware_pipeline.py tests/test_file_monitor_safety.py -v
python -m pytest tests -q
```

Do not enable EMIT or execute the old standalone test scripts against the live SOC.
Full Windows regression and live event accuracy remain unverified until you share results.
