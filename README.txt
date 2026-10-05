SENTINEL-X — File Detection Safety Update (Phase 1)

CHANGED:
  endpoint/collectors/file_monitor.py (complete replacement)
NEW:
  tests/test_file_monitor_safety.py (isolated pytest coverage)
UNCHANGED:
  endpoint/agent/telemetry_manager.py
  endpoint/storage/database.py
  endpoint/storage/init_database.py

RATIONALE:
  EMBER malware inference is currently deferred due to incompatible LIEF/NumPy
  interfaces and unverified training-feature parity. The FileMonitor previously
  eagerly constructed and called the predictor on PE changes. It now defaults
  to malware_detection_enabled=False, avoids loading the model, and reports
  its disabled state in metadata. Do not explicitly enable it until retraining,
  feature-schema validation, and real benign-file inference have passed.

  Previously any valid model result, including prediction=0 (BENIGN), was
  saved as a malware detection. Only a valid prediction=1 now creates a
  malware ML detection row. No changes made to static file analysis,
  file-create/modify/delete/rename telemetry, existing ransomware detector,
  persistence APIs, thresholds or correlation interfaces.

KNOWN ITEMS FOR LATER PHASES:
  1) File watcher does not reliably identify the responsible Windows PID.
     Never manufacture process attribution.
  2) Existing ransomware detector and live correlation require their own
     coordinated inspection; they are not validated by this package.
  3) FileMonitor currently scans all eligible new/modified files with static
     analyzer; benchmark latency on real workloads before wide deployment.
  4) The real behavior of external malware and ransomware dependencies has
     not been integration-tested here; test only with backed-up data.

INSTALL (PowerShell in project root):
  git status --short
  # Back up or commit your work before extracting.
  Expand-Archive -Path .\sentinelx_file_phase_update.zip -DestinationPath . -Force
  python -m py_compile endpoint\collectors\file_monitor.py
  python -m pytest tests\test_file_monitor_safety.py -v
  python -m pytest tests -q

All new tests are isolated: no filesystem watcher, real SQLite persistence,
malware models, or synthetic SOC events are invoked.
