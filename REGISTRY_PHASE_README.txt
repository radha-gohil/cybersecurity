SENTINEL-X Registry Detection — Phase 1 evidence reliability update

Files to copy into repository root:
  endpoint/collectors/registry_monitor.py
  tests/test_registry_monitor_safety.py

BACK UP / COMMIT your work before extracting.

This update maintains the existing RegistryMonitor API and HKCU Run/RunOnce coverage.
It does NOT change response/persistence_response_manager.py, telemetry_manager.py,
or database.py. It does NOT add autorun detection rules, modify registry keys,
or generate synthetic production telemetry.

Changes:
- Treat permission/partial enumeration failures as unavailable snapshots, never
  as empty snapshots, preventing spurious delete/recreate events.
- Require a reliable first baseline before reporting changes.
- Detect actual changes in registry VALUE TYPE as well as VALUE CONTENT.
- Preserve INFO severity and unknown process attribution (snapshot polling
  cannot establish the originating PID).
- Preserve read-only registry OpenKey(KEY_READ) monitoring.

Windows validation:
  python -m py_compile endpoint/collectors/registry_monitor.py
  python -m pytest tests/test_registry_monitor_safety.py -v
  python -m pytest tests -q

Limitations:
- HKCU Run/RunOnce only; does not cover HKLM, services, scheduled tasks,
  other user profiles, or all persistence techniques.
- Snapshot polling can miss fast add/remove transitions.
- No maliciousness verdict is inferred from a registry change alone.
- Live Windows behavior must be validated separately.
