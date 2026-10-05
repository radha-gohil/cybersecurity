# SENTINEL-X Multi-stage Correlation Safety Update

## Contents
- detection/fusion/event_correlator.py — full replacement
- tests/test_correlation_safety_v2.py — 11 new pytest cases; in-memory events, monkeypatched IncidentStore, no live DB writes

## What changed
- Scopes event relationships to the same endpoint/device. Unknown versus a known device does not match.
- Uses SecurityEvent ISO timestamp when timestamp_unix is absent; rejects invalid timestamps for correlations rather than inventing ingestion-time proximity.
- Requires a related event and at least one authoritative MEDIUM/HIGH/CRITICAL signal before reporting correlation; raw INFO telemetry continues to flow into event storage.
- Excludes SHADOW and simulation_mode=true events from attack corroboration and stops duplicate event_id self-corroboration.
- Reports INFO correlation severity when no valid correlation exists.
- Retains existing scoring engine, entity linking, manager, store and telemetry interfaces.

## Install (Windows PowerShell, at repository root)
Back up/commit existing work first; unzip into D:\R_project\cybersecurity:

    Expand-Archive -Path .\sentinelx_correlation_phase_update.zip -DestinationPath . -Force

    python -m py_compile detection/fusion/event_correlator.py
    python -m pytest tests/test_correlation_safety_v2.py -v
    python -m pytest tests -q

## Scope/limitations
- Live Windows end-to-end event-to-incident persistence not yet validated; run when ready with real telemetry and backed-up DB.
- Legacy tests in the review ZIP expose standalone `main()` calls and are not auto-collected as pytest functions; run them only in an isolated environment after auditing side effects.
- Legacy phishing/authentication scoring remains present in historical source for compatibility; these detections are outside the project scope and should not be actively sourced.
- A real EntityLinker implementation is expected in the user's repository. The isolated test harness used a no-link stub solely because it was not supplied in the review archive; this stub is NOT shipped in the ZIP.
- The entity index is still keyed by PID/path/hash/IP and filters by device after lookup; process-identity reuse and evidence lineage deserve later full SOC validation.
